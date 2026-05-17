<?php
/**
 * session_analysis.php — build attributed sessions from nginx_visits
 *
 * Groups nginx requests per IP into sessions (30-min idle = new session),
 * computes behavioural signals, scores, and classifies each session.
 * Also enriches ip_intel with ASN/provider/bot-verification data.
 *
 * ── Cron entry ───────────────────────────────────────────────────────────────
 *
 *   * * * * * www-data /usr/bin/php /var/www/thameur.org/cron/session_analysis.php
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

if (php_sapi_name() !== 'cli') { http_response_code(403); exit; }

define('ADMIN_NO_LOG', true);
require_once __DIR__ . '/../config.php';

define('SESSION_GAP',   30);   // idle minutes before a new session begins
define('MAX_LOOK_BACK', 1440); // cap first-run look-back to 24 h (minutes)

$pdo = admin_pdo();
if (!$pdo) { fwrite(STDERR, "[session_analysis] DB unavailable\n"); exit(1); }

// ── Cursor ────────────────────────────────────────────────────────────────────
$row          = $pdo->query("SELECT last_analyzed FROM session_cursor WHERE id=1")->fetch();
$last_ts      = $row ? strtotime($row['last_analyzed']) : 0;
$min_ts       = max($last_ts, time() - MAX_LOOK_BACK * 60);

// look_from: one SESSION_GAP before last run to re-capture sessions that were open
$look_from    = date('Y-m-d H:i:s.000', $min_ts - SESSION_GAP * 60);
// process_up_to: only sessions whose last request is older than SESSION_GAP (closed)
$process_upto = date('Y-m-d H:i:s.000', time() - SESSION_GAP * 60);

if ($look_from >= $process_upto) exit(0); // too soon since last run

// ── IPs active in window ──────────────────────────────────────────────────────
$st = $pdo->prepare(
    "SELECT DISTINCT ip FROM nginx_visits
     WHERE created_at BETWEEN ? AND ? AND ip != ''"
);
$st->execute([$look_from, $process_upto]);
$ips = $st->fetchAll(PDO::FETCH_COLUMN);
if (!$ips) {
    _cursor_save($pdo, $process_upto);
    exit(0);
}

// ── Process each IP ───────────────────────────────────────────────────────────
$upsert = $pdo->prepare(
    "INSERT INTO sessions
       (ip,session_start,session_end,duration_s,req_count,uniq_paths,ua_count,
        c404,c5xx,exploit_hits,has_scanner,replay_pairs,pki_hits,score,classification,signals)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
     ON DUPLICATE KEY UPDATE
       session_end=VALUES(session_end), duration_s=VALUES(duration_s),
       req_count=VALUES(req_count), uniq_paths=VALUES(uniq_paths),
       ua_count=VALUES(ua_count), c404=VALUES(c404), c5xx=VALUES(c5xx),
       exploit_hits=VALUES(exploit_hits), has_scanner=VALUES(has_scanner),
       replay_pairs=VALUES(replay_pairs), pki_hits=VALUES(pki_hits),
       score=VALUES(score), classification=VALUES(classification),
       signals=VALUES(signals), analyzed_at=NOW()"
);

$bot_claim_upd = $pdo->prepare(
    "INSERT INTO ip_intel (ip, bot_claimed) VALUES (?, ?)
     ON DUPLICATE KEY UPDATE bot_claimed=VALUES(bot_claimed)"
);

$total_sessions = 0;
$req_st = $pdo->prepare(
    "SELECT created_at, method, uri, query_string, status, user_agent
     FROM nginx_visits WHERE ip=? AND created_at BETWEEN ? AND ?
     ORDER BY created_at ASC"
);

foreach ($ips as $ip) {
    $req_st->execute([$ip, $look_from, $process_upto]);
    $reqs = $req_st->fetchAll();
    if (!$reqs) continue;

    foreach (_split_sessions($reqs) as $sess) {
        $a = analyzeSession($sess);
        $upsert->execute([
            $ip, $a['session_start'], $a['session_end'], $a['duration_s'],
            $a['req_count'], $a['uniq_paths'], $a['ua_count'],
            $a['c404'], $a['c5xx'], $a['exploit_hits'], $a['has_scanner'],
            $a['replay_pairs'], $a['pki_hits'], $a['score'],
            $a['classification'], $a['signals'],
        ]);
        $total_sessions++;

        // Record bot claim for rDNS verification
        if ($a['bot_claimed']) {
            try { $bot_claim_upd->execute([$ip, $a['bot_claimed']]); } catch (Throwable) {}
        }
    }
}

// ── ASN / provider enrichment ─────────────────────────────────────────────────
ip_intel_enrich($ips);

// ── Bot rDNS verification ─────────────────────────────────────────────────────
_verify_claimed_bots($pdo);

// ── Save cursor ───────────────────────────────────────────────────────────────
_cursor_save($pdo, $process_upto);

if ($total_sessions > 0) {
    echo '[' . gmdate('Y-m-d H:i:s') . " UTC] Analyzed $total_sessions sessions across " . count($ips) . " IPs\n";
}
exit(0);

// ── Helpers ───────────────────────────────────────────────────────────────────

function _split_sessions(array $reqs): array {
    if (!$reqs) return [];
    $gap  = SESSION_GAP * 60;
    $out  = [];
    $curr = [$reqs[0]];
    $prev = strtotime($reqs[0]['created_at']);
    for ($i = 1; $i < count($reqs); $i++) {
        $ts = strtotime($reqs[$i]['created_at']);
        if ($ts - $prev > $gap) { $out[] = $curr; $curr = []; }
        $curr[] = $reqs[$i];
        $prev   = $ts;
    }
    if ($curr) $out[] = $curr;
    return $out;
}

// Standard web resources often absent but legitimately probed by OS/social platforms.
const NORMAL_MISS_PATHS = [
    '/favicon.ico', '/favicon-16.png', '/favicon-32.png',
    '/apple-touch-icon.png', '/apple-touch-icon-precomposed.png',
    '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
    '/img/og-social.png',
];

function detectThreats(array $paths, array $uas): array {
    $scanner_rx  = '/nikto|nmap|sqlmap|masscan|zgrab|gobuster|nuclei|whatweb|wapiti|'
                 . 'burp|acunetix|nessus|openvas|hydra|metasploit|feroxbuster|ffuf|wfuzz|dirsearch/i';
    $exploit_rx  = '#' . honeypot_php_fragment()
                 . '|UNION.{1,20}SELECT|<script|base64_decode#i';
    $pki_rx      = '\/(cert_factory|mpca_factory|x509parse|artifact_parser|'
                 . 'cps_to_br_assessor|csr_generator|ct_log|tsa|eseal|linters|revocation)\.php';

    $has_scanner     = false;
    $bot_claimed     = null;
    $social_platform = null;
    foreach ($uas as $ua) {
        if (!$has_scanner && preg_match($scanner_rx, $ua)) { $has_scanner = true; }
        if (!$bot_claimed)     { $bot_claimed     = _detect_bot_claim($ua); }
        if (!$social_platform) { $social_platform = detectSocialPlatform($ua); }
    }

    return [
        'has_scanner'     => $has_scanner,
        'bot_claimed'     => $bot_claimed,
        'social_platform' => $social_platform,
        'exploit_hits'    => count(array_filter($paths, fn($p) => preg_match($exploit_rx, $p))),
        'pki_hits'        => count(array_filter($paths, fn($p) => preg_match("/$pki_rx/i", $p))),
    ];
}

function scoreSession(array $reqs, array $paths, int $ua_count, int $c5xx,
                      float $req_rate, array $threats): array {
    $has_scanner  = $threats['has_scanner'];
    $exploit_hits = $threats['exploit_hits'];
    $pki_hits     = $threats['pki_hits'];

    // 404 enumeration — exclude standard missing resources (favicon, OG, robots, etc.)
    $scan_404_uris  = array_unique(array_filter(array_map(
        fn($r) => (int)$r['status'] === 404 && !in_array($r['uri'], NORMAL_MISS_PATHS) ? $r['uri'] : null,
        $reqs
    )));
    $uniq_scan_404s = count($scan_404_uris);

    // Replay detection — same uri+qs ≥2 times (skip trivial paths)
    $skip_replay = ['/', '/index.php', '/favicon.ico', '/robots.txt'];
    $uri_freq    = [];
    foreach ($reqs as $r) {
        if (in_array($r['uri'], $skip_replay)) { continue; }
        $key = $r['uri'] . '?' . ($r['query_string'] ?? '');
        $uri_freq[$key] = ($uri_freq[$key] ?? 0) + 1;
    }
    $replay_pairs = count(array_filter($uri_freq, fn($c) => $c >= 2));

    // Recon sequence — robots.txt or sitemap in first 5 requests
    $first5    = array_slice($paths, 0, 5);
    $recon_seq = (bool)array_filter($first5, fn($p) => preg_match('/robots\.txt|sitemap/i', $p));

    if ($req_rate > 100)    { $s_rate = 20; }
    elseif ($req_rate > 30) { $s_rate = 10; }
    else                    { $s_rate = 0; }

    if ($pki_hits > 20)     { $s_pki = 15; }
    elseif ($pki_hits > 10) { $s_pki = 8; }
    else                    { $s_pki = 0; }

    $s_ua_switch = $ua_count > 1 ? 30 : 0;
    $s_scanner   = $has_scanner  ? 25 : 0;
    $s_probe     = min($exploit_hits * 15, 45);
    $s_enum      = min($uniq_scan_404s * 8, 40);
    $s_5xx       = min($c5xx * 5, 20);
    $s_replay    = min($replay_pairs * 8, 24);
    $s_recon     = $recon_seq ? 8 : 0;

    return [
        'replay_pairs' => $replay_pairs,
        'score'        => min($s_ua_switch + $s_scanner + $s_probe + $s_enum
                            + $s_5xx + $s_rate + $s_replay + $s_pki + $s_recon, 100),
        'signals'      => [
            'ua_switch' => $s_ua_switch, 'scanner' => $s_scanner,
            'probe'     => $s_probe,     'enum'    => $s_enum,
            '5xx'       => $s_5xx,       'rate'    => $s_rate,
            'replay'    => $s_replay,    'pki'     => $s_pki,
            'recon'     => $s_recon,
        ],
    ];
}

function analyzeSession(array $reqs): array {
    $start     = strtotime($reqs[0]['created_at']);
    $end       = strtotime(end($reqs)['created_at']);
    $duration  = max($end - $start, 1);
    $req_count = count($reqs);
    $req_rate  = $req_count / max($duration / 60, 0.1);

    $paths    = array_column($reqs, 'uri');
    $statuses = array_column($reqs, 'status');
    $uas      = array_unique(array_filter(
        array_column($reqs, 'user_agent'),
        fn($u) => $u !== '' && $u !== '-'
    ));

    $c404       = count(array_filter($statuses, fn($s) => (int)$s === 404));
    $c5xx       = count(array_filter($statuses, fn($s) => (int)$s >= 500));
    $uniq_paths = count(array_unique($paths));
    $ua_count   = max(1, count($uas));

    $threats = detectThreats($paths, $uas);
    $scored  = scoreSession($reqs, $paths, $ua_count, $c5xx, $req_rate, $threats);

    $score           = $scored['score'];
    $has_scanner     = $threats['has_scanner'];
    $exploit_hits    = $threats['exploit_hits'];
    $bot_claimed     = $threats['bot_claimed'];
    $social_platform = $threats['social_platform'];

    $class = match(true) {
        ($has_scanner || $exploit_hits > 0) && $score >= 50 => 'attacker',
        $score >= 70                                         => 'attacker',
        $score >= 40                                         => 'scanner',
        $score >= 15                                         => 'researcher',
        $social_platform !== null && $score < 15            => 'social_probe',
        $bot_claimed !== null                                => 'crawler',
        $req_count <= 5 && $score < 10                      => 'human',
        default                                              => 'unknown',
    };

    return [
        'session_start'  => $reqs[0]['created_at'],
        'session_end'    => end($reqs)['created_at'],
        'duration_s'     => $duration,
        'req_count'      => $req_count,
        'uniq_paths'     => $uniq_paths,
        'ua_count'       => $ua_count,
        'c404'           => $c404,
        'c5xx'           => $c5xx,
        'exploit_hits'   => $exploit_hits,
        'has_scanner'    => $has_scanner ? 1 : 0,
        'replay_pairs'   => $scored['replay_pairs'],
        'pki_hits'       => $threats['pki_hits'],
        'score'          => $score,
        'classification' => $class,
        'bot_claimed'    => $bot_claimed,
        'signals'        => json_encode(
            $scored['signals'] + ['social' => $social_platform]
        ),
    ];
}

function _detect_bot_claim(string $ua): ?string {
    static $BOTS = [
        'Googlebot'   => 'googlebot',
        'bingbot'     => 'bingbot',
        'Applebot'    => 'applebot',
        'DuckDuckBot' => 'duckduckbot',
        'YandexBot'   => 'yandexbot',
        'Baiduspider' => 'baiduspider',
    ];
    foreach ($BOTS as $sig => $name) {
        if (stripos($ua, $sig) !== false) return $name;
    }
    // Generic self-identified bot: Mozilla/5.0 (compatible; BotName/ver; +https://contact-url)
    // The +https:// convention is how well-behaved bots announce a contact/info URL.
    if (preg_match('/\(compatible;\s*([a-z][a-z0-9._-]*\/[^\s;)]+)[^)]*\+https?:\/\//i', $ua, $m)) {
        return strtolower(preg_replace('/[^a-z0-9._-]/', '-', $m[1]));
    }
    return null;
}

function detectSocialPlatform(string $ua): ?string {
    static $PLATFORMS = [
        'LinkedInBot'         => 'linkedin',
        'LinkedInApp'         => 'linkedin',
        'facebookexternalhit' => 'facebook',
        'Facebot'             => 'facebook',
        'Twitterbot'          => 'twitter',
        'Instagram'           => 'instagram',
        'WhatsApp'            => 'whatsapp',
        'Slackbot'            => 'slack',
        'TelegramBot'         => 'telegram',
        'NetworkingExtension' => 'ios_os',
        'Discordbot'          => 'discord',
        'Pinterest'           => 'pinterest',
    ];
    foreach ($PLATFORMS as $sig => $name) {
        if (stripos($ua, $sig) !== false) { return $name; }
    }
    return null;
}

function _verify_claimed_bots(PDO $pdo): void {
    static $RDNS_SUFFIXES = [
        'googlebot'   => ['.googlebot.com', '.google.com'],
        'bingbot'     => ['.search.msn.com'],
        'applebot'    => ['.applebot.apple.com', '.apple.com'],
        'duckduckbot' => ['.duckduckgo.com'],
        'yandexbot'   => ['.yandex.ru', '.yandex.net', '.yandex.com'],
        'baiduspider' => ['.baidu.com'],
    ];

    $pending = $pdo->query(
        "SELECT ip, bot_claimed FROM ip_intel
         WHERE bot_claimed IS NOT NULL AND bot_verified IS NULL
         LIMIT 20"
    )->fetchAll();

    $upd = $pdo->prepare(
        "UPDATE ip_intel SET bot_verified=?, rdns=? WHERE ip=?"
    );
    foreach ($pending as $row) {
        $ip       = $row['ip'];
        $bot      = $row['bot_claimed'];
        $hostname = @gethostbyaddr($ip);
        if (!$hostname || $hostname === $ip) { $upd->execute([0, null, $ip]); continue; }

        // Forward DNS must resolve back to the same IP
        if (@gethostbyname($hostname) !== $ip) { $upd->execute([0, $hostname, $ip]); continue; }

        $suffixes = $RDNS_SUFFIXES[$bot] ?? [];
        $hn_lower = strtolower($hostname);
        $verified = (int)(bool)array_filter($suffixes, fn($s) => str_ends_with($hn_lower, $s));
        $upd->execute([$verified, $hostname, $ip]);
    }
}

function _cursor_save(PDO $pdo, string $ts): void {
    $pdo->prepare(
        "INSERT INTO session_cursor (id, last_analyzed) VALUES (1, ?)
         ON DUPLICATE KEY UPDATE last_analyzed=VALUES(last_analyzed)"
    )->execute([$ts]);
}
