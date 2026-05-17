<?php
define('ADMIN_NO_LOG', true);
require_once __DIR__ . '/config.php';

$email = admin_auth_check();
if (!$email) { header('Location: ' . ADMIN_LOGIN_URL, true, 302); exit; }

$pdo = admin_pdo();

// Record admin's current IP as "mine" on every page load
$_admin_ip = substr(trim(explode(',',
    $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_REAL_IP'] ??
    $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '')[0]), 0, 45);
if ($_admin_ip !== '') my_ip_record($_admin_ip);
$my_ips_set = my_ips_load(); // [ip => row] — used everywhere for "me" badge

// ── Tab ────────────────────────────────────────────────────────────────────────
$tab = match($_GET['tab'] ?? '') {
    'users'   => 'users',
    'blocked' => 'blocked',
    'nginx'   => 'nginx',
    'soc'     => 'soc',
    'myips'   => 'myips',
    default   => 'php',
};

// ── Block / Unblock — global POST, any tab ────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && _admin_csrf_ok()) {
    $__act = $_POST['action'] ?? '';
    if ($__act === 'block_ip') {
        $__ip    = trim($_POST['ip']     ?? '');
        $__rsn   = trim($_POST['reason'] ?? '');
        $__redir = in_array($_POST['redirect_tab'] ?? '', ['php','nginx','soc','blocked','users'])
            ? ($_POST['redirect_tab']) : 'blocked';
        $__err   = filter_var($__ip, FILTER_VALIDATE_IP)
            ? block_ip($__ip, $__rsn ?: null, $email)
            : 'Invalid IP address.';
        header('Location: ?tab=' . $__redir . ($__err ? '&err=' . urlencode($__err) : '&ok=1'));
        exit;
    }
    if ($__act === 'unblock_ip') {
        $__ip  = trim($_POST['ip'] ?? '');
        $__err = $__ip ? unblock_ip($__ip) : 'Invalid IP.';
        header('Location: ?tab=blocked' . ($__err ? '&err=' . urlencode($__err) : '&ok=1'));
        exit;
    }
    if ($__act === 'ack_error') {
        $__id = (int)($_POST['id'] ?? 0);
        if ($__id > 0) ack_error($__id);
        header('Location: ' . ($_SERVER['HTTP_REFERER'] ?? '?'));
        exit;
    }
    if ($__act === 'ack_all_errors') {
        ack_all_errors();
        header('Location: ' . ($_SERVER['HTTP_REFERER'] ?? '?'));
        exit;
    }
}

// ── My IPs CRUD (POST) ───────────────────────────────────────────────────────
$mi_flash = ''; $mi_flash_ok = true;
if ($tab === 'myips' && $_SERVER['REQUEST_METHOD'] === 'POST' && _admin_csrf_ok()) {
    $act = $_POST['action'] ?? '';
    $err = '';
    if ($act === 'add_myip') {
        $mi_ip  = trim($_POST['ip']    ?? '');
        $mi_lbl = trim($_POST['label'] ?? '');
        $err = my_ips_add($mi_ip, $mi_lbl);
    } elseif ($act === 'update_myip') {
        $mi_ip  = trim($_POST['ip']    ?? '');
        $mi_lbl = trim($_POST['label'] ?? '');
        $err = $mi_ip ? my_ips_update($mi_ip, $mi_lbl) : 'Invalid IP.';
    } elseif ($act === 'delete_myip') {
        $mi_ip = trim($_POST['ip'] ?? '');
        $err = $mi_ip ? my_ips_delete($mi_ip) : 'Invalid IP.';
    }
    header('Location: ?tab=myips' . ($err ? '&err=' . urlencode($err) : '&ok=1'));
    exit;
}
if ($tab === 'myips') {
    if (isset($_GET['ok']))  { $mi_flash = 'Done.';                              $mi_flash_ok = true; }
    if (isset($_GET['err'])) { $mi_flash = htmlspecialchars($_GET['err'] ?? ''); $mi_flash_ok = false; }
    $my_ips_set = my_ips_load(); // reload after any mutation
}

// ── Users CRUD (POST) ─────────────────────────────────────────────────────────
$u_flash = ''; $u_flash_ok = true;
if ($tab === 'users' && $_SERVER['REQUEST_METHOD'] === 'POST' && _admin_csrf_ok()) {
    $act = $_POST['action'] ?? '';
    $err = '';
    if ($act === 'add_user') {
        $u_em = trim($_POST['email'] ?? ''); $u_nm = trim($_POST['name'] ?? '');
        $u_at = trim($_POST['attributes'] ?? '');
        if ($u_at !== '' && json_decode($u_at) === null)       $err = 'Attributes: invalid JSON.';
        elseif (!filter_var($u_em, FILTER_VALIDATE_EMAIL))     $err = 'Invalid email address.';
        else $err = user_create($u_em, $u_nm, $u_at !== '' ? $u_at : null);
    } elseif ($act === 'update_user') {
        $u_id = (int)($_POST['id'] ?? 0); $u_em = trim($_POST['email'] ?? '');
        $u_nm = trim($_POST['name'] ?? ''); $u_at = trim($_POST['attributes'] ?? '');
        if ($u_id < 1)                                         $err = 'Invalid user.';
        elseif ($u_at !== '' && json_decode($u_at) === null)   $err = 'Attributes: invalid JSON.';
        elseif (!filter_var($u_em, FILTER_VALIDATE_EMAIL))     $err = 'Invalid email address.';
        else $err = user_update($u_id, $u_em, $u_nm, $u_at !== '' ? $u_at : null);
    } elseif ($act === 'delete_user') {
        $u_id = (int)($_POST['id'] ?? 0);
        if ($u_id < 1) { $err = 'Invalid user.'; }
        else {
            $tgt = admin_pdo()?->prepare("SELECT email FROM users WHERE id=? LIMIT 1");
            $tgt?->execute([$u_id]);
            $tgt_email = (string)($tgt?->fetchColumn() ?? '');
            if ($tgt_email === $email) $err = 'You cannot delete your own account.';
            else $err = user_delete($u_id);
        }
    } elseif ($act === 'toggle_user') {
        $u_id = (int)($_POST['id'] ?? 0);
        if ($u_id < 1) { $err = 'Invalid user.'; }
        else {
            $tgt = admin_pdo()?->prepare("SELECT email FROM users WHERE id=? LIMIT 1");
            $tgt?->execute([$u_id]);
            $tgt_email = (string)($tgt?->fetchColumn() ?? '');
            if ($tgt_email === $email) $err = 'You cannot disable your own account.';
            else $err = user_toggle_disabled($u_id);
        }
    }
    header('Location: ?tab=users' . ($err ? '&err=' . urlencode($err) : '&ok=1'));
    exit;
}
if ($tab === 'users') {
    if (isset($_GET['ok']))  { $u_flash = 'Done.';                              $u_flash_ok = true; }
    if (isset($_GET['err'])) { $u_flash = htmlspecialchars($_GET['err'] ?? ''); $u_flash_ok = false; }
}
$b_flash = ''; $b_flash_ok = true;
if ($tab === 'blocked') {
    if (isset($_GET['ok']))  { $b_flash = 'Done.';                              $b_flash_ok = true; }
    if (isset($_GET['err'])) { $b_flash = htmlspecialchars($_GET['err'] ?? ''); $b_flash_ok = false; }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
$TOOL_NAMES = [
    'index.php'              => 'Home',
    'x509parse.php'          => 'X.509 Parser',
    'cert_factory.php'       => 'TLS Cert Factory',
    'mpca_factory.php'       => 'MPCA Factory',
    'linters.php'            => 'Multi-Linter',
    'artifact_parser.php'    => 'Artifact Parser',
    'cps_to_br_assessor.php' => 'CPS-to-BR Assessor',
    'csr_generator.php'      => 'CSR Generator',
    'ct_log.php'             => 'CT Log API',
    'ct_log_doc.php'         => 'CT Log Docs',
    'tsa.php'                => 'TSA API',
    'tsa_doc.php'            => 'TSA Docs',
    'timestamp_it.php'       => 'TimeStampIt',
    'eseal.php'              => 'e-Seal API',
    'eseal_doc.php'          => 'e-Seal Docs',
    'eseal_signer.php'       => 'e-Seal Signer',
    'acme-endpoint.php'      => 'ACME Endpoint',
    'acme_tester.php'        => 'ACME Tester',
    'revocation.php'         => 'Revocation',
    'feed.php'               => 'News Feed',
    'community_tools.php'    => 'Community Tools',
    'references.php'         => 'References',
    'privacy.php'            => 'Privacy',
];
$tool_name = fn(string $s) => $TOOL_NAMES[$s] ?? $s;

function status_badge(int $s): string {
    $c = match(true) { $s < 300 => 'ok', $s < 400 => 'redir', $s < 500 => 'warn', default => 'err' };
    return "<span class=\"badge badge--$c\">$s</span>";
}
function method_badge(string $m): string {
    $c = match($m) { 'GET' => 'get', 'POST' => 'post', default => 'oth' };
    return "<span class=\"badge badge--$c\">$m</span>";
}
function me_badge(string $ip, array $set): string {
    if (!isset($set[$ip])) return '';
    $lbl = $set[$ip]['label'] ?? '';
    $tip = $lbl !== '' ? htmlspecialchars($lbl) : 'my IP';
    return " <span class=\"badge badge--me\" title=\"$tip\">me</span>";
}
function ua_label(string $ua): string {
    if ($ua === '') return '<span class="muted">—</span>';
    $t = 'title="' . htmlspecialchars($ua) . '"';

    // ── Named bots (most specific first) ─────────────────────────────────────
    static $BOT_MAP = [
        'GPTBot'               => 'OpenAI / GPTBot',
        'ChatGPT-User'         => 'OpenAI / ChatGPT',
        'OAI-SearchBot'        => 'OpenAI / Search',
        'Googlebot'            => 'Google / Bot',
        'Google-Extended'      => 'Google / AI',
        'AdsBot-Google'        => 'Google / Ads',
        'Bingbot'              => 'Bing / Bot',
        'BingPreview'          => 'Bing / Preview',
        'Applebot'             => 'Apple / Bot',
        'anthropic-ai'         => 'Anthropic / AI',
        'ClaudeBot'            => 'Anthropic / Claude',
        'FacebookExternalHit'  => 'Meta / Facebook',
        'Facebot'              => 'Meta / Facebook',
        'Twitterbot'           => 'X / Twitter',
        'LinkedInBot'          => 'LinkedIn / Bot',
        'Slackbot'             => 'Slack',
        'Discordbot'           => 'Discord',
        'TelegramBot'          => 'Telegram',
        'WhatsApp'             => 'WhatsApp',
        'Amazonbot'            => 'Amazon / Bot',
        'AhrefsBot'            => 'Ahrefs',
        'SemrushBot'           => 'Semrush',
        'DotBot'               => 'Moz',
        'MJ12bot'              => 'Majestic',
        'YandexBot'            => 'Yandex',
        'DuckDuckBot'          => 'DuckDuckGo',
        'Bytespider'           => 'ByteDance',
        'PetalBot'             => 'Huawei',
        'CCBot'                => 'CommonCrawl',
        'ia_archiver'          => 'Wayback',
        'archive.org_bot'      => 'Wayback',
    ];
    foreach ($BOT_MAP as $sig => $label) {
        if (stripos($ua, $sig) !== false)
            return "<span class=\"ua-bot\" $t>$label</span>";
    }

    // ── Generic tools ─────────────────────────────────────────────────────────
    static $TOOL_MAP = [
        'curl'       => 'curl',
        'python'     => 'python',
        'go-http'    => 'Go HTTP',
        'wget'       => 'wget',
        'java'       => 'Java',
        'scrapy'     => 'Scrapy',
        'zgrab'      => 'zgrab',
        'nuclei'     => 'Nuclei',
        'libwww'     => 'libwww',
        'masscan'    => 'masscan',
        'nmap'       => 'nmap',
    ];
    foreach ($TOOL_MAP as $sig => $label) {
        if (stripos($ua, $sig) !== false)
            return "<span class=\"ua-bot\" $t>$label</span>";
    }
    if (preg_match('/bot|crawl|spider|slurp/i', $ua))
        return "<span class=\"ua-bot\" $t>bot</span>";

    // ── Platform ─────────────────────────────────────────────────────────────
    $plat = '';
    if (stripos($ua, 'iPhone') !== false)        $plat = 'iPhone';
    elseif (stripos($ua, 'iPad') !== false)      $plat = 'iPad';
    elseif (stripos($ua, 'Android') !== false)   $plat = 'Android';
    elseif (stripos($ua, 'CrOS') !== false)      $plat = 'ChromeOS';
    elseif (stripos($ua, 'Windows') !== false)   $plat = 'Windows';
    elseif (stripos($ua, 'Macintosh') !== false) $plat = 'Mac';
    elseif (stripos($ua, 'Linux') !== false)     $plat = 'Linux';

    // ── Browser (order matters: Edge/Opera embed Chrome token) ────────────────
    $browser = '';
    if (stripos($ua, 'EdgiOS/') !== false ||
        stripos($ua, 'EdgA/')   !== false ||
        stripos($ua, 'Edg/')    !== false)             $browser = 'Edge';
    elseif (stripos($ua, 'OPR/')           !== false)  $browser = 'Opera';
    elseif (stripos($ua, 'SamsungBrowser/') !== false) $browser = 'Samsung';
    elseif (stripos($ua, 'FxiOS/')         !== false)  $browser = 'Firefox';
    elseif (stripos($ua, 'Firefox/')       !== false)  $browser = 'Firefox';
    elseif (stripos($ua, 'CriOS/')         !== false)  $browser = 'Chrome';  // Chrome on iOS
    elseif (stripos($ua, 'Chrome/')        !== false)  $browser = 'Chrome';
    elseif (stripos($ua, 'Safari/')        !== false)  $browser = 'Safari';

    if ($browser) {
        $label = $plat ? "$browser / $plat" : $browser;
        return "<span class=\"ua-browser\" $t>$label</span>";
    }
    return '<span class="muted" ' . $t . '>' . htmlspecialchars(substr($ua, 0, 22)) . '…</span>';
}
function flag(string $cc): string {
    $cc = strtoupper(trim($cc));
    if (!preg_match('/^[A-Z]{2}$/', $cc) || $cc === 'XX') return '';
    return mb_chr(0x1F1E6 + ord($cc[0]) - 65) . mb_chr(0x1F1E6 + ord($cc[1]) - 65);
}
function uriLink(string $uri, ?string $qs = null, int $max = 60): string {
    $full = $uri . ($qs !== null && $qs !== '' ? '?' . $qs : '');
    $disp = strlen($full) > $max ? substr($full, 0, $max) . '…' : $full;
    $href = htmlspecialchars('https://' . SITE_DOMAIN . $full, ENT_QUOTES);
    $tip  = htmlspecialchars($full, ENT_QUOTES);
    $txt  = htmlspecialchars($disp);
    return "<a href=\"$href\" class=\"uri\" target=\"_blank\" rel=\"noopener noreferrer\" title=\"$tip\">$txt</a>";
}
function geo_label(string $ip, array $geo): string {
    $cc = $geo[$ip] ?? '';
    if (!$cc || $cc === 'XX') return '<span class="muted">—</span>';
    $f = flag($cc);
    return "<span class=\"geo\" title=\"$cc\">$f <span class=\"geo-cc\">$cc</span></span>";
}
function rel_time(string $dt): string {
    $d = time() - strtotime($dt . ' UTC');
    if ($d < 60)    return $d . 's ago';
    if ($d < 3600)  return floor($d/60) . 'm ago';
    if ($d < 86400) return floor($d/3600) . 'h ago';
    return floor($d/86400) . 'd ago';
}
function q(array $over = [], array $drop = []): string {
    $p = array_filter($_GET, fn($v) => $v !== '');
    foreach ($drop as $k) unset($p[$k]);
    unset($p['page']);
    return '?' . http_build_query(array_merge($p, $over));
}
function pg_url(int $p): string {
    return '?' . http_build_query(array_merge(array_filter($_GET, fn($v) => $v !== ''), ['page' => $p]));
}

// ── Filters ───────────────────────────────────────────────────────────────────
$period  = in_array($_GET['period'] ?? '24h', ['1h', '24h', '7d', '30d']) ? $_GET['period'] : '24h';
$fip     = preg_replace('/[^\d\.:a-fA-F]/', '', $_GET['ip']     ?? '');
$fstatus = $_GET['status'] ?? '';
$fmethod = strtoupper(preg_replace('/[^A-Za-z]/', '', $_GET['method'] ?? ''));
$fvhost  = in_array($_GET['vhost'] ?? '', ['', 'thameur.org', 'pki.thameur.org']) ? ($_GET['vhost'] ?? '') : '';
$page    = max(1, (int)($_GET['page'] ?? 1));
$_pp_opts = [50, 100, 200];
$pp = in_array((int)($_GET['pp'] ?? 0), $_pp_opts) ? (int)$_GET['pp']
    : (in_array((int)($_COOKIE['mkt_pp'] ?? 0), $_pp_opts) ? (int)$_COOKIE['mkt_pp'] : 50);
if (isset($_GET['pp']) && in_array($pp, $_pp_opts)) {
    setcookie('mkt_pp', (string)$pp, ['path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
}
unset($_pp_opts);

// IP scope filter — persisted as a session cookie (expires when browser closes)
$_ipf_opts = ['all', 'mine', 'others'];
$ipf = in_array($_GET['ipf'] ?? '', $_ipf_opts) ? $_GET['ipf']
    : (in_array($_COOKIE['mkt_ipf'] ?? '', $_ipf_opts) ? $_COOKIE['mkt_ipf'] : 'all');
if (isset($_GET['ipf']) && in_array($ipf, $_ipf_opts)) {
    setcookie('mkt_ipf', $ipf, ['path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
}
unset($_ipf_opts);
// Build SQL snippet for the IP scope filter. Uses a subquery so no extra bound params needed.
// $ipf_sql(alias) — alias is the table alias prefixed to the ip column (empty = bare column).
$ipf_sql = fn(string $a = '') => match($ipf) {
    'mine'   => 'AND ' . ($a ? "$a." : '') . 'ip IN (SELECT ip FROM my_ips)',
    'others' => 'AND ' . ($a ? "$a." : '') . 'ip NOT IN (SELECT ip FROM my_ips)',
    default  => '',
};

if (!in_array($fmethod, ['', 'GET', 'POST', 'DELETE', 'PUT', 'HEAD', 'OPTIONS'])) $fmethod = '';
if (!preg_match('/^(\d{3}|\dxx)$/', $fstatus)) $fstatus = '';

$pstart = match($period) {
    '1h'  => 'DATE_SUB(NOW(), INTERVAL 1 HOUR)',
    '7d'  => 'DATE_SUB(NOW(), INTERVAL 7 DAY)',
    '30d' => 'DATE_SUB(NOW(), INTERVAL 30 DAY)',
    default => 'DATE_SUB(NOW(), INTERVAL 24 HOUR)',
};

$w = ["created_at >= $pstart"]; $bp = [];
if ($fip)     { $w[] = 'ip = ?';     $bp[] = $fip; }
if ($fmethod) { $w[] = 'method = ?'; $bp[] = $fmethod; }
if ($fstatus !== '') {
    if (preg_match('/^(\d)xx$/', $fstatus, $m)) {
        $lo = (int)$m[1] * 100; $hi = $lo + 99;
        $w[] = 'status BETWEEN ? AND ?'; $bp[] = $lo; $bp[] = $hi;
    } else { $w[] = 'status = ?'; $bp[] = (int)$fstatus; }
}
if ($ipf !== 'all') $w[] = ltrim($ipf_sql(), 'AND ');
$wsql = implode(' AND ', $w);

// nginx WHERE clause (same base filters + optional vhost)
$nw = ["created_at >= $pstart"]; $nbp = [];
if ($fip)     { $nw[] = 'ip = ?';     $nbp[] = $fip; }
if ($fmethod) { $nw[] = 'method = ?'; $nbp[] = $fmethod; }
if ($fvhost)  { $nw[] = 'vhost = ?';  $nbp[] = $fvhost; }
if ($fstatus !== '') {
    if (preg_match('/^(\d)xx$/', $fstatus, $m)) {
        $lo = (int)$m[1] * 100; $hi = $lo + 99;
        $nw[] = 'status BETWEEN ? AND ?'; $nbp[] = $lo; $nbp[] = $hi;
    } else { $nw[] = 'status = ?'; $nbp[] = (int)$fstatus; }
}
if ($ipf !== 'all') $nw[] = ltrim($ipf_sql(), 'AND ');
$nwsql = implode(' AND ', $nw);

// ── Data ──────────────────────────────────────────────────────────────────────
$stats      = ['total' => 0, 'uniq' => 0, 'errs' => 0, 'epct' => 0, 'top_tool' => '—', 'top_cnt' => 0];
$rows       = [];
$total_rows = 0;
$tool_usage = [];
$top_ips    = [];
$err_rows   = [];

if ($tab === 'php' && $pdo) {
    // Stats (always full period, ignore column filters)
    $r = $pdo->query("SELECT COUNT(*) AS t, COUNT(DISTINCT ip) AS u FROM visits WHERE created_at >= $pstart")->fetch();
    $stats['total'] = (int)$r['t']; $stats['uniq'] = (int)$r['u'];

    $r = $pdo->query("SELECT COUNT(*) AS c FROM visits WHERE created_at >= $pstart AND status >= 400")->fetch();
    $stats['errs'] = (int)$r['c'];
    $stats['epct'] = $stats['total'] > 0 ? round($stats['errs'] / $stats['total'] * 100, 1) : 0;

    $r = $pdo->query("SELECT script_name, COUNT(*) AS c FROM visits WHERE created_at >= $pstart AND script_name NOT IN ('','index.php') GROUP BY script_name ORDER BY c DESC LIMIT 1")->fetch();
    if ($r) { $stats['top_tool'] = $r['script_name']; $stats['top_cnt'] = (int)$r['c']; }

    // Activity table
    $st = $pdo->prepare("SELECT COUNT(*) FROM visits WHERE $wsql"); $st->execute($bp);
    $total_rows = (int)$st->fetchColumn();
    $st = $pdo->prepare("SELECT created_at,ip,method,uri,query_string,status,user_agent,referer,script_name FROM visits WHERE $wsql ORDER BY created_at DESC LIMIT $pp OFFSET " . (($page-1)*$pp));
    $st->execute($bp); $rows = $st->fetchAll();

    // Tool usage
    $tool_usage = $pdo->query("SELECT script_name, COUNT(*) AS c FROM visits WHERE created_at >= $pstart AND script_name != '' GROUP BY script_name ORDER BY c DESC LIMIT 40")->fetchAll();

    // Top IPs (blocked IPs excluded so they don't crowd out active ones)
    $top_ips = $pdo->query("SELECT ip, COUNT(*) AS c, MAX(created_at) AS last, ROUND(SUM(status>=400)/COUNT(*)*100) AS epct FROM visits WHERE created_at >= $pstart {$ipf_sql()} AND ip NOT IN (SELECT ip FROM blocked_ips) GROUP BY ip ORDER BY c DESC LIMIT 40")->fetchAll();

    // Errors (unacknowledged only)
    $err_rows = $pdo->query("SELECT id,created_at,ip,uri,error_type,error_msg,error_file,error_line FROM errors WHERE acknowledged_at IS NULL {$ipf_sql()} ORDER BY created_at DESC LIMIT 25")->fetchAll();
}

$total_pages = max(1, (int)ceil($total_rows / $pp));
$tool_max    = $tool_usage ? (int)$tool_usage[0]['c'] : 1;

// Geo lookup for PHP activity
$geo_ips = array_unique(array_merge(array_column($rows, 'ip'), array_column($top_ips, 'ip')));
$geo     = $pdo ? geoip_country($geo_ips) : [];

// ── nginx / Server Activity data ──────────────────────────────────────────────
$ng_stats      = ['total' => 0, 'uniq' => 0, 'errs' => 0, 'epct' => 0, 'top_uri' => '—', 'top_cnt' => 0];
$ng_rows       = [];
$ng_total_rows = 0;
$ng_top_uris   = [];
$ng_top_ips    = [];

if ($tab === 'nginx' && $pdo) {
    try {
        $r = $pdo->query("SELECT COUNT(*) AS t, COUNT(DISTINCT ip) AS u FROM nginx_visits WHERE created_at >= $pstart")->fetch();
        $ng_stats['total'] = (int)$r['t']; $ng_stats['uniq'] = (int)$r['u'];

        $r = $pdo->query("SELECT COUNT(*) AS c FROM nginx_visits WHERE created_at >= $pstart AND status >= 400")->fetch();
        $ng_stats['errs'] = (int)$r['c'];
        $ng_stats['epct'] = $ng_stats['total'] > 0 ? round($ng_stats['errs'] / $ng_stats['total'] * 100, 1) : 0;

        $r = $pdo->query("SELECT uri, COUNT(*) AS c FROM nginx_visits WHERE created_at >= $pstart AND uri != '' GROUP BY uri ORDER BY c DESC LIMIT 1")->fetch();
        if ($r) { $ng_stats['top_uri'] = $r['uri']; $ng_stats['top_cnt'] = (int)$r['c']; }

        $st = $pdo->prepare("SELECT COUNT(*) FROM nginx_visits WHERE $nwsql"); $st->execute($nbp);
        $ng_total_rows = (int)$st->fetchColumn();

        $st = $pdo->prepare("SELECT created_at,ip,method,host,vhost,uri,query_string,status,bytes_sent,user_agent,country FROM nginx_visits WHERE $nwsql ORDER BY created_at DESC LIMIT $pp OFFSET " . (($page-1)*$pp));
        $st->execute($nbp); $ng_rows = $st->fetchAll();

        $ng_top_uris = $pdo->query("SELECT uri, COUNT(*) AS c FROM nginx_visits WHERE created_at >= $pstart AND uri != '' GROUP BY uri ORDER BY c DESC LIMIT 40")->fetchAll();

        $ng_top_ips = $pdo->query("SELECT ip, COUNT(*) AS c, MAX(created_at) AS last, ROUND(SUM(status>=400)/COUNT(*)*100) AS epct FROM nginx_visits WHERE created_at >= $pstart AND ip != '' {$ipf_sql()} AND ip NOT IN (SELECT ip FROM blocked_ips) GROUP BY ip ORDER BY c DESC LIMIT 40")->fetchAll();
    } catch (Throwable) {}
}

$ng_total_pages = max(1, (int)ceil($ng_total_rows / $pp));
$ng_uri_max     = $ng_top_uris ? (int)$ng_top_uris[0]['c'] : 1;

// Geo lookup for nginx activity — geoip_cache is populated by cron/nginx_import.php
$ng_geo_ips = array_unique(array_merge(array_column($ng_rows, 'ip'), array_column($ng_top_ips, 'ip')));
$ng_geo     = $pdo ? geoip_country($ng_geo_ips) : [];

$users        = $tab === 'users'   ? user_list()        : [];
$blocked_list = $tab === 'blocked' ? blocked_ip_list()  : [];
if ($ipf !== 'all' && $blocked_list) {
    $blocked_list = array_values(array_filter($blocked_list,
        fn($b) => $ipf === 'mine' ? isset($my_ips_set[$b['ip']]) : !isset($my_ips_set[$b['ip']])
    ));
}
$blocked_set  = $pdo ? array_flip($pdo->query("SELECT ip FROM blocked_ips")->fetchAll(PDO::FETCH_COLUMN)) : [];

// ── SOC data ──────────────────────────────────────────────────────────────────
$soc_threat_ips   = [];
$soc_probe_paths  = [];
$soc_events       = [];
$soc_rate_ips     = [];
$soc_threat_level = 'low';
$soc_period_key   = '1h';
$soc_c_crit = $soc_c_high = $soc_c_medium = 0;

if ($tab === 'soc' && $pdo) {
    try {
        $soc_period_key = in_array($_GET['soc_period'] ?? '1h', ['1h','6h','24h'])
            ? ($_GET['soc_period'] ?? '1h') : '1h';
        $soc_win = match($soc_period_key) {
            '6h'  => 'DATE_SUB(NOW(), INTERVAL 6 HOUR)',
            '24h' => 'DATE_SUB(NOW(), INTERVAL 24 HOUR)',
            default => 'DATE_SUB(NOW(), INTERVAL 1 HOUR)',
        };

        // PHP errors per IP in the window
        $php_err_lookup = [];
        foreach ($pdo->query(
            "SELECT ip, COUNT(*) AS cnt FROM errors
             WHERE created_at >= $soc_win AND ip != '' {$ipf_sql()} GROUP BY ip"
        )->fetchAll() as $r) {
            $php_err_lookup[$r['ip']] = (int)$r['cnt'];
        }

        // Rate anomaly: IPs with ≥15 reqs in the last 5 min
        $rate_lookup = [];
        foreach ($pdo->query(
            "SELECT ip, COUNT(*) AS reqs FROM nginx_visits
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) AND ip != '' {$ipf_sql()}
             GROUP BY ip HAVING reqs >= 15"
        )->fetchAll() as $r) {
            $rate_lookup[$r['ip']] = (int)$r['reqs'];
        }

        // Per-IP aggregation of all signals
        $soc_raw = $pdo->query("
            SELECT n.ip,
                   COALESCE(MAX(g.country), MAX(n.country), '') AS country,
                   COUNT(*)                                           AS total_reqs,
                   COUNT(DISTINCT n.uri)                             AS uniq_paths,
                   SUM(n.status = 404)                               AS c404,
                   COUNT(DISTINCT CASE WHEN n.status=404 THEN n.uri END) AS uniq_404,
                   SUM(n.status BETWEEN 500 AND 599)                 AS c5xx,
                   SUM(n.status BETWEEN 400 AND 499)                 AS c4xx,
                   MAX(n.created_at)                                 AS last_seen,
                   MAX(CASE WHEN n.user_agent REGEXP
                     'nikto|nmap|sqlmap|masscan|zgrab|gobuster|nuclei|whatweb|wapiti|burp|acunetix|nessus|openvas|hydra|metasploit|feroxbuster|ffuf|wfuzz|dirsearch|python-requests|go-http-client|zgrab|shodan'
                   THEN 1 ELSE 0 END)                                AS has_scanner,
                   SUM(CASE WHEN
                         n.uri REGEXP '[.](env|git|htaccess|htpasswd|bak|backup|sql|zip)$'
                         OR n.uri REGEXP '(wp-admin|wp-login|xmlrpc|phpinfo|phpmyadmin|adminer)'
                         OR n.uri REGEXP '(/shell[.]php|/cmd[.]php|/webshell|/c99[.]php|/r57[.]php)'
                         OR n.uri REGEXP '(/etc/passwd|/proc/self|[.][.]/)'
                         OR n.uri LIKE '%UNION%SELECT%'
                         OR n.uri LIKE '%<script%'
                         OR n.uri LIKE '%base64_decode%'
                         OR LENGTH(n.uri) > 500
                       THEN 1 ELSE 0 END)                            AS exploit_hits
            FROM nginx_visits n
            LEFT JOIN geoip_cache g ON g.ip = n.ip
            WHERE n.created_at >= $soc_win AND n.ip != '' {$ipf_sql('n')}
            GROUP BY n.ip
            ORDER BY COUNT(*) DESC
            LIMIT 200
        ")->fetchAll();

        // Score each IP and build threat list
        foreach ($soc_raw as $r) {
            $ip       = $r['ip'];
            $php_errs = $php_err_lookup[$ip] ?? 0;
            $rate     = $rate_lookup[$ip]    ?? 0;

            $s_enum    = min((int)$r['uniq_404'] * 8, 40);
            $s_scanner = (int)$r['has_scanner'] * 25;
            $s_probe   = min((int)$r['exploit_hits'] * 15, 45);
            $s_5xx     = min((int)$r['c5xx'] * 5, 20);
            $s_php     = min($php_errs * 10, 30);
            $s_rate    = $rate >= 50 ? 20 : ($rate >= 20 ? 10 : 0);
            $score     = min($s_enum + $s_scanner + $s_probe + $s_5xx + $s_php + $s_rate, 100);

            if ($score === 0 && (int)$r['total_reqs'] < 3) continue;

            $soc_threat_ips[] = array_merge($r, [
                'php_errs'   => $php_errs,
                'rate_5m'    => $rate,
                'score'      => $score,
                's_enum'     => $s_enum,
                's_scanner'  => $s_scanner,
                's_probe'    => $s_probe,
                's_5xx'      => $s_5xx,
                's_php'      => $s_php,
                's_rate'     => $s_rate,
                'is_blocked' => isset($blocked_set[$ip]),
            ]);
        }
        usort($soc_threat_ips, fn($a, $b) => $b['score'] <=> $a['score']);
        $soc_threat_ips = array_slice($soc_threat_ips, 0, 50);

        // Probe path breakdown (for the probe signal card)
        $soc_probe_paths = $pdo->query("
            SELECT uri, COUNT(*) AS hits, COUNT(DISTINCT ip) AS ips
            FROM nginx_visits
            WHERE created_at >= $soc_win
              AND (
                uri REGEXP '[.](env|git|htaccess|htpasswd|bak|backup|sql)$'
                OR uri REGEXP '(wp-admin|wp-login|xmlrpc|phpinfo|phpmyadmin|adminer|shell[.]php|/etc/passwd)'
                OR uri LIKE '%UNION%SELECT%'
                OR uri LIKE '%<script%'
              )
            GROUP BY uri ORDER BY hits DESC LIMIT 15
        ")->fetchAll();

        // Rate anomaly IPs (for the rate signal card display)
        $soc_rate_ips = $pdo->query("
            SELECT nv.ip, COUNT(*) AS reqs,
                   COALESCE(MAX(g.country), MAX(nv.country), '') AS country
            FROM nginx_visits nv
            LEFT JOIN geoip_cache g ON g.ip = nv.ip
            WHERE nv.created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) AND nv.ip != '' {$ipf_sql('nv')}
            GROUP BY nv.ip HAVING reqs >= 15
            ORDER BY reqs DESC LIMIT 10
        ")->fetchAll();

        // Recent security events feed
        $soc_events = $pdo->query("
            SELECT n.created_at, n.ip, COALESCE(g.country, n.country, '') AS country,
                   n.method, n.uri, n.status, n.user_agent,
                   CASE
                     WHEN n.user_agent REGEXP 'nikto|nmap|sqlmap|masscan|zgrab|gobuster|nuclei|burp|acunetix|nessus|hydra|metasploit|feroxbuster|ffuf|wfuzz|dirsearch' THEN 'scanner'
                     WHEN n.uri REGEXP '[.](env|git|htaccess|htpasswd|bak)$|wp-admin|xmlrpc|phpinfo|phpmyadmin|shell[.]php|/etc/passwd' THEN 'probe'
                     WHEN n.status >= 500 THEN '5xx'
                     WHEN n.status = 403 THEN '403'
                     WHEN n.status = 404 THEN '404'
                     ELSE 'anomaly'
                   END AS ev_type
            FROM nginx_visits n
            LEFT JOIN geoip_cache g ON g.ip = n.ip
            WHERE n.created_at >= $soc_win {$ipf_sql('n')}
              AND (
                n.status >= 400
                OR n.user_agent REGEXP 'nikto|nmap|sqlmap|masscan|zgrab|gobuster|nuclei|burp|acunetix|nessus|hydra|metasploit|feroxbuster|ffuf|wfuzz|dirsearch'
                OR n.uri REGEXP '[.](env|git|htaccess|htpasswd|bak)$|wp-admin|xmlrpc|phpinfo|phpmyadmin|shell[.]php'
                OR LENGTH(n.uri) > 300
              )
            ORDER BY n.created_at DESC LIMIT 100
        ")->fetchAll();

        // Sessions (from session_analysis cron)
        $soc_sessions = $pdo->query("
            SELECT s.ip, s.session_start, s.session_end, s.duration_s, s.req_count,
                   s.uniq_paths, s.ua_count, s.c404, s.c5xx, s.exploit_hits,
                   s.has_scanner, s.replay_pairs, s.pki_hits, s.score, s.classification,
                   s.signals, COALESCE(g.country,'') AS country,
                   i.org, i.asn, i.provider_type, i.is_hosting, i.is_proxy,
                   i.bot_verified, i.bot_claimed
            FROM sessions s
            LEFT JOIN geoip_cache g ON g.ip = s.ip
            LEFT JOIN ip_intel i    ON i.ip = s.ip
            WHERE s.session_start >= $soc_win {$ipf_sql('s')}
            ORDER BY s.score DESC, s.session_start DESC
            LIMIT 40
        ")->fetchAll();

        // Distributed scans — same 404 path hit by ≥3 distinct IPs
        $soc_distrib = $pdo->query("
            SELECT uri,
                   COUNT(DISTINCT ip) AS c_ips,
                   COUNT(*)           AS c_hits,
                   MIN(created_at)    AS first_seen,
                   MAX(created_at)    AS last_seen
            FROM nginx_visits
            WHERE created_at >= $soc_win
              AND status = 404
              AND uri NOT IN ('/','/favicon.ico','/robots.txt','/sitemap.xml','/index.php')
              AND uri NOT REGEXP '[.](css|js|ico|png|jpg|jpeg|gif|svg|woff2?|ttf)$'
            GROUP BY uri
            HAVING c_ips >= 3
            ORDER BY c_ips DESC, c_hits DESC
            LIMIT 15
        ")->fetchAll();

        // Honeypot hits — requests to known-decoy paths
        $soc_honeypot = $pdo->query("
            SELECT n.created_at, n.ip, COALESCE(g.country, n.country,'') AS country,
                   n.method, n.uri, n.status, n.user_agent
            FROM nginx_visits n
            LEFT JOIN geoip_cache g ON g.ip = n.ip
            WHERE n.created_at >= $soc_win {$ipf_sql('n')}
              AND n.uri REGEXP '(wp-login[.]php|wp-admin|xmlrpc[.]php|phpinfo|phpmyadmin|adminer|[.]env$|[.]git/|shell[.]php|cmd[.]php|c99[.]php|r57[.]php|webshell|setup[.]php|install[.]php|/etc/passwd|/proc/self|/backup[./])'
            ORDER BY n.created_at DESC
            LIMIT 40
        ")->fetchAll();

        // Determine overall threat level
        $soc_c_crit   = count(array_filter($soc_threat_ips, fn($r) => $r['score'] >= 80));
        $soc_c_high   = count(array_filter($soc_threat_ips, fn($r) => $r['score'] >= 50 && $r['score'] < 80));
        $soc_c_medium = count(array_filter($soc_threat_ips, fn($r) => $r['score'] >= 25 && $r['score'] < 50));
        $soc_threat_level = match(true) {
            $soc_c_crit > 0   => 'critical',
            $soc_c_high > 0   => 'high',
            $soc_c_medium > 0 => 'medium',
            default           => 'low',
        };
    } catch (Throwable) {}
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= match($tab) { 'users' => 'Users', 'blocked' => 'Blocked IPs', 'nginx' => 'Server Activity', 'soc' => 'SOC', 'myips' => 'My IPs', default => 'PHP Activity' } ?> — <?= SITE_DOMAIN ?></title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,600;1,300&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:      #0e1014; --surface: #13171e; --surface2: #181d26;
      --border:  #2a3040; --border2: #3a4458;
      --accent:  #00d4aa; --accent2: #0099ff;
      --text:    #d4dae6; --muted:   #6b7a90;
      --ok:      #22c55e; --redir: #0099ff; --warn: #f59e0b; --err: #ef4444;
      --mono: 'IBM Plex Mono', monospace; --sans: 'IBM Plex Sans', sans-serif;
      --radius: 6px; --tr: 160ms ease;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 14px; overflow-x: hidden; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.6; min-height: 100vh; }
    a { color: var(--accent); text-decoration: none; transition: color var(--tr); }
    a:hover { color: #fff; }

    /* admin bar */
    .admin-bar { background: rgba(18,22,28,.98); border-bottom: 1px solid #1a2030; padding: 0 1.75rem; height: 34px; display: flex; align-items: center; justify-content: space-between; font-family: var(--mono); font-size: .68rem; letter-spacing: .04em; }
    .admin-bar-user { color: #4a5a70; } .admin-bar-user span { color: var(--accent); }
    .admin-bar-logout { color: #4a5a70; transition: color var(--tr); } .admin-bar-logout:hover { color: #fca5a5; }

    /* layout */
    .wrap { max-width: 100%; margin: 0 auto; padding: 2rem 1.75rem; }

    /* page header */
    .page-hd { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: .75rem; margin-bottom: 1.75rem; }
    .page-hd h1 { font-size: 1.15rem; font-weight: 600; color: #fff; }
    .period-tabs { display: flex; gap: .25rem; }
    .period-tabs a { font-family: var(--mono); font-size: .68rem; letter-spacing: .08em; text-transform: uppercase; padding: .3rem .75rem; border-radius: var(--radius); border: 1px solid var(--border2); color: var(--muted); transition: all var(--tr); }
    .period-tabs a:hover { color: var(--text); border-color: var(--accent); }
    .period-tabs a.active { background: rgba(0,212,170,.1); border-color: var(--accent); color: var(--accent); }

    /* stat cards */
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.75rem; }
    @media(max-width:760px) { .stats-grid { grid-template-columns: repeat(2,1fr); } }
    .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.1rem 1.25rem; }
    .stat-val { font-family: var(--mono); font-size: 1.5rem; font-weight: 600; color: #fff; line-height: 1.1; }
    .stat-val.warn { color: var(--warn); } .stat-val.err { color: var(--err); }
    .stat-lbl { font-size: .73rem; color: var(--muted); margin-top: .3rem; }
    .stat-sub { font-family: var(--mono); font-size: .65rem; color: #3d4f68; margin-top: .15rem; }

    /* analytics row (tool usage + top IPs side by side, above full-width table) */
    .side-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; margin-bottom: 0; }
    @media(max-width:760px) { .side-row { grid-template-columns: 1fr; } }

    /* cards */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 1.25rem; }
    .card-hd { padding: .75rem 1.1rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
    .card-hd h2 { font-family: var(--mono); font-size: .7rem; letter-spacing: .1em; text-transform: uppercase; color: var(--accent); }
    .card-hd .card-meta { font-family: var(--mono); font-size: .65rem; color: #3d4f68; }
    .card-body { padding: 1rem; }

    /* filter bar */
    .filter-bar { display: flex; flex-wrap: wrap; gap: .6rem; align-items: flex-end; margin-bottom: 1rem; }
    .flt { display: flex; flex-direction: column; gap: .3rem; }
    .flt label { font-family: var(--mono); font-size: .62rem; letter-spacing: .08em; text-transform: uppercase; color: #3d4f68; }
    .flt input, .flt select { background: var(--surface2); border: 1px solid var(--border2); border-radius: 4px; color: var(--text); font-family: var(--mono); font-size: .75rem; padding: .35rem .6rem; outline: none; transition: border-color var(--tr); }
    .flt input:focus, .flt select:focus { border-color: var(--accent); }
    .flt input { width: 140px; } .flt select { width: 100px; }
    .btn-sm { padding: .35rem .85rem; background: rgba(0,212,170,.12); border: 1px solid rgba(0,212,170,.3); border-radius: 4px; color: var(--accent); font-family: var(--mono); font-size: .72rem; cursor: pointer; transition: all var(--tr); }
    .btn-sm:hover { background: rgba(0,212,170,.2); } .btn-sm.clear { background: transparent; border-color: var(--border2); color: var(--muted); }
    .btn-sm.clear:hover { border-color: var(--border2); color: var(--text); }

    /* result meta */
    .result-meta { font-family: var(--mono); font-size: .68rem; color: #3d4f68; margin-bottom: .6rem; }
    .result-meta span { color: var(--muted); }

    /* table */
    .tbl-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: .78rem; }
    th { font-family: var(--mono); font-size: .62rem; letter-spacing: .08em; text-transform: uppercase; color: #3d4f68; padding: .5rem .75rem; border-bottom: 1px solid var(--border); text-align: left; white-space: nowrap; }
    td { padding: .45rem .75rem; border-bottom: 1px solid rgba(42,48,64,.6); vertical-align: middle; white-space: nowrap; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,.02); }
    .ts { font-family: var(--mono); font-size: .68rem; color: var(--muted); }
    .uri { font-family: var(--mono); font-size: .72rem; color: var(--text); max-width: 420px; overflow: hidden; text-overflow: ellipsis; }
    .ip-link { font-family: var(--mono); font-size: .72rem; color: var(--accent2); }
    .ip-link:hover { color: #fff; }
    .muted { color: var(--muted); font-size: .68rem; }
    .referer { max-width: 220px; overflow: hidden; text-overflow: ellipsis; font-size: .68rem; color: var(--muted); }

    /* badges */
    .badge { font-family: var(--mono); font-size: .63rem; padding: .15rem .45rem; border-radius: 3px; display: inline-block; font-weight: 600; }
    .badge--ok   { background: rgba(34,197,94,.12);  color: var(--ok);   border: 1px solid rgba(34,197,94,.25); }
    .badge--redir{ background: rgba(0,153,255,.12);  color: var(--redir);border: 1px solid rgba(0,153,255,.25); }
    .badge--warn { background: rgba(245,158,11,.12); color: var(--warn); border: 1px solid rgba(245,158,11,.25); }
    .badge--err  { background: rgba(239,68,68,.12);  color: var(--err);  border: 1px solid rgba(239,68,68,.25); }
    .badge--get  { background: rgba(0,153,255,.08);  color: var(--accent2); border: 1px solid rgba(0,153,255,.2); }
    .badge--post { background: rgba(245,158,11,.08); color: var(--warn);    border: 1px solid rgba(245,158,11,.2); }
    .badge--oth  { background: rgba(255,255,255,.04); color: var(--muted);  border: 1px solid var(--border); }
    .ua-bot     { font-family: var(--mono); font-size: .65rem; color: var(--err);  background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.2); border-radius: 3px; padding: .1rem .35rem; }
    .ua-browser { font-family: var(--mono); font-size: .65rem; color: var(--muted); }

    /* pagination */
    .pager { display: flex; gap: .35rem; flex-wrap: wrap; margin-top: .85rem; align-items: center; }
    .pager a, .pager span { font-family: var(--mono); font-size: .68rem; padding: .3rem .6rem; border-radius: 4px; border: 1px solid var(--border); color: var(--muted); transition: all var(--tr); }
    .pager a:hover { border-color: var(--accent); color: var(--accent); }
    .pager span.cur { border-color: var(--accent); color: var(--accent); background: rgba(0,212,170,.08); }
    .pager .ellipsis { border: none; color: #3d4f68; padding: .3rem .2rem; }

    /* tool usage bars */
    .tool-row { display: flex; align-items: center; gap: .6rem; margin-bottom: .5rem; }
    .tool-row:last-child { margin-bottom: 0; }
    .tool-lbl { font-family: var(--mono); font-size: .72rem; color: var(--muted); width: 170px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tool-bar-bg { flex: 1; height: 6px; background: var(--surface2); border-radius: 3px; overflow: hidden; }
    .tool-bar-fill { height: 100%; background: var(--accent); border-radius: 3px; transition: width .4s ease; }
    .tool-cnt { font-family: var(--mono); font-size: .65rem; color: #3d4f68; width: 40px; text-align: right; flex-shrink: 0; }

    /* errors table */
    .err-msg { font-family: var(--mono); font-size: .68rem; color: var(--text); max-width: 520px; white-space: pre-wrap; word-break: break-word; }
    .err-file { font-family: var(--mono); font-size: .63rem; color: #3d4f68; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .empty-state { padding: 2rem; text-align: center; font-family: var(--mono); font-size: .72rem; color: #3d4f68; }

    /* geo */
    .geo { font-size: 1rem; white-space: nowrap; display: inline-flex; align-items: center; gap: .35rem; }
    .geo-cc { font-family: var(--mono); font-size: .8rem; color: var(--text); font-weight: 600; letter-spacing: .04em; }

    /* IP table side */
    .ip-table td:first-child { font-family: var(--mono); font-size: .72rem; }
    .epct-warn { color: var(--warn); }

    /* tab nav */
    .tab-nav { background: rgba(18,22,28,.98); border-bottom: 1px solid var(--border); padding: 0 1.75rem; display: flex; }
    .tab-nav a { display: inline-flex; align-items: center; padding: .55rem 1.1rem; font-family: var(--mono); font-size: .68rem; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); border-bottom: 2px solid transparent; margin-bottom: -1px; transition: all var(--tr); text-decoration: none; }
    .tab-nav a:hover { color: var(--text); }
    .tab-nav a.active { color: var(--accent); border-bottom-color: var(--accent); }

    /* flash */
    .flash { padding: .65rem 1rem; border-radius: var(--radius); font-size: .8rem; margin-bottom: 1.25rem; }
    .flash--ok  { background: rgba(34,197,94,.08);  border: 1px solid rgba(34,197,94,.25);  color: #86efac; }
    .flash--err { background: rgba(239,68,68,.08);  border: 1px solid rgba(239,68,68,.25);  color: #fca5a5; }

    /* users page header */
    .users-hd { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem; }
    .users-hd h1 { font-size: 1.15rem; font-weight: 600; color: #fff; }

    /* user table action buttons */
    .btn-act { font-family: var(--mono); font-size: .65rem; padding: .2rem .55rem; border-radius: 3px; border: 1px solid var(--border2); background: transparent; color: var(--muted); cursor: pointer; transition: all var(--tr); text-decoration: none; display: inline-block; }
    .btn-act:hover { color: var(--text); border-color: var(--text); }
    .btn-act.primary { border-color: rgba(0,212,170,.35); color: var(--accent); }
    .btn-act.primary:hover { background: rgba(0,212,170,.1); }
    .btn-act.warn-act { border-color: rgba(245,158,11,.3); color: var(--warn); }
    .btn-act.warn-act:hover { background: rgba(245,158,11,.08); }
    .btn-act.danger { border-color: rgba(239,68,68,.3); color: #fca5a5; }
    .btn-act.danger:hover { background: rgba(239,68,68,.1); border-color: var(--err); }

    /* user status/role badges */
    .badge--me       { background: rgba(0,212,170,.18);  border: 1px solid rgba(0,212,170,.5);  color: var(--accent); font-size: .58rem; padding: .1rem .35rem; border-radius: 3px; font-family: var(--mono); font-weight: 600; letter-spacing: .04em; }
    .badge--root     { background: rgba(0,212,170,.08);  border: 1px solid rgba(0,212,170,.2);  color: var(--accent); font-size: .62rem; padding: .1rem .4rem; border-radius: 3px; font-family: var(--mono); }
    .badge--active   { background: rgba(34,197,94,.08);  border: 1px solid rgba(34,197,94,.2);  color: var(--ok);     font-size: .62rem; padding: .1rem .4rem; border-radius: 3px; font-family: var(--mono); }
    .badge--disabled { background: rgba(239,68,68,.08);  border: 1px solid rgba(239,68,68,.2);  color: #fca5a5;       font-size: .62rem; padding: .1rem .4rem; border-radius: 3px; font-family: var(--mono); }

    /* inline block button (activity table IP cell) */
    .btn-block-sm { background: none; border: none; cursor: pointer; color: #2a3040; font-size: .72rem; padding: 0 .2rem; line-height: 1; transition: color var(--tr); vertical-align: middle; }
    .btn-block-sm:hover { color: var(--err); }
    .badge--blocked-sm { font-family: var(--mono); font-size: .65rem; color: rgba(239,68,68,.5); vertical-align: middle; margin-left: .15rem; cursor: default; }

    /* ── SOC styles ─────────────────────────────────────────────────────────── */
    .threat-banner { display:flex; align-items:center; gap:1.5rem; padding:1.25rem 1.5rem; border-radius:var(--radius); border:1px solid; margin-bottom:1.75rem; flex-wrap:wrap; }
    .threat-banner.threat-low      { background:rgba(34,197,94,.05);   border-color:rgba(34,197,94,.2);  }
    .threat-banner.threat-medium   { background:rgba(245,158,11,.05);  border-color:rgba(245,158,11,.2); }
    .threat-banner.threat-high     { background:rgba(249,115,22,.06);  border-color:rgba(249,115,22,.3); }
    .threat-banner.threat-critical { background:rgba(239,68,68,.08);   border-color:rgba(239,68,68,.35); }
    .threat-icon  { font-size:2.2rem; line-height:1; flex-shrink:0; }
    .threat-body  { flex:1; min-width:180px; }
    .threat-level { font-family:var(--mono); font-size:1rem; font-weight:600; letter-spacing:.14em; text-transform:uppercase; }
    .threat-level.low      { color:var(--ok); }
    .threat-level.medium   { color:var(--warn); }
    .threat-level.high     { color:#f97316; }
    .threat-level.critical { color:var(--err); }
    .threat-sub   { font-size:.78rem; color:var(--muted); margin-top:.2rem; }
    .threat-kpis  { display:flex; gap:2.5rem; margin-left:auto; flex-wrap:wrap; }
    .threat-kpi-val { font-family:var(--mono); font-size:1.4rem; font-weight:600; color:#fff; line-height:1.1; }
    .threat-kpi-lbl { font-size:.65rem; color:var(--muted); margin-top:.2rem; }

    .signal-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:1rem; margin-bottom:1.75rem; }
    @media(max-width:900px) { .signal-grid { grid-template-columns:repeat(2,1fr); } }
    @media(max-width:560px) { .signal-grid { grid-template-columns:1fr; } }

    .signal-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); }
    .signal-card.triggered { border-color:var(--sig-clr, var(--border)); }
    .signal-hd   { padding:.7rem 1rem; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:.55rem; }
    .signal-icon { font-size:.95rem; line-height:1; }
    .signal-title { font-family:var(--mono); font-size:.66rem; letter-spacing:.1em; text-transform:uppercase; color:var(--accent); flex:1; }
    .signal-count { font-family:var(--mono); font-size:.95rem; font-weight:600; }
    .signal-count.zero { color:#2a3040; }
    .signal-count.c-low  { color:var(--warn); }
    .signal-count.c-high { color:#f97316; }
    .signal-count.c-crit { color:var(--err); }
    .signal-body { padding:.65rem 1rem; min-height:80px; }
    .signal-item { display:flex; justify-content:space-between; align-items:center; padding:.18rem 0; border-bottom:1px solid rgba(42,48,64,.4); }
    .signal-item:last-child { border-bottom:none; }
    .signal-ip  { font-family:var(--mono); font-size:.7rem; color:var(--accent2); }
    .signal-val { font-family:var(--mono); font-size:.65rem; color:var(--muted); }
    .signal-empty { font-family:var(--mono); font-size:.7rem; color:#2a3040; padding:.25rem 0; }

    .risk-score { font-family:var(--mono); font-size:.72rem; font-weight:600; padding:.2rem .5rem; border-radius:3px; display:inline-block; min-width:38px; text-align:center; }
    .risk-0  { background:rgba(107,122,144,.06); color:#4a5a70; border:1px solid #2a3040; }
    .risk-low  { background:rgba(34,197,94,.08);  color:var(--ok);  border:1px solid rgba(34,197,94,.2); }
    .risk-med  { background:rgba(245,158,11,.1);  color:var(--warn); border:1px solid rgba(245,158,11,.25); }
    .risk-high { background:rgba(249,115,22,.1);  color:#f97316;    border:1px solid rgba(249,115,22,.25); }
    .risk-crit { background:rgba(239,68,68,.12);  color:var(--err); border:1px solid rgba(239,68,68,.3); }

    .sig-pills { display:flex; gap:.2rem; flex-wrap:wrap; }
    .sig-pill  { font-family:var(--mono); font-size:.58rem; padding:.1rem .3rem; border-radius:2px; border:1px solid; display:inline-block; white-space:nowrap; }
    .sig-enum  { background:rgba(0,153,255,.07); border-color:rgba(0,153,255,.25); color:var(--redir); }
    .sig-scan  { background:rgba(239,68,68,.08); border-color:rgba(239,68,68,.3);  color:var(--err); }
    .sig-probe { background:rgba(249,115,22,.08); border-color:rgba(249,115,22,.3); color:#f97316; }
    .sig-rate  { background:rgba(168,85,247,.08); border-color:rgba(168,85,247,.3); color:#c084fc; }
    .sig-5xx   { background:rgba(239,68,68,.05);  border-color:rgba(239,68,68,.2);  color:#fca5a5; }
    .sig-php   { background:rgba(245,158,11,.07); border-color:rgba(245,158,11,.25); color:var(--warn); }

    /* classification badges */
    .cls-badge    { font-family:var(--mono); font-size:.63rem; padding:.15rem .45rem; border-radius:3px; display:inline-block; font-weight:600; white-space:nowrap; }
    .cls-human      { background:rgba(34,197,94,.08);   color:var(--ok);    border:1px solid rgba(34,197,94,.2); }
    .cls-researcher { background:rgba(0,153,255,.08);   color:var(--redir); border:1px solid rgba(0,153,255,.2); }
    .cls-crawler    { background:rgba(107,122,144,.06); color:var(--muted); border:1px solid var(--border2); }
    .cls-scanner    { background:rgba(249,115,22,.1);   color:#f97316;      border:1px solid rgba(249,115,22,.3); }
    .cls-attacker   { background:rgba(239,68,68,.12);   color:var(--err);   border:1px solid rgba(239,68,68,.3); }
    .cls-social     { background:rgba(99,102,241,.08);  color:#818cf8;      border:1px solid rgba(99,102,241,.25); }
    .cls-unknown    { background:rgba(255,255,255,.03); color:var(--muted); border:1px solid var(--border); }

    /* provider / ASN badges */
    .pvdr-badge { font-family:var(--mono); font-size:.58rem; padding:.1rem .3rem; border-radius:2px; border:1px solid; display:inline-block; white-space:nowrap; }
    .pvdr-hosting { background:rgba(239,68,68,.05);  border-color:rgba(239,68,68,.2);  color:#fca5a5; }
    .pvdr-proxy   { background:rgba(168,85,247,.07); border-color:rgba(168,85,247,.25);color:#c084fc; }
    .pvdr-mobile  { background:rgba(0,153,255,.06);  border-color:rgba(0,153,255,.2);  color:var(--redir); }
    .pvdr-unknown { background:rgba(255,255,255,.03);border-color:var(--border);        color:#3d4f68; }
    .asn-lbl { font-family:var(--mono); font-size:.62rem; color:#4a5a70; }
    .org-lbl { font-family:var(--mono); font-size:.65rem; color:var(--muted); max-width:140px; overflow:hidden; text-overflow:ellipsis; display:inline-block; vertical-align:middle; white-space:nowrap; }
    .bot-ok  { color:var(--ok);  font-size:.7rem; }
    .bot-bad { color:var(--err); font-size:.7rem; }

    /* session duration */
    .dur-lbl { font-family:var(--mono); font-size:.65rem; color:var(--muted); }

    .ev-pill { font-family:var(--mono); font-size:.6rem; padding:.1rem .35rem; border-radius:3px; border:1px solid; display:inline-block; font-weight:600; }
    .ev-scanner { background:rgba(239,68,68,.1);   border-color:rgba(239,68,68,.35);  color:var(--err); }
    .ev-probe   { background:rgba(249,115,22,.1);  border-color:rgba(249,115,22,.35); color:#f97316; }
    .ev-5xx     { background:rgba(239,68,68,.06);  border-color:rgba(239,68,68,.2);   color:#fca5a5; }
    .ev-403     { background:rgba(0,153,255,.07);  border-color:rgba(0,153,255,.2);   color:var(--redir); }
    .ev-404     { background:rgba(245,158,11,.07); border-color:rgba(245,158,11,.25); color:var(--warn); }
    .ev-anomaly { background:rgba(255,255,255,.03); border-color:var(--border); color:var(--muted); }

    /* modal — [hidden] must win over display:flex */
    [hidden] { display: none !important; }
    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.72); display: flex; align-items: center; justify-content: center; z-index: 100; padding: 1rem; }
    .modal-card { background: var(--surface); border: 1px solid var(--border2); border-radius: 8px; width: 100%; max-width: 440px; }
    .modal-hd { padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
    .modal-hd h3 { font-family: var(--mono); font-size: .75rem; letter-spacing: .1em; text-transform: uppercase; color: var(--accent); }
    .modal-close { background: none; border: none; color: var(--muted); font-size: 1.3rem; cursor: pointer; line-height: 1; padding: 0 .2rem; transition: color var(--tr); }
    .modal-close:hover { color: var(--text); }
    .modal-body { padding: 1.25rem; display: flex; flex-direction: column; gap: .9rem; }
    .form-row { display: flex; flex-direction: column; gap: .35rem; }
    .form-row label { font-family: var(--mono); font-size: .62rem; letter-spacing: .08em; text-transform: uppercase; color: #3d4f68; }
    .form-row input, .form-row textarea { background: var(--surface2); border: 1px solid var(--border2); border-radius: 4px; color: var(--text); font-family: var(--mono); font-size: .78rem; padding: .45rem .7rem; outline: none; transition: border-color var(--tr); width: 100%; resize: vertical; }
    .form-row input:focus, .form-row textarea:focus { border-color: var(--accent); }
    .form-actions { display: flex; justify-content: flex-end; gap: .5rem; padding: .75rem 1.25rem; border-top: 1px solid var(--border); }
  </style>
</head>
<body>

<?php $navLabel = 'Admin Panel'; require_once __DIR__ . '/includes/site_nav.php'; ?>
<div class="admin-bar">
  <span class="admin-bar-user">Signed in as <span><?= htmlspecialchars($email) ?></span></span>
  <a href="<?= ADMIN_LOGIN_URL ?>?logout=1" class="admin-bar-logout">Sign out</a>
</div>
<nav class="tab-nav">
  <a href="?" class="<?= $tab === 'php' ? 'active' : '' ?>">PHP Activity</a>
  <a href="?tab=nginx" class="<?= $tab === 'nginx' ? 'active' : '' ?>">Server Activity</a>
  <a href="?tab=soc" class="<?= $tab === 'soc' ? 'active' : '' ?>" style="color:<?= $tab !== 'soc' ? 'var(--warn)' : '' ?>">SOC</a>
  <a href="?tab=blocked" class="<?= $tab === 'blocked' ? 'active' : '' ?>">Blocked IPs <?php if ($blocked_set): ?><span style="font-size:.6rem;opacity:.6">(<?= count($blocked_set) ?>)</span><?php endif; ?></a>
  <a href="?tab=myips" class="<?= $tab === 'myips' ? 'active' : '' ?>">My IPs <?php if ($my_ips_set): ?><span style="font-size:.6rem;opacity:.6">(<?= count($my_ips_set) ?>)</span><?php endif; ?></a>
  <a href="?tab=users" class="<?= $tab === 'users' ? 'active' : '' ?>">Users</a>
</nav>

<div class="wrap">

  <?php if ($tab === 'php'): ?>
  <!-- ── Header ──────────────────────────────────────────────────────────────── -->
  <div class="page-hd">
    <h1>PHP Activity</h1>
    <div class="period-tabs">
      <?php foreach (['1h' => 'Last hour', '24h' => 'Last 24 h', '7d' => '7 days', '30d' => '30 days'] as $k => $lbl): ?>
      <a href="<?= q(['period' => $k]) ?>" class="<?= $period === $k ? 'active' : '' ?>"><?= $lbl ?></a>
      <?php endforeach; ?>
    </div>
  </div>

  <!-- ── Stats ───────────────────────────────────────────────────────────────── -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-val"><?= number_format($stats['total']) ?></div>
      <div class="stat-lbl">Requests</div>
    </div>
    <div class="stat-card">
      <div class="stat-val"><?= number_format($stats['uniq']) ?></div>
      <div class="stat-lbl">Unique IPs</div>
    </div>
    <div class="stat-card">
      <div class="stat-val <?= $stats['epct'] > 10 ? 'err' : ($stats['epct'] > 3 ? 'warn' : '') ?>">
        <?= $stats['epct'] ?>%
      </div>
      <div class="stat-lbl">Error rate (4xx+5xx)</div>
      <div class="stat-sub"><?= number_format($stats['errs']) ?> requests</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="font-size:1rem;line-height:1.4"><?= htmlspecialchars($tool_name($stats['top_tool'])) ?></div>
      <div class="stat-lbl">Top tool</div>
      <div class="stat-sub"><?= number_format($stats['top_cnt']) ?> requests</div>
    </div>
  </div>

  <!-- ── Analytics row (tool usage + top IPs) ──────────────────────────────── -->
  <div class="side-row">

    <div class="card">
      <div class="card-hd"><h2>Tool Usage</h2></div>
      <div class="card-body" style="padding-bottom:.5rem">
        <?php if ($tool_usage): ?>
        <div style="max-height:290px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border2) transparent;padding-right:.25rem">
        <?php foreach ($tool_usage as $t): ?>
        <div class="tool-row">
          <span class="tool-lbl" title="<?= htmlspecialchars($t['script_name']) ?>"><?= htmlspecialchars($tool_name($t['script_name'])) ?></span>
          <div class="tool-bar-bg"><div class="tool-bar-fill" style="width:<?= round($t['c']/$tool_max*100) ?>%"></div></div>
          <span class="tool-cnt"><?= number_format($t['c']) ?></span>
        </div>
        <?php endforeach; ?>
        </div>
        <?php else: ?><div class="empty-state">No data yet.</div><?php endif; ?>
      </div>
    </div>

    <div class="card">
      <div class="card-hd"><h2>Top IPs</h2></div>
      <div class="tbl-wrap" style="max-height:296px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border2) transparent">
        <table class="ip-table">
          <thead style="position:sticky;top:0;background:var(--surface);z-index:1"><tr><th>IP</th><th>Country</th><th>Req</th><th>Err%</th><th>Last seen</th><th></th></tr></thead>
          <tbody>
          <?php if ($top_ips): ?>
          <?php foreach ($top_ips as $row): ?>
          <tr>
            <td><a href="<?= q(['ip' => $row['ip']]) ?>" class="ip-link"><?= htmlspecialchars($row['ip']) ?></a><?= me_badge($row['ip'], $my_ips_set) ?></td>
            <td><?= geo_label($row['ip'], $geo) ?></td>
            <td><?= number_format($row['c']) ?></td>
            <td class="<?= (int)$row['epct'] > 30 ? 'epct-warn' : '' ?> muted"><?= (int)$row['epct'] ?>%</td>
            <td class="muted"><?= rel_time($row['last']) ?></td>
            <td>
              <form method="POST" style="display:inline" onsubmit="return confirm('Block <?= htmlspecialchars(addslashes($row['ip'])) ?>?')">
                <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
                <input type="hidden" name="action" value="block_ip">
                <input type="hidden" name="ip" value="<?= htmlspecialchars($row['ip']) ?>">
                <button type="submit" class="btn-act danger" style="font-size:.6rem;padding:.15rem .45rem">Block</button>
              </form>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php else: ?><tr><td colspan="5" class="empty-state">No data yet.</td></tr><?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

  </div><!-- .side-row -->

  <!-- ── Activity table (full width) ────────────────────────────────────────── -->
  <div class="card">
    <div class="card-hd">
      <h2>Activity Feed</h2>
      <div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">
        <span class="card-meta"><?= number_format($total_rows) ?> rows matched</span>
        <a href="<?= htmlspecialchars($_SERVER['REQUEST_URI']) ?>" class="btn-sm" style="font-size:.65rem;padding:.28rem .65rem" title="Refresh">↻</a>
        <?php if ($fip): ?>
        <?php if (isset($blocked_set[$fip])): ?>
        <form method="POST" style="display:inline">
          <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
          <input type="hidden" name="action" value="unblock_ip">
          <input type="hidden" name="ip" value="<?= htmlspecialchars($fip) ?>">
          <button type="submit" class="btn-sm" style="border-color:rgba(34,197,94,.3);color:#86efac;font-size:.65rem;padding:.25rem .7rem">↩ Unblock <?= htmlspecialchars($fip) ?></button>
        </form>
        <?php else: ?>
        <form method="POST" style="display:inline" onsubmit="return confirm('Block <?= htmlspecialchars(addslashes($fip)) ?>?')">
          <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
          <input type="hidden" name="action" value="block_ip">
          <input type="hidden" name="ip" value="<?= htmlspecialchars($fip) ?>">
          <button type="submit" class="btn-sm" style="border-color:rgba(239,68,68,.3);color:#fca5a5;font-size:.65rem;padding:.25rem .7rem">⊘ Block <?= htmlspecialchars($fip) ?></button>
        </form>
        <?php endif; ?>
        <?php endif; ?>
      </div>
    </div>
    <div class="card-body">

      <!-- Filters -->
      <form method="GET" class="filter-bar">
        <input type="hidden" name="period" value="<?= htmlspecialchars($period) ?>">
        <div class="flt">
          <label>IP</label>
          <input type="text" name="ip" value="<?= htmlspecialchars($fip) ?>" placeholder="1.2.3.4">
        </div>
        <div class="flt">
          <label>Status</label>
          <select name="status">
            <option value="">All</option>
            <?php foreach (['2xx','3xx','4xx','5xx'] as $opt): ?>
            <option value="<?= $opt ?>" <?= $fstatus === $opt ? 'selected' : '' ?>><?= $opt ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="flt">
          <label>Method</label>
          <select name="method">
            <option value="">All</option>
            <?php foreach (['GET','POST','HEAD','OPTIONS','DELETE','PUT'] as $m): ?>
            <option value="<?= $m ?>" <?= $fmethod === $m ? 'selected' : '' ?>><?= $m ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="flt">
          <label>View</label>
          <select name="ipf" style="width:110px" <?= !$my_ips_set ? 'disabled title="Add IPs in My IPs tab first"' : '' ?>>
            <option value="all"    <?= $ipf === 'all'    ? 'selected' : '' ?>>All IPs</option>
            <option value="mine"   <?= $ipf === 'mine'   ? 'selected' : '' ?>>My IPs only</option>
            <option value="others" <?= $ipf === 'others' ? 'selected' : '' ?>>Exclude mine</option>
          </select>
        </div>
        <div class="flt">
          <label>Display</label>
          <select name="pp" style="width:80px">
            <?php foreach ([50, 100, 200] as $opt): ?>
            <option value="<?= $opt ?>" <?= $pp === $opt ? 'selected' : '' ?>><?= $opt ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="flt" style="flex-direction:row;gap:.4rem;align-items:flex-end">
          <button type="submit" class="btn-sm">Filter</button>
          <a href="<?= q([], ['ip','status','method','page']) ?>" class="btn-sm clear">Clear</a>
        </div>
      </form>

      <!-- Table -->
      <?php if ($rows): ?>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th><th>IP</th><th>Country</th><th>M</th><th>Path</th>
              <th>Status</th><th>Tool</th><th>UA</th><th>Referer</th>
            </tr>
          </thead>
          <tbody>
          <?php foreach ($rows as $r): ?>
          <tr>
            <td><span class="ts" title="<?= htmlspecialchars($r['created_at']) ?> UTC"><?= rel_time($r['created_at']) ?></span></td>
            <td style="white-space:nowrap">
              <a href="<?= q(['ip' => $r['ip']]) ?>" class="ip-link"><?= htmlspecialchars($r['ip']) ?></a><?= me_badge($r['ip'], $my_ips_set) ?>
              <?php if (isset($blocked_set[$r['ip']])): ?>
              <span class="badge--blocked-sm" title="Blocked">⊘</span>
              <?php else: ?>
              <form method="POST" style="display:inline" onsubmit="return confirm('Block <?= htmlspecialchars(addslashes($r['ip'])) ?>?')"><input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>"><input type="hidden" name="action" value="block_ip"><input type="hidden" name="ip" value="<?= htmlspecialchars($r['ip']) ?>"><button type="submit" class="btn-block-sm" title="Block this IP">⊘</button></form>
              <?php endif; ?>
            </td>
            <td><?= geo_label($r['ip'], $geo) ?></td>
            <td><?= method_badge($r['method']) ?></td>
            <td><?= uriLink($r['uri'], $r['query_string'] ?: null) ?></td>
            <td><?= status_badge((int)$r['status']) ?></td>
            <td><span class="muted"><?= htmlspecialchars($tool_name($r['script_name'])) ?></span></td>
            <td><?= ua_label($r['user_agent']) ?></td>
            <td><span class="referer" title="<?= htmlspecialchars($r['referer']) ?>"><?= $r['referer'] ? htmlspecialchars($r['referer']) : '<span class="muted">—</span>' ?></span></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php else: ?>
      <div class="empty-state">No activity found for this filter.</div>
      <?php endif; ?>

      <!-- Pagination -->
      <?php if ($total_pages > 1): ?>
      <div class="pager">
        <?php if ($page > 1): ?><a href="<?= pg_url($page-1) ?>">← Prev</a><?php endif; ?>
        <?php
          $pages_to_show = [];
          for ($i = 1; $i <= $total_pages; $i++) {
            if ($i === 1 || $i === $total_pages || abs($i - $page) <= 2) $pages_to_show[] = $i;
          }
          $prev = null;
          foreach ($pages_to_show as $pn):
            if ($prev !== null && $pn - $prev > 1): ?><span class="ellipsis">…</span><?php endif;
            $prev = $pn;
        ?>
        <?php if ($pn === $page): ?><span class="cur"><?= $pn ?></span>
        <?php else: ?><a href="<?= pg_url($pn) ?>"><?= $pn ?></a><?php endif; ?>
        <?php endforeach; ?>
        <?php if ($page < $total_pages): ?><a href="<?= pg_url($page+1) ?>">Next →</a><?php endif; ?>
      </div>
      <?php endif; ?>

    </div>
  </div><!-- activity card -->

  <!-- ── Errors ──────────────────────────────────────────────────────────────── -->
  <div class="card">
    <div class="card-hd">
      <h2>PHP Errors</h2>
      <div style="display:flex;align-items:center;gap:.75rem">
        <span class="card-meta"><?= count($err_rows) ?> unacknowledged</span>
        <?php if ($err_rows): ?>
        <form method="POST" style="display:inline" onsubmit="return confirm('Acknowledge all errors?')">
          <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
          <input type="hidden" name="action" value="ack_all_errors">
          <button type="submit" class="btn-sm" style="font-size:.65rem;padding:.28rem .65rem">✓ Ack All</button>
        </form>
        <?php endif; ?>
      </div>
    </div>
    <?php if ($err_rows): ?>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Time</th><th>IP</th><th>Type</th><th>URI</th><th>Message</th><th>File : line</th><th></th></tr></thead>
        <tbody>
        <?php foreach ($err_rows as $e): ?>
        <tr>
          <td><span class="ts" title="<?= htmlspecialchars($e['created_at']) ?> UTC"><?= rel_time($e['created_at']) ?></span></td>
          <td><a href="<?= q(['ip' => $e['ip']]) ?>" class="ip-link"><?= htmlspecialchars($e['ip']) ?></a><?= me_badge($e['ip'], $my_ips_set) ?></td>
          <td><span class="badge badge--warn"><?= htmlspecialchars($e['error_type']) ?></span></td>
          <td><?= uriLink($e['uri']) ?></td>
          <td><span class="err-msg"><?= htmlspecialchars($e['error_msg']) ?></span></td>
          <td><span class="err-file" title="<?= htmlspecialchars($e['error_file']) ?>"><?= htmlspecialchars(basename($e['error_file'])) ?> : <?= (int)$e['error_line'] ?></span></td>
          <td>
            <form method="POST" style="display:inline">
              <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
              <input type="hidden" name="action" value="ack_error">
              <input type="hidden" name="id" value="<?= (int)$e['id'] ?>">
              <button type="submit" class="btn-act" style="font-size:.62rem;padding:.15rem .45rem;border-color:rgba(34,197,94,.25);color:var(--ok)" title="Acknowledge — hide from list">✓</button>
            </form>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php else: ?>
    <div class="empty-state">No unacknowledged PHP errors.</div>
    <?php endif; ?>
  </div>

  <?php endif; /* $tab === 'php' */ ?>

  <?php if ($tab === 'nginx'): ?>
  <!-- ── Header ──────────────────────────────────────────────────────────────── -->
  <div class="page-hd">
    <h1>Server Activity</h1>
    <div class="period-tabs">
      <?php foreach (['1h' => 'Last hour', '24h' => 'Last 24 h', '7d' => '7 days', '30d' => '30 days'] as $k => $lbl): ?>
      <a href="<?= q(['period' => $k]) ?>" class="<?= $period === $k ? 'active' : '' ?>"><?= $lbl ?></a>
      <?php endforeach; ?>
    </div>
  </div>

  <!-- ── Stats ───────────────────────────────────────────────────────────────── -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-val"><?= number_format($ng_stats['total']) ?></div>
      <div class="stat-lbl">Requests</div>
    </div>
    <div class="stat-card">
      <div class="stat-val"><?= number_format($ng_stats['uniq']) ?></div>
      <div class="stat-lbl">Unique IPs</div>
    </div>
    <div class="stat-card">
      <div class="stat-val <?= $ng_stats['epct'] > 10 ? 'err' : ($ng_stats['epct'] > 3 ? 'warn' : '') ?>">
        <?= $ng_stats['epct'] ?>%
      </div>
      <div class="stat-lbl">Error rate (4xx+5xx)</div>
      <div class="stat-sub"><?= number_format($ng_stats['errs']) ?> requests</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="font-size:.85rem;line-height:1.5;word-break:break-all"><?= $ng_stats['top_uri'] !== '—' ? uriLink($ng_stats['top_uri'], null, 80) : '—' ?></div>
      <div class="stat-lbl">Top URI</div>
      <div class="stat-sub"><?= number_format($ng_stats['top_cnt']) ?> requests</div>
    </div>
  </div>

  <!-- ── Analytics row ─────────────────────────────────────────────────────── -->
  <div class="side-row">

    <div class="card">
      <div class="card-hd"><h2>Top URIs</h2></div>
      <div class="card-body" style="padding-bottom:.5rem">
        <?php if ($ng_top_uris): ?>
        <div style="max-height:290px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border2) transparent;padding-right:.25rem">
        <?php foreach ($ng_top_uris as $t): ?>
        <div class="tool-row">
          <?= uriLink($t['uri'], null, 40) ?>
          <div class="tool-bar-bg"><div class="tool-bar-fill" style="width:<?= round($t['c']/$ng_uri_max*100) ?>%"></div></div>
          <span class="tool-cnt"><?= number_format($t['c']) ?></span>
        </div>
        <?php endforeach; ?>
        </div>
        <?php else: ?><div class="empty-state">No data yet.</div><?php endif; ?>
      </div>
    </div>

    <div class="card">
      <div class="card-hd"><h2>Top IPs</h2></div>
      <div class="tbl-wrap" style="max-height:296px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border2) transparent">
        <table class="ip-table">
          <thead style="position:sticky;top:0;background:var(--surface);z-index:1"><tr><th>IP</th><th>Country</th><th>Req</th><th>Err%</th><th>Last seen</th><th></th></tr></thead>
          <tbody>
          <?php if ($ng_top_ips): ?>
          <?php foreach ($ng_top_ips as $row): ?>
          <tr>
            <td><a href="<?= q(['ip' => $row['ip']]) ?>" class="ip-link"><?= htmlspecialchars($row['ip']) ?></a><?= me_badge($row['ip'], $my_ips_set) ?></td>
            <td><?= geo_label($row['ip'], $ng_geo) ?></td>
            <td><?= number_format($row['c']) ?></td>
            <td class="<?= (int)$row['epct'] > 30 ? 'epct-warn' : '' ?> muted"><?= (int)$row['epct'] ?>%</td>
            <td class="muted"><?= rel_time($row['last']) ?></td>
            <td>
              <form method="POST" style="display:inline" onsubmit="return confirm('Block <?= htmlspecialchars(addslashes($row['ip'])) ?>?')">
                <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
                <input type="hidden" name="action" value="block_ip">
                <input type="hidden" name="ip" value="<?= htmlspecialchars($row['ip']) ?>">
                <button type="submit" class="btn-act danger" style="font-size:.6rem;padding:.15rem .45rem">Block</button>
              </form>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php else: ?><tr><td colspan="6" class="empty-state">No data yet.</td></tr><?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

  </div><!-- .side-row -->

  <!-- ── Activity table ─────────────────────────────────────────────────────── -->
  <div class="card">
    <div class="card-hd">
      <h2>Server Activity</h2>
      <div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">
        <span class="card-meta"><?= number_format($ng_total_rows) ?> rows matched</span>
        <a href="<?= htmlspecialchars($_SERVER['REQUEST_URI']) ?>" class="btn-sm" style="font-size:.65rem;padding:.28rem .65rem" title="Refresh">↻</a>
        <?php if ($fip): ?>
        <?php if (isset($blocked_set[$fip])): ?>
        <form method="POST" style="display:inline">
          <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
          <input type="hidden" name="action" value="unblock_ip">
          <input type="hidden" name="ip" value="<?= htmlspecialchars($fip) ?>">
          <button type="submit" class="btn-sm" style="border-color:rgba(34,197,94,.3);color:#86efac;font-size:.65rem;padding:.25rem .7rem">↩ Unblock <?= htmlspecialchars($fip) ?></button>
        </form>
        <?php else: ?>
        <form method="POST" style="display:inline" onsubmit="return confirm('Block <?= htmlspecialchars(addslashes($fip)) ?>?')">
          <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
          <input type="hidden" name="action" value="block_ip">
          <input type="hidden" name="ip" value="<?= htmlspecialchars($fip) ?>">
          <button type="submit" class="btn-sm" style="border-color:rgba(239,68,68,.3);color:#fca5a5;font-size:.65rem;padding:.25rem .7rem">⊘ Block <?= htmlspecialchars($fip) ?></button>
        </form>
        <?php endif; ?>
        <?php endif; ?>
      </div>
    </div>
    <div class="card-body">

      <form method="GET" class="filter-bar">
        <input type="hidden" name="tab" value="nginx">
        <input type="hidden" name="period" value="<?= htmlspecialchars($period) ?>">
        <div class="flt">
          <label>IP</label>
          <input type="text" name="ip" value="<?= htmlspecialchars($fip) ?>" placeholder="1.2.3.4">
        </div>
        <div class="flt">
          <label>Status</label>
          <select name="status">
            <option value="">All</option>
            <?php foreach (['2xx','3xx','4xx','5xx'] as $opt): ?>
            <option value="<?= $opt ?>" <?= $fstatus === $opt ? 'selected' : '' ?>><?= $opt ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="flt">
          <label>Method</label>
          <select name="method">
            <option value="">All</option>
            <?php foreach (['GET','POST','HEAD','OPTIONS','DELETE','PUT'] as $m): ?>
            <option value="<?= $m ?>" <?= $fmethod === $m ? 'selected' : '' ?>><?= $m ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="flt">
          <label>Host</label>
          <select name="vhost">
            <option value="">All</option>
            <option value="thameur.org" <?= $fvhost === 'thameur.org' ? 'selected' : '' ?>>thameur.org</option>
            <option value="pki.thameur.org" <?= $fvhost === 'pki.thameur.org' ? 'selected' : '' ?>>pki.thameur.org</option>
          </select>
        </div>
        <div class="flt">
          <label>View</label>
          <select name="ipf" style="width:110px" <?= !$my_ips_set ? 'disabled title="Add IPs in My IPs tab first"' : '' ?>>
            <option value="all"    <?= $ipf === 'all'    ? 'selected' : '' ?>>All IPs</option>
            <option value="mine"   <?= $ipf === 'mine'   ? 'selected' : '' ?>>My IPs only</option>
            <option value="others" <?= $ipf === 'others' ? 'selected' : '' ?>>Exclude mine</option>
          </select>
        </div>
        <div class="flt">
          <label>Display</label>
          <select name="pp" style="width:80px">
            <?php foreach ([50, 100, 200] as $opt): ?>
            <option value="<?= $opt ?>" <?= $pp === $opt ? 'selected' : '' ?>><?= $opt ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="flt" style="flex-direction:row;gap:.4rem;align-items:flex-end">
          <button type="submit" class="btn-sm">Filter</button>
          <a href="<?= q([], ['ip','status','method','vhost','page']) ?>" class="btn-sm clear">Clear</a>
        </div>
      </form>

      <?php if ($ng_rows): ?>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th><th>IP</th><th>Country</th><th>M</th><th>Host</th>
              <th>Path</th><th>Status</th><th>UA</th><th>Bytes</th>
            </tr>
          </thead>
          <tbody>
          <?php foreach ($ng_rows as $r): ?>
          <tr>
            <td><span class="ts" title="<?= htmlspecialchars($r['created_at']) ?> UTC"><?= rel_time($r['created_at']) ?></span></td>
            <td style="white-space:nowrap">
              <a href="<?= q(['ip' => $r['ip']]) ?>" class="ip-link"><?= htmlspecialchars($r['ip']) ?></a><?= me_badge($r['ip'], $my_ips_set) ?>
              <?php if (isset($blocked_set[$r['ip']])): ?>
              <span class="badge--blocked-sm" title="Blocked">⊘</span>
              <?php else: ?>
              <form method="POST" style="display:inline" onsubmit="return confirm('Block <?= htmlspecialchars(addslashes($r['ip'])) ?>?')"><input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>"><input type="hidden" name="action" value="block_ip"><input type="hidden" name="ip" value="<?= htmlspecialchars($r['ip']) ?>"><button type="submit" class="btn-block-sm" title="Block this IP">⊘</button></form>
              <?php endif; ?>
            </td>
            <td><?= geo_label($r['ip'], $ng_geo) ?></td>
            <td><?= method_badge($r['method']) ?></td>
            <td><span class="muted" style="font-family:var(--mono);font-size:.68rem"><?= htmlspecialchars($r['host']) ?></span></td>
            <td><?= uriLink($r['uri'], $r['query_string'] ?: null) ?></td>
            <td><?= status_badge((int)$r['status']) ?></td>
            <td><?= ua_label($r['user_agent']) ?></td>
            <td class="muted" style="font-family:var(--mono);font-size:.68rem;text-align:right"><?= $r['bytes_sent'] !== null ? number_format((int)$r['bytes_sent']) : '—' ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php else: ?>
      <div class="empty-state">No server activity found for this filter.</div>
      <?php endif; ?>

      <?php if ($ng_total_pages > 1): ?>
      <div class="pager">
        <?php if ($page > 1): ?><a href="<?= pg_url($page-1) ?>">← Prev</a><?php endif; ?>
        <?php
          $pages_to_show = [];
          for ($i = 1; $i <= $ng_total_pages; $i++) {
            if ($i === 1 || $i === $ng_total_pages || abs($i - $page) <= 2) $pages_to_show[] = $i;
          }
          $prev = null;
          foreach ($pages_to_show as $pn):
            if ($prev !== null && $pn - $prev > 1): ?><span class="ellipsis">…</span><?php endif;
            $prev = $pn;
        ?>
        <?php if ($pn === $page): ?><span class="cur"><?= $pn ?></span>
        <?php else: ?><a href="<?= pg_url($pn) ?>"><?= $pn ?></a><?php endif; ?>
        <?php endforeach; ?>
        <?php if ($page < $ng_total_pages): ?><a href="<?= pg_url($page+1) ?>">Next →</a><?php endif; ?>
      </div>
      <?php endif; ?>

    </div>
  </div><!-- server activity card -->

  <?php endif; /* $tab === 'nginx' */ ?>

  <?php if ($tab === 'users'): ?>

  <?php if ($u_flash): ?>
  <div class="flash flash--<?= $u_flash_ok ? 'ok' : 'err' ?>"><?= $u_flash ?></div>
  <?php endif; ?>

  <div class="users-hd">
    <h1>Users</h1>
    <button class="btn-sm" onclick="document.getElementById('modal-add').hidden=false">+ Add User</button>
  </div>

  <div class="card">
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Email</th><th>Status</th><th>Role</th><th>Attributes</th><th>Created</th><th>Actions</th></tr>
        </thead>
        <tbody>
        <?php if ($users): ?>
        <?php foreach ($users as $u): ?>
        <tr>
          <td><?= htmlspecialchars($u['name'] ?: '—') ?></td>
          <td><span class="ip-link" style="color:var(--text)"><?= htmlspecialchars($u['email']) ?></span></td>
          <td><?= $u['is_disabled'] ? '<span class="badge--disabled">Disabled</span>' : '<span class="badge--active">Active</span>' ?></td>
          <td><?= $u['is_root'] ? '<span class="badge--root">Root Admin</span>' : '<span class="muted">User</span>' ?></td>
          <td>
            <?php if ($u['attributes']): ?>
            <span class="muted" style="font-family:var(--mono);font-size:.65rem;cursor:default" title="<?= htmlspecialchars($u['attributes']) ?>">{…}</span>
            <?php else: ?><span class="muted">—</span><?php endif; ?>
          </td>
          <td><span class="ts"><?= htmlspecialchars(substr($u['created_at'], 0, 10)) ?></span></td>
          <td style="white-space:nowrap">
            <?php if ($u['is_root']): ?>
            <span class="muted" style="font-size:.65rem;font-family:var(--mono)">protected</span>
            <?php else: ?>
            <button class="btn-act primary"
              onclick="openEditModal(<?= (int)$u['id'] ?>,<?= json_encode($u['name']) ?>,<?= json_encode($u['email']) ?>,<?= json_encode($u['attributes'] ?? '') ?>)">Edit</button>
            <?php if ($u['email'] !== $email): ?>
            <form method="POST" style="display:inline"
              onsubmit="return confirm('<?= $u['is_disabled'] ? 'Enable' : 'Disable' ?> this user?')">
              <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
              <input type="hidden" name="action" value="toggle_user">
              <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
              <button type="submit" class="btn-act <?= $u['is_disabled'] ? '' : 'warn-act' ?>"><?= $u['is_disabled'] ? 'Enable' : 'Disable' ?></button>
            </form>
            <form method="POST" style="display:inline"
              onsubmit="return confirm('Delete this user? This cannot be undone.')">
              <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
              <input type="hidden" name="action" value="delete_user">
              <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
              <button type="submit" class="btn-act danger">Delete</button>
            </form>
            <?php else: ?>
            <span class="muted" style="font-size:.65rem;font-family:var(--mono)">you</span>
            <?php endif; ?>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
        <?php else: ?>
        <tr><td colspan="7" class="empty-state">No users found.</td></tr>
        <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Add User Modal -->
  <div class="modal-overlay" id="modal-add" hidden onclick="if(event.target===this)this.hidden=true">
    <div class="modal-card">
      <div class="modal-hd">
        <h3>Add User</h3>
        <button class="modal-close" onclick="document.getElementById('modal-add').hidden=true">×</button>
      </div>
      <form method="POST">
        <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
        <input type="hidden" name="action" value="add_user">
        <div class="modal-body">
          <div class="form-row">
            <label>Name</label>
            <input type="text" name="name" placeholder="Full name">
          </div>
          <div class="form-row">
            <label>Email</label>
            <input type="email" name="email" required placeholder="user@example.com">
          </div>
          <div class="form-row">
            <label>Attributes <span style="text-transform:none;color:var(--muted)">(optional JSON)</span></label>
            <textarea name="attributes" rows="3" placeholder='{"department":"engineering"}'></textarea>
          </div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn-sm clear" onclick="document.getElementById('modal-add').hidden=true">Cancel</button>
          <button type="submit" class="btn-sm">Add User</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Edit User Modal -->
  <div class="modal-overlay" id="modal-edit" hidden onclick="if(event.target===this)this.hidden=true">
    <div class="modal-card">
      <div class="modal-hd">
        <h3>Edit User</h3>
        <button class="modal-close" onclick="document.getElementById('modal-edit').hidden=true">×</button>
      </div>
      <form method="POST">
        <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
        <input type="hidden" name="action" value="update_user">
        <input type="hidden" name="id" id="edit-id">
        <div class="modal-body">
          <div class="form-row">
            <label>Name</label>
            <input type="text" name="name" id="edit-name" placeholder="Full name">
          </div>
          <div class="form-row">
            <label>Email</label>
            <input type="email" name="email" id="edit-email" required placeholder="user@example.com">
          </div>
          <div class="form-row">
            <label>Attributes <span style="text-transform:none;color:var(--muted)">(optional JSON)</span></label>
            <textarea name="attributes" id="edit-attrs" rows="3" placeholder='{"department":"engineering"}'></textarea>
          </div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn-sm clear" onclick="document.getElementById('modal-edit').hidden=true">Cancel</button>
          <button type="submit" class="btn-sm">Save</button>
        </div>
      </form>
    </div>
  </div>

  <?php endif; /* $tab === 'users' */ ?>

  <?php if ($tab === 'blocked'): ?>

  <?php if ($b_flash): ?>
  <div class="flash flash--<?= $b_flash_ok ? 'ok' : 'err' ?>"><?= $b_flash ?></div>
  <?php endif; ?>

  <!-- Manual block form -->
  <div class="users-hd" style="align-items:flex-end;flex-wrap:wrap;gap:.75rem">
    <h1>Blocked IPs</h1>
    <form method="GET" style="display:flex;align-items:flex-end;gap:.4rem;margin-left:auto">
      <input type="hidden" name="tab" value="blocked">
      <div class="flt" style="margin:0">
        <label style="font-family:var(--mono);font-size:.62rem;letter-spacing:.08em;text-transform:uppercase;color:#3d4f68">View</label>
        <select name="ipf" style="width:110px" <?= !$my_ips_set ? 'disabled' : '' ?>
                onchange="this.form.submit()">
          <option value="all"    <?= $ipf === 'all'    ? 'selected' : '' ?>>All IPs</option>
          <option value="mine"   <?= $ipf === 'mine'   ? 'selected' : '' ?>>My IPs only</option>
          <option value="others" <?= $ipf === 'others' ? 'selected' : '' ?>>Exclude mine</option>
        </select>
      </div>
    </form>
    <form method="POST" style="display:flex;align-items:flex-end;gap:.5rem;flex-wrap:wrap">
      <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
      <input type="hidden" name="action" value="block_ip">
      <div class="flt">
        <label>IP Address</label>
        <input type="text" name="ip" placeholder="1.2.3.4" required style="width:150px">
      </div>
      <div class="flt" style="flex:1;min-width:160px">
        <label>Reason <span style="text-transform:none;color:var(--muted)">(optional)</span></label>
        <input type="text" name="reason" placeholder="Abuse, scanning…" style="width:100%">
      </div>
      <button type="submit" class="btn-sm" style="border-color:rgba(239,68,68,.3);color:#fca5a5" onclick="return confirm('Block this IP?')">⊘ Block</button>
    </form>
  </div>

  <div class="card">
    <?php if ($ipf !== 'all'): ?>
    <div class="card-hd" style="background:rgba(0,212,170,.04)">
      <h2>Blocked IPs</h2>
      <span class="card-meta"><?= $ipf === 'mine' ? 'Showing my IPs only' : 'Excluding my IPs' ?> · <?= count($blocked_list) ?> matched</span>
    </div>
    <?php endif; ?>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th>IP</th><th>Country</th><th>All-time req</th><th>Last seen</th><th>Err%</th><th>Blocked by</th><th>Blocked at</th><th>Reason</th><th></th></tr>
        </thead>
        <tbody>
        <?php if ($blocked_list): ?>
        <?php foreach ($blocked_list as $b): ?>
        <tr>
          <td>
            <a href="?ip=<?= urlencode($b['ip']) ?>" class="ip-link" title="View activity for this IP"><?= htmlspecialchars($b['ip']) ?></a><?= me_badge($b['ip'], $my_ips_set) ?>
          </td>
          <td>
            <?php if ($b['country'] && $b['country'] !== 'XX'): ?>
            <?= geo_label($b['ip'], [$b['ip'] => $b['country']]) ?>
            <?php else: ?><span class="muted">—</span><?php endif; ?>
          </td>
          <td><?= $b['total_req'] ? number_format((int)$b['total_req']) : '<span class="muted">—</span>' ?></td>
          <td><?= $b['last_seen'] ? rel_time($b['last_seen']) : '<span class="muted">—</span>' ?></td>
          <td class="<?= (int)$b['err_pct'] > 30 ? 'epct-warn' : 'muted' ?>"><?= $b['total_req'] ? (int)$b['err_pct'] . '%' : '<span class="muted">—</span>' ?></td>
          <td><span class="muted" style="font-size:.72rem"><?= htmlspecialchars($b['blocked_by']) ?></span></td>
          <td><span class="ts" title="<?= htmlspecialchars($b['blocked_at']) ?> UTC"><?= rel_time($b['blocked_at']) ?></span></td>
          <td><span class="muted" style="font-family:var(--mono);font-size:.68rem;max-width:180px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?= htmlspecialchars($b['reason'] ?? '') ?>"><?= $b['reason'] ? htmlspecialchars($b['reason']) : '—' ?></span></td>
          <td>
            <form method="POST" style="display:inline" onsubmit="return confirm('Unblock <?= htmlspecialchars(addslashes($b['ip'])) ?>?')">
              <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
              <input type="hidden" name="action" value="unblock_ip">
              <input type="hidden" name="ip" value="<?= htmlspecialchars($b['ip']) ?>">
              <button type="submit" class="btn-act">Unblock</button>
            </form>
          </td>
        </tr>
        <?php endforeach; ?>
        <?php else: ?>
        <tr><td colspan="9" class="empty-state">No blocked IPs.</td></tr>
        <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>

  <?php endif; /* $tab === 'blocked' */ ?>

  <?php if ($tab === 'soc'): ?>
  <?php
    // Helpers for SOC section
    $soc_risk_class = fn(int $s): string => match(true) {
        $s >= 80 => 'risk-crit', $s >= 50 => 'risk-high',
        $s >= 25 => 'risk-med',  $s > 0   => 'risk-low',
        default  => 'risk-0',
    };
    $soc_sig_ips  = fn(string $k) => array_filter($soc_threat_ips, fn($r) => $r[$k] > 0);
    $soc_enum_top    = array_slice(iterator_to_array($soc_sig_ips('s_enum'),    false), 0, 5);
    $soc_scanner_top = array_slice(iterator_to_array($soc_sig_ips('s_scanner'), false), 0, 5);
    $soc_probe_top   = array_slice(iterator_to_array($soc_sig_ips('s_probe'),   false), 0, 5);
    $soc_5xx_top     = array_slice(iterator_to_array($soc_sig_ips('s_5xx'),     false), 0, 5);
    $soc_php_top     = array_slice(iterator_to_array($soc_sig_ips('s_php'),     false), 0, 5);
    $soc_geo_ips     = array_unique(array_merge(
        array_column($soc_threat_ips, 'ip'), array_column($soc_events, 'ip')
    ));
    $soc_geo = $pdo ? geoip_country($soc_geo_ips) : [];
    $ev_label = ['scanner' => 'Scanner', 'probe' => 'Probe', '5xx' => '5xx',
                 '403' => '403', '404' => '404', 'anomaly' => 'Anomaly'];
    $soc_period_labels = ['1h' => 'Last hour', '6h' => 'Last 6 h', '24h' => 'Last 24 h'];
    $soc_period_label  = $soc_period_labels[$soc_period_key];
    $threat_icons = ['low' => '🟢', 'medium' => '🟡', 'high' => '🟠', 'critical' => '🔴'];
  ?>

  <!-- ── SOC Header ───────────────────────────────────────────────────────── -->
  <div class="page-hd">
    <h1>Security Operations</h1>
    <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap">
      <div class="period-tabs">
        <?php foreach ($soc_period_labels as $k => $lbl): ?>
        <a href="?tab=soc&soc_period=<?= $k ?>&ipf=<?= urlencode($ipf) ?>" class="<?= $soc_period_key === $k ? 'active' : '' ?>"><?= $lbl ?></a>
        <?php endforeach; ?>
      </div>
      <form method="GET" style="display:flex;align-items:center;gap:.4rem">
        <input type="hidden" name="tab"        value="soc">
        <input type="hidden" name="soc_period" value="<?= htmlspecialchars($soc_period_key) ?>">
        <div class="flt" style="margin:0">
          <label style="font-family:var(--mono);font-size:.62rem;letter-spacing:.08em;text-transform:uppercase;color:#3d4f68">View</label>
          <select name="ipf" style="width:110px" <?= !$my_ips_set ? 'disabled title="Add IPs in My IPs tab first"' : '' ?>
                  onchange="this.form.submit()">
            <option value="all"    <?= $ipf === 'all'    ? 'selected' : '' ?>>All IPs</option>
            <option value="mine"   <?= $ipf === 'mine'   ? 'selected' : '' ?>>My IPs only</option>
            <option value="others" <?= $ipf === 'others' ? 'selected' : '' ?>>Exclude mine</option>
          </select>
        </div>
      </form>
    </div>
  </div>

  <!-- ── Threat Level Banner ──────────────────────────────────────────────── -->
  <div class="threat-banner threat-<?= $soc_threat_level ?>">
    <div class="threat-icon"><?= $threat_icons[$soc_threat_level] ?></div>
    <div class="threat-body">
      <div class="threat-level <?= $soc_threat_level ?>"><?= strtoupper($soc_threat_level) ?></div>
      <div class="threat-sub">
        <?php $active = count($soc_threat_ips); ?>
        <?= $active ?> IP<?= $active !== 1 ? 's' : '' ?> with signals · <?= $soc_c_crit ?> critical · <?= $soc_c_high ?> high · <?= $soc_c_medium ?> medium · <?= $soc_period_label ?>
      </div>
    </div>
    <div class="threat-kpis">
      <div>
        <div class="threat-kpi-val <?= $soc_c_crit > 0 ? 'err' : '' ?>"><?= $soc_c_crit ?></div>
        <div class="threat-kpi-lbl">Critical (≥80)</div>
      </div>
      <div>
        <div class="threat-kpi-val <?= $soc_c_high > 0 ? 'warn' : '' ?>"><?= $soc_c_high ?></div>
        <div class="threat-kpi-lbl">High (50–79)</div>
      </div>
      <div>
        <div class="threat-kpi-val"><?= count($soc_events) ?></div>
        <div class="threat-kpi-lbl">Security events</div>
      </div>
      <div>
        <div class="threat-kpi-val"><?= count($blocked_set) ?></div>
        <div class="threat-kpi-lbl">Blocked IPs</div>
      </div>
    </div>
  </div>

  <!-- ── Detection Signal Cards ───────────────────────────────────────────── -->
  <div class="signal-grid">

    <!-- Path Enumeration -->
    <?php $cnt = count($soc_enum_top); $cc = $cnt >= 3 ? 'c-crit' : ($cnt >= 1 ? 'c-low' : 'zero'); ?>
    <div class="signal-card <?= $cnt ? 'triggered' : '' ?>" style="--sig-clr:rgba(0,153,255,.35)">
      <div class="signal-hd">
        <span class="signal-icon">🔎</span>
        <span class="signal-title">Path Enumeration</span>
        <span class="signal-count <?= $cc ?>"><?= $cnt ?></span>
      </div>
      <div class="signal-body">
        <?php if ($soc_enum_top): foreach ($soc_enum_top as $r): ?>
        <div class="signal-item">
          <span class="signal-ip"><?= htmlspecialchars($r['ip']) ?></span>
          <span class="signal-val"><?= (int)$r['uniq_404'] ?> uniq 404s</span>
        </div>
        <?php endforeach; else: ?>
        <div class="signal-empty">No enumeration detected</div>
        <?php endif; ?>
      </div>
    </div>

    <!-- Scanner Agents -->
    <?php $cnt = count($soc_scanner_top); $cc = $cnt >= 2 ? 'c-crit' : ($cnt >= 1 ? 'c-high' : 'zero'); ?>
    <div class="signal-card <?= $cnt ? 'triggered' : '' ?>" style="--sig-clr:rgba(239,68,68,.4)">
      <div class="signal-hd">
        <span class="signal-icon">🤖</span>
        <span class="signal-title">Scanner Agents</span>
        <span class="signal-count <?= $cc ?>"><?= $cnt ?></span>
      </div>
      <div class="signal-body">
        <?php if ($soc_scanner_top): foreach ($soc_scanner_top as $r): ?>
        <div class="signal-item">
          <span class="signal-ip"><?= htmlspecialchars($r['ip']) ?></span>
          <span class="signal-val"><?= number_format((int)$r['total_reqs']) ?> reqs</span>
        </div>
        <?php endforeach; else: ?>
        <div class="signal-empty">No scanner user-agents</div>
        <?php endif; ?>
      </div>
    </div>

    <!-- Exploit Probes -->
    <?php $cnt = count($soc_probe_top); $cc = $cnt >= 1 ? 'c-crit' : 'zero'; ?>
    <div class="signal-card <?= $cnt ? 'triggered' : '' ?>" style="--sig-clr:rgba(249,115,22,.4)">
      <div class="signal-hd">
        <span class="signal-icon">💉</span>
        <span class="signal-title">Exploit Probes</span>
        <span class="signal-count <?= $cc ?>"><?= $cnt ?></span>
      </div>
      <div class="signal-body">
        <?php if ($soc_probe_paths): foreach (array_slice($soc_probe_paths, 0, 5) as $r): ?>
        <div class="signal-item">
          <?= uriLink($r['uri'], null, 32) ?>
          <span class="signal-val"><?= (int)$r['hits'] ?>×, <?= (int)$r['ips'] ?> IP<?= (int)$r['ips'] !== 1 ? 's' : '' ?></span>
        </div>
        <?php endforeach; else: ?>
        <div class="signal-empty">No exploit probes detected</div>
        <?php endif; ?>
      </div>
    </div>

    <!-- Rate Anomaly -->
    <?php $cnt = count($soc_rate_ips); $cc = $cnt >= 2 ? 'c-crit' : ($cnt >= 1 ? 'c-high' : 'zero'); ?>
    <div class="signal-card <?= $cnt ? 'triggered' : '' ?>" style="--sig-clr:rgba(168,85,247,.4)">
      <div class="signal-hd">
        <span class="signal-icon">⚡</span>
        <span class="signal-title">Rate Anomaly <span style="font-size:.58rem;color:var(--muted);font-weight:normal;text-transform:none;letter-spacing:0">/5 min</span></span>
        <span class="signal-count <?= $cc ?>"><?= $cnt ?></span>
      </div>
      <div class="signal-body">
        <?php if ($soc_rate_ips): foreach ($soc_rate_ips as $r): ?>
        <div class="signal-item">
          <span class="signal-ip"><?= htmlspecialchars($r['ip']) ?></span>
          <span class="signal-val"><?= (int)$r['reqs'] ?> req/5m</span>
        </div>
        <?php endforeach; else: ?>
        <div class="signal-empty">No rate spikes in last 5 min</div>
        <?php endif; ?>
      </div>
    </div>

    <!-- Server Error Storms -->
    <?php $cnt = count($soc_5xx_top); $cc = $cnt >= 2 ? 'c-crit' : ($cnt >= 1 ? 'c-low' : 'zero'); ?>
    <div class="signal-card <?= $cnt ? 'triggered' : '' ?>" style="--sig-clr:rgba(239,68,68,.25)">
      <div class="signal-hd">
        <span class="signal-icon">💥</span>
        <span class="signal-title">Server Errors</span>
        <span class="signal-count <?= $cc ?>"><?= $cnt ?></span>
      </div>
      <div class="signal-body">
        <?php if ($soc_5xx_top): foreach ($soc_5xx_top as $r): ?>
        <div class="signal-item">
          <span class="signal-ip"><?= htmlspecialchars($r['ip']) ?></span>
          <span class="signal-val"><?= (int)$r['c5xx'] ?> × 5xx</span>
        </div>
        <?php endforeach; else: ?>
        <div class="signal-empty">No 5xx clusters</div>
        <?php endif; ?>
      </div>
    </div>

    <!-- PHP Correlation -->
    <?php $cnt = count($soc_php_top); $cc = $cnt >= 2 ? 'c-high' : ($cnt >= 1 ? 'c-low' : 'zero'); ?>
    <div class="signal-card <?= $cnt ? 'triggered' : '' ?>" style="--sig-clr:rgba(245,158,11,.3)">
      <div class="signal-hd">
        <span class="signal-icon">🔗</span>
        <span class="signal-title">PHP Correlation</span>
        <span class="signal-count <?= $cc ?>"><?= $cnt ?></span>
      </div>
      <div class="signal-body">
        <?php if ($soc_php_top): foreach ($soc_php_top as $r): ?>
        <div class="signal-item">
          <span class="signal-ip"><?= htmlspecialchars($r['ip']) ?></span>
          <span class="signal-val"><?= (int)$r['php_errs'] ?> PHP err<?= (int)$r['php_errs'] !== 1 ? 's' : '' ?></span>
        </div>
        <?php endforeach; else: ?>
        <div class="signal-empty">No nginx↔PHP correlation</div>
        <?php endif; ?>
      </div>
    </div>

  </div><!-- .signal-grid -->

  <!-- ── Threat IP Table ──────────────────────────────────────────────────── -->
  <div class="card" style="margin-bottom:1.25rem">
    <div class="card-hd">
      <h2>Threat IPs</h2>
      <span class="card-meta"><?= count($soc_threat_ips) ?> IPs · scored · <?= $soc_period_label ?></span>
    </div>
    <div class="tbl-wrap">
      <?php if ($soc_threat_ips): ?>
      <table>
        <?php
          // Enrich threat IPs with ASN (reads from cache only — cron writes it)
          $soc_intel = ip_intel_get(array_column($soc_threat_ips, 'ip'));
        ?>
        <thead>
          <tr>
            <th>IP</th><th>CC</th><th>Provider</th><th>Score</th><th>Signals</th>
            <th>Reqs</th><th>404s</th><th>5xx</th><th>PHP&nbsp;Err</th><th>Rate/5m</th><th>Last&nbsp;Seen</th><th></th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($soc_threat_ips as $r):
            $ip  = $r['ip'];
            $cc  = $soc_geo[$ip] ?? $r['country'] ?? '';
            $sc  = $r['score'];
        ?>
        <tr>
          <td>
            <a href="?tab=nginx&ip=<?= urlencode($ip) ?>" class="ip-link"><?= htmlspecialchars($ip) ?></a><?= me_badge($ip, $my_ips_set) ?>
            <?php if ($r['is_blocked']): ?>
            <span class="badge--blocked-sm">blocked</span>
            <?php endif; ?>
          </td>
          <td><?= $cc ? geo_label($ip, $soc_geo) : '<span class="muted">—</span>' ?></td>
          <td style="white-space:normal;min-width:110px">
            <?php $intel = $soc_intel[$ip] ?? null;
            if ($intel):
                $org_short = $intel['org'] ? htmlspecialchars(substr($intel['org'], 0, 18)) : '';
                $tip = htmlspecialchars(($intel['org'] ?? '') . ($intel['asn'] ? ' · '.$intel['asn'] : ''));
            ?>
              <?php if ($org_short): ?><span class="org-lbl" title="<?= $tip ?>"><?= $org_short ?><?= strlen($intel['org'] ?? '') > 18 ? '…' : '' ?></span><?php endif; ?>
              <?php if ($intel['provider_type'] && $intel['provider_type'] !== 'unknown'): ?>
              <span class="pvdr-badge pvdr-<?= htmlspecialchars($intel['provider_type']) ?>"><?= htmlspecialchars($intel['provider_type']) ?></span>
              <?php endif; ?>
              <?php if ($intel['bot_claimed'] && $intel['bot_verified'] !== null): ?>
              <span class="<?= (int)$intel['bot_verified'] ? 'bot-ok' : 'bot-bad' ?>"><?= (int)$intel['bot_verified'] ? '✓' : '✗' ?></span>
              <?php endif; ?>
            <?php else: ?><span class="muted">—</span><?php endif; ?>
          </td>
          <td><span class="risk-score <?= $soc_risk_class($sc) ?>"><?= $sc ?></span></td>
          <td>
            <div class="sig-pills">
              <?php if ($r['s_enum'])    echo '<span class="sig-pill sig-enum">enum</span>'; ?>
              <?php if ($r['s_scanner']) echo '<span class="sig-pill sig-scan">scanner</span>'; ?>
              <?php if ($r['s_probe'])   echo '<span class="sig-pill sig-probe">probe</span>'; ?>
              <?php if ($r['s_rate'])    echo '<span class="sig-pill sig-rate">rate</span>'; ?>
              <?php if ($r['s_5xx'])     echo '<span class="sig-pill sig-5xx">5xx</span>'; ?>
              <?php if ($r['s_php'])     echo '<span class="sig-pill sig-php">php-err</span>'; ?>
            </div>
          </td>
          <td class="ts"><?= number_format((int)$r['total_reqs']) ?></td>
          <td><?= (int)$r['c404'] > 0 ? '<span class="badge badge--warn">' . (int)$r['c404'] . '</span>' : '<span class="muted">0</span>' ?></td>
          <td><?= (int)$r['c5xx'] > 0 ? '<span class="badge badge--err">'  . (int)$r['c5xx'] . '</span>' : '<span class="muted">0</span>' ?></td>
          <td><?= (int)$r['php_errs'] > 0 ? '<span style="color:var(--warn)">' . (int)$r['php_errs'] . '</span>' : '<span class="muted">0</span>' ?></td>
          <td><?= (int)$r['rate_5m'] > 0 ? '<span style="color:#c084fc">' . (int)$r['rate_5m'] . '</span>' : '<span class="muted">—</span>' ?></td>
          <td class="ts" title="<?= htmlspecialchars($r['last_seen']) ?>"><?= rel_time($r['last_seen']) ?></td>
          <td>
            <?php if (!$r['is_blocked']): ?>
            <form method="post" style="display:inline">
              <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
              <input type="hidden" name="action" value="block_ip">
              <input type="hidden" name="redirect_tab" value="soc">
              <input type="hidden" name="ip" value="<?= htmlspecialchars($ip) ?>">
              <input type="hidden" name="reason" value="SOC: score <?= $sc ?>">
              <button type="submit" class="btn-act danger" title="Block IP">Block</button>
            </form>
            <?php else: ?>
            <form method="post" style="display:inline">
              <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
              <input type="hidden" name="action" value="unblock_ip">
              <input type="hidden" name="redirect_tab" value="soc">
              <input type="hidden" name="ip" value="<?= htmlspecialchars($ip) ?>">
              <button type="submit" class="btn-act warn-act">Unblock</button>
            </form>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php else: ?>
      <div class="empty-state">No threat IPs detected in <?= $soc_period_label ?>. Server looks clean.</div>
      <?php endif; ?>
    </div>
  </div>

  <!-- ── Session Intelligence ────────────────────────────────────────────── -->
  <?php
    // Duration formatter
    $dur = fn(int $s): string => $s >= 3600
        ? floor($s/3600).'h '.floor(($s%3600)/60).'m'
        : ($s >= 60 ? floor($s/60).'m '.($s%60).'s' : $s.'s');

    // Signal pill helper for sessions
    $sess_pills = function(array $r): string {
        $sig = json_decode($r['signals'] ?? '{}', true) ?? [];
        $out = '';
        if (($sig['ua_switch'] ?? 0) > 0) $out .= '<span class="sig-pill sig-scan">ua-switch</span> ';
        if (($sig['scanner']  ?? 0) > 0) $out .= '<span class="sig-pill sig-scan">scanner</span> ';
        if (($sig['probe']    ?? 0) > 0) $out .= '<span class="sig-pill sig-probe">probe</span> ';
        if (($sig['enum']     ?? 0) > 0) $out .= '<span class="sig-pill sig-enum">enum</span> ';
        if (($sig['replay']   ?? 0) > 0) $out .= '<span class="sig-pill sig-php">replay</span> ';
        if (($sig['pki']      ?? 0) > 0) $out .= '<span class="sig-pill sig-5xx">pki</span> ';
        if (($sig['rate']     ?? 0) > 0) $out .= '<span class="sig-pill sig-rate">rate</span> ';
        if (($sig['recon']    ?? 0) > 0) $out .= '<span class="sig-pill sig-enum">recon</span> ';
        return trim($out);
    };

    $soc_sess_geo_ips = array_unique(array_column($soc_sessions, 'ip'));
    $soc_sess_geo     = $pdo ? geoip_country($soc_sess_geo_ips) : [];
  ?>
  <div class="card" style="margin-bottom:1.25rem">
    <div class="card-hd">
      <h2>Session Intelligence</h2>
      <span class="card-meta"><?= count($soc_sessions) ?> sessions · <?= $soc_period_label ?> · scored by cron/session_analysis.php</span>
    </div>
    <div class="tbl-wrap">
      <?php if ($soc_sessions): ?>
      <table>
        <thead>
          <tr>
            <th>Start</th><th>IP</th><th>CC</th><th>Provider</th>
            <th>Class</th><th>Score</th><th>Dur</th><th>Reqs</th>
            <th>404s</th><th>5xx</th><th>Signals</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($soc_sessions as $s):
            $sip = $s['ip'];
            $scc = $soc_sess_geo[$sip] ?? $s['country'] ?? '';
            $cls = $s['classification'];
            $sc  = (int)$s['score'];
            // Provider display
            $pvdr = '';
            if ($s['org']) {
                $pvdr = '<span class="org-lbl" title="' . htmlspecialchars($s['org'] . ($s['asn'] ? ' · ' . $s['asn'] : '')) . '">'
                      . htmlspecialchars(substr($s['org'], 0, 22)) . ($s['asn'] ? '</span> <span class="asn-lbl">' . htmlspecialchars($s['asn']) . '</span>' : '</span>');
            }
            if ($s['provider_type'] && $s['provider_type'] !== 'unknown') {
                $pvdr .= ' <span class="pvdr-badge pvdr-' . htmlspecialchars($s['provider_type']) . '">' . htmlspecialchars($s['provider_type']) . '</span>';
            }
            if ($s['bot_claimed'] && $s['bot_verified'] !== null) {
                $pvdr .= ' <span class="' . ((int)$s['bot_verified'] ? 'bot-ok' : 'bot-bad') . '">'
                       . ((int)$s['bot_verified'] ? '✓' : '✗') . ' bot</span>';
            }
        ?>
        <tr>
          <td class="ts" title="<?= htmlspecialchars($s['session_start']) ?>"><?= rel_time($s['session_start']) ?></td>
          <td><a href="?tab=nginx&ip=<?= urlencode($sip) ?>" class="ip-link"><?= htmlspecialchars($sip) ?></a><?= me_badge($sip, $my_ips_set) ?></td>
          <td><?= $scc ? geo_label($sip, $soc_sess_geo) : '<span class="muted">—</span>' ?></td>
          <td style="white-space:normal;min-width:130px"><?= $pvdr ?: '<span class="muted">—</span>' ?></td>
          <td><span class="cls-badge cls-<?= htmlspecialchars($cls) ?>"><?= htmlspecialchars($cls) ?></span></td>
          <td><span class="risk-score <?= $soc_risk_class($sc) ?>"><?= $sc ?></span></td>
          <td class="dur-lbl"><?= $dur((int)$s['duration_s']) ?></td>
          <td class="ts"><?= number_format((int)$s['req_count']) ?></td>
          <td><?= (int)$s['c404'] > 0 ? '<span class="badge badge--warn">'.(int)$s['c404'].'</span>' : '<span class="muted">0</span>' ?></td>
          <td><?= (int)$s['c5xx'] > 0 ? '<span class="badge badge--err">'.(int)$s['c5xx'].'</span>'  : '<span class="muted">0</span>' ?></td>
          <td><div class="sig-pills"><?= $sess_pills($s) ?></div></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php else: ?>
      <div class="empty-state">No sessions in <?= $soc_period_label ?> — cron/session_analysis.php may not have run yet.</div>
      <?php endif; ?>
    </div>
  </div>

  <!-- ── Distributed Scans + Honeypot ─────────────────────────────────────── -->
  <div class="side-row" style="margin-bottom:1.25rem">

    <div class="card" style="margin-bottom:0">
      <div class="card-hd">
        <h2>Distributed Scans</h2>
        <span class="card-meta">≥3 IPs · same 404 path · <?= $soc_period_label ?></span>
      </div>
      <div class="tbl-wrap">
        <?php if ($soc_distrib): ?>
        <table>
          <thead><tr><th>Path</th><th>IPs</th><th>Hits</th><th>Window</th></tr></thead>
          <tbody>
          <?php foreach ($soc_distrib as $d): ?>
          <tr>
            <td><?= uriLink($d['uri'], null, 50) ?></td>
            <td><span class="badge badge--err"><?= (int)$d['c_ips'] ?></span></td>
            <td class="ts"><?= number_format((int)$d['c_hits']) ?></td>
            <td class="ts" title="<?= htmlspecialchars($d['first_seen']) ?> → <?= htmlspecialchars($d['last_seen']) ?>"><?= rel_time($d['first_seen']) ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        <?php else: ?>
        <div class="empty-state">No coordinated scans detected.</div>
        <?php endif; ?>
      </div>
    </div>

    <div class="card" style="margin-bottom:0">
      <div class="card-hd">
        <h2>Honeypot Hits</h2>
        <span class="card-meta"><?= count($soc_honeypot) ?> hits · decoy paths · <?= $soc_period_label ?></span>
      </div>
      <div class="tbl-wrap">
        <?php if ($soc_honeypot): ?>
        <table>
          <thead><tr><th>Time</th><th>IP</th><th>Path</th><th>Status</th><th>UA</th></tr></thead>
          <tbody>
          <?php foreach ($soc_honeypot as $h):
              $hip = $h['ip'];
              $hcc = $soc_geo[$hip] ?? $h['country'] ?? '';
          ?>
          <tr>
            <td class="ts" title="<?= htmlspecialchars($h['created_at']) ?>"><?= rel_time($h['created_at']) ?></td>
            <td>
              <a href="?tab=soc&soc_period=<?= $soc_period_key ?>" class="ip-link"><?= htmlspecialchars($hip) ?></a><?= me_badge($hip, $my_ips_set) ?>
              <?php if ($hcc): ?> <?= flag($hcc) ?><?php endif; ?>
            </td>
            <td><?= uriLink($h['uri'], null, 40) ?></td>
            <td><?= status_badge((int)$h['status']) ?></td>
            <td><?= ua_label($h['user_agent'] ?? '') ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        <?php else: ?>
        <div class="empty-state">No honeypot hits in <?= $soc_period_label ?>.</div>
        <?php endif; ?>
      </div>
    </div>

  </div><!-- .side-row -->

  <!-- ── Recent Security Events ───────────────────────────────────────────── -->
  <div class="card">
    <div class="card-hd">
      <h2>Security Event Feed</h2>
      <span class="card-meta"><?= count($soc_events) ?> events · <?= $soc_period_label ?> · most recent first</span>
    </div>
    <div class="tbl-wrap">
      <?php if ($soc_events): ?>
      <table>
        <thead>
          <tr><th>Time</th><th>IP</th><th>CC</th><th>Type</th><th>M</th><th>Path</th><th>Status</th><th>UA</th></tr>
        </thead>
        <tbody>
        <?php foreach ($soc_events as $ev):
            $eip = $ev['ip'];
            $ecc = $soc_geo[$eip] ?? $ev['country'] ?? '';
            $et  = $ev['ev_type'];
        ?>
        <tr>
          <td class="ts" title="<?= htmlspecialchars($ev['created_at']) ?>"><?= rel_time($ev['created_at']) ?></td>
          <td><a href="?tab=soc&soc_period=<?= $soc_period_key ?>" class="ip-link"><?= htmlspecialchars($eip) ?></a><?= me_badge($eip, $my_ips_set) ?></td>
          <td><?= $ecc ? '<span class="geo" title="' . htmlspecialchars($ecc) . '">' . flag($ecc) . ' <span class="geo-cc">' . htmlspecialchars($ecc) . '</span></span>' : '<span class="muted">—</span>' ?></td>
          <td><span class="ev-pill ev-<?= htmlspecialchars($et) ?>"><?= htmlspecialchars($ev_label[$et] ?? $et) ?></span></td>
          <td><?= method_badge($ev['method']) ?></td>
          <td><?= uriLink($ev['uri'], null, 60) ?></td>
          <td><?= status_badge((int)$ev['status']) ?></td>
          <td><?= ua_label($ev['user_agent'] ?? '') ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php else: ?>
      <div class="empty-state">No security events in <?= $soc_period_label ?>.</div>
      <?php endif; ?>
    </div>
  </div>

  <?php endif; /* $tab === 'soc' */ ?>

  <?php if ($tab === 'myips'): ?>

  <!-- ── My IPs ─────────────────────────────────────────────────────────────── -->
  <div class="users-hd" style="margin-bottom:1.25rem">
    <h1>My IPs</h1>
    <button onclick="document.getElementById('modal-add-myip').hidden=false" class="btn-act primary">+ Add IP manually</button>
  </div>

  <?php if ($mi_flash): ?>
  <div class="flash flash--<?= $mi_flash_ok ? 'ok' : 'err' ?>"><?= $mi_flash ?></div>
  <?php endif; ?>

  <div class="card">
    <div class="card-hd">
      <h2>Known Admin IPs</h2>
      <span class="card-meta"><?= count($my_ips_set) ?> IPs · auto-detected on login + manually pinned</span>
    </div>
    <?php if ($my_ips_set): ?>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>IP</th><th>Label</th><th>Type</th><th>First seen</th><th>Last seen</th><th></th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($my_ips_set as $mip => $mrow): ?>
        <tr>
          <td style="font-family:var(--mono);font-size:.78rem"><?= htmlspecialchars($mip) ?></td>
          <td>
            <?php if ($mrow['label']): ?>
            <span style="font-size:.78rem"><?= htmlspecialchars($mrow['label']) ?></span>
            <?php else: ?><span class="muted">—</span><?php endif; ?>
          </td>
          <td>
            <?php if ($mrow['type'] === 'auto'): ?>
            <span class="badge badge--ok" style="font-size:.6rem">auto</span>
            <?php else: ?>
            <span class="badge badge--redir" style="font-size:.6rem">manual</span>
            <?php endif; ?>
          </td>
          <td class="ts" title="<?= htmlspecialchars($mrow['first_seen']) ?> UTC"><?= rel_time($mrow['first_seen']) ?></td>
          <td class="ts" title="<?= htmlspecialchars($mrow['last_seen']) ?> UTC"><?= rel_time($mrow['last_seen']) ?></td>
          <td style="white-space:nowrap">
            <button onclick="openEditMyIp(<?= htmlspecialchars(json_encode($mip)) ?>, <?= htmlspecialchars(json_encode($mrow['label'] ?? '')) ?>)"
                    class="btn-act primary" style="margin-right:.3rem">Edit</button>
            <form method="POST" style="display:inline" onsubmit="return confirm('Remove <?= htmlspecialchars(addslashes($mip)) ?> from My IPs?')">
              <input type="hidden" name="_csrf"   value="<?= _admin_csrf_token() ?>">
              <input type="hidden" name="action"  value="delete_myip">
              <input type="hidden" name="ip"      value="<?= htmlspecialchars($mip) ?>">
              <button type="submit" class="btn-act danger">Remove</button>
            </form>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php else: ?>
    <div class="empty-state">No IPs recorded yet — they appear automatically on each admin page load.</div>
    <?php endif; ?>
  </div>

  <!-- Add IP modal -->
  <div id="modal-add-myip" class="modal-overlay" hidden>
    <div class="modal-card">
      <div class="modal-hd">
        <h3>Add IP manually</h3>
        <button class="modal-close" onclick="document.getElementById('modal-add-myip').hidden=true">×</button>
      </div>
      <form method="POST">
        <input type="hidden" name="_csrf"   value="<?= _admin_csrf_token() ?>">
        <input type="hidden" name="action"  value="add_myip">
        <div class="modal-body">
          <div class="form-row">
            <label>IP address</label>
            <input type="text" name="ip" placeholder="203.0.113.42" required autocomplete="off">
          </div>
          <div class="form-row">
            <label>Label <span style="color:var(--muted)">(optional)</span></label>
            <input type="text" name="label" placeholder="Home router, VPN exit node, …" maxlength="60">
          </div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn-act" onclick="document.getElementById('modal-add-myip').hidden=true">Cancel</button>
          <button type="submit" class="btn-act primary">Add IP</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Edit label modal -->
  <div id="modal-edit-myip" class="modal-overlay" hidden>
    <div class="modal-card">
      <div class="modal-hd">
        <h3>Edit label</h3>
        <button class="modal-close" onclick="document.getElementById('modal-edit-myip').hidden=true">×</button>
      </div>
      <form method="POST">
        <input type="hidden" name="_csrf"   value="<?= _admin_csrf_token() ?>">
        <input type="hidden" name="action"  value="update_myip">
        <input type="hidden" name="ip"      id="edit-myip-ip">
        <div class="modal-body">
          <div class="form-row">
            <label>IP address</label>
            <input type="text" id="edit-myip-ip-display" readonly style="opacity:.5">
          </div>
          <div class="form-row">
            <label>Label</label>
            <input type="text" name="label" id="edit-myip-label" placeholder="Home router, VPN exit node, …" maxlength="60">
          </div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn-act" onclick="document.getElementById('modal-edit-myip').hidden=true">Cancel</button>
          <button type="submit" class="btn-act primary">Save</button>
        </div>
      </form>
    </div>
  </div>

  <?php endif; /* $tab === 'myips' */ ?>

</div><!-- .wrap -->

<script>
// Convert UTC timestamps to local time on hover title
document.querySelectorAll('.ts').forEach(function(el) {
  var utc = el.title;
  if (!utc) return;
  var d = new Date(utc.replace(' ', 'T') + 'Z');
  el.title = d.toLocaleString();
});
// Auto-submit selects
document.querySelectorAll('.filter-bar select').forEach(function(s) {
  s.addEventListener('change', function() { this.closest('form').submit(); });
});
// User edit modal
function openEditModal(id, name, email, attrs) {
  document.getElementById('edit-id').value    = id;
  document.getElementById('edit-name').value  = name;
  document.getElementById('edit-email').value = email;
  document.getElementById('edit-attrs').value = attrs;
  document.getElementById('modal-edit').hidden = false;
}
// My IPs edit modal
function openEditMyIp(ip, label) {
  document.getElementById('edit-myip-ip').value         = ip;
  document.getElementById('edit-myip-ip-display').value = ip;
  document.getElementById('edit-myip-label').value      = label;
  document.getElementById('modal-edit-myip').hidden     = false;
}
</script>

</body>
</html>
