<?php
/**
 * threat_alert.php — periodic threat-digest email via local MTA
 *
 * Queries for events since the last run, scores them, and sends one
 * plain-text email per run when anything is above the alert threshold.
 * Uses a DB cursor so every event is reported exactly once.
 *
 * ── Recommended cron entry ───────────────────────────────────────────────────
 *
 *   * /5 * * * * www-data /usr/bin/php /var/www/thameur.org/cron/threat_alert.php
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

if (php_sapi_name() !== 'cli') { http_response_code(403); exit; }

define('ADMIN_NO_LOG', true);
require_once __DIR__ . '/../config.php';

// ── Config ────────────────────────────────────────────────────────────────────
const ALERT_TO        = 'tbelghith@gmail.com';
const ALERT_FROM_NAME = 'Bista El Kalba';
const ALERT_FROM_ADDR = 'watchdog@thameur.org';
const ALERT_MIN_SCORE = 40;   // sessions below this are silent
const ALERT_HIGH      = 50;   // score threshold for HIGH level
const ALERT_CRITICAL  = 80;   // score threshold for CRITICAL level
const ALERT_LOOKBACK  = 21600; // max look-back in seconds (6 h) after a gap
const DASHBOARD_URL   = 'https://thameur.org/adminIBBjATBgNVHSUEDDAKBg.php?tab=soc';

// ── Bootstrap ─────────────────────────────────────────────────────────────────
$pdo = admin_pdo();
if (!$pdo) { fwrite(STDERR, "[threat_alert] DB unavailable\n"); exit(1); }

ensureAlertCursor($pdo);

$cursor = $pdo->query(
    "SELECT last_run_at FROM alert_cursor WHERE id=1"
)->fetch();
$since = resolveSince($cursor ? $cursor['last_run_at'] : null);
$now   = gmdate('Y-m-d H:i:s');

// ── Gather ────────────────────────────────────────────────────────────────────
$honeypots   = fetchHoneypotHits($pdo, $since);
$threats     = fetchThreatSessions($pdo, $since);
$escalations = fetchEscalations($pdo, $since);
$blocks      = fetchNewBlocks($pdo, $since);

// ── Always advance cursor ─────────────────────────────────────────────────────
$pdo->prepare(
    "INSERT INTO alert_cursor (id, last_run_at) VALUES (1,?)
     ON DUPLICATE KEY UPDATE last_run_at=VALUES(last_run_at)"
)->execute([$now]);

// ── Decide ────────────────────────────────────────────────────────────────────
$level = deriveLevel($honeypots, $threats, $escalations, $blocks);
if ($level === 'clean') exit(0);

// ── Send ──────────────────────────────────────────────────────────────────────
$subject  = buildSubject($level, $honeypots, $threats, $escalations, $blocks);
$textBody = buildBodyText($level, $honeypots, $threats, $escalations, $blocks, $since, $now);
$htmlBody = buildBodyHtml($level, $honeypots, $threats, $escalations, $blocks, $since, $now);

if (sendAlert($subject, $textBody, $htmlBody)) {
    $pdo->prepare(
        "INSERT INTO alert_cursor (id, last_alert_at) VALUES (1,?)
         ON DUPLICATE KEY UPDATE last_alert_at=VALUES(last_alert_at)"
    )->execute([$now]);
    echo '[' . $now . " UTC] Alert sent ($level): $subject\n";
} else {
    fwrite(STDERR, "[threat_alert] mail() failed\n");
    exit(1);
}
exit(0);

// ═════════════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════════════

function ensureAlertCursor(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS alert_cursor (
        id            INT UNSIGNED PRIMARY KEY DEFAULT 1,
        last_run_at   DATETIME     NOT NULL DEFAULT '2000-01-01 00:00:00',
        last_alert_at DATETIME     DEFAULT NULL,
        updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                            ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}

function resolveSince(?string $lastRun): string {
    $ts = $lastRun ? strtotime($lastRun) : 0;
    $floor = time() - ALERT_LOOKBACK;
    return gmdate('Y-m-d H:i:s', max($ts, $floor));
}

// ── Queries ───────────────────────────────────────────────────────────────────

function fetchHoneypotHits(PDO $pdo, string $since): array {
    $st = $pdo->prepare("
        SELECT n.ip, COALESCE(g.country, n.country, '') AS cc,
               n.uri, n.user_agent, n.created_at
        FROM   nginx_visits n
        LEFT JOIN geoip_cache g ON g.ip = n.ip
        WHERE  n.created_at > ?
          AND  n.uri REGEXP ?
        ORDER BY n.created_at DESC
        LIMIT  50
    ");
    $st->execute([$since, honeypot_mysql_regexp()]);
    return $st->fetchAll();
}

function fetchThreatSessions(PDO $pdo, string $since): array {
    $st = $pdo->prepare("
        SELECT s.ip, s.score, s.classification,
               s.req_count, s.has_scanner, s.exploit_hits,
               s.c404, s.c5xx, s.signals,
               COALESCE(g.country, '') AS cc,
               i.org, i.asn, i.provider_type
        FROM   sessions s
        LEFT JOIN geoip_cache g ON g.ip = s.ip
        LEFT JOIN ip_intel    i ON i.ip  = s.ip
        WHERE  s.analyzed_at > ?
          AND  s.score >= ?
          AND  s.classification NOT IN ('human','researcher','crawler','social_probe')
        ORDER BY s.score DESC
        LIMIT  20
    ");
    $st->execute([$since, ALERT_MIN_SCORE]);
    return $st->fetchAll();
}

function fetchEscalations(PDO $pdo, string $since): array {
    $st = $pdo->prepare("
        SELECT ip, reason, escalated_reason, escalated_at, score_at_add
        FROM   ip_watchlist
        WHERE  status = 'candidate'
          AND  escalated_at > ?
        ORDER BY escalated_at DESC
        LIMIT  10
    ");
    $st->execute([$since]);
    return $st->fetchAll();
}

function fetchNewBlocks(PDO $pdo, string $since): array {
    $st = $pdo->prepare("
        SELECT ip, reason, blocked_at, blocked_by
        FROM   blocked_ips
        WHERE  blocked_at > ?
        ORDER BY blocked_at DESC
        LIMIT  20
    ");
    $st->execute([$since]);
    return $st->fetchAll();
}

// ── Scoring ───────────────────────────────────────────────────────────────────

function deriveLevel(array $honeypots, array $threats, array $escalations, array $blocks): string {
    if (!$honeypots && !$threats && !$escalations && !$blocks) return 'clean';

    foreach ($threats as $t) {
        if ((int)$t['score'] >= ALERT_CRITICAL) return 'critical';
    }
    if ($honeypots || !empty($escalations)) {
        foreach ($threats as $t) {
            if ((int)$t['score'] >= ALERT_HIGH) return 'critical';
        }
        return 'high';
    }
    foreach ($threats as $t) {
        if ((int)$t['score'] >= ALERT_HIGH) return 'high';
    }
    if ($blocks || $threats) return 'medium';
    return 'clean';
}

// ── Formatting ────────────────────────────────────────────────────────────────

function buildSubject(string $level, array $h, array $t, array $e, array $b): string {
    $tag   = strtoupper($level);
    $parts = [];
    if ($h) $parts[] = count($h) . ' honeypot hit' . (count($h) > 1 ? 's' : '');
    if ($t) $parts[] = count($t) . ' threat IP'    . (count($t) > 1 ? 's' : '');
    if ($e) $parts[] = count($e) . ' escalation'   . (count($e) > 1 ? 's' : '');
    if ($b) $parts[] = count($b) . ' new block'    . (count($b) > 1 ? 's' : '');
    return '[WATCHDOG] ' . $tag . ' — ' . implode(', ', $parts) . ' | thameur.org';
}

function buildBodyText(string $level, array $h, array $t, array $e, array $b, string $since, string $now): string {
    $sep = str_repeat('─', 70);
    $out  = "THAMEUR.ORG SECURITY ALERT\n";
    $out .= str_repeat('=', 70) . "\n";
    $out .= 'Threat Level : ' . strtoupper($level) . "\n";
    $out .= 'Period       : ' . $since . ' → ' . $now . " UTC\n";
    $out .= 'Generated    : ' . $now . " UTC\n\n";

    $out .= "$sep\nHONEYPOT HITS [" . count($h) . "]\n$sep\n";
    if ($h) {
        $out .= sprintf("  %-45s %-4s %-21s %s\n", 'IP', 'CC', 'Time (UTC)', 'Path');
        foreach ($h as $r) {
            $ts  = substr($r['created_at'], 0, 19);
            $uri = substr($r['uri'], 0, 55);
            $out .= sprintf("  %-45s %-4s %-21s %s\n", $r['ip'], $r['cc'] ?: '??', $ts, $uri);
        }
    } else {
        $out .= "  None\n";
    }

    $out .= "\n$sep\nTHREAT SESSIONS [" . count($t) . "]\n$sep\n";
    foreach ($t as $r) {
        $sc  = (int)$r['score'];
        $lvl = $sc >= ALERT_CRITICAL ? 'CRITICAL' : ($sc >= ALERT_HIGH ? 'HIGH' : 'MEDIUM');
        $out .= sprintf("  %-45s %s  score=%-3d [%s] %s\n",
            $r['ip'], $r['cc'] ?: '??', $sc, $lvl, $r['classification']);
        $out .= '    Signals :' . buildSignals($r) . "\n";
        if ($r['org'] || $r['asn']) {
            $out .= '    Org     : ' . trim(($r['asn'] ?? '') . ' ' . ($r['org'] ?? '')) . "\n";
        }
        $out .= sprintf("    Activity: %d reqs  %d exploits  %d×404  %d×5xx\n\n",
            $r['req_count'], $r['exploit_hits'], $r['c404'], $r['c5xx']);
    }
    if (!$t) $out .= "  None\n";

    $out .= "\n$sep\nWATCHLIST ESCALATIONS [" . count($e) . "]\n$sep\n";
    foreach ($e as $r) {
        $out .= sprintf("  %-45s → candidate for blocking\n", $r['ip']);
        if ($r['escalated_reason']) {
            $out .= '    Reason  : ' . $r['escalated_reason'] . "\n";
        }
    }
    if (!$e) $out .= "  None\n";

    $out .= "\n$sep\nNEW BLOCKS [" . count($b) . "]\n$sep\n";
    foreach ($b as $r) {
        $out .= sprintf("  %-45s  %s\n", $r['ip'], substr($r['reason'] ?? '—', 0, 60));
    }
    if (!$b) $out .= "  None\n";

    $out .= "\n$sep\n";
    $out .= 'Dashboard: ' . DASHBOARD_URL . "\n";
    $out .= "\nThis alert was generated automatically by " . ALERT_FROM_NAME . ".\n";
    return $out;
}

function buildSignals(array $row): string {
    $sig = [];
    if ($row['has_scanner'])           $sig[] = 'scanner';
    if ((int)$row['exploit_hits'] > 0) $sig[] = 'exploit-probe';
    if ((int)$row['c404'] > 5)         $sig[] = 'enumeration';
    if ((int)$row['c5xx'] > 0)         $sig[] = '5xx-errors';
    $extra = json_decode($row['signals'] ?? '{}', true) ?? [];
    if (!empty($extra['ua_switch']))  $sig[] = 'ua-switch';
    if (!empty($extra['replay']))     $sig[] = 'replay';
    if (!empty($extra['recon']))      $sig[] = 'recon';
    return $sig ? ' ' . implode('  ', $sig) : ' —';
}

// ── HTML email ────────────────────────────────────────────────────────────────

function htmlEmailCss(string $lvlColor, string $lvlBg): string {
    return 'body{margin:0;padding:0;background:#0d1117;font-family:sans-serif;font-size:14px;color:#e6edf3}'
         . 'table{border-collapse:collapse}'
         . '.wrap{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:24px 28px;max-width:700px;margin:24px auto}'
         . '.hdr{border-left:4px solid ' . $lvlColor . ';background:' . $lvlBg . ';padding:10px 14px;border-radius:3px;margin-bottom:18px}'
         . '.hdr h2{margin:0;font-size:16px;color:' . $lvlColor . ';letter-spacing:.05em}'
         . '.hdr p{margin:4px 0 0;font-size:12px;color:#8b949e}'
         . 'h3{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;border-bottom:1px solid #21262d;padding-bottom:5px;margin:18px 0 8px}'
         . '.dt{width:100%}'
         . '.dt td,.dt th{padding:5px 8px;vertical-align:top;border-bottom:1px solid #21262d}'
         . '.dt th{font-size:11px;color:#8b949e;text-align:left;white-space:nowrap}'
         . '.dt td{font-family:monospace;font-size:12px;color:#e6edf3}'
         . '.badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;font-family:monospace}'
         . '.bc{color:#f85149;background:#3d1f1f}.bh{color:#d29922;background:#2e2008}.bm{color:#388bfd;background:#0d2040}'
         . '.sig{color:#7ee787;font-size:11px}'
         . '.muted{color:#8b949e}'
         . '.footer{font-size:11px;color:#8b949e;text-align:center;margin-top:20px;padding-top:14px;border-top:1px solid #21262d}'
         . '.footer a{color:#58a6ff}';
}

function htmlScoreBadge(int $sc): string {
    if ($sc >= ALERT_CRITICAL) {
        return '<span class="badge bc">CRITICAL ' . $sc . '</span>';
    }
    if ($sc >= ALERT_HIGH) {
        return '<span class="badge bh">HIGH ' . $sc . '</span>';
    }
    return '<span class="badge bm">MEDIUM ' . $sc . '</span>';
}

function htmlHoneypotSection(array $h): string {
    $o = '<h3>Honeypot Hits (' . count($h) . ')</h3>';
    if (!$h) {
        return $o . '<p class="muted">None</p>';
    }
    $o .= '<table class="dt"><tr><th>IP</th><th>CC</th><th>Time (UTC)</th><th>Path</th></tr>';
    foreach ($h as $r) {
        $o .= '<tr><td>' . htmlspecialchars($r['ip']) . '</td>'
            . '<td>' . htmlspecialchars($r['cc'] ?: '—') . '</td>'
            . '<td>' . htmlspecialchars(substr($r['created_at'], 0, 19)) . '</td>'
            . '<td>' . htmlspecialchars(substr($r['uri'], 0, 60)) . '</td></tr>';
    }
    return $o . '</table>';
}

function htmlThreatSection(array $t): string {
    $o = '<h3>Threat Sessions (' . count($t) . ')</h3>';
    if (!$t) {
        return $o . '<p class="muted">None</p>';
    }
    $o .= '<table class="dt"><tr><th>IP</th><th>CC</th><th>Score</th><th>Class</th><th>Signals</th></tr>';
    foreach ($t as $r) {
        $sc  = (int)$r['score'];
        $org = trim(($r['asn'] ?? '') . ' ' . ($r['org'] ?? ''));
        $orgHtml = $org
            ? '<br><span class="muted" style="font-size:11px">' . htmlspecialchars($org) . '</span>'
            : '';
        $o .= '<tr><td>' . htmlspecialchars($r['ip']) . $orgHtml . '</td>'
            . '<td>' . htmlspecialchars($r['cc'] ?: '—') . '</td>'
            . '<td>' . htmlScoreBadge($sc) . '</td>'
            . '<td>' . htmlspecialchars($r['classification']) . '</td>'
            . '<td class="sig">' . htmlspecialchars(trim(buildSignals($r))) . '</td></tr>';
    }
    return $o . '</table>';
}

function htmlEscalationSection(array $e): string {
    $o = '<h3>Watchlist Escalations (' . count($e) . ')</h3>';
    if (!$e) {
        return $o . '<p class="muted">None</p>';
    }
    $o .= '<table class="dt"><tr><th>IP</th><th>Reason</th></tr>';
    foreach ($e as $r) {
        $reason = $r['escalated_reason'] ?: ($r['reason'] ?: '—');
        $o .= '<tr><td>' . htmlspecialchars($r['ip']) . '</td>'
            . '<td>' . htmlspecialchars($reason) . '</td></tr>';
    }
    return $o . '</table>';
}

function htmlBlockSection(array $b): string {
    $o = '<h3>New Blocks (' . count($b) . ')</h3>';
    if (!$b) {
        return $o . '<p class="muted">None</p>';
    }
    $o .= '<table class="dt"><tr><th>IP</th><th>Reason</th><th>By</th></tr>';
    foreach ($b as $r) {
        $o .= '<tr><td>' . htmlspecialchars($r['ip']) . '</td>'
            . '<td>' . htmlspecialchars(substr($r['reason'] ?? '—', 0, 70)) . '</td>'
            . '<td>' . htmlspecialchars($r['blocked_by'] ?? '—') . '</td></tr>';
    }
    return $o . '</table>';
}

function buildBodyHtml(string $level, array $h, array $t, array $e, array $b, string $since, string $now): string {
    $lvlColor = match($level) {
        'critical' => '#f85149',
        'high'     => '#d29922',
        default    => '#388bfd',
    };
    $lvlBg = match($level) {
        'critical' => '#3d1f1f',
        'high'     => '#2e2008',
        default    => '#0d2040',
    };

    return '<!DOCTYPE html><html><head><meta charset="UTF-8">'
        . '<meta name="viewport" content="width=device-width">'
        . '<title>Security Alert</title>'
        . '<style>' . htmlEmailCss($lvlColor, $lvlBg) . '</style></head><body>'
        . '<div class="wrap">'
        . '<div class="hdr">'
        . '<h2>' . strtoupper($level) . ' — thameur.org</h2>'
        . '<p>Period: ' . htmlspecialchars($since) . ' &rarr; ' . htmlspecialchars($now) . ' UTC</p>'
        . '</div>'
        . htmlHoneypotSection($h)
        . htmlThreatSection($t)
        . htmlEscalationSection($e)
        . htmlBlockSection($b)
        . '<div class="footer">'
        . '<a href="' . htmlspecialchars(DASHBOARD_URL) . '">Open SOC Dashboard</a>'
        . ' &nbsp;&middot;&nbsp; Generated by ' . htmlspecialchars(ALERT_FROM_NAME)
        . '</div></div></body></html>';
}

// ── Mail ──────────────────────────────────────────────────────────────────────

function sendAlert(string $subject, string $textBody, string $htmlBody): bool {
    $boundary = 'alt_' . bin2hex(random_bytes(8));
    $from     = ALERT_FROM_NAME . ' <' . ALERT_FROM_ADDR . '>';

    $headers = implode("\r\n", [
        'From: '         . $from,
        'Reply-To: '     . $from,
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
        'X-Mailer: thameur-watchdog/1.0',
        'X-Priority: '   . (str_contains($subject, 'CRITICAL') ? '1' : '3'),
    ]);

    $mime  = '--' . $boundary . "\r\n"
           . "Content-Type: text/plain; charset=UTF-8\r\n"
           . "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
           . quoted_printable_encode($textBody) . "\r\n"
           . '--' . $boundary . "\r\n"
           . "Content-Type: text/html; charset=UTF-8\r\n"
           . "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
           . quoted_printable_encode($htmlBody) . "\r\n"
           . '--' . $boundary . "--\r\n";

    return mail(ALERT_TO, $subject, $mime, $headers, '-f ' . ALERT_FROM_ADDR);
}
