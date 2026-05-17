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
$subject = buildSubject($level, $honeypots, $threats, $escalations, $blocks);
$body    = buildBody($level, $honeypots, $threats, $escalations, $blocks, $since, $now);

if (sendAlert($subject, $body)) {
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

function buildBody(string $level, array $h, array $t, array $e, array $b, string $since, string $now): string {
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

// ── Mail ──────────────────────────────────────────────────────────────────────

function sendAlert(string $subject, string $body): bool {
    $from    = ALERT_FROM_NAME . ' <' . ALERT_FROM_ADDR . '>';
    $headers = implode("\r\n", [
        'From: '       . $from,
        'Reply-To: '   . $from,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'X-Mailer: thameur-watchdog/1.0',
        'X-Priority: ' . (str_contains($subject, 'CRITICAL') ? '1' : '3'),
    ]);
    return mail(ALERT_TO, $subject, $body, $headers, '-f ' . ALERT_FROM_ADDR);
}
