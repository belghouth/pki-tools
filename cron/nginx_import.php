<?php
/**
 * nginx_import.php — tail nginx JSON access log into nginx_visits DB table
 *
 * Reads new lines from the JSON access log since the last run, parses each
 * line, and batch-INSERTs into nginx_visits. The byte offset + inode are
 * stored in the nginx_import_cursor table so log rotation is handled cleanly.
 *
 * ── Recommended cron entry ───────────────────────────────────────────────────
 *
 *   * * * * * www-data /usr/bin/php /var/www/thameur.org/cron/nginx_import.php
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

if (php_sapi_name() !== 'cli') { http_response_code(403); exit; }

define('ADMIN_NO_LOG', true);
require_once __DIR__ . '/../config.php';

define('NGINX_JSON_LOG', '/var/log/nginx/thameur_json.log');
define('IMPORT_BATCH',   500);
define('DT_FORMAT',      'Y-m-d H:i:s');

$pdo = admin_pdo();
if (!$pdo) { fwrite(STDERR, "[nginx_import] DB unavailable\n"); exit(1); }

if (!file_exists(NGINX_JSON_LOG) || !is_readable(NGINX_JSON_LOG)) {
    fwrite(STDERR, "[nginx_import] Log not readable: " . NGINX_JSON_LOG . "\n");
    exit(1);
}

// ── Cursor ────────────────────────────────────────────────────────────────────
$cursor = $pdo->query(
    "SELECT log_inode, log_offset FROM nginx_import_cursor WHERE id=1"
)->fetch();
$cur_inode  = $cursor ? (int)$cursor['log_inode']  : 0;
$cur_offset = $cursor ? (int)$cursor['log_offset'] : 0;

$stat       = stat(NGINX_JSON_LOG);
$file_inode = (int)$stat['ino'];
$file_size  = (int)$stat['size'];

// Rotation detected (new inode or file shrank) — reset to start of new file
if ($file_inode !== $cur_inode || $file_size < $cur_offset) {
    $cur_offset = 0;
}
if ($file_size <= $cur_offset) {
    exit(0); // nothing new
}

// ── Read & import ─────────────────────────────────────────────────────────────
$fh = fopen(NGINX_JSON_LOG, 'rb');
if (!$fh) { fwrite(STDERR, "[nginx_import] Cannot open log\n"); exit(1); }
fseek($fh, $cur_offset);

$stmt = $pdo->prepare(
    "INSERT INTO nginx_visits
     (created_at,ip,method,host,vhost,uri,query_string,status,bytes_sent,
      user_agent,referer,is_https,proto,request_time,country)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
);

$inserted = 0;
$batch    = [];

function nginxFlush(PDO $pdo, PDOStatement $stmt, array &$batch): int {
    if (!$batch) {
        return 0;
    }
    $n = 0;
    try {
        $pdo->beginTransaction();
        foreach ($batch as $row) { $stmt->execute($row); $n++; }
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        fwrite(STDERR, "[nginx_import] Batch error: " . $e->getMessage() . "\n");
        $n = 0;
    }
    $batch = [];
    return $n;
}

while (($line = fgets($fh)) !== false) {
    $line = trim($line);
    if ($line === '') {
        continue;
    }

    $d = json_decode($line, true);
    if (!is_array($d)) {
        continue;
    }

    // Millisecond-precision timestamp from nginx $msec variable
    $ms = isset($d['ms']) ? (float)$d['ms'] : 0.0;
    if ($ms <= 0) {
        continue;
    }
    $sec        = (int)$ms;
    $msec       = (int)round(($ms - $sec) * 1000);
    $created_at = gmdate(DT_FORMAT, $sec) . '.' . sprintf('%03d', $msec);

    // Real client IP: prefer Cloudflare header, fallback to direct edge IP
    $ip = trim($d['ip'] ?? '');
    if ($ip === '' || $ip === '-') {
        $ip = trim($d['edge'] ?? '');
    }

    // Country from Cloudflare header; store in geoip_cache for the admin panel
    $cc = strtoupper(trim($d['cc'] ?? ''));
    if ($cc === '-' || strlen($cc) !== 2 || !ctype_alpha($cc)) {
        $cc = '';
    }
    if ($cc && $ip) {
        geoip_cache_store($ip, $cc);
    }

    // Nullable numerics
    $rt    = isset($d['rt'])    && is_numeric($d['rt'])    ? (float)$d['rt']    : null;
    $bytes = isset($d['bytes']) && is_numeric($d['bytes']) ? (int)$d['bytes']   : null;

    // Optional strings — treat nginx placeholder '-' as empty
    // $request_uri already contains the query string; split it out cleanly.
    $raw_uri    = $d['uri'] ?? '/';
    $qpos       = strpos($raw_uri, '?');
    $uri_path   = $qpos !== false ? substr($raw_uri, 0, $qpos) : $raw_uri;
    $legacy_qs  = ($d['query'] ?? '-') === '-' ? '' : ($d['query'] ?? '');
    $qs         = $qpos !== false ? substr($raw_uri, $qpos + 1) : $legacy_qs;
    $ref = ($d['referer'] ?? '-') === '-' ? '' : ($d['referer'] ?? '');

    $batch[] = [
        $created_at,
        substr($ip, 0, 45),
        substr($d['method'] ?? 'GET', 0, 10),
        substr($d['host']   ?? '',    0, 255),
        substr($d['vhost']  ?? '',    0, 255),
        substr($uri_path, 0, 2048),
        $qs  !== '' ? substr($qs,  0, 2048) : null,
        (int)($d['status'] ?? 200),
        $bytes,
        substr($d['ua']  ?? '', 0, 500),
        $ref !== '' ? substr($ref, 0, 500) : null,
        ($d['https'] ?? '') === 'on' ? 1 : 0,
        substr($d['proto'] ?? '', 0, 20),
        $rt,
        $cc !== '' ? $cc : null,
    ];

    if (count($batch) >= IMPORT_BATCH) {
        $inserted += nginxFlush($pdo, $stmt, $batch);
    }
}
$inserted += nginxFlush($pdo, $stmt, $batch);

$new_offset = (int)ftell($fh);
fclose($fh);

// ── Save cursor ───────────────────────────────────────────────────────────────
$pdo->prepare(
    "INSERT INTO nginx_import_cursor (id, log_inode, log_offset) VALUES (1, ?, ?)
     ON DUPLICATE KEY UPDATE log_inode=VALUES(log_inode), log_offset=VALUES(log_offset)"
)->execute([$file_inode, $new_offset]);

if ($inserted > 0) {
    echo '[' . gmdate(DT_FORMAT) . " UTC] Imported $inserted nginx access log entries\n";
}

// ── Honeypot + enumeration auto-watch ─────────────────────────────────────────
// Window and thresholds — adjust here before enabling auto-block.
const AUTOWATCH_HP_WINDOW   = 15; // minutes to look back for honeypot hits
const AUTOWATCH_HP_HITS     =  3; // honeypot URI hits required to trigger watch
const AUTOWATCH_ENUM_WINDOW = 15; // minutes to look back for 404 enumeration
const AUTOWATCH_ENUM_404S   = 10; // distinct non-trivial 404 URIs required to trigger watch

function autoWatchThreats(PDO $pdo): void {
    $doBlock = settingGet('autoblock_enabled', '0') === '1';

    // ── 1. Honeypot hits ──────────────────────────────────────────────────────
    $excludeCol = $doBlock ? 'blocked_ips' : 'ip_watchlist';
    $st = $pdo->prepare("
        SELECT ip, COUNT(*) AS hits
        FROM   nginx_visits
        WHERE  created_at >= NOW() - INTERVAL ? MINUTE
          AND  uri REGEXP ?
          AND  ip NOT IN (SELECT ip FROM blocked_ips)
          AND  ip NOT IN (SELECT ip FROM my_ips)
          AND  ip NOT IN (SELECT ip FROM $excludeCol)
          AND  ip != ''
        GROUP BY ip
        HAVING COUNT(*) >= ?
    ");
    $st->execute([AUTOWATCH_HP_WINDOW, honeypot_mysql_regexp(), AUTOWATCH_HP_HITS]);
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $reason = 'Honeypot: ' . $row['hits'] . ' hits in ' . AUTOWATCH_HP_WINDOW . 'min';
        if ($doBlock) {
            block_ip($row['ip'], $reason, 'autoblock');
            echo '[' . gmdate(DT_FORMAT) . " UTC] Auto-block {$row['ip']}: $reason\n";
        } else {
            watchIp($row['ip'], $reason, 'soc_honeypot');
            echo '[' . gmdate(DT_FORMAT) . " UTC] Auto-watch {$row['ip']}: $reason\n";
        }
    }

    // ── 2. 404 enumeration ────────────────────────────────────────────────────
    $placeholders = implode(',', array_fill(0, count(NORMAL_MISS_PATHS), '?'));
    $params = array_merge(
        [AUTOWATCH_ENUM_WINDOW],
        NORMAL_MISS_PATHS,
        [AUTOWATCH_ENUM_404S]
    );
    $st2 = $pdo->prepare("
        SELECT ip, COUNT(DISTINCT uri) AS uniq_404s
        FROM   nginx_visits
        WHERE  created_at >= NOW() - INTERVAL ? MINUTE
          AND  status = 404
          AND  uri NOT IN ($placeholders)
          AND  ip NOT IN (SELECT ip FROM blocked_ips)
          AND  ip NOT IN (SELECT ip FROM my_ips)
          AND  ip NOT IN (SELECT ip FROM $excludeCol)
          AND  ip != ''
        GROUP BY ip
        HAVING COUNT(DISTINCT uri) >= ?
    ");
    $st2->execute($params);
    foreach ($st2->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $reason = 'Enumeration: ' . $row['uniq_404s'] . ' distinct 404 URIs in ' . AUTOWATCH_ENUM_WINDOW . 'min';
        if ($doBlock) {
            block_ip($row['ip'], $reason, 'autoblock');
            echo '[' . gmdate(DT_FORMAT) . " UTC] Auto-block {$row['ip']}: $reason\n";
        } else {
            watchIp($row['ip'], $reason, 'soc_event');
            echo '[' . gmdate(DT_FORMAT) . " UTC] Auto-watch {$row['ip']}: $reason\n";
        }
    }
}

try {
    autoWatchThreats($pdo);
} catch (Throwable $e) {
    fwrite(STDERR, '[nginx_import] auto-watch error: ' . $e->getMessage() . "\n");
}

exit(0);
