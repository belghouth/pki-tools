<?php
/**
 * ccadb_sync.php — download and cache CCADB public CSV resources
 *
 * Downloads each resource CSV, parses it line-by-line, batch-INSERTs into
 * ccadb_rows with a new sync_id, then deletes the old rows on success.
 * Old rows are preserved if the download or parse fails.
 *
 * ── Recommended cron entry ────────────────────────────────────────────────────
 *
 *   0 3 * * 0 www-data /usr/bin/php /var/www/thameur.org/cron/ccadb_sync.php
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

if (php_sapi_name() !== 'cli') { http_response_code(403); exit; }

define('ADMIN_NO_LOG', true);
require_once __DIR__ . '/../config.php';

define('CCADB_BATCH',   500);
define('CCADB_TIMEOUT', 120);
define('DT_FMT',        'Y-m-d H:i:s');

const CCADB_RESOURCES = [
    'caa' => [
        'name' => 'CAA Identifiers',
        'url'  => 'https://ccadb.my.salesforce-sites.com/ccadb/AllCAAIdentifiersReportCSVV2',
    ],
    'problem_reporting' => [
        'name' => 'Problem Reporting Mechanisms',
        'url'  => 'https://ccadb.my.salesforce-sites.com/ccadb/AllProblemReportingMechanismsCSV',
    ],
    'all_certs' => [
        'name' => 'All Certificate Records (V5)',
        'url'  => 'https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV5',
    ],
    'included_roots' => [
        'name' => 'Included Root Certificates',
        'url'  => 'https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV',
    ],
];

$pdo = admin_pdo();
if (!$pdo) {
    fwrite(STDERR, "[ccadb_sync] DB unavailable\n");
    exit(1);
}

$resourceKey = $argv[1] ?? null;
if ($resourceKey !== null) {
    $targets = isset(CCADB_RESOURCES[$resourceKey]) ? [$resourceKey => CCADB_RESOURCES[$resourceKey]] : [];
} else {
    $targets = CCADB_RESOURCES;
}

if (!$targets) {
    fwrite(STDERR, "[ccadb_sync] Unknown resource key: $resourceKey\n");
    exit(1);
}

foreach ($targets as $key => $res) {
    syncResource($pdo, $key, $res);
}

exit(0);

// ── Core sync function ────────────────────────────────────────────────────────

function recentSyncAt(PDO $pdo, string $key): ?string {
    $st = $pdo->prepare(
        "SELECT synced_at FROM ccadb_sync_log
         WHERE resource_key = ? AND status = 'ok' AND synced_at >= NOW() - INTERVAL 1 DAY
         ORDER BY synced_at DESC LIMIT 1"
    );
    $st->execute([$key]);
    $val = $st->fetchColumn();
    return $val !== false ? (string)$val : null;
}

function downloadToTemp(PDO $pdo, string $key, string $url): ?string {
    $tmp = tempnam(sys_get_temp_dir(), 'ccadb_');
    $fh  = $tmp !== false ? fopen($tmp, 'wb') : false;
    if ($fh === false) {
        if ($tmp !== false) {
            @unlink($tmp);
        }
        logSync($pdo, $key, 'error', 0, $tmp === false ? 'tempnam() failed' : 'Cannot open temp file');
        return null;
    }
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_FILE           => $fh,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => CCADB_TIMEOUT,
        CURLOPT_USERAGENT      => 'ccadb-sync/1.0 (thameur.org)',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $ok      = curl_exec($ch);
    $http    = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = $ok ? '' : curl_error($ch);
    curl_close($ch);
    fclose($fh);
    if (!$ok || $http !== 200) {
        @unlink($tmp);
        $msg = $curlErr ?: "HTTP $http";
        logSync($pdo, $key, 'error', 0, "Download failed: $msg");
        fwrite(STDERR, "[ccadb_sync] $key download failed: $msg\n");
        return null;
    }
    return $tmp;
}

function syncResource(PDO $pdo, string $key, array $res): void {
    $lastSync = recentSyncAt($pdo, $key);
    if ($lastSync !== null) {
        echo '[' . gmdate(DT_FMT) . " UTC] {$res['name']} ($key) synced at $lastSync UTC — skipping\n";
        return;
    }

    echo '[' . gmdate(DT_FMT) . " UTC] Syncing {$res['name']} ($key)…\n";

    $tmp = downloadToTemp($pdo, $key, $res['url']);
    if ($tmp === null) {
        return;
    }

    $result = importCsv($pdo, $key, $tmp);
    @unlink($tmp);

    if ($result['error']) {
        logSync($pdo, $key, 'error', $result['rows'], $result['error']);
        fwrite(STDERR, "[ccadb_sync] $key import failed: {$result['error']}\n");
    } else {
        logSync($pdo, $key, 'ok', $result['rows'], null);
        echo '[' . gmdate(DT_FMT) . " UTC] $key synced: {$result['rows']} rows\n";
    }
}

// ── CSV import ────────────────────────────────────────────────────────────────

function importCsv(PDO $pdo, string $key, string $filePath): array {
    $fh = fopen($filePath, 'rb');
    if (!$fh) {
        return ['rows' => 0, 'error' => 'Cannot open temp file for reading'];
    }

    // Read header row
    $headers = fgetcsv($fh);
    if (!is_array($headers) || count($headers) === 0) {
        fclose($fh);
        return ['rows' => 0, 'error' => 'Empty or invalid CSV (no header row)'];
    }
    $headers = array_map('trim', $headers);

    // Register new sync — get sync_id first
    $pdo->prepare(
        "INSERT INTO ccadb_sync_log (resource_key, status, row_count) VALUES (?, 'ok', 0)"
    )->execute([$key]);
    $syncId = (int)$pdo->lastInsertId();

    $stmt = $pdo->prepare(
        "INSERT INTO ccadb_rows (resource_key, sync_id, `row_number`, data_json, search_text)
         VALUES (?, ?, ?, ?, ?)"
    );

    $rowNum   = 0;
    $inserted = 0;
    $batch    = [];
    $error    = null;

    while (($cols = fgetcsv($fh)) !== false) {
        $rowNum++;
        if (count($cols) !== count($headers)) {
            continue; // skip malformed rows silently
        }
        $data       = array_combine($headers, $cols);
        $searchText = implode(' ', array_filter(array_values($data)));
        $batch[] = [$key, $syncId, $rowNum, json_encode($data, JSON_UNESCAPED_UNICODE), $searchText];

        if (count($batch) >= CCADB_BATCH) {
            $flushed = flushBatch($pdo, $stmt, $batch);
            if ($flushed < 0) {
                $error = 'DB batch insert failed';
                break;
            }
            $inserted += $flushed;
        }
    }
    fclose($fh);

    if (!$error && $batch) {
        $flushed = flushBatch($pdo, $stmt, $batch);
        if ($flushed < 0) {
            $error = 'DB batch insert failed (final batch)';
        } else {
            $inserted += $flushed;
        }
    }

    if ($error) {
        // Roll back: delete the partial sync rows and mark log as error
        try {
            $pdo->prepare("DELETE FROM ccadb_rows WHERE sync_id = ?")->execute([$syncId]);
            $pdo->prepare(
                "UPDATE ccadb_sync_log SET status='error', error_message=? WHERE id=?"
            )->execute([$error, $syncId]);
        } catch (Throwable $e) {
            fwrite(STDERR, "[ccadb_sync] Rollback error: " . $e->getMessage() . "\n");
        }
        return ['rows' => $inserted, 'error' => $error];
    }

    // Success: delete old rows for this resource (any sync_id != $syncId)
    try {
        $pdo->prepare(
            "DELETE FROM ccadb_rows WHERE resource_key = ? AND sync_id != ?"
        )->execute([$key, $syncId]);
        $pdo->prepare(
            "UPDATE ccadb_sync_log SET row_count = ? WHERE id = ?"
        )->execute([$inserted, $syncId]);
    } catch (Throwable $e) {
        fwrite(STDERR, "[ccadb_sync] Cleanup error: " . $e->getMessage() . "\n");
    }

    return ['rows' => $inserted, 'error' => null];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function flushBatch(PDO $pdo, PDOStatement $stmt, array &$batch): int {
    $n = 0;
    try {
        $pdo->beginTransaction();
        foreach ($batch as $row) {
            $stmt->execute($row);
            $n++;
        }
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        fwrite(STDERR, "[ccadb_sync] Batch error: " . $e->getMessage() . "\n");
        $batch = [];
        return -1;
    }
    $batch = [];
    return $n;
}

function logSync(PDO $pdo, string $key, string $status, int $rows, ?string $msg): void {
    try {
        $pdo->prepare(
            "INSERT INTO ccadb_sync_log (resource_key, status, row_count, error_message)
             VALUES (?, ?, ?, ?)"
        )->execute([$key, $status, $rows, $msg]);
    } catch (Throwable $e) {
        fwrite(STDERR, "[ccadb_sync] Log error: " . $e->getMessage() . "\n");
    }
}
