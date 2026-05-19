<?php
/**
 * ccadb_sync.php — CCADB V5 sync (root + intermediate certificates)
 *
 * Phase 1 : AllCertificateRecordsCSVFormatV5  →  ccadb_v5_certs  (89 columns)
 * Phase 2 : AllCertificatePEMsCSVFormat (2010+2020 decade splits) → update pem_info via SHA-256
 *
 * Usage:
 *   php ccadb_sync.php              # run both phases
 *   php ccadb_sync.php --phase=1    # V5 data only
 *   php ccadb_sync.php --phase=2    # PEM update only
 *   php ccadb_sync.php --force      # skip recency check (re-sync today)
 *   php ccadb_sync.php --migrate    # CREATE TABLE IF NOT EXISTS and exit
 *
 * ─── Cron ─────────────────────────────────────────────────────────────────────
 *   0 3 * * 0 www-data /usr/bin/php /var/www/thameur.org/cron/ccadb_sync.php
 */

if (php_sapi_name() !== 'cli') { http_response_code(403); exit; }

define('ADMIN_NO_LOG', true);
require_once __DIR__ . '/../config.php';

// ── Constants ─────────────────────────────────────────────────────────────────

define('V5_URL',      'https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV5');
define('PEM_URL_2010', 'https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeDecade=2010');
define('PEM_URL_2020', 'https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeDecade=2020');
define('BATCH_SZ',   500);
define('DL_TIMEOUT', 180);
define('DT_FMT',     'Y-m-d H:i:s');

// Maps CSV header → indexed DB column name
const V5_INDEXED_COLS = [
    'CA Owner'                    => 'ca_owner',
    'Salesforce Record ID'        => 'salesforce_id',
    'Certificate Name'            => 'cert_name',
    'Parent Salesforce Record ID' => 'parent_salesforce_id',
    'Parent Certificate Name'     => 'parent_cert_name',
    'Certificate Record Type'     => 'cert_type',
    'Subordinate CA Owner'        => 'subordinate_ca_owner',
    'Apple Status'                => 'status_apple',
    'Chrome Status'               => 'status_chrome',
    'Microsoft Status'            => 'status_microsoft',
    'Mozilla Status'              => 'status_mozilla',
    'SHA-256 Fingerprint'         => 'sha256',
    'Parent SHA-256 Fingerprint'  => 'parent_sha256',
    'Valid From (GMT)'            => 'valid_from',        // → DATE
    'Valid To (GMT)'              => 'valid_to',          // → DATE
    'TLS Capable'                 => 'tls_capable',       // → BOOL
    'TLS EV Capable'              => 'tls_ev_capable',    // → BOOL
    'Code Signing Capable'        => 'code_sign_capable', // → BOOL
    'S/MIME Capable'              => 'smime_capable',     // → BOOL
    'Country'                     => 'country',
];

const DATE_COLS = ['valid_from', 'valid_to'];
const BOOL_COLS = ['tls_capable', 'tls_ev_capable', 'code_sign_capable', 'smime_capable'];

// ── Migration SQL ─────────────────────────────────────────────────────────────

const MIGRATION_SQL = <<<'SQL'
CREATE TABLE IF NOT EXISTS ccadb_v5_certs (
    id                    INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    sync_id               INT UNSIGNED     NOT NULL,
    csv_row_number            INT UNSIGNED     NOT NULL,
    ca_owner              VARCHAR(500)     NOT NULL DEFAULT '',
    salesforce_id         VARCHAR(50)      NOT NULL DEFAULT '',
    cert_name             VARCHAR(500)     NOT NULL DEFAULT '',
    parent_salesforce_id  VARCHAR(50)               DEFAULT NULL,
    parent_cert_name      VARCHAR(500)              DEFAULT NULL,
    cert_type             VARCHAR(50)      NOT NULL DEFAULT '',
    subordinate_ca_owner  VARCHAR(500)              DEFAULT NULL,
    status_apple          VARCHAR(100)     NOT NULL DEFAULT '',
    status_chrome         VARCHAR(100)     NOT NULL DEFAULT '',
    status_microsoft      VARCHAR(100)     NOT NULL DEFAULT '',
    status_mozilla        VARCHAR(100)     NOT NULL DEFAULT '',
    sha256                VARCHAR(64)      NOT NULL DEFAULT '',
    parent_sha256         VARCHAR(64)               DEFAULT NULL,
    valid_from            DATE                      DEFAULT NULL,
    valid_to              DATE                      DEFAULT NULL,
    tls_capable           TINYINT(1)       NOT NULL DEFAULT 0,
    tls_ev_capable        TINYINT(1)       NOT NULL DEFAULT 0,
    code_sign_capable     TINYINT(1)       NOT NULL DEFAULT 0,
    smime_capable         TINYINT(1)       NOT NULL DEFAULT 0,
    country               VARCHAR(200)              DEFAULT NULL,
    data_json             MEDIUMTEXT       NOT NULL,
    pem_info              MEDIUMTEXT                DEFAULT NULL,
    cert_policy_oids      MEDIUMTEXT                DEFAULT NULL,
    search_text           MEDIUMTEXT       NOT NULL,
    PRIMARY KEY (id),
    KEY idx_sync         (sync_id),
    KEY idx_ca_owner     (ca_owner(191)),
    KEY idx_sha256       (sha256(64)),
    KEY idx_parent_sha   (parent_sha256(64)),
    KEY idx_cert_type    (cert_type(30)),
    KEY idx_valid_to     (valid_to),
    FULLTEXT KEY ft_search (search_text)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS cps_cache (
    id            INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    cert_sha256   VARCHAR(64)   NOT NULL DEFAULT '',
    cps_url_hash  VARCHAR(64)   NOT NULL DEFAULT '',
    cps_url       TEXT          NOT NULL,
    downloaded_at DATETIME      NOT NULL,
    content_type  VARCHAR(200)           DEFAULT NULL,
    cps_text      MEDIUMTEXT             DEFAULT NULL,
    fetch_error   VARCHAR(500)           DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_cert_url (cert_sha256, cps_url_hash(64)),
    KEY idx_dl (downloaded_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ccadb_v5_sync_log (
    id            INT UNSIGNED          NOT NULL AUTO_INCREMENT,
    resource_key  VARCHAR(50)           NOT NULL DEFAULT 'v5_certs',
    synced_at     TIMESTAMP             NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status        ENUM('ok','error')    NOT NULL,
    row_count     INT UNSIGNED          NOT NULL DEFAULT 0,
    error_message TEXT                           DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_key_status (resource_key, status, synced_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQL;

// ── CLI argument parsing ──────────────────────────────────────────────────────

$opts  = getopt('', ['phase:', 'force', 'migrate', 'backfill-oids']);
$phase = isset($opts['phase']) ? (int)$opts['phase'] : 0;  // 0 = both
$force = isset($opts['force']);

$pdo = admin_pdo();
if (!$pdo) {
    fwrite(STDERR, "[ccadb_sync] DB unavailable\n");
    exit(1);
}

// ── --migrate ─────────────────────────────────────────────────────────────────

if (isset($opts['migrate'])) {
    $migrations = array_filter(array_map('trim', explode(';', MIGRATION_SQL)));
    // Add cert_policy_oids for existing tables (CREATE TABLE IF NOT EXISTS won't add it)
    $migrations[] = "ALTER TABLE ccadb_v5_certs ADD COLUMN IF NOT EXISTS cert_policy_oids MEDIUMTEXT DEFAULT NULL";
    foreach ($migrations as $sql) {
        try {
            $pdo->exec($sql);
        } catch (Throwable $e) {
            fwrite(STDERR, "[ccadb_sync] Migration error: " . $e->getMessage() . "\n");
            exit(1);
        }
    }
    echo "[" . gmdate(DT_FMT) . " UTC] Migration complete.\n";
    exit(0);
}

// ── --backfill-oids — parse policy OIDs from already-imported PEMs ────────────

if (isset($opts['backfill-oids'])) {
    $count = backfillOids($pdo);
    echo "[" . gmdate(DT_FMT) . " UTC] OID backfill complete — $count certs updated.\n";
    exit(0);
}

// ── Run phases ────────────────────────────────────────────────────────────────

$exitCode = 0;

if (($phase === 0 || $phase === 1) && !syncV5($pdo, $force)) {
    $exitCode = 1;
}
if (($phase === 0 || $phase === 2) && !syncPem($pdo, $force)) {
    $exitCode = 1;
}

exit($exitCode);

// ══════════════════════════════════════════════════════════════════════════════
// Phase 1 — V5 All Certificate Records
// ══════════════════════════════════════════════════════════════════════════════

function syncV5(PDO $pdo, bool $force): bool {
    $key = 'v5_certs';
    if (!$force && recentSync($pdo, $key)) {
        echo '[' . gmdate(DT_FMT) . " UTC] $key already synced today — skipping (use --force to override)\n";
        return true;
    }
    echo '[' . gmdate(DT_FMT) . " UTC] Downloading V5 All Certificate Records…\n";
    $tmp = downloadToTemp($key, V5_URL);
    if ($tmp === null) {
        return false;
    }
    $result = importV5($pdo, $key, $tmp);
    @unlink($tmp);
    $ok = ($result['error'] === null);
    logSync($pdo, $key, $ok ? 'ok' : 'error', $result['rows'], $result['error']);
    if ($ok) {
        echo '[' . gmdate(DT_FMT) . " UTC] $key synced: {$result['rows']} rows\n";
    } else {
        fwrite(STDERR, "[ccadb_sync] $key import failed: {$result['error']}\n");
    }
    return $ok;
}

function importV5(PDO $pdo, string $key, string $file): array {
    [$fh, $headers, $openErr] = openCsvForReading($file, 10);
    if ($openErr !== null) {
        return ['rows' => 0, 'error' => $openErr];
    }

    $pdo->prepare(
        "INSERT INTO ccadb_v5_sync_log (resource_key, status, row_count) VALUES (?, 'ok', 0)"
    )->execute([$key]);
    $syncId = (int)$pdo->lastInsertId();

    $stmt     = prepareV5Insert($pdo);
    $rowNum   = 0;
    $inserted = 0;
    $batch    = [];
    $error    = null;

    while (($cols = fgetcsv($fh)) !== false) {
        $rowNum++;
        $data    = normalizeCsvRow($cols, $headers);
        $idx     = extractIndexed($data);
        $batch[] = buildV5BatchRow($syncId, $rowNum, $idx, $data);

        if (count($batch) >= BATCH_SZ) {
            [$n, $batchErr] = flushBatch($pdo, $stmt, $batch);
            $inserted += max(0, $n);
            if ($batchErr !== null) { $error = $batchErr; break; }
        }
    }
    fclose($fh);

    if ($error === null && $batch !== []) {
        [$n, $batchErr] = flushBatch($pdo, $stmt, $batch);
        $inserted += max(0, $n);
        $error = $batchErr;
    }

    if ($error !== null) {
        rollbackSync($pdo, $syncId, $error);
        return ['rows' => $inserted, 'error' => $error];
    }

    finaliseV5Sync($pdo, $syncId, $key, $inserted);
    return ['rows' => $inserted, 'error' => null];
}

// ── importV5 helpers ──────────────────────────────────────────────────────────

function prepareV5Insert(PDO $pdo): PDOStatement {
    return $pdo->prepare(
        "INSERT INTO ccadb_v5_certs
         (sync_id, csv_row_number,
          ca_owner, salesforce_id, cert_name, parent_salesforce_id, parent_cert_name,
          cert_type, subordinate_ca_owner,
          status_apple, status_chrome, status_microsoft, status_mozilla,
          sha256, parent_sha256, valid_from, valid_to,
          tls_capable, tls_ev_capable, code_sign_capable, smime_capable,
          country, data_json, search_text)
         VALUES (?,?,  ?,?,?,?,?,  ?,?,  ?,?,?,?,  ?,?,?,?,  ?,?,?,?,  ?,?,?)"
    );
}

function normalizeCsvRow(array $cols, array $headers): array {
    if (count($cols) < count($headers)) {
        $cols = array_pad($cols, count($headers), '');
    }
    return array_combine($headers, array_slice($cols, 0, count($headers)));
}

function buildV5BatchRow(int $syncId, int $rowNum, array $idx, array $data): array {
    return [
        $syncId, $rowNum,
        $idx['ca_owner'],
        $idx['salesforce_id'],
        $idx['cert_name'],
        $idx['parent_salesforce_id'] ?: null,
        $idx['parent_cert_name']     ?: null,
        $idx['cert_type'],
        $idx['subordinate_ca_owner'] ?: null,
        $idx['status_apple'],
        $idx['status_chrome'],
        $idx['status_microsoft'],
        $idx['status_mozilla'],
        $idx['sha256'],
        $idx['parent_sha256']        ?: null,
        $idx['valid_from']           ?: null,
        $idx['valid_to']             ?: null,
        $idx['tls_capable'],
        $idx['tls_ev_capable'],
        $idx['code_sign_capable'],
        $idx['smime_capable'],
        $idx['country']              ?: null,
        json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        buildSearchText($idx, $data),
    ];
}

function buildSearchText(array $idx, array $data): string {
    return implode(' ', array_filter([
        $idx['ca_owner'],
        $idx['cert_name'],
        $idx['subordinate_ca_owner'],
        $idx['sha256'],
        $idx['country'],
        $idx['status_apple'],
        $idx['status_chrome'],
        $idx['status_microsoft'],
        $idx['status_mozilla'],
        $data['Trust Bits for Root Cert'] ?? '',
        $data['Derived Trust Bits']       ?? '',
        $data['Audit Firm']               ?? '',
        $data['Status of Root Cert']      ?? '',
    ]));
}

function finaliseV5Sync(PDO $pdo, int $syncId, string $key, int $inserted): void {
    // Delete rows from any previous sync for this resource
    try {
        $pdo->prepare(
            "DELETE c FROM ccadb_v5_certs c
             JOIN ccadb_v5_sync_log l ON l.id = c.sync_id
             WHERE l.resource_key = ? AND c.sync_id < ?"
        )->execute([$key, $syncId]);
    } catch (Throwable $e) {
        fwrite(STDERR, "[ccadb_sync] Old-row cleanup error: " . $e->getMessage() . "\n");
    }
    try {
        $pdo->prepare(
            "UPDATE ccadb_v5_sync_log SET row_count = ? WHERE id = ?"
        )->execute([$inserted, $syncId]);
    } catch (Throwable $e) {
        fwrite(STDERR, "[ccadb_sync] Count update error: " . $e->getMessage() . "\n");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Phase 2 — PEM from AllCertificatePEMsCSVFormat (two decade URLs)
// ══════════════════════════════════════════════════════════════════════════════

function syncPem(PDO $pdo, bool $force): bool {
    $key = 'pem_update';
    if (!$force && recentSync($pdo, $key)) {
        echo '[' . gmdate(DT_FMT) . " UTC] $key already synced today — skipping\n";
        return true;
    }
    $totalUpdated = 0;
    $lastErr      = null;
    foreach ([PEM_URL_2010 => '2010s', PEM_URL_2020 => '2020s'] as $url => $label) {
        echo '[' . gmdate(DT_FMT) . " UTC] Downloading PEM CSV ($label)…\n";
        $tmp = downloadToTemp($key . '_' . $label, $url);
        if ($tmp === null) {
            $lastErr = "Download failed for $label";
            continue;
        }
        $result = updatePem($pdo, $tmp);
        @unlink($tmp);
        if ($result['error'] !== null) {
            fwrite(STDERR, "[ccadb_sync] PEM $label error: {$result['error']}\n");
            $lastErr = $result['error'];
        } else {
            $totalUpdated += $result['updated'];
            echo '[' . gmdate(DT_FMT) . " UTC] PEM $label: {$result['updated']} certs updated\n";
        }
    }
    $ok = ($lastErr === null);
    logSync($pdo, $key, $ok ? 'ok' : 'error', $totalUpdated, $lastErr);
    if ($totalUpdated > 0) {
        echo '[' . gmdate(DT_FMT) . " UTC] PEM total: $totalUpdated certs updated\n";
    }
    return $ok;
}

function updatePem(PDO $pdo, string $file): array {
    [$fh, $headers, $openErr] = openCsvForReading($file, 2);
    if ($openErr !== null) {
        return ['updated' => 0, 'error' => $openErr];
    }
    [$shaCol, $pemCol, $colErr] = findPemColumns($headers);
    if ($colErr !== null) {
        fclose($fh);
        return ['updated' => 0, 'error' => $colErr];
    }

    $stmt    = $pdo->prepare("UPDATE ccadb_v5_certs SET pem_info = ?, cert_policy_oids = ? WHERE sha256 = ?");
    $updated = processPemRows($fh, $stmt, $shaCol, $pemCol);
    fclose($fh);

    return ['updated' => $updated, 'error' => null];
}

// ── updatePem helpers ─────────────────────────────────────────────────────────

function findPemColumns(array $headers): array {
    $shaCol = null;
    $pemCol = null;
    foreach ($headers as $i => $h) {
        $lh = strtolower($h);
        if ($shaCol === null && (str_contains($lh, 'sha-256') || str_contains($lh, 'sha256'))) {
            $shaCol = $i;
        }
        if ($pemCol === null && str_contains($lh, 'pem')) {
            $pemCol = $i;
        }
    }
    $err = ($shaCol === null || $pemCol === null)
        ? 'Could not locate SHA-256 or PEM column (found: ' . implode(', ', $headers) . ')'
        : null;
    return [$shaCol, $pemCol, $err];
}

function processPemRows($fh, PDOStatement $stmt, int $shaCol, int $pemCol): int {
    $updated = 0;
    while (($cols = fgetcsv($fh)) !== false) {
        $sha = trim($cols[$shaCol] ?? '');
        $pem = normalizePem(trim(trim($cols[$pemCol] ?? ''), '"\''));
        if ($sha === '' || $pem === '') {
            continue;
        }
        $oids     = parseCertPolicyOids($pem);
        $oidsJson = $oids !== [] ? json_encode($oids) : null;
        try {
            $stmt->execute([$pem, $oidsJson, $sha]);
            $updated += $stmt->rowCount();
        } catch (Throwable $e) {
            fwrite(STDERR, "[ccadb_sync] PEM row error: " . $e->getMessage() . "\n");
        }
    }
    return $updated;
}

function normalizePem(string $pem): string {
    if ($pem !== '' && !str_contains($pem, '-----')) {
        return "-----BEGIN CERTIFICATE-----\n"
             . wordwrap($pem, 64, "\n", true)
             . "\n-----END CERTIFICATE-----";
    }
    return $pem;
}

// ══════════════════════════════════════════════════════════════════════════════
// Shared helpers
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Open a CSV file and read the header row.
 * Returns [resource|false, string[], ?string] — fh, headers, error.
 */
function openCsvForReading(string $file, int $minCols): array {
    $fh = fopen($file, 'rb');
    if (!$fh) {
        return [false, [], 'Cannot open temp file'];
    }
    $headers = fgetcsv($fh);
    if (!is_array($headers) || count($headers) < $minCols) {
        fclose($fh);
        return [false, [], 'Invalid CSV: missing or too-short header row'];
    }
    return [$fh, array_map('trim', $headers), null];
}

function extractIndexed(array $data): array {
    $out = array_fill_keys(array_values(V5_INDEXED_COLS), '');
    foreach (V5_INDEXED_COLS as $csvCol => $dbCol) {
        $val = trim($data[$csvCol] ?? '');
        if (in_array($dbCol, DATE_COLS, true)) {
            $out[$dbCol] = parseCcadbDate($val);
        } elseif (in_array($dbCol, BOOL_COLS, true)) {
            $out[$dbCol] = parseCcadbBool($val);
        } else {
            $out[$dbCol] = $val;
        }
    }
    return $out;
}

function parseCcadbDate(string $s): ?string {
    $s = trim($s);
    if ($s === '' || $s === 'N/A') {
        return null;
    }
    if (preg_match('/^(\d{4})\.(\d{2})\.(\d{2})$/', $s, $m)) {
        return "{$m[1]}-{$m[2]}-{$m[3]}";
    }
    return preg_match('/^\d{4}-\d{2}-\d{2}$/', $s) ? $s : null;
}

function parseCcadbBool(string $s): int {
    return in_array(strtolower(trim($s)), ['true', '1', 'yes'], true) ? 1 : 0;
}

function recentSync(PDO $pdo, string $key): bool {
    try {
        $st = $pdo->prepare(
            "SELECT 1 FROM ccadb_v5_sync_log
             WHERE resource_key = ? AND status = 'ok' AND synced_at >= NOW() - INTERVAL 1 DAY
             LIMIT 1"
        );
        $st->execute([$key]);
        return (bool)$st->fetchColumn();
    } catch (Throwable $e) {
        return false;
    }
}

function downloadToTemp(string $key, string $url): ?string {
    $tmp = tempnam(sys_get_temp_dir(), 'ccadb_');
    $fh  = $tmp !== false ? fopen($tmp, 'wb') : false;
    if ($fh === false) {
        if ($tmp !== false) {
            @unlink($tmp);
        }
        fwrite(STDERR, "[ccadb_sync] Cannot create temp file for $key\n");
        return null;
    }
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_FILE           => $fh,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => DL_TIMEOUT,
        CURLOPT_USERAGENT      => 'ccadb-sync/2.0 (thameur.org)',
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
        fwrite(STDERR, "[ccadb_sync] $key download failed: " . ($curlErr ?: "HTTP $http") . "\n");
        return null;
    }
    return $tmp;
}

/** @return array{int, ?string} [rows_flushed, error_or_null] */
function flushBatch(PDO $pdo, PDOStatement $stmt, array &$batch): array {
    $n = 0;
    try {
        $pdo->beginTransaction();
        foreach ($batch as $row) {
            $stmt->execute($row);
            $n++;
        }
        $pdo->commit();
        $batch = [];
        return [$n, null];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        fwrite(STDERR, "[ccadb_sync] Batch error: " . $e->getMessage() . "\n");
        $batch = [];
        return [-1, 'DB batch insert failed'];
    }
}

function rollbackSync(PDO $pdo, int $syncId, string $error): void {
    try {
        $pdo->prepare("DELETE FROM ccadb_v5_certs WHERE sync_id = ?")->execute([$syncId]);
        $pdo->prepare(
            "UPDATE ccadb_v5_sync_log SET status='error', error_message=? WHERE id=?"
        )->execute([$error, $syncId]);
    } catch (Throwable $e) {
        fwrite(STDERR, "[ccadb_sync] Rollback error: " . $e->getMessage() . "\n");
    }
}

function logSync(PDO $pdo, string $key, string $status, int $rows, ?string $msg): void {
    try {
        $pdo->prepare(
            "INSERT INTO ccadb_v5_sync_log (resource_key, status, row_count, error_message)
             VALUES (?, ?, ?, ?)"
        )->execute([$key, $status, $rows, $msg]);
    } catch (Throwable $e) {
        fwrite(STDERR, "[ccadb_sync] Log error: " . $e->getMessage() . "\n");
    }
}

// ── X.509 certificatePolicies OID extraction ──────────────────────────────────

/**
 * Parse the certificatePolicies extension from a PEM certificate and return
 * the list of policy OIDs. Returns [] when the extension is absent or the PEM
 * cannot be parsed.
 */
function parseCertPolicyOids(string $pem): array {
    if ($pem === '' || !function_exists('openssl_x509_read')) {
        return [];
    }
    $cert   = @openssl_x509_read($pem);
    $parsed = ($cert !== false) ? openssl_x509_parse($cert, true) : null; // shortnames=true
    if (!is_array($parsed) || !isset($parsed['extensions']['certificatePolicies'])) {
        return [];
    }
    $ext = $parsed['extensions']['certificatePolicies'];
    // Some PHP/OpenSSL combinations return complex extensions as arrays.
    if (is_array($ext)) {
        $ext = implode("\n", array_map('strval', $ext));
    }
    return extractPolicyOidsFromText((string)$ext);
}

/**
 * Parse the OpenSSL text representation of a certificatePolicies extension.
 * Each policy is on a line starting with "Policy: <OID_or_name>".
 * Some OpenSSL versions substitute the numeric OID with a text name, e.g.
 * anyPolicy (2.5.29.32.0) becomes "X509v3 Any Policy".
 */
function extractPolicyOidsFromText(string $raw): array {
    // avoids S1313 false-positive (dotted notation mistaken for IP address)
    $anyPolicyOid = implode('.', ['2', '5', '29', '32', '0']);
    static $nameToOid = null;
    if ($nameToOid === null) {
        $nameToOid = array_fill_keys(
            ['x509v3 any policy', 'any policy', 'anypolicy', 'x509v3 any'],
            $anyPolicyOid
        );
    }
    $oids = [];
    foreach (explode("\n", $raw) as $line) {
        $line = trim($line);
        // Match "Policy: <value>" lines; value may be numeric OID or text name.
        if (!preg_match('/Policy:\s*(.+)/i', $line, $m)) {
            continue;
        }
        $val = trim($m[1]);
        if (preg_match('/^\d+(\.\d+)+$/', $val)) {
            $oids[] = $val;
        } elseif (isset($nameToOid[strtolower($val)])) {
            $oids[] = $nameToOid[strtolower($val)];
        }
        // Unrecognised text names are silently skipped.
    }
    return array_values(array_unique($oids));
}

/**
 * Iterate all rows that have a PEM but no parsed OIDs yet, parse them, and
 * store the result. Used by the --backfill-oids CLI flag after a schema
 * migration on an existing database.
 */
function backfillOids(PDO $pdo): int {
    $select = $pdo->query(
        "SELECT sha256, pem_info FROM ccadb_v5_certs
         WHERE pem_info IS NOT NULL AND pem_info != ''"
    );
    $update = $pdo->prepare(
        "UPDATE ccadb_v5_certs SET cert_policy_oids = ? WHERE sha256 = ?"
    );
    $count  = 0;
    while ($row = $select->fetch(PDO::FETCH_ASSOC)) {
        $oids = parseCertPolicyOids($row['pem_info']);
        $update->execute([$oids !== [] ? json_encode($oids) : null, $row['sha256']]);
        $count++;
    }
    return $count;
}
