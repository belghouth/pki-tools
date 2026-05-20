<?php
/**
 * ccadb.php — CCADB V5 browser
 *
 * Single grouped view: CA Owner accordions → certificate rows → detail modal.
 * Data source: ccadb_v5_certs (AllCertificateRecordsCSVFormatV5 + PEM overlay).
 *
 * Endpoints (same file, detected by query string):
 *   ?json=1&q=…&p=…   →  JSON list of CA owner groups (compact cert rows)
 *   ?detail=<sha256>   →  JSON full data_json + pem_info for one cert
 */

header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: "
    . "default-src 'self'; "
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    . "font-src 'self' https://fonts.gstatic.com; "
    . "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com https://www.recaptcha.net; "
    . "frame-src https://www.google.com https://www.recaptcha.net; "
    . "connect-src 'self' https://www.google.com https://www.gstatic.com https://www.recaptcha.net; "
    . "img-src 'self' data:; "
    . "object-src 'none'; "
    . "base-uri 'self'; "
    . "form-action 'self'; "
    . "frame-ancestors 'self'; "
    . "upgrade-insecure-requests;"
);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/recaptcha.php';

const OWNERS_PER_PAGE = 25;

define('HDR_JSON',       'Content-Type: application/json; charset=utf-8');
define('ERR_RECAPTCHA', 'reCAPTCHA failed');

// ── Input ─────────────────────────────────────────────────────────────────────

$search     = trim(substr($_GET['q']          ?? '', 0, 200));
$page       = max(1, (int)($_GET['p']         ?? 1));
$isJson     = isset($_GET['json'])   && $_GET['json']   === '1';
$detail     = trim($_GET['detail']   ?? '');
$verifyUrl  = trim($_POST['verify_url'] ?? '');
$verifyCps  = isset($_POST['verify_cps'])  && $_POST['verify_cps']  === '1';
$chainLint  = isset($_POST['chain_lint'])  && $_POST['chain_lint']  === '1';

// ── ?verify_url= — must run before DB init to guarantee clean JSON output ────

if ($verifyUrl !== '') {
    header(HDR_JSON);
    $rcToken = trim($_POST['g_recaptcha_token'] ?? '');
    if (recaptcha_configured() && !recaptcha_verify($rcToken, 'verify_url')) {
        echo json_encode(['ok' => false, 'status' => ERR_RECAPTCHA]);
        exit;
    }
    if (!preg_match('#^https?://#i', $verifyUrl)) {
        echo json_encode(['ok' => false, 'status' => 'Invalid URL']);
        exit;
    }
    $vcOpts = [
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS      => 0,
        CURLOPT_TIMEOUT        => 12,
        CURLOPT_CONNECTTIMEOUT => 6,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; pki-tools/1.0)',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS=> CURLPROTO_HTTPS,
        CURLOPT_HTTPHEADER     => ['Accept: */*'],
    ];
    // Phase 1: HEAD
    $vch = curl_init($verifyUrl);
    curl_setopt_array($vch, $vcOpts + [CURLOPT_NOBODY => true]);
    curl_exec($vch);
    $vCode = (int) curl_getinfo($vch, CURLINFO_HTTP_CODE);
    $vErr  = curl_error($vch);
    curl_close($vch);
    // Phase 2: plain GET fallback when HEAD gives no response or 405
    if ($vErr === '' && ($vCode === 0 || $vCode === 405)) {
        $vch2 = curl_init($verifyUrl);
        curl_setopt_array($vch2, $vcOpts + [CURLOPT_NOBODY => false, CURLOPT_TIMEOUT => 8]);
        curl_exec($vch2);
        $vCode = (int) curl_getinfo($vch2, CURLINFO_HTTP_CODE);
        $vErr  = curl_error($vch2);
        curl_close($vch2);
    }
    if ($vErr !== '') {
        $vErrLc = strtolower($vErr);
        if (str_contains($vErrLc, 'ssl') || str_contains($vErrLc, 'tls') || str_contains($vErrLc, 'certificate')) {
            $vLabel = 'SSL Error';
        } elseif (str_contains($vErrLc, 'timed out') || str_contains($vErrLc, 'timeout')) {
            $vLabel = 'Timeout';
        } elseif (str_contains($vErrLc, 'could not resolve') || str_contains($vErrLc, 'name resolution')) {
            $vLabel = 'DNS Error';
        } elseif (str_contains($vErrLc, 'connection refused')) {
            $vLabel = 'Refused';
        } else {
            $vLabel = 'Network Error';
        }
        echo json_encode(['ok' => false, 'status' => $vLabel]);
    } elseif ($vCode >= 200 && $vCode < 400) {
        echo json_encode(['ok' => true,  'status' => (string)$vCode]);
    } else {
        echo json_encode(['ok' => false, 'status' => $vCode > 0 ? (string)$vCode : 'No Response']);
    }
    exit;
}

// ── DB ────────────────────────────────────────────────────────────────────────

$pdo     = admin_pdo();
$dbError = null;
$syncInfo = null;

if ($pdo) {
    try {
        $si = $pdo->prepare(
            "SELECT synced_at, row_count FROM ccadb_v5_sync_log
             WHERE resource_key = 'v5_certs' AND status = 'ok'
             ORDER BY synced_at DESC LIMIT 1"
        );
        $si->execute();
        $syncInfo = $si->fetch() ?: null;
    } catch (Throwable $e) {
        $dbError = $e->getMessage();
    }
}

// ── ?verify_cps=1 — download CP/CPS docs and check policy OIDs ───────────────

if ($verifyCps) {
    header(HDR_JSON);
    if (!$pdo) {
        echo json_encode(['ok' => false, 'error' => 'Database unavailable']);
        exit;
    }
    $rcToken = trim($_POST['g_recaptcha_token'] ?? '');
    if (recaptcha_configured() && !recaptcha_verify($rcToken, 'verify_cps')) {
        echo json_encode(['ok' => false, 'error' => ERR_RECAPTCHA]);
        exit;
    }
    $cpsSha    = substr(preg_replace('/[^a-f0-9]/i', '', trim($_POST['cert_sha256'] ?? '')), 0, 64);
    $rawUrls   = json_decode(trim($_POST['cert_urls'] ?? '[]'), true) ?? [];
    $rawOids   = json_decode(trim($_POST['cert_oids'] ?? '[]'), true) ?? [];
    $certOids  = array_values(array_filter(
        array_map('trim', is_array($rawOids) ? $rawOids : []),
        fn($o) => (bool)preg_match('/^\d+(\.\d+)+$/', $o)
    ));
    $certUrls  = [];
    foreach (is_array($rawUrls) ? $rawUrls : [] as $entry) {
        if (!is_array($entry)) { continue; }
        $url = substr(trim((string)($entry['url'] ?? '')), 0, 2000);
        $lbl = substr(trim((string)($entry['label'] ?? '')), 0, 100);
        if (preg_match('#^https?://#i', $url)) {
            $certUrls[] = ['label' => $lbl, 'url' => $url];
        }
    }
    if ($cpsSha === '' || empty($certUrls)) {
        echo json_encode(['ok' => false, 'error' => 'Invalid parameters']);
        exit;
    }
    try {
        ensureCpsCacheTable($pdo);
        echo json_encode(doVerifyAllDocs($pdo, $cpsSha, $certUrls, $certOids));
    } catch (Throwable $e) {
        echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

// ── ?chain_lint=1 — run lint_pkix_signer_signee_cert_chain inline ────────────

if ($chainLint) {
    header(HDR_JSON);
    $rcToken = trim($_POST['g_recaptcha_token'] ?? '');
    if (recaptcha_configured() && !recaptcha_verify($rcToken, 'chain_lint')) {
        echo json_encode(['ok' => false, 'error' => ERR_RECAPTCHA]);
        exit;
    }
    $certPem   = trim($_POST['cert_pem']   ?? '');
    $parentPem = trim($_POST['parent_pem'] ?? '');
    if ($certPem === '' || $parentPem === '') {
        echo json_encode(['ok' => false, 'error' => 'Both certificate PEMs are required']);
        exit;
    }
    $linters_dir = __DIR__ . '/linters';
    require_once $linters_dir . '/pkilint.php';
    $chainBin = pkilint_binary('lint_pkix_signer_signee_cert_chain');
    if ($chainBin === null) {
        echo json_encode(['ok' => false, 'error' => 'lint_pkix_signer_signee_cert_chain is not installed on this server']);
        exit;
    }
    try {
        $run = pkilint_make_run('lint_pkix_signer_signee_cert_chain', [], true);
        echo json_encode(['ok' => true, 'html' => $run($certPem, $parentPem)]);
    } catch (Throwable $e) {
        echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

// ── ?detail=<sha256> — full cert data for modal ───────────────────────────────

if ($detail !== '' && $pdo) {
    header(HDR_JSON);
    try {
        $st = $pdo->prepare(
            "SELECT data_json, pem_info, cert_policy_oids FROM ccadb_v5_certs WHERE sha256 = ? LIMIT 1"
        );
        $st->execute([$detail]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if ($row) {
            $fields = json_decode($row['data_json'], true) ?? [];
            echo json_encode([
                'found'      => true,
                'fields'     => $fields,
                'pemInfo'    => $row['pem_info'],
                'policyOids' => decodePolicyOids($row['cert_policy_oids'] ?? null),
            ]);
        } else {
            echo json_encode(['found' => false]);
        }
    } catch (Throwable $e) {
        echo json_encode(['found' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

// ── ?json=1 — grouped list for live search ────────────────────────────────────

if ($isJson && $pdo) {
    header(HDR_JSON);
    echo json_encode(queryGrouped($pdo, $search, $page));
    exit;
}

// ── Server-side initial data (avoids first-paint round-trip) ─────────────────

$initialData = null;
if ($pdo && !$dbError) {
    try {
        $initialData = queryGrouped($pdo, $search, $page);
    } catch (Throwable $e) {
        $dbError = $e->getMessage();
    }
}

// ── Sync badge ────────────────────────────────────────────────────────────────

$syncClass = 'never';
$syncText  = 'Never synced';
if ($syncInfo) {
    $syncDate  = new DateTimeImmutable($syncInfo['synced_at'] . ' UTC');
    $now       = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    $ageDays   = (int)$now->diff($syncDate)->days;
    $syncClass = $ageDays > 10 ? 'stale' : '';
    $syncText  = 'Synced ' . $syncDate->format('Y-m-d') . ' · ' . number_format($syncInfo['row_count']) . ' certs';
}

$navLabel = 'CCADB Browser';

// ── Query helpers ─────────────────────────────────────────────────────────────

/** Decode cert_policy_oids JSON and return only valid dotted-numeric OIDs. */
function decodePolicyOids(?string $json): array {
    $raw = json_decode($json ?? 'null', true);
    if (!is_array($raw)) { return []; }
    return array_values(array_filter(
        $raw,
        fn($o) => is_string($o) && (bool)preg_match('/^\d+(\.\d+){3,}$/', $o)
    ));
}

function queryGrouped(PDO $pdo, string $search, int $page): array {
    $offset     = ($page - 1) * OWNERS_PER_PAGE;
    $hasSearch  = $search !== '';
    $likeArg    = $hasSearch
        ? '%' . str_replace(['%', '_', '\\'], ['\\%', '\\_', '\\\\'], $search) . '%'
        : null;

    // Phase 1: distinct CA owners matching the search, paginated
    if ($hasSearch) {
        $countSql = "SELECT COUNT(DISTINCT ca_owner) FROM ccadb_v5_certs
                     WHERE search_text LIKE ?";
        $ownerSql = "SELECT DISTINCT ca_owner FROM ccadb_v5_certs
                     WHERE search_text LIKE ?
                     ORDER BY ca_owner LIMIT " . OWNERS_PER_PAGE . " OFFSET $offset";
        $cSt = $pdo->prepare($countSql); $cSt->execute([$likeArg]);
        $oSt = $pdo->prepare($ownerSql); $oSt->execute([$likeArg]);
    } else {
        $countSql = "SELECT COUNT(DISTINCT ca_owner) FROM ccadb_v5_certs";
        $ownerSql = "SELECT DISTINCT ca_owner FROM ccadb_v5_certs
                     ORDER BY ca_owner LIMIT " . OWNERS_PER_PAGE . " OFFSET $offset";
        $cSt = $pdo->prepare($countSql); $cSt->execute();
        $oSt = $pdo->prepare($ownerSql); $oSt->execute();
    }

    $totalOwners = (int)$cSt->fetchColumn();
    $ownerNames  = $oSt->fetchAll(PDO::FETCH_COLUMN);

    if (!$ownerNames) {
        return ['owners' => [], 'totalOwners' => $totalOwners, 'page' => $page,
                'pages' => max(1, (int)ceil($totalOwners / OWNERS_PER_PAGE))];
    }

    // Phase 2: all certs for those owners (unfiltered — show full owner context)
    $in   = implode(',', array_fill(0, count($ownerNames), '?'));
    $certs = $pdo->prepare(
        "SELECT ca_owner, cert_name, cert_type, sha256,
                salesforce_id, parent_salesforce_id, parent_sha256,
                valid_from, valid_to,
                status_apple, status_chrome, status_microsoft, status_mozilla,
                tls_capable, tls_ev_capable, code_sign_capable, smime_capable,
                country, subordinate_ca_owner,
                (pem_info IS NOT NULL AND pem_info != '') AS has_pem,
                cert_policy_oids, data_json
         FROM ccadb_v5_certs
         WHERE ca_owner IN ($in)
         ORDER BY ca_owner, cert_type DESC, cert_name"
    );
    $certs->execute($ownerNames);

    // Group by ca_owner
    $grouped = [];
    foreach ($ownerNames as $name) {
        $grouped[$name] = ['name' => $name, 'country' => '', 'certs' => []];
    }
    while ($row = $certs->fetch(PDO::FETCH_ASSOC)) {
        $owner = $row['ca_owner'];
        if (!isset($grouped[$owner])) {
            continue;
        }
        if ($grouped[$owner]['country'] === '' && !empty($row['country'])) {
            $grouped[$owner]['country'] = $row['country'];
        }
        $raw = json_decode($row['data_json'], true) ?? [];
        $grouped[$owner]['certs'][] = [
            'name'        => $row['cert_name'],
            'type'        => $row['cert_type'],
            'sha256'      => $row['sha256'],
            'validFrom'   => $row['valid_from'],
            'validTo'     => $row['valid_to'],
            'statusApple' => $row['status_apple'],
            'statusChrome'=> $row['status_chrome'],
            'statusMs'    => $row['status_microsoft'],
            'statusMoz'   => $row['status_mozilla'],
            'trustBits'   => $raw['Trust Bits for Root Cert']  ?? '',
            'derivedBits' => $raw['Derived Trust Bits']        ?? '',
            'tlsCap'      => (bool)$row['tls_capable'],
            'evCap'       => (bool)$row['tls_ev_capable'],
            'csCap'       => (bool)$row['code_sign_capable'],
            'smimeCap'    => (bool)$row['smime_capable'],
            'hasPem'      => (bool)$row['has_pem'],
            'sfId'        => $row['salesforce_id']           ?? '',
            'parentSfId'  => $row['parent_salesforce_id']    ?? '',
            'parentSha256'=> $row['parent_sha256']           ?? '',
            'aki'         => $raw['Authority Key Identifier'] ?? '',
            'ski'         => $raw['Subject Key Identifier']   ?? '',
            'revocation'  => $raw['Revocation Status']        ?? '',
            'constrained' => $raw['Technically Constrained']  ?? '',
            'policyOids'  => decodePolicyOids($row['cert_policy_oids'] ?? null),
        ];
    }

    return [
        'owners'      => array_values($grouped),
        'totalOwners' => $totalOwners,
        'page'        => $page,
        'pages'       => max(1, (int)ceil($totalOwners / OWNERS_PER_PAGE)),
    ];
}

// ══════════════════════════════════════════════════════════════════════════════
// CPS OID verification helpers
// ══════════════════════════════════════════════════════════════════════════════

function ensureCpsCacheTable(PDO $pdo): void {
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS cps_cache (
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
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    );
}

function doVerifyAllDocs(PDO $pdo, string $sha256, array $certUrls, array $certOids): array {
    $docs = [];
    foreach ($certUrls as $entry) {
        $url     = $entry['url'];
        $urlHash = hash('sha256', $url);
        $row     = loadOrRefreshCps($pdo, $sha256, $urlHash, $url);
        if (isset($row['__error'])) {
            $docs[] = $row['__error'] + ['label' => $entry['label']];
            continue;
        }
        $docs[] = buildCpsSearchResult($certOids, $row) + ['label' => $entry['label']];
    }
    $summary = buildOidSummary($certOids, $docs);
    $allOk   = !empty($certOids) && array_reduce(
        $summary,
        fn($c, $s) => $c && $s['status'] === 'VERIFIED_IN_CPS',
        true
    );
    return ['ok' => $allOk, 'docs' => $docs, 'summary' => $summary];
}

function buildOidSummary(array $certOids, array $docs): array {
    $summary = [];
    foreach ($certOids as $oid) {
        $best = bestOidAcrossDocs($oid, $docs);
        if ($best !== null) {
            $summary[] = $best;
        }
    }
    return $summary;
}

function bestOidAcrossDocs(string $oid, array $docs): ?array {
    static $priority = [
        'VERIFIED_IN_CPS'     => 0,
        'FOUND_ELSEWHERE'     => 1,
        'DIFFERENT_OIDS_FOUND'=> 2,
        'NOT_FOUND'           => 3,
        'CPS_PARSE_FAILED'    => 4,
        'CPS_UNAVAILABLE'     => 5,
    ];
    $best = null;
    foreach ($docs as $doc) {
        foreach ($doc['results'] ?? [] as $r) {
            if ($r['oid'] !== $oid) { continue; }
            $rp = $priority[$r['status']] ?? 99;
            $bp = $priority[$best['status'] ?? ''] ?? 99;
            if ($best === null || $rp < $bp) {
                $best = $r + ['docLabel' => $doc['label'] ?? '', 'docUrl' => $doc['cpsUrl'] ?? ''];
            }
        }
    }
    return $best;
}

function loadOrRefreshCps(PDO $pdo, string $sha256, string $urlHash, string $cpsUrl): array {
    $cached = getCpsCache($pdo, $sha256, $urlHash);
    if ($cached !== null) {
        $ageDays = (int)floor((time() - strtotime($cached['downloaded_at'])) / 86400);
        if ($ageDays <= 30 && $cached['cps_url'] === $cpsUrl) {
            $cached['from_cache']    = true;
            $cached['cache_age_days'] = $ageDays;
            return $cached;
        }
    }
    return fetchAndCacheCps($pdo, $sha256, $urlHash, $cpsUrl);
}

function fetchAndCacheCps(PDO $pdo, string $sha256, string $urlHash, string $cpsUrl): array {
    $now               = gmdate('Y-m-d H:i:s');
    [$body, $ct, $err] = downloadCpsDocument($cpsUrl);
    if ($err !== null) {
        upsertCpsCache($pdo, $sha256, $cpsUrl, $now, null, null, $err);
        return ['__error' => ['ok' => false, 'status' => 'CPS_UNAVAILABLE', 'error' => $err,
                              'cpsUrl' => $cpsUrl, 'downloadedAt' => $now]];
    }
    [$text, $parseErr] = extractCpsText($body, $ct ?? '', $cpsUrl);
    upsertCpsCache($pdo, $sha256, $cpsUrl, $now, $ct, $text, $parseErr);
    if ($parseErr !== null || $text === null) {
        return ['__error' => ['ok' => false, 'status' => 'CPS_PARSE_FAILED', 'error' => $parseErr,
                              'cpsUrl' => $cpsUrl, 'downloadedAt' => $now, 'contentType' => $ct]];
    }
    return (getCpsCache($pdo, $sha256, $urlHash) ?? [])
        + ['from_cache' => false, 'cache_age_days' => 0];
}

function buildCpsSearchResult(array $certOids, array $row): array {
    $text     = (string)($row['cps_text'] ?? '');
    $sections = extractRfc3647Sections($text);
    $cpsOids  = extractAllCpsOids($text);
    $results  = [];
    $hasIssue = false;
    foreach ($certOids as $oid) {
        $r        = searchOneOid($oid, $text, $sections, $cpsOids);
        $hasIssue = $hasIssue || ($r['status'] !== 'VERIFIED_IN_CPS');
        $results[] = $r;
    }
    return [
        'ok'          => !$hasIssue,
        'cpsUrl'      => $row['cps_url'],
        'downloadedAt'=> $row['downloaded_at'],
        'fromCache'   => (bool)($row['from_cache'] ?? false),
        'cacheAgeDays'=> (int)($row['cache_age_days'] ?? 0),
        'contentType' => $row['content_type'] ?? null,
        'results'     => $results,
        'allCpsOids'  => $cpsOids,
    ];
}

function searchOneOid(string $oid, string $text, array $sections, array $cpsOids): array {
    foreach (['7.1.6', '7.1.8', '7.1.9', '1.2'] as $sec) {
        if (isset($sections[$sec]) && str_contains($sections[$sec], $oid)) {
            return ['oid' => $oid, 'status' => 'VERIFIED_IN_CPS', 'section' => $sec,
                    'snippet' => extractSnippet($sections[$sec], $oid), 'notes' => ''];
        }
    }
    if (str_contains($text, $oid)) {
        return ['oid' => $oid, 'status' => 'FOUND_ELSEWHERE', 'section' => '',
                'snippet' => extractSnippet($text, $oid),
                'notes'   => 'OID found in CPS but outside expected RFC 3647 sections (1.2, 7.1.6, 7.1.8, 7.1.9)'];
    }
    $status = !empty($cpsOids) ? 'DIFFERENT_OIDS_FOUND' : 'NOT_FOUND';
    $notes  = $status === 'DIFFERENT_OIDS_FOUND'
        ? 'CPS contains policy OIDs but not this one'
        : 'No policy OIDs found in CPS';
    return ['oid' => $oid, 'status' => $status, 'section' => '', 'snippet' => '', 'notes' => $notes];
}

function extractRfc3647Sections(string $text): array {
    $found = [];
    foreach (['1.2', '7.1', '7.1.6', '7.1.8', '7.1.9'] as $sec) {
        $pat = '/(?:^|\n)\s*' . preg_quote($sec, '/') . '[\s\.\:]/';
        if (!preg_match($pat, $text, $m, PREG_OFFSET_CAPTURE)) {
            continue;
        }
        $start   = (int)$m[0][1];
        $tail    = substr($text, $start + 1);
        $nextPos = preg_match('/(?:^|\n)\s*\d+\.\d+/m', $tail, $nm, PREG_OFFSET_CAPTURE)
            ? $start + 1 + (int)$nm[0][1]
            : strlen($text);
        $found[$sec] = substr($text, $start, min(4000, $nextPos - $start));
    }
    return $found;
}

define('WS_RE', '/\s+/');

function extractAllCpsOids(string $text): array {
    preg_match_all('/\b\d+(?:\.\d+){2,}\b/', $text, $m);
    $raw = array_unique($m[0] ?? []);
    return array_values(array_filter($raw, fn($o) => count(explode('.', $o)) >= 4));
}

function extractSnippet(string $text, string $needle, int $ctx = 120): string {
    $pos = strpos($text, $needle);
    if ($pos === false) {
        return '';
    }
    $start   = max(0, $pos - $ctx);
    $raw     = substr($text, $start, min(strlen($text), $pos + strlen($needle) + $ctx) - $start);
    return trim(preg_replace(WS_RE, ' ', $raw));
}

// ── CPS download ──────────────────────────────────────────────────────────────

function downloadCpsDocument(string $url): array {
    [$body, $http, $ct, $err] = cpsFetchUrl($url);
    return cpsDownloadResult($body, $http, $ct, $err);
}

function cpsFetchUrl(string $url): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => 45,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; pki-tools/1.0)',
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ]);
    $body = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $ct   = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $err  = curl_error($ch);
    curl_close($ch);
    return [$body, $http, $ct, $err];
}

function cpsDownloadResult(string|bool $body, int $http, string $ct, string $err): array {
    if ($err !== '') {
        return [null, null, "Download failed: $err"];
    }
    if ($http < 200 || $http >= 400) {
        return [null, null, "HTTP $http"];
    }
    $str = is_string($body) && $body !== '' ? $body : null;
    return [$str, $ct ?: null, $str === null ? 'Empty response' : null];
}

// ── CPS text extraction ───────────────────────────────────────────────────────

function extractCpsText(string $body, string $ct, string $url): array {
    $ext    = strtolower(pathinfo((string)parse_url($url, PHP_URL_PATH), PATHINFO_EXTENSION));
    $lcCt   = strtolower($ct);
    $isPdf  = str_contains($lcCt, 'pdf') || $ext === 'pdf' || str_starts_with($body, '%PDF');
    $isHtml = str_contains($lcCt, 'html') || in_array($ext, ['html', 'htm'], true);
    if ($isPdf) {
        return extractPdfText($body);
    }
    if ($isHtml) {
        return extractHtmlText($body);
    }
    $safe = mb_convert_encoding($body, 'UTF-8', 'ASCII, UTF-8, ISO-8859-1');
    return [$safe !== false ? $safe : $body, null];
}

function extractPdfText(string $pdf): array {
    $text = extractPdfViaCli($pdf);
    if ($text !== null) {
        return [$text, null];
    }
    $raw = extractRawPdfText($pdf);
    if ($raw !== '') {
        return [$raw, null];
    }
    return [null, 'PDF text extraction requires pdftotext (poppler-utils) — install it on the server'];
}

function extractPdfViaCli(string $pdf): ?string {
    if (!function_exists('proc_open')) {
        return null;
    }
    exec('which pdftotext 2>/dev/null', $which);
    if (empty($which)) {
        return null;
    }
    return runPdfToText($pdf);
}

function runPdfToText(string $pdf): ?string {
    $tmpIn = tempnam(sys_get_temp_dir(), 'cpspdf_');
    if ($tmpIn === false) {
        return null;
    }
    $tmpOut = $tmpIn . '.txt';
    file_put_contents($tmpIn, $pdf);
    exec('pdftotext -layout -enc UTF-8 ' . escapeshellarg($tmpIn) . ' ' . escapeshellarg($tmpOut) . ' 2>/dev/null');
    $text = is_file($tmpOut) ? (string)file_get_contents($tmpOut) : null;
    @unlink($tmpIn);
    @unlink($tmpOut);
    return ($text !== null && $text !== '') ? $text : null;
}

function extractRawPdfText(string $pdf): string {
    $text = '';
    if (preg_match_all('/stream\r?\n(.*?)\r?\nendstream/s', $pdf, $streams)) {
        foreach ($streams[1] as $stream) {
            $dec = @zlib_decode($stream);
            if ($dec !== false) {
                $text .= extractPdfStreamText($dec) . ' ';
            }
        }
    }
    return trim(preg_replace(WS_RE, ' ', $text . extractPdfStreamText($pdf)));
}

function extractPdfStreamText(string $content): string {
    $text = '';
    preg_match_all('/\(([^)]*)\)\s*(?:Tj|\'|")/s', $content, $simple);
    foreach ($simple[1] as $s) {
        $text .= $s . ' ';
    }
    preg_match_all('/\[([^\]]*)\]\s*TJ/s', $content, $arrays);
    foreach ($arrays[1] as $arr) {
        preg_match_all('/\(([^)]*)\)/', $arr, $strings);
        foreach ($strings[1] as $s) {
            $text .= $s . ' ';
        }
    }
    return $text;
}

function extractHtmlText(string $html): array {
    $doc = new DOMDocument();
    libxml_use_internal_errors(true);
    @$doc->loadHTML('<?xml encoding="UTF-8">' . $html, LIBXML_NOWARNING | LIBXML_NOERROR);
    libxml_clear_errors();
    $remove = [];
    foreach (['script', 'style', 'nav', 'header', 'footer'] as $tag) {
        foreach (iterator_to_array($doc->getElementsByTagName($tag)) as $node) {
            $remove[] = $node;
        }
    }
    foreach ($remove as $node) {
        $node->parentNode?->removeChild($node);
    }
    $raw = html_entity_decode($doc->textContent ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return [trim(preg_replace(WS_RE, ' ', $raw)), null];
}

// ── cps_cache DB helpers ──────────────────────────────────────────────────────

function getCpsCache(PDO $pdo, string $sha256, string $urlHash): ?array {
    $st = $pdo->prepare(
        "SELECT * FROM cps_cache WHERE cert_sha256 = ? AND cps_url_hash = ? LIMIT 1"
    );
    $st->execute([$sha256, $urlHash]);
    return $st->fetch(PDO::FETCH_ASSOC) ?: null;
}

function upsertCpsCache(PDO $pdo, string $sha256, string $url,
                        string $downloadedAt, ?string $ct, ?string $text, ?string $err): void {
    $urlHash    = hash('sha256', $url);
    // Truncate stored text to 5 MB to avoid oversized rows
    $storedText = ($text !== null && strlen($text) > 5242880) ? substr($text, 0, 5242880) : $text;
    $pdo->prepare(
        "INSERT INTO cps_cache
             (cert_sha256, cps_url_hash, cps_url, downloaded_at, content_type, cps_text, fetch_error)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           cps_url = VALUES(cps_url), downloaded_at = VALUES(downloaded_at),
           content_type = VALUES(content_type), cps_text = VALUES(cps_text),
           fetch_error = VALUES(fetch_error)"
    )->execute([$sha256, $urlHash, $url, $downloadedAt, $ct, $storedText, $err]);
}

?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'CCADB Browser — CA Certificate Records | ' . SITE_DOMAIN,
    'description' => 'Browse all CCADB V5 root and intermediate CA certificates grouped by CA owner, with browser trust status, audit info, and EKU.',
    'url'         => SITE_BASE_URL . '/ccadb.php',
  ]);
  ?>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">
  <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png">
  <?= recaptcha_head() ?>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:#0e1014; --surface:#13171e; --surface2:#1a1f28; --border:#2a3040;
      --accent:#00d4aa; --text:#d4dae6; --muted:#6b7a90;
      --sans:'IBM Plex Sans',sans-serif; --mono:'IBM Plex Mono',monospace;
      --radius:8px;
      --red:#e85555; --amber:#f5a623; --green:#00d4aa; --purple:#a78bfa;
    }
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    html{font-size:15px;scroll-behavior:smooth}
    body{background:var(--bg);color:var(--text);font-family:var(--sans);font-weight:300;line-height:1.7}
    a{color:var(--accent);text-decoration:none}
    a:hover{color:#fff}
    .sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}

    /* ── Layout ── */
    html,body{max-width:100%;overflow-x:hidden}
    .page{max-width:1400px;margin:0 auto;padding:2.5rem 1.5rem 6rem}
    .page-hd{margin-bottom:1.8rem}
    .page-hd h1{font-size:1.75rem;font-weight:600;color:#fff;margin-bottom:.25rem}
    .page-hd p{font-size:.85rem;color:var(--muted)}

    /* ── Toolbar ── */
    .toolbar{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;margin-bottom:1rem}
    .search-wrap{position:relative;flex:0 0 380px}
    .search-wrap input{
      width:100%;background:var(--surface);border:1px solid var(--border);
      border-radius:6px;color:var(--text);font-family:var(--mono);
      font-size:.8rem;padding:.45rem 2.2rem .45rem .75rem;outline:none;
      transition:border-color 150ms
    }
    .search-wrap input:focus{border-color:var(--accent)}
    .search-wrap input::placeholder{color:var(--muted)}
    .search-clear{
      position:absolute;right:.5rem;top:50%;transform:translateY(-50%);
      background:none;border:none;color:var(--muted);cursor:pointer;font-size:1rem;line-height:1;padding:0
    }
    .search-clear:hover{color:var(--text)}
    .search-spinner{
      display:none;width:14px;height:14px;border:2px solid var(--border);
      border-top-color:var(--accent);border-radius:50%;
      animation:spin .6s linear infinite;flex-shrink:0
    }
    .search-spinner.active{display:inline-block}
    @keyframes spin{to{transform:rotate(360deg)}}
    .toolbar-meta{font-size:.78rem;color:var(--muted);margin-left:auto;white-space:nowrap}

    /* ── Filter chips ── */
    .filter-chips{display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:1rem;border:none;padding:0;margin-top:0}
    .chip{
      font-family:var(--mono);font-size:.65rem;font-weight:600;
      letter-spacing:.06em;text-transform:uppercase;
      border:1px solid var(--border);border-radius:20px;
      padding:.2rem .7rem;cursor:pointer;background:none;color:var(--muted);
      transition:color 120ms,border-color 120ms,background 120ms
    }
    .chip:hover{color:var(--text);border-color:#3a4458}
    .chip.active{color:var(--accent);border-color:rgba(0,212,170,.4);background:rgba(0,212,170,.07)}

    /* ── Grouped table ── */
    .tbl-wrap{border:1px solid var(--border);border-radius:var(--radius);overflow-x:auto;overflow-y:hidden}
    table{width:100%;border-collapse:collapse;font-size:.78rem}
    thead th{
      background:var(--surface2);color:var(--muted);
      font-family:var(--mono);font-size:.68rem;font-weight:600;
      letter-spacing:.05em;text-transform:uppercase;
      padding:.6rem .85rem;text-align:left;
      border-bottom:1px solid var(--border);white-space:nowrap
    }
    /* ── CA Owner group rows ── */
    tr.owner-row{
      background:var(--surface2);cursor:pointer;
      border-bottom:1px solid var(--border)
    }
    tr.owner-row:hover{background:#1e2430}
    tr.owner-row td{padding:.65rem .85rem}
    .owner-toggle{
      display:inline-block;font-size:.8rem;color:var(--muted);
      margin-right:.5rem;transition:transform 200ms;user-select:none
    }
    tr.owner-row.expanded .owner-toggle{transform:rotate(90deg);color:var(--accent)}
    .owner-name{font-weight:600;color:#e8edf7;font-size:.85rem}
    .owner-meta{font-size:.7rem;color:var(--muted);margin-left:.75rem;font-family:var(--mono)}
    .owner-count{
      font-family:var(--mono);font-size:.65rem;
      background:rgba(255,255,255,.06);border:1px solid var(--border);
      border-radius:10px;padding:.1rem .5rem;margin-left:.5rem;color:var(--muted)
    }
    /* ── Cert rows (children) ── */
    tr.cert-row{
      display:none;border-bottom:1px solid #1a1f26;
      background:#0d1016;cursor:pointer;
      transition:background 80ms
    }
    tr.cert-row.visible{display:table-row}
    tr.cert-row:hover{background:rgba(0,212,170,.03)}
    tr.cert-row td{padding:.45rem .85rem .45rem 1.75rem;vertical-align:middle}
    .cert-name{color:var(--text);max-width:260px;word-break:break-word;line-height:1.4}
    .cert-type-badge{
      font-family:var(--mono);font-size:.6rem;font-weight:600;
      letter-spacing:.06em;text-transform:uppercase;border-radius:3px;
      padding:.1rem .35rem;white-space:nowrap
    }
    .badge-root{color:var(--accent);background:rgba(0,212,170,.1);border:1px solid rgba(0,212,170,.25)}
    .badge-inter{color:var(--purple);background:rgba(167,139,250,.1);border:1px solid rgba(167,139,250,.25)}
    .badge-cross{color:var(--amber);background:rgba(245,166,35,.1);border:1px solid rgba(245,166,35,.25)}
    .cert-fp{font-family:var(--mono);font-size:.67rem;color:#6b7a90;white-space:nowrap}
    .cert-fp abbr{text-decoration:none;cursor:default}
    .cert-valid{font-family:var(--mono);font-size:.68rem;color:var(--muted);white-space:nowrap}
    .cert-valid .vto.expired{color:var(--red)}
    .cert-chevron{color:var(--muted);font-size:.75rem;opacity:.4}
    tr.cert-row:hover .cert-chevron{opacity:1;color:var(--accent)}

    /* ── Tree structure ── */
    .tree-toggle{background:none;border:none;color:var(--muted);cursor:pointer;font-size:.7rem;padding:0 .3rem 0 0;line-height:1;flex-shrink:0;transition:transform 150ms;user-select:none;vertical-align:middle}
    .tree-toggle:hover{color:var(--accent)}
    .tree-toggle.open{transform:rotate(90deg);color:var(--accent)}
    .tree-toggle.leaf{opacity:0;pointer-events:none}
    .cert-name-wrap{display:flex;align-items:center;gap:0}
    .tree-connector{display:inline-block;font-size:.75rem;color:#2a3040;margin-right:.25rem;font-family:var(--mono);flex-shrink:0;user-select:none}
    /* ── Status mini-badges ── */
    .cert-status-badges{display:flex;flex-wrap:wrap;gap:.2rem;margin-left:.5rem;align-items:center;flex-shrink:0}
    .badge-revoked{font-family:var(--mono);font-size:.55rem;font-weight:700;letter-spacing:.06em;background:rgba(232,85,85,.15);color:var(--red);border:1px solid rgba(232,85,85,.4);border-radius:3px;padding:.05rem .3rem;text-transform:uppercase}
    .badge-expired{font-family:var(--mono);font-size:.55rem;font-weight:700;letter-spacing:.06em;background:rgba(245,166,35,.12);color:var(--amber);border:1px solid rgba(245,166,35,.35);border-radius:3px;padding:.05rem .3rem;text-transform:uppercase}
    .badge-constrained{font-family:var(--mono);font-size:.55rem;color:var(--muted);border:1px solid var(--border);border-radius:3px;padding:.05rem .3rem}
    .badge-orphan{font-family:var(--mono);font-size:.55rem;color:var(--amber);border:1px solid rgba(245,166,35,.35);border-radius:3px;padding:.05rem .3rem}
    .badge-mismatch{font-family:var(--mono);font-size:.55rem;color:#f97316;border:1px solid rgba(249,115,22,.35);border-radius:3px;padding:.05rem .3rem}
    /* ── Revoked / expired row tint ── */
    tr.cert-row.is-revoked{background:rgba(232,85,85,.04)}
    tr.cert-row.is-revoked:hover{background:rgba(232,85,85,.08)}
    tr.cert-row.is-expired{background:rgba(245,166,35,.03)}
    tr.cert-row.is-expired:hover{background:rgba(245,166,35,.07)}

    /* ── Trust bits tags ── */
    .trust-tags{display:flex;flex-wrap:wrap;gap:.2rem}
    .trust-tag{
      font-size:.62rem;font-family:var(--mono);
      background:rgba(167,139,250,.1);color:var(--purple);
      border:1px solid rgba(167,139,250,.25);border-radius:3px;
      padding:.05rem .3rem;white-space:nowrap
    }
    .trust-tag.tls{color:var(--green);background:rgba(0,212,170,.1);border-color:rgba(0,212,170,.25)}
    .trust-tag.email{color:var(--amber);background:rgba(245,166,35,.1);border-color:rgba(245,166,35,.25)}
    .trust-tag.cs{color:#f97316;background:rgba(249,115,22,.1);border-color:rgba(249,115,22,.25)}

    /* ── Browser trust badges ── */
    .br-badges{display:flex;gap:10px;align-items:center;flex-wrap:nowrap;white-space:nowrap}
    .br-badge{display:inline-flex;flex-shrink:0}
    .br-badge img{width:26px;height:26px;display:block;transition:transform .15s}
    .br-badge img.br-grey{opacity:.2}
    .br-badge:hover img{transform:scale(1.15)}

    /* ── Empty / loading ── */
    .tbl-empty{text-align:center;padding:4rem 1rem;color:var(--muted);font-family:var(--mono);font-size:.82rem}
    .tbl-loading{text-align:center;padding:3rem 1rem;color:var(--muted);font-size:.82rem}

    /* ── Pagination ── */
    .pagination{display:flex;align-items:center;justify-content:center;gap:.3rem;margin-top:1.5rem;flex-wrap:wrap}
    .pagination a,.pagination span{
      display:inline-flex;align-items:center;justify-content:center;
      min-width:32px;height:32px;padding:0 .5rem;
      border-radius:5px;font-size:.78rem;font-family:var(--mono);
      border:1px solid var(--border);color:var(--muted);
      text-decoration:none;transition:color 120ms,border-color 120ms,background 120ms
    }
    .pagination a:hover{color:var(--text);border-color:#3a4458;background:rgba(255,255,255,.04)}
    .pagination .cur{color:var(--accent);border-color:rgba(0,212,170,.35);background:rgba(0,212,170,.07)}
    .pagination .dots{border:none;color:var(--muted)}

    /* ── Sync badge ── */
    .sync-badge{
      display:inline-flex;align-items:center;gap:.4rem;
      font-size:.72rem;font-family:var(--mono);color:var(--muted);
      background:var(--surface);border:1px solid var(--border);
      border-radius:4px;padding:.25rem .6rem
    }
    .sync-badge .dot{width:6px;height:6px;border-radius:50%;background:var(--accent);flex-shrink:0}
    .sync-badge.stale .dot{background:var(--amber)}
    .sync-badge.never .dot{background:var(--red)}

    /* ════════════════════════════════════════════════════════════════════════
       DETAIL MODAL
    ════════════════════════════════════════════════════════════════════════ */
    dialog.cert-modal{
      position:fixed;inset:0;width:100vw;height:100vh;
      max-width:100%;max-height:100%;
      background:transparent;border:none;padding:0
    }
    dialog.cert-modal[open]{display:flex;align-items:center;justify-content:center}
    dialog.cert-modal::backdrop{background:rgba(0,0,0,.8);backdrop-filter:blur(5px)}

    .cm-box{
      background:var(--surface);border:1px solid var(--border);
      border-radius:12px;width:min(900px,96vw);
      max-height:min(90vh,820px);display:flex;flex-direction:column;
      box-shadow:0 32px 100px rgba(0,0,0,.8);overflow:hidden
    }

    /* header */
    .cm-hd{
      display:flex;align-items:flex-start;gap:1rem;
      padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);
      flex-shrink:0;background:#0f1318
    }
    .cm-hd-text{flex:1;min-width:0}
    .cm-eyebrow{font-family:var(--mono);font-size:.6rem;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);margin-bottom:.2rem}
    .cm-title{font-size:1rem;font-weight:600;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .cm-owner{font-size:.78rem;color:var(--muted);margin-top:.15rem}
    .cm-close{background:none;border:none;color:var(--muted);cursor:pointer;font-size:1.4rem;line-height:1;padding:.2rem .4rem;border-radius:4px;flex-shrink:0;transition:color 120ms,background 120ms}
    .cm-close:hover{color:var(--text);background:rgba(255,255,255,.06)}

    /* ── Revoked/expired modal header accent ── */
    .cm-box.is-revoked{border-color:rgba(232,85,85,.5);box-shadow:0 32px 100px rgba(0,0,0,.8),0 0 0 1px rgba(232,85,85,.2)}
    .cm-box.is-revoked .cm-hd{background:rgba(232,85,85,.06);border-bottom-color:rgba(232,85,85,.25)}
    .cm-box.is-expired{border-color:rgba(245,166,35,.4);box-shadow:0 32px 100px rgba(0,0,0,.8),0 0 0 1px rgba(245,166,35,.15)}
    .cm-box.is-expired .cm-hd{background:rgba(245,166,35,.05);border-bottom-color:rgba(245,166,35,.2)}
    .cm-status-banner{font-family:var(--mono);font-size:.67rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:.3rem 1.5rem;text-align:center;display:none}
    .cm-status-banner.show-revoked{display:block;background:rgba(232,85,85,.12);color:var(--red);border-bottom:1px solid rgba(232,85,85,.25)}
    .cm-status-banner.show-expired{display:block;background:rgba(245,166,35,.08);color:var(--amber);border-bottom:1px solid rgba(245,166,35,.2)}

    /* loading state */
    .cm-loading{text-align:center;padding:4rem 1rem;color:var(--muted);font-family:var(--mono);font-size:.82rem}
    .cm-loading-inline{color:var(--muted);font-family:var(--mono);font-size:.72rem;font-style:italic}

    /* pkilint output injected into modal — must live in <head>, not inside innerHTML */
    .pkilint-output{font-family:var(--mono);font-size:.72rem}
    .pkilint-clean{padding:.9rem;color:#3ddc7a;background:rgba(0,212,100,0.07);border:1px solid rgba(0,212,100,0.22);border-radius:4px;font-weight:600}
    .pkilint-parse-error{padding:.55rem .85rem;color:#f5a623;background:rgba(245,166,35,0.09);border:1px solid rgba(245,166,35,0.28);border-radius:4px;margin-bottom:.5rem}
    .pkilint-raw{font-family:var(--mono);font-size:.7rem;color:#d4dae6;background:#161a21;border:1px solid #2a3040;border-radius:4px;padding:.9rem;white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto}
    .pkilint-summary{display:flex;align-items:center;gap:1.25rem;flex-wrap:wrap;padding:.55rem .85rem;background:rgba(29,35,48,.85);border:1px solid #2a3040;border-radius:4px;margin-bottom:.65rem;font-size:.7rem;letter-spacing:.05em}
    .pkilint-summary-total{color:#ffffff;font-weight:700}
    .pkilint-summary-total strong{font-size:.85rem}
    .pkilint-summary-item{display:flex;align-items:center;gap:.3rem}
    .pkilint-summary-item strong{font-size:.82rem}
    .pkilint-rows{display:flex;flex-direction:column;gap:2px;max-height:560px;overflow-y:auto;border:1px solid #2a3040;border-radius:4px;background:#161a21}
    .pkilint-row{display:flex;align-items:flex-start;gap:.75rem;padding:.35rem .75rem;line-height:1.6;transition:filter 80ms ease}
    .pkilint-row:hover{filter:brightness(1.2)}
    .pkilint-badge{flex-shrink:0;width:5.5rem;text-align:center;font-weight:700;font-size:.6rem;letter-spacing:.1em;border-radius:2px;padding:.15em .3em;margin-top:.15em}
    .pkilint-body{display:flex;flex-direction:column;gap:.1rem;flex:1;word-break:break-all}
    .pkilint-code{color:#ffffff !important;font-weight:700 !important}
    .pkilint-message{color:#c8d4e4 !important;font-size:.69rem}
    .pkilint-path{color:#8899aa !important;font-size:.67rem;font-style:italic}
    .pkilint-validator{color:#6b7a90 !important;font-size:.65rem}

    /* scrollable body */
    .cm-body{overflow-y:auto;flex:1}

    /* sections */
    .cm-sect{padding:.9rem 1.5rem;border-bottom:1px solid #1e2430}
    .cm-sect:last-of-type{border-bottom:none}
    .cm-sect-title{font-family:var(--mono);font-size:.63rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:.65rem}

    /* definition rows */
    .cm-dl{display:grid;grid-template-columns:180px 1fr;gap:.1rem .75rem}
    .cm-dt{font-family:var(--mono);font-size:.67rem;color:var(--muted);padding:.18rem 0;align-self:start;white-space:nowrap}
    .cm-dd{font-family:var(--mono);font-size:.74rem;color:var(--text);padding:.18rem 0;word-break:break-word}
    .cm-dd a{color:var(--accent)}
    .cm-dd a:hover{color:#fff}
    .cm-dd-muted{color:var(--muted)}

    /* browser trust cards */
    .cm-trust-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:.5rem}
    .cm-tc{border:1px solid var(--border);border-left:3px solid var(--border);border-radius:6px;padding:.6rem .8rem;background:rgba(255,255,255,.02)}
    .cm-tc.tc-included{border-left-color:var(--green);background:rgba(0,212,170,.04)}
    .cm-tc.tc-ev{border-left-color:#00b894;background:rgba(0,184,148,.04)}
    .cm-tc.tc-pending{border-left-color:var(--amber);background:rgba(245,166,35,.04)}
    .cm-tc.tc-removed{border-left-color:var(--red);background:rgba(232,85,85,.04)}
    .cm-tc.tc-na{opacity:.5}
    .cm-tc-browser{font-family:var(--mono);font-size:.6rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:.2rem}
    .cm-tc-status{font-size:.78rem;font-weight:500;color:var(--text);line-height:1.3}
    .cm-tc-status.s-included{color:var(--green)}
    .cm-tc-status.s-ev{color:#00b894}
    .cm-tc-status.s-pending{color:var(--amber)}
    .cm-tc-status.s-removed{color:var(--red)}
    .cm-tc-ev-lbl{font-family:var(--mono);font-size:.63rem;color:var(--muted);margin-top:.2rem}

    /* capability flags */
    .cm-caps{display:flex;flex-wrap:wrap;gap:.35rem}
    .cm-cap{font-family:var(--mono);font-size:.65rem;border:1px solid;border-radius:3px;padding:.08rem .4rem;white-space:nowrap}
    .cm-cap.on-tls{color:var(--green);border-color:rgba(0,212,170,.35);background:rgba(0,212,170,.07)}
    .cm-cap.on-cs{color:#f97316;border-color:rgba(249,115,22,.35);background:rgba(249,115,22,.07)}
    .cm-cap.on-smime{color:var(--amber);border-color:rgba(245,166,35,.35);background:rgba(245,166,35,.07)}
    .cm-cap.off{color:var(--muted);border-color:var(--border);opacity:.45}
    /* trust bit chips */
    .cm-tag-list{display:flex;flex-wrap:wrap;gap:.3rem}
    .cm-tag{font-family:var(--mono);font-size:.65rem;border:1px solid rgba(0,212,170,.3);border-radius:3px;padding:.08rem .45rem;background:rgba(0,212,170,.06);color:var(--green);white-space:nowrap}
    /* bool badge */
    .cm-bool-true{font-family:var(--mono);font-size:.74rem;color:var(--green)}
    .cm-bool-false{font-family:var(--mono);font-size:.74rem;color:var(--muted)}
    /* status-of-root mini cards */
    .cm-sor{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.1rem}
    .cm-sor-card{border:1px solid var(--border);border-left:3px solid var(--border);border-radius:5px;padding:.3rem .55rem;background:rgba(255,255,255,.02);min-width:90px}
    .cm-sor-card.tc-included{border-left-color:var(--green);background:rgba(0,212,170,.04)}
    .cm-sor-card.tc-ev{border-left-color:#00b894;background:rgba(0,184,148,.04)}
    .cm-sor-card.tc-pending{border-left-color:var(--amber);background:rgba(245,166,35,.04)}
    .cm-sor-card.tc-removed{border-left-color:var(--red);background:rgba(232,85,85,.04)}
    .cm-sor-card.tc-na{opacity:.45}
    .cm-sor-br{font-family:var(--mono);font-size:.55rem;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin-bottom:.15rem}
    .cm-sor-st{font-size:.71rem;font-weight:500;line-height:1.25}
    .cm-sor-st.s-included{color:var(--green)}
    .cm-sor-st.s-ev{color:#00b894}
    .cm-sor-st.s-pending{color:var(--amber)}
    .cm-sor-st.s-removed{color:var(--red)}
    .cm-sor-st.s-na{color:var(--muted)}
    /* revocation badge */
    .cm-revok-ok{font-family:var(--mono);font-size:.74rem;color:var(--green)}
    .cm-revok-bad{font-family:var(--mono);font-size:.74rem;color:var(--red)}
    .cm-revok-na{font-family:var(--mono);font-size:.74rem;color:var(--muted)}
    /* CRL URL rows */
    .cm-crl-list{display:flex;flex-direction:column;gap:.35rem}
    .cm-crl-row{display:flex;align-items:center;gap:.4rem}
    .cm-crl-input{flex:1;font-family:var(--mono);font-size:.67rem;background:#0e1219;border:1px solid var(--border);border-radius:4px;color:var(--accent);padding:.28rem .5rem;overflow-x:auto;white-space:nowrap;cursor:pointer;min-width:0;text-decoration:underline;text-underline-offset:2px;text-decoration-color:rgba(0,212,170,.35)}
    .cm-crl-input:hover{border-color:var(--accent);color:#fff;text-decoration-color:rgba(0,212,170,.7)}
    .cm-crl-open{background:transparent;border:1px solid var(--border);border-radius:4px;color:var(--muted);cursor:pointer;padding:.2rem .35rem;flex-shrink:0;line-height:1;font-size:.8rem}
    .cm-crl-open:hover{color:var(--accent);border-color:var(--accent)}
    .cm-crl-verify{font-family:var(--mono);font-size:.62rem;padding:.2rem .55rem;border-radius:4px;border:1px solid rgba(0,212,170,.35);background:transparent;color:var(--green);cursor:pointer;white-space:nowrap;flex-shrink:0}
    .cm-crl-verify:hover{background:rgba(0,212,170,.08)}
    .cm-crl-verify.checking{color:var(--muted);border-color:var(--border);cursor:default;pointer-events:none}
    .cm-crl-verify.ok{color:var(--green);border-color:rgba(0,212,170,.5)}
    .cm-crl-verify.broken{color:var(--red);border-color:rgba(232,85,85,.4)}

    /* audit sub-block */
    .cm-audit-block{margin-bottom:.5rem;padding-bottom:.5rem;border-bottom:1px solid rgba(42,48,64,.6)}
    .cm-audit-block:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}
    .cm-audit-label{font-family:var(--mono);font-size:.62rem;font-weight:600;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;margin-bottom:.25rem}

    /* ── Policy OID section ── */
    .oid-source{background:var(--surface2);border-radius:6px;padding:.65rem .85rem;margin-bottom:.6rem}
    .oid-source-hd{display:flex;align-items:center;gap:.5rem;margin-bottom:.45rem;flex-wrap:wrap}
    .oid-source-label{font-size:.7rem;font-weight:600;color:var(--text);text-transform:uppercase;letter-spacing:.06em}
    .oid-source-badge{font-size:.62rem;padding:.1rem .4rem;border-radius:3px;font-weight:600;font-family:var(--mono)}
    .oid-src-cert{background:rgba(0,212,170,.12);color:var(--accent);border:1px solid rgba(0,212,170,.25)}
    .oid-src-ccadb{background:rgba(167,139,250,.12);color:var(--purple);border:1px solid rgba(167,139,250,.25)}
    .oid-chips{display:flex;flex-wrap:wrap;gap:.4rem}
    .oid-chip{display:inline-flex;flex-direction:column;background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:.22rem .5rem;font-family:var(--mono);font-size:.67rem;line-height:1.3}
    .oid-chip-label{font-size:.58rem;color:var(--accent);font-weight:600;font-family:var(--sans);letter-spacing:.03em}
    .oid-chip-oid{color:var(--text)}
    .oid-empty{color:var(--muted);font-size:.78rem;font-style:italic}
    .oid-compare{margin-top:.25rem;padding:.65rem .85rem;background:rgba(10,13,18,.4);border-radius:6px}
    .oid-compare-hd{font-size:.68rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.45rem}
    .oid-issue{display:flex;align-items:baseline;gap:.45rem;padding:.25rem 0;font-size:.8rem;line-height:1.4;border-bottom:1px solid rgba(42,48,64,.4)}
    .oid-issue:last-child{border-bottom:none;padding-bottom:0}
    .oid-icon{flex-shrink:0;font-weight:700;width:1em;text-align:center}
    .oid-ok    .oid-icon{color:var(--green)}
    .oid-warn  .oid-icon{color:var(--amber)}
    .oid-error .oid-icon{color:var(--red)}
    .oid-info  .oid-icon{color:var(--muted)}
    .oid-issue-text{color:var(--text)}

    /* CPS verification */
    .oid-cps-btn{margin-top:.6rem;padding:.3rem .75rem;font-size:.72rem;font-family:var(--mono);font-weight:600;color:var(--accent);background:rgba(0,212,170,.08);border:1px solid rgba(0,212,170,.3);border-radius:4px;cursor:pointer;transition:background .15s,border-color .15s}
    .oid-cps-btn:hover{background:rgba(0,212,170,.16);border-color:rgba(0,212,170,.55)}
    .oid-cps-btn:disabled{opacity:.45;cursor:not-allowed}
    .oid-cps-results{margin-top:.75rem;display:none}
    .oid-cps-results.visible{display:block}
    .oid-cps-meta{font-size:.7rem;color:var(--muted);margin-bottom:.55rem;display:flex;flex-wrap:wrap;gap:.35rem .9rem}
    .oid-cps-meta-item{display:flex;gap:.3rem;align-items:baseline}
    .oid-cps-meta-label{font-weight:600;color:var(--text);text-transform:uppercase;letter-spacing:.05em;font-size:.6rem}
    .oid-cps-ok-msg{padding:.45rem .7rem;background:rgba(0,212,170,.1);border:1px solid rgba(0,212,170,.25);border-radius:4px;font-size:.8rem;color:var(--accent)}
    .oid-cps-flag{padding:.45rem .7rem;border-radius:4px;font-size:.8rem;margin-bottom:.5rem}
    .oid-cps-flag.cps-ok{background:rgba(0,212,170,.1);border:1px solid rgba(0,212,170,.25);color:var(--accent)}
    .oid-cps-flag.cps-warn{background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.25);color:var(--amber)}
    .oid-cps-flag.cps-err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);color:var(--red)}
    .oid-cps-table{width:100%;border-collapse:collapse;font-size:.72rem;margin-top:.4rem}
    .oid-cps-table th{text-align:left;font-size:.6rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;padding:.25rem .5rem;border-bottom:1px solid var(--border)}
    .oid-cps-table td{padding:.3rem .5rem;border-bottom:1px solid rgba(42,48,64,.3);vertical-align:top;color:var(--text)}
    .oid-cps-table tr:last-child td{border-bottom:none}
    .oid-cps-status{font-size:.6rem;font-weight:700;padding:.1rem .35rem;border-radius:3px;font-family:var(--mono);white-space:nowrap}
    .cps-s-verified{background:rgba(0,212,170,.15);color:var(--accent)}
    .cps-s-elsewhere{background:rgba(167,139,250,.15);color:var(--purple)}
    .cps-s-different{background:rgba(251,191,36,.15);color:var(--amber)}
    .cps-s-notfound{background:rgba(239,68,68,.15);color:var(--red)}
    .cps-s-unavail,.cps-s-failed{background:rgba(100,116,139,.15);color:var(--muted)}
    .oid-cps-section{font-size:.62rem;color:var(--muted);font-family:var(--mono)}
    .oid-cps-snippet{font-size:.65rem;color:var(--muted);font-style:italic;margin-top:.15rem;line-height:1.4;max-width:34rem;word-break:break-word}
    .oid-cps-snippet mark{background:rgba(0,212,170,.2);color:var(--text);font-style:normal;border-radius:2px;padding:0 .15rem}
    .oid-cps-all-oids{margin-top:.7rem;padding-top:.5rem;border-top:1px solid var(--border)}
    .oid-cps-all-label{font-size:.6rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.35rem}

    /* PEM + actions (same style as artifact_parser.php) */
    .ap-embed-cert-pem{
      display:block;width:100%;height:140px;resize:vertical;min-height:80px;
      background:rgba(0,0,0,.35);color:#8a9ab8;
      border:1px solid var(--border);border-radius:4px;
      font-family:var(--mono);font-size:.6rem;line-height:1.5;
      padding:.5rem .65rem;outline:none;white-space:pre;overflow-y:auto;
      margin-bottom:.6rem;user-select:text;cursor:text
    }
    .ap-embed-cert-pem.pem-empty{
      color:#2e3748;font-style:italic;cursor:default;user-select:none;
      display:flex;align-items:center;justify-content:center;text-align:center;
      height:72px;resize:none
    }
    .ap-embed-cert-actions{display:flex;gap:.5rem;flex-wrap:wrap}
    .ap-embed-cert-btn{
      font-family:var(--mono);font-size:.65rem;text-transform:uppercase;
      letter-spacing:.07em;font-weight:600;cursor:pointer;
      border-radius:4px;padding:.3em .8em;background:none;
      transition:background .15s,border-color .15s
    }
    .ap-embed-cert-btn:disabled{opacity:.3;cursor:not-allowed;pointer-events:none}
    .ap-embed-cert-lint{color:var(--accent);border:1px solid rgba(0,212,170,.35)}
    .ap-embed-cert-lint:hover{background:rgba(0,212,170,.08);border-color:var(--accent)}
    .ap-embed-cert-parse{color:var(--purple);border:1px solid rgba(167,139,250,.35)}
    .ap-embed-cert-parse:hover{background:rgba(167,139,250,.08);border-color:var(--purple)}
    .ap-embed-cert-copy{color:var(--muted);border:1px solid var(--border)}
    .ap-embed-cert-copy:hover{color:var(--text);border-color:#3a4458;background:rgba(255,255,255,.04)}
    .ap-embed-cert-dl{color:var(--muted);border:1px solid var(--border)}
    .ap-embed-cert-dl:hover{color:var(--text);border-color:#3a4458;background:rgba(255,255,255,.04)}

    @media(max-width:640px){
      .search-wrap{flex:1 1 100%}
      .toolbar-meta{margin-left:0;width:100%}
      .cm-dl{grid-template-columns:1fr}
      .cm-dt{padding-bottom:0}
    }
  </style>
</head>
<body>
<?php require_once __DIR__ . '/includes/site_nav.php'; ?>

<div class="page">
  <div class="page-hd">
    <h1>CCADB Browser</h1>
    <p>CCADB V5 — all root and intermediate CA certificates, grouped by CA owner.</p>
  </div>

  <!-- ── Toolbar ── -->
  <div class="toolbar">
    <div class="search-wrap">
      <input type="search" id="cSearch" value="<?= htmlspecialchars($search) ?>"
             placeholder="Search CA owner, certificate name, SHA-256, country…"
             autocomplete="off" spellcheck="false" aria-label="Search certificates">
      <button type="button" class="search-clear" id="cClear"
              style="<?= $search === '' ? 'display:none' : '' ?>"
              aria-label="Clear search">×</button>
    </div>
    <div class="search-spinner" id="cSpinner" aria-hidden="true"></div>
    <span class="toolbar-meta" id="cMeta" aria-live="polite"></span>
    <span class="sync-badge <?= $syncClass ?>" style="margin-left:0">
      <span class="dot"></span><?= htmlspecialchars($syncText) ?>
    </span>
  </div>

  <!-- ── Filter chips ── -->
  <fieldset class="filter-chips">
    <legend class="sr-only">Filter by type</legend>
    <button class="chip active" data-filter="all">All</button>
    <button class="chip" data-filter="root">Root only</button>
    <button class="chip" data-filter="intermediate">Intermediate only</button>
    <button class="chip" data-filter="tls">TLS capable</button>
    <button class="chip" data-filter="smime">S/MIME capable</button>
    <button class="chip" data-filter="cs">Code signing</button>
    <button class="chip" data-filter="valid">Valid</button>
    <button class="chip" data-filter="expired">Expired</button>
    <button class="chip" data-filter="revoked">Revoked</button>
    <button class="chip" data-filter="trusted">Trusted</button>
    <button class="chip" data-filter="untrusted">Untrusted</button>
  </fieldset>

  <!-- ── Table ── -->
  <?php if (!$pdo): ?>
  <div class="tbl-empty">Database unavailable.</div>
  <?php elseif ($dbError !== null): ?>
  <div class="tbl-empty">Query error — try again shortly.</div>
  <?php else: ?>

  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th style="width:30%">Certificate / CA Owner</th>
          <th>Type</th>
          <th title="Apple · Chrome · Microsoft · Mozilla">Trust</th>
          <th>Capabilities</th>
          <th>Valid Until</th>
          <th><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody id="cTbody">
        <tr><td colspan="6" class="tbl-loading">Loading…</td></tr>
      </tbody>
    </table>
  </div>

  <nav class="pagination" id="cPagination" aria-label="Page navigation"></nav>

  <?php endif; ?>

  <!-- ═══════════════════════════════════════════════════════════════════════
       DETAIL MODAL
  ═══════════════════════════════════════════════════════════════════════ -->
  <dialog class="cert-modal" id="certModal" aria-labelledby="cmTitle">
    <div class="cm-box">

      <div class="cm-hd">
        <div class="cm-hd-text">
          <div class="cm-eyebrow" id="cmEyebrow">Certificate</div>
          <h2 class="cm-title"  id="cmTitle">—</h2>
          <div class="cm-owner" id="cmOwner"></div>
        </div>
        <button class="cm-close" id="cmClose" aria-label="Close">×</button>
      </div>

      <div class="cm-status-banner" id="cmStatusBanner"></div>

      <div class="cm-body" id="cmBody">
        <div class="cm-loading" id="cmLoading">Loading…</div>
      </div>

    </div>
  </dialog>

</div><!-- /.page -->

<script>
(function () {
  'use strict';

  // ── Initial data injected by PHP ──────────────────────────────────────────
  var initData       = <?= json_encode($initialData) ?>;
  var RCAPTCHA_KEY   = <?= json_encode(RECAPTCHA_SITE_KEY) ?>;

  // ── State ─────────────────────────────────────────────────────────────────
  var allOwners      = [];   // current page data
  var collapsedNodes = new Set();
  var activeFilter = sessionStorage.getItem('ccadb_filter') || 'all';
  var searchQ     = '';
  var curPage     = 1;
  var totalPages  = 1;
  var totalOwners = 0;
  var searchTimer = null;
  var activeCert  = null; // { sha256, name, hasPem }

  // ── DOM refs ──────────────────────────────────────────────────────────────
  var searchEl   = document.getElementById('cSearch');
  var clearBtn   = document.getElementById('cClear');
  var spinner    = document.getElementById('cSpinner');
  var metaEl     = document.getElementById('cMeta');
  var tbody      = document.getElementById('cTbody');
  var pagination = document.getElementById('cPagination');
  var modal      = document.getElementById('certModal');
  var cmTitle    = document.getElementById('cmTitle');
  var cmOwner    = document.getElementById('cmOwner');
  var cmEyebrow  = document.getElementById('cmEyebrow');
  var cmBody     = document.getElementById('cmBody');
  var cmLoading  = document.getElementById('cmLoading');

  // ── HTML escaping ─────────────────────────────────────────────────────────
  function esc(s) {
    return String(s || '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Status classification ─────────────────────────────────────────────────
  function statusClass(s) {
    var lc = (s || '').toLowerCase().trim();
    if (!lc || lc === '-' || lc === 'n/a' || lc === '') { return 'na'; }
    if (lc.indexOf('ev included') !== -1) { return 'ev'; }
    // "not trusted", "not yet trusted" → orange (check before plain "trusted")
    if (lc.indexOf('not') !== -1) { return 'pending'; }
    if (lc.indexOf('included') !== -1 || lc.indexOf('trusted') !== -1) { return 'included'; }
    if (lc.indexOf('pending') !== -1 || lc.indexOf('transitional') !== -1) { return 'pending'; }
    // removed / revoked / untrusted / rejected / expired
    if (lc.indexOf('remov') !== -1 || lc.indexOf('revok') !== -1 ||
        lc.indexOf('untrust') !== -1 || lc.indexOf('reject') !== -1 ||
        lc.indexOf('expir') !== -1 || lc.indexOf('disabl') !== -1) { return 'removed'; }
    return 'na';
  }

  // ── Browser logo filenames (maps internal key → PNG base name) ───────────
  var BR_IMG = {
    apple:     'safari',
    chrome:    'chrome',
    microsoft: 'edge',
    mozilla:   'firefox'
  };

  // ── Browser trust badges ──────────────────────────────────────────────────
  function browserDots(cert) {
    var pairs = [
      ['apple',     'Apple',     cert.statusApple],
      ['chrome',    'Chrome',    cert.statusChrome],
      ['microsoft', 'Microsoft', cert.statusMs],
      ['mozilla',   'Mozilla',   cert.statusMoz]
    ];
    var html = '<div class="br-badges">';
    pairs.forEach(function(p) {
      var sc      = statusClass(p[2]);
      var trusted = sc === 'included' || sc === 'ev';
      var name    = BR_IMG[p[0]];
      var src     = 'img/logos/32/' + name + (trusted ? '_32.png' : '_grey_32.png');
      var tip     = esc(p[1]) + ': ' + esc(p[2] || 'N/A');
      html += '<span class="br-badge" title="' + tip + '">'
            +   '<img src="' + src + '" alt="' + esc(p[1]) + '" width="26" height="26"' + (trusted ? '' : ' class="br-grey"') + '>'
            + '</span>';
    });
    return html + '</div>';
  }

  // ── Type badge ────────────────────────────────────────────────────────────
  function typeBadge(cert) {
    var type = cert.type || '';
    var t = type.toLowerCase();
    if (t.indexOf('root') !== -1) { return '<span class="cert-type-badge badge-root">Root</span>'; }
    if (t.indexOf('cross') !== -1) { return '<span class="cert-type-badge badge-cross">Cross</span>'; }
    if (t.indexOf('inter') !== -1) {
      var label = (cert._children && cert._children.length === 0) ? 'Issuing' : 'Intermediate';
      return '<span class="cert-type-badge badge-inter">' + label + '</span>';
    }
    return '<span class="cert-type-badge badge-inter">' + esc(type) + '</span>';
  }

  // ── Trust/capability tags ─────────────────────────────────────────────────
  function capTags(cert) {
    var src = cert.trustBits || cert.derivedBits || '';
    var tags = '';
    if (cert.tlsCap) { tags += '<span class="trust-tag tls">TLS</span>'; }
    if (cert.evCap)  { tags += '<span class="trust-tag tls">EV</span>'; }
    if (cert.smimeCap){ tags += '<span class="trust-tag email">S/MIME</span>'; }
    if (cert.csCap)  { tags += '<span class="trust-tag cs">Code Signing</span>'; }
    if (!tags && src) {
      src.split(/[;,]+/).forEach(function(item) {
        item = item.trim();
        if (item) { tags += '<span class="trust-tag">' + esc(item) + '</span>'; }
      });
    }
    return tags ? '<div class="trust-tags">' + tags + '</div>' : '<span style="color:var(--muted);font-size:.7rem">—</span>';
  }

  // ── Validity ──────────────────────────────────────────────────────────────
  function validUntil(to) {
    if (!to) { return '<span style="color:var(--muted)">—</span>'; }
    var exp = (new Date(to)) < new Date();
    return '<span class="vto' + (exp ? ' expired' : '') + '">' + esc(to) + '</span>';
  }

  // ── Filter predicate ─────────────────────────────────────────────────────
  function certMatchesFilter(cert) {
    if (activeFilter === 'all')        { return true; }
    if (activeFilter === 'root')       { return (cert.type || '').toLowerCase().indexOf('root') !== -1; }
    if (activeFilter === 'intermediate') { return (cert.type || '').toLowerCase().indexOf('inter') !== -1; }
    if (activeFilter === 'tls')        { return cert.tlsCap; }
    if (activeFilter === 'smime')      { return cert.smimeCap; }
    if (activeFilter === 'cs')         { return cert.csCap; }
    if (activeFilter === 'valid')      { return !isRevoked(cert) && !isExpired(cert); }
    if (activeFilter === 'expired')    { return isExpired(cert); }
    if (activeFilter === 'revoked')    { return isRevoked(cert); }
    if (activeFilter === 'trusted')    { return isTrustedInAny(cert); }
    if (activeFilter === 'untrusted')  { return !isTrustedInAny(cert); }
    return true;
  }

  // ── Cert status helpers ───────────────────────────────────────────────────
  function isRevoked(cert) {
    var lc = (cert.revocation || '').toLowerCase();
    return lc.indexOf('revok') !== -1 && lc.indexOf('not revok') === -1;
  }
  function isExpired(cert) {
    return cert.validTo && (new Date(cert.validTo)) < new Date();
  }
  function isTrustedInAny(cert) {
    return [cert.statusApple, cert.statusChrome, cert.statusMs, cert.statusMoz].some(function(s) {
      var sc = statusClass(s);
      return sc === 'included' || sc === 'ev';
    });
  }

  // ── Build cert tree for one CA owner group ────────────────────────────────
  function buildCertTree(certs) {
    var sfMap = {}, sha256Map = {}, skiMap = {};
    certs.forEach(function(c) {
      c._parent   = null;
      c._children = [];
      c._orphan   = false;
      c._mismatch = false;
      c._baseVis  = true;
      if (c.sfId)   { sfMap[c.sfId]       = c; }
      if (c.sha256) { sha256Map[c.sha256] = c; }
      if (c.ski)    { skiMap[c.ski]       = c; }
    });

    certs.forEach(function(c) {
      var isRoot = (c.type || '').toLowerCase().indexOf('root') !== -1;
      if (isRoot) { return; }

      var p1 = c.parentSfId    ? (sfMap[c.parentSfId]       || null) : null;
      var p2 = c.parentSha256  ? (sha256Map[c.parentSha256] || null) : null;
      var p3 = c.aki           ? (skiMap[c.aki]             || null) : null;
      var parent = p1 || p2 || p3;

      if (!parent) {
        c._orphan = true;
        return;
      }
      if (p1 && p2 && p1 !== p2) { c._mismatch = true; }
      c._parent = parent;
      parent._children.push(c);
    });

    var roots   = certs.filter(function(c) { return !c._parent && !c._orphan; });
    var orphans = certs.filter(function(c) { return c._orphan; });
    return { roots: roots, orphans: orphans };
  }

  // ── Flatten tree DFS ──────────────────────────────────────────────────────
  function flattenTree(roots, orphans) {
    var flat = [];
    function walk(node, depth, parentSha) {
      flat.push({ cert: node, depth: depth, parentSha: parentSha || '' });
      node._children.forEach(function(child) { walk(child, depth + 1, node.sha256); });
    }
    roots.forEach(function(r) { walk(r, 0, ''); });
    orphans.forEach(function(o) { flat.push({ cert: o, depth: 0, parentSha: '', isOrphan: true }); });
    return flat;
  }

  // ── Apply filter: mark baseVis on each flat item ──────────────────────────
  function applyFilterToFlat(flat) {
    if (activeFilter === 'all') {
      flat.forEach(function(item) { item.baseVis = true; });
      return;
    }
    flat.forEach(function(item) { item.baseVis = certMatchesFilter(item.cert); });
    // Propagate up: if a descendant matches, ancestors are also visible
    flat.forEach(function(item) {
      if (!item.baseVis) { return; }
      var p = item.cert._parent;
      while (p) {
        p._propVis = true;
        p = p._parent;
      }
    });
    flat.forEach(function(item) {
      if (item.cert._propVis) { item.baseVis = true; }
      item.cert._propVis = false; // reset for next call
    });
  }

  // ── Render one tree item as a table row HTML string ───────────────────────
  function renderTreeRow(item, oi, ci, ownerVis) {
    var cert      = item.cert;
    var depth     = item.depth;
    var parentSha = item.parentSha || '';

    var revoked  = isRevoked(cert);
    var expired  = isExpired(cert);
    var hasKids  = cert._children && cert._children.length > 0;
    var isOrphan = cert._orphan || item.isOrphan;

    var rowClass = 'cert-row'
      + (item.baseVis && ownerVis ? ' visible' : '')
      + (revoked ? ' is-revoked' : '')
      + (expired && !revoked ? ' is-expired' : '');

    var indent = depth * 18; // px
    var connector = depth > 0 ? '<span class="tree-connector" aria-hidden="true">└</span>' : '';
    var toggleBtn = hasKids
      ? '<button class="tree-toggle open" data-sha="' + esc(cert.sha256) + '" data-oi="' + oi + '" aria-label="Collapse" type="button">›</button>'
      : '<button class="tree-toggle leaf" aria-hidden="true" tabindex="-1" type="button">›</button>';

    var statusBadges = '';
    if (revoked) { statusBadges += '<span class="badge-revoked">Revoked</span>'; }
    if (expired && !revoked) { statusBadges += '<span class="badge-expired">Expired</span>'; }
    if ((cert.constrained || '').toLowerCase() === 'true') { statusBadges += '<span class="badge-constrained">Constrained</span>'; }
    if (isOrphan) { statusBadges += '<span class="badge-orphan">⚠ Orphan</span>'; }
    if (cert._mismatch) { statusBadges += '<span class="badge-mismatch">⚠ Mismatch</span>'; }
    if (statusBadges) { statusBadges = '<div class="cert-status-badges">' + statusBadges + '</div>'; }

    return '<tr class="' + rowClass + '"'
      + ' data-oi="' + oi + '" data-ci="' + ci + '"'
      + ' data-sha="' + esc(cert.sha256) + '"'
      + ' data-parent-sha="' + esc(parentSha) + '"'
      + ' data-depth="' + depth + '"'
      + ' data-base-vis="' + (item.baseVis ? '1' : '0') + '">'
      + '<td class="cert-name" style="padding-left:' + (indent + 28) + 'px">'
      +   '<div class="cert-name-wrap">'
      +     connector + toggleBtn
      +     '<span>' + esc(cert.name) + '</span>'
      +     statusBadges
      +   '</div>'
      + '</td>'
      + '<td>' + typeBadge(cert) + '</td>'
      + '<td style="white-space:nowrap">' + browserDots(cert) + '</td>'
      + '<td>' + capTags(cert) + '</td>'
      + '<td class="cert-valid">' + validUntil(cert.validTo) + '</td>'
      + '<td class="cert-chevron" aria-hidden="true">›</td>'
      + '</tr>';
  }

  // ── Tree visibility update after collapse/expand ──────────────────────────
  function updateTreeVisibility(oi) {
    tbody.querySelectorAll('tr.cert-row[data-oi="' + oi + '"]').forEach(function(row) {
      var baseVis = row.dataset.baseVis === '1';
      if (!baseVis) { row.classList.remove('visible'); return; }
      // Walk ancestor chain checking collapsedNodes
      var sha = row.dataset.parentSha;
      var blocked = false;
      while (sha && !blocked) {
        if (collapsedNodes.has(sha)) { blocked = true; break; }
        var parentRow = tbody.querySelector('tr.cert-row[data-sha="' + sha + '"][data-oi="' + oi + '"]');
        sha = parentRow ? parentRow.dataset.parentSha : null;
      }
      row.classList.toggle('visible', !blocked);
    });
  }

  // ── Render table ──────────────────────────────────────────────────────────
  function renderTable(data, expandAll) {
    allOwners   = data.owners   || [];
    totalOwners = data.totalOwners || 0;
    curPage     = data.page     || 1;
    totalPages  = data.pages    || 1;

    if (!allOwners.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="tbl-empty">'
        + (searchQ ? 'No results for &ldquo;' + esc(searchQ) + '&rdquo;.' : 'No data — run the sync cron to populate.')
        + '</td></tr>';
      metaEl.textContent = '';
      pagination.innerHTML = '';
      return;
    }

    var html = '';
    var totalCerts = 0;
    collapsedNodes.clear();  // reset on new data
    allOwners.forEach(function(owner, oi) {
      var ownerVisible = false;
      var tree = buildCertTree(owner.certs);
      var flat = flattenTree(tree.roots, tree.orphans);
      applyFilterToFlat(flat);
      var matchCount = flat.filter(function(item) { return item.baseVis; }).length;
      totalCerts += matchCount;

      html += '<tr class="owner-row' + (ownerVisible ? ' expanded' : '') + '" data-oi="' + oi + '">'
        + '<td colspan="6">'
        + '<span class="owner-toggle" aria-hidden="true">›</span>'
        + '<span class="owner-name">' + esc(owner.name) + '</span>'
        + (owner.country ? '<span class="owner-meta">' + esc(owner.country) + '</span>' : '')
        + '<span class="owner-count">' + matchCount + ' cert' + (matchCount !== 1 ? 's' : '') + '</span>'
        + '</td></tr>';

      flat.forEach(function(item, ci) {
        html += renderTreeRow(item, oi, ci, ownerVisible);
      });
    });

    tbody.innerHTML = html || '<tr><td colspan="6" class="tbl-empty">No certs match the current filter.</td></tr>';

    var ownerWord = totalOwners === 1 ? 'CA' : 'CAs';
    metaEl.textContent = totalOwners.toLocaleString() + ' ' + ownerWord
      + (searchQ ? ' matching' : '')
      + (totalPages > 1 ? ' · page ' + curPage + ' of ' + totalPages : '');

    renderPagination();
  }

  // ── Pagination ────────────────────────────────────────────────────────────
  function renderPagination() {
    if (totalPages <= 1) { pagination.innerHTML = ''; return; }
    var html = '';
    var prev = curPage > 1, next = curPage < totalPages;
    html += prev ? '<a href="#" data-p="1" aria-label="First">&laquo;</a>' : '<span aria-disabled="true">&laquo;</span>';
    html += prev ? '<a href="#" data-p="' + (curPage-1) + '" aria-label="Previous">&lsaquo;</a>' : '<span aria-disabled="true">&lsaquo;</span>';
    var s = Math.max(1, curPage-2), e = Math.min(totalPages, curPage+2);
    if (s > 1) { html += '<span class="dots">&hellip;</span>'; }
    for (var i = s; i <= e; i++) {
      if (i === curPage) { html += '<span class="cur" aria-current="page">' + i + '</span>'; }
      else { html += '<a href="#" data-p="' + i + '">' + i + '</a>'; }
    }
    if (e < totalPages) { html += '<span class="dots">&hellip;</span>'; }
    html += next ? '<a href="#" data-p="' + (curPage+1) + '" aria-label="Next">&rsaquo;</a>' : '<span aria-disabled="true">&rsaquo;</span>';
    html += next ? '<a href="#" data-p="' + totalPages + '" aria-label="Last">&raquo;</a>' : '<span aria-disabled="true">&raquo;</span>';
    pagination.innerHTML = html;
  }

  // ── Fetch grouped data ────────────────────────────────────────────────────
  function fetchPage(q, page, expandAll) {
    searchQ = q;
    spinner.classList.add('active');
    var url = '/ccadb.php?json=1&q=' + encodeURIComponent(q) + '&p=' + page;
    fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
      .then(function(r) { return r.json(); })
      .then(function(data) { renderTable(data, expandAll); })
      .catch(function() {
        tbody.innerHTML = '<tr><td colspan="6" class="tbl-empty">Request failed — please try again.</td></tr>';
      })
      .finally(function() { spinner.classList.remove('active'); });
  }

  // ── Search input ──────────────────────────────────────────────────────────
  searchEl.addEventListener('input', function() {
    var q = this.value;
    clearBtn.style.display = q ? '' : 'none';
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function() { fetchPage(q, 1, false); }, 320);
  });
  clearBtn.addEventListener('click', function() {
    searchEl.value = '';
    clearBtn.style.display = 'none';
    fetchPage('', 1, false);
    searchEl.focus();
  });

  // ── Pagination clicks ─────────────────────────────────────────────────────
  pagination.addEventListener('click', function(e) {
    var a = e.target.closest('a[data-p]');
    if (!a) { return; }
    e.preventDefault();
    fetchPage(searchQ, parseInt(a.dataset.p, 10), false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  // ── Filter chips ──────────────────────────────────────────────────────────
  document.querySelectorAll('.chip').forEach(function(btn) {
    // Restore saved filter highlight on page load
    if (btn.dataset.filter === activeFilter) {
      document.querySelectorAll('.chip').forEach(function(c) { c.classList.remove('active'); });
      btn.classList.add('active');
    }
    btn.addEventListener('click', function() {
      document.querySelectorAll('.chip').forEach(function(c) { c.classList.remove('active'); });
      this.classList.add('active');
      activeFilter = this.dataset.filter;
      sessionStorage.setItem('ccadb_filter', activeFilter);
      renderTable({ owners: allOwners, totalOwners: totalOwners, page: curPage, pages: totalPages }, false);
    });
  });

  // ── Owner row expand/collapse ─────────────────────────────────────────────
  tbody.addEventListener('click', function(e) {
    var ownerRow = e.target.closest('tr.owner-row');
    if (ownerRow) {
      var oi = ownerRow.dataset.oi;
      var expanded = ownerRow.classList.toggle('expanded');
      if (!expanded) {
        tbody.querySelectorAll('tr.cert-row[data-oi="' + oi + '"]').forEach(function(r) {
          r.classList.remove('visible');
        });
      } else {
        updateTreeVisibility(oi);
      }
      return;
    }

    // Tree node toggle
    var toggleBtn = e.target.closest('.tree-toggle');
    if (toggleBtn && !toggleBtn.classList.contains('leaf')) {
      e.stopPropagation();
      var sha = toggleBtn.getAttribute('data-sha');
      if (collapsedNodes.has(sha)) {
        collapsedNodes.delete(sha);
        toggleBtn.classList.add('open');
        toggleBtn.setAttribute('aria-label', 'Collapse');
      } else {
        collapsedNodes.add(sha);
        toggleBtn.classList.remove('open');
        toggleBtn.setAttribute('aria-label', 'Expand');
      }
      updateTreeVisibility(toggleBtn.closest('tr').dataset.oi);
      return;
    }

    var certRow = e.target.closest('tr.cert-row');
    if (certRow) {
      var sha2 = certRow.dataset.sha;
      var oi2 = parseInt(certRow.dataset.oi, 10);
      if (isNaN(oi2) || !sha2 || !allOwners[oi2]) { return; }
      var owner = allOwners[oi2];
      var cert  = owner.certs.find(function(c) { return c.sha256 === sha2; });
      if (cert) { openModal(cert, owner); }
    }
  });
  tbody.addEventListener('keydown', function(e) {
    if (e.key !== 'Enter' && e.key !== ' ') { return; }
    var certRow = e.target.closest('tr.cert-row');
    if (!certRow) { return; }
    e.preventDefault();
    var sha = certRow.dataset.sha;
    var oi  = parseInt(certRow.dataset.oi, 10);
    if (isNaN(oi) || !sha || !allOwners[oi]) { return; }
    var owner = allOwners[oi];
    var cert  = owner.certs.find(function(c) { return c.sha256 === sha; });
    if (cert) { openModal(cert, owner); }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // Modal
  // ══════════════════════════════════════════════════════════════════════════

  function openModal(cert, owner) {
    var ownerName  = (owner && typeof owner === 'object') ? owner.name  : (owner || '');
    var ownerCerts = (owner && typeof owner === 'object') ? owner.certs : [];
    activeCert = cert;
    cmEyebrow.textContent = cert.type || 'Certificate';
    cmTitle.textContent   = cert.name || ownerName;
    cmOwner.textContent   = 'CA Owner: ' + ownerName;
    cmBody.innerHTML      = '<div class="cm-loading">Loading…</div>';
    modal.showModal();

    var cmBox = modal.querySelector('.cm-box');
    var banner = document.getElementById('cmStatusBanner');
    cmBox.classList.remove('is-revoked', 'is-expired');
    banner.className = 'cm-status-banner';
    banner.textContent = '';
    if (isRevoked(cert)) {
      cmBox.classList.add('is-revoked');
      banner.classList.add('show-revoked');
      banner.textContent = '⚠ This certificate has been revoked';
    } else if (isExpired(cert)) {
      cmBox.classList.add('is-expired');
      banner.classList.add('show-expired');
      banner.textContent = '⚠ This certificate has expired';
    }

    fetch('/ccadb.php?detail=' + encodeURIComponent(cert.sha256))
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.found) {
          cmBody.innerHTML = buildModalBody(cert, data.fields, data.pemInfo, data.policyOids || [], ownerCerts);
          wirePemButtons(data.pemInfo, cert);
          wireVerifyButtons(cmBody);
          wireCpsVerifyButton(cmBody);
          autoChainLint(cert, data.pemInfo);
        } else {
          cmBody.innerHTML = '<div class="cm-loading">Certificate data not found.</div>';
        }
      })
      .catch(function() {
        cmBody.innerHTML = '<div class="cm-loading">Failed to load certificate details.</div>';
      });
  }

  function closeModal() { modal.close(); activeCert = null; }
  document.getElementById('cmClose').addEventListener('click', closeModal);
  modal.addEventListener('click', function(e) { if (e.target === this) { closeModal(); } });
  modal.addEventListener('cancel', function(e) { e.preventDefault(); closeModal(); });

  // ── Modal body builder ────────────────────────────────────────────────────

  function f(fields, key) {
    var val = fields[key] || '';
    return val;
  }

  function dlRow(label, value, isLink) {
    var v;
    if (!value || value === '-') {
      v = '<span class="cm-dd-muted">—</span>';
    } else if (isLink && /^https?:\/\//.test(value)) {
      var disp = value.length > 70 ? value.substring(0, 67) + '…' : value;
      v = '<a href="' + esc(value) + '" target="_blank" rel="noopener noreferrer">' + esc(disp) + '</a>';
    } else {
      v = esc(value);
    }
    return '<dt class="cm-dt">' + esc(label) + '</dt><dd class="cm-dd">' + v + '</dd>';
  }

  function multiLinkRow(label, value) {
    var dt = '<dt class="cm-dt">' + esc(label) + '</dt>';
    if (!value || value === '-') {
      return dt + '<dd class="cm-dd"><span class="cm-dd-muted">—</span></dd>';
    }
    var rows = '';
    value.split(/[;\n]+/).forEach(function(u) {
      u = u.trim();
      if (!u) { return; }
      if (/^https?:\/\//.test(u)) {
        rows += urlInput(u, label);
      } else {
        rows += '<div class="cm-crl-row"><span class="cm-dd">' + esc(u) + '</span></div>';
      }
    });
    return dt + '<dd class="cm-dd"><div class="cm-crl-list">' + rows + '</div></dd>';
  }

  // ── Bool badge ────────────────────────────────────────────────────────────
  function boolBadge(value) {
    var lc = (value || '').toLowerCase().trim();
    if (lc === 'true' || lc === 'yes' || lc === '1') {
      return '<span class="cm-bool-true">&#10003; True</span>';
    }
    if (lc === 'false' || lc === 'no' || lc === '0') {
      return '<span class="cm-bool-false">False</span>';
    }
    return '<span class="cm-dd-muted">—</span>';
  }

  // ── Revocation badge ──────────────────────────────────────────────────────
  function revokBadge(value) {
    if (!value || value === '-') { return '<span class="cm-dd-muted">—</span>'; }
    var lc = value.toLowerCase();
    if (lc.indexOf('not revok') !== -1) { return '<span class="cm-revok-ok">&#10003; ' + esc(value) + '</span>'; }
    if (lc.indexOf('revok') !== -1 || lc.indexOf('remov') !== -1) { return '<span class="cm-revok-bad">&#10007; ' + esc(value) + '</span>'; }
    return '<span class="cm-revok-na">' + esc(value) + '</span>';
  }

  // ── Tag list row (semicolon-separated) ───────────────────────────────────
  function tagListRow(label, value) {
    var dt = '<dt class="cm-dt">' + esc(label) + '</dt>';
    if (!value || value === '-') {
      return dt + '<dd class="cm-dd"><span class="cm-dd-muted">—</span></dd>';
    }
    var tags = value.split(/[;,]+/).map(function(t) {
      t = t.trim();
      return t ? '<span class="cm-tag">' + esc(t) + '</span>' : '';
    }).filter(Boolean).join('');
    return dt + '<dd class="cm-dd"><div class="cm-tag-list">' + tags + '</div></dd>';
  }

  // ── Status-of-Root row ────────────────────────────────────────────────────
  function sorRow(label, value) {
    var dt = '<dt class="cm-dt">' + esc(label) + '</dt>';
    if (!value || value === '-') {
      return dt + '<dd class="cm-dd"><span class="cm-dd-muted">—</span></dd>';
    }
    var cards = '';
    value.split(/;/).forEach(function(seg) {
      seg = seg.trim();
      if (!seg) { return; }
      var colon = seg.indexOf(':');
      var br  = colon !== -1 ? seg.substring(0, colon).trim() : seg;
      var st  = colon !== -1 ? seg.substring(colon + 1).trim() : '';
      var sc  = statusClass(st);
      cards += '<div class="cm-sor-card tc-' + sc + '">'
             +   '<div class="cm-sor-br">' + esc(br) + '</div>'
             +   '<div class="cm-sor-st s-' + sc + '">' + esc(st || '—') + '</div>'
             + '</div>';
    });
    return dt + '<dd class="cm-dd"><div class="cm-sor">' + cards + '</div></dd>';
  }

  // ── CRL / JSON-URL-array row ──────────────────────────────────────────────
  var _crlVerifyId = 0;
  function crlRow(label, jsonValue) {
    var dt = '<dt class="cm-dt">' + esc(label) + '</dt>';
    if (!jsonValue || jsonValue === '-') {
      return dt + '<dd class="cm-dd"><span class="cm-dd-muted">—</span></dd>';
    }
    var urls = [];
    try { urls = JSON.parse(jsonValue); } catch(e) {
      // fallback: treat as a single URL or newline/semicolon list
      urls = jsonValue.split(/[\n;]+/).map(function(u){ return u.trim(); }).filter(Boolean);
    }
    if (!Array.isArray(urls) || !urls.length) {
      return dt + '<dd class="cm-dd"><span class="cm-dd-muted">—</span></dd>';
    }
    var rows = '';
    urls.forEach(function(url) {
      rows += urlInput(url, label + ' URL');
    });
    return dt + '<dd class="cm-dd"><div class="cm-crl-list">' + rows + '</div></dd>';
  }

  // ── URL field row (non-truncated, scrollable) ─────────────────────────────
  function urlFieldRow(label, value) {
    var dt = '<dt class="cm-dt">' + esc(label) + '</dt>';
    if (!value || value === '-' || !/^https?:\/\//.test(value)) {
      return dt + '<dd class="cm-dd">'
           + (!value || value === '-' ? '<span class="cm-dd-muted">—</span>' : esc(value)) + '</dd>';
    }
    return dt + '<dd class="cm-dd"><div class="cm-crl-list">' + urlInput(value, label) + '</div></dd>';
  }

  // ── Shared: single URL input row with open + verify buttons ──────────────
  function urlInput(url, ariaLabel) {
    var id = 'url-verify-' + (++_crlVerifyId);
    return '<div class="cm-crl-row">'
         +   '<input class="cm-crl-input" type="text" readonly value="' + esc(url) + '"'
         +     ' aria-label="' + esc(ariaLabel || 'URL') + '"'
         +     ' data-href="' + esc(url) + '" tabindex="0">'
         +   '<button class="cm-crl-open" data-href="' + esc(url) + '" title="Open in new tab" aria-label="Open ' + esc(url) + '">'
         +     '&#8599;'
         +   '</button>'
         +   '<button class="cm-crl-verify" data-url="' + esc(url) + '" id="' + id + '">Verify</button>'
         + '</div>';
  }

  function trustCard(browser, status, evStatus) {
    var sc      = statusClass(status);
    var cls     = 'cm-tc tc-' + sc;
    var sCls    = 's-' + sc;
    var ev      = evStatus ? '<div class="cm-tc-ev-lbl">EV: ' + esc(evStatus) + '</div>' : '';
    var key     = browser.toLowerCase();
    var trusted = sc === 'included' || sc === 'ev';
    var name    = BR_IMG[key] || key;
    var imgSrc  = 'img/logos/32/' + name + (trusted ? '_32.png' : '_grey_32.png');
    return '<div class="' + cls + '">'
      + '<img src="' + imgSrc + '" alt="' + esc(browser) + '" width="26" height="26" style="display:block;margin:0 auto .4rem' + (trusted ? '' : ';opacity:.2') + '">'
      + '<div class="cm-tc-browser">' + esc(browser) + '</div>'
      + '<div class="cm-tc-status ' + sCls + '">' + esc(status || 'Not listed') + '</div>'
      + ev + '</div>';
  }

  function capRow(fields) {
    var caps = [
      ['TLS',          f(fields,'TLS Capable')          === 'True', 'on-tls'],
      ['TLS EV',       f(fields,'TLS EV Capable')       === 'True', 'on-tls'],
      ['Code Signing', f(fields,'Code Signing Capable') === 'True', 'on-cs'],
      ['S/MIME',       f(fields,'S/MIME Capable')       === 'True', 'on-smime'],
    ];
    var html = caps.map(function(c) {
      return '<span class="cm-cap ' + (c[1] ? c[2] : 'off') + '">' + c[0] + '</span>';
    }).join('');
    return '<div class="cm-caps">' + html + '</div>';
  }

  function auditBlock(label, url, type, date, start, end) {
    if (!url && !type && !date) { return ''; }
    var rows = urlFieldRow('Audit URL', url)
             + dlRow('Type',       type)
             + dlRow('Statement',  date)
             + dlRow('Period',     start && end ? start + ' – ' + end : (start || end || ''));
    return '<div class="cm-audit-block">'
      + '<div class="cm-audit-label">' + esc(label) + '</div>'
      + '<dl class="cm-dl">' + rows + '</dl>'
      + '</div>';
  }

  // ── Policy OID helpers ────────────────────────────────────────────────────

  var KNOWN_OIDS = {
    '2.5.29.32.0':    'anyPolicy',
    '2.23.140.1.1':   'CA/B EV TLS',
    '2.23.140.1.2.1': 'CA/B DV TLS',
    '2.23.140.1.2.2': 'CA/B OV TLS',
    '2.23.140.1.2.3': 'CA/B IV TLS',
    '2.23.140.1.3':   'CA/B EV CS',
    '2.23.140.1.4.1': 'CA/B DV CS',
    '2.23.140.1.4.2': 'CA/B OV CS',
    '2.23.140.2.1':   'CA/B S/MIME MV',
    '2.23.140.2.2':   'CA/B S/MIME OV',
    '2.23.140.2.3':   'CA/B S/MIME SV',
    '2.23.140.2.4':   'CA/B S/MIME IV',
  };

  function oidChip(oid) {
    var label = KNOWN_OIDS[oid] || '';
    return '<span class="oid-chip">'
      + (label ? '<span class="oid-chip-label">' + esc(label) + '</span>' : '')
      + '<span class="oid-chip-oid">' + esc(oid) + '</span>'
      + '</span>';
  }

  function parseOidList(str) {
    if (!str) { return []; }
    return str.split(/[;,\s]+/).map(function(s) { return s.trim(); }).filter(function(s) {
      return /^[\d.]+$/.test(s);
    });
  }

  function buildOidSection(cert, fields, certPolicyOids, ownerCerts) {
    var certOids    = Array.isArray(certPolicyOids) ? certPolicyOids : [];
    var ccadbEvOids = parseOidList(f(fields, 'EV OIDs for Root Cert'));

    // Collect all distinct CP/CPS document URLs present on this cert
    var docUrlDefs = [
      { label: 'CP',      key: 'Certificate Policy (CP) URL' },
      { label: 'CPS',     key: 'Certificate Practice Statement (CPS) URL' },
      { label: 'CP/CPS',  key: 'Certificate Practice & Policy Statement' },
      { label: 'CP/CPS',  key: 'MD/AsciiDoc CP/CPS URL' },
    ];
    var seenUrls = {};
    var certUrls = [];
    docUrlDefs.forEach(function(d) {
      var u = f(fields, d.key);
      if (u && /^https?:\/\//.test(u) && !seenUrls[u]) {
        seenUrls[u] = true;
        certUrls.push({ label: d.label, url: u });
      }
    });

    // Build the section HTML
    var html = '<div class="cm-sect">'
      + '<div class="cm-sect-title">Policy OIDs</div>';

    // ── Source A: Certificate (cryptographic fact) ────────────────────────────
    html += '<div class="oid-source">'
      + '<div class="oid-source-hd">'
      + '<span class="oid-source-label">Certificate</span>'
      + '<span class="oid-source-badge oid-src-cert">X.509 certificatePolicies · cryptographic fact</span>'
      + '</div>';
    if (certOids.length > 0) {
      html += '<div class="oid-chips">' + certOids.map(oidChip).join('') + '</div>';
    } else {
      html += '<div class="oid-empty">'
        + (cert.hasPem ? 'No certificatePolicies extension in certificate' : 'PEM not yet imported — run CCADB PEM sync')
        + '</div>';
    }
    if (certOids.length > 0 && certUrls.length > 0) {
      var btnLabel = certUrls.length > 1 ? 'Verify OIDs in CP/CPS' : 'Verify OIDs in ' + certUrls[0].label;
      html += '<button type="button" class="oid-cps-btn"'
        + ' data-sha256="' + esc(cert.sha256) + '"'
        + ' data-oids="' + esc(JSON.stringify(certOids)) + '"'
        + ' data-cert-urls="' + esc(JSON.stringify(certUrls)) + '"'
        + '>' + esc(btnLabel) + '</button>'
        + '<div id="cmCpsResults" class="oid-cps-results"></div>';
    }
    html += '</div>';

    // ── Source B: CCADB (administrative declaration) ──────────────────────────
    html += '<div class="oid-source">'
      + '<div class="oid-source-hd">'
      + '<span class="oid-source-label">CCADB</span>'
      + '<span class="oid-source-badge oid-src-ccadb">EV OIDs for Root Cert · administrative declaration</span>'
      + '</div>';
    if (ccadbEvOids.length > 0) {
      html += '<div class="oid-chips">' + ccadbEvOids.map(oidChip).join('') + '</div>';
    } else {
      html += '<div class="oid-empty">No OID data in CCADB record</div>';
    }
    html += '</div>';

    // ── Comparison ────────────────────────────────────────────────────────────
    var issues = [];

    if (!cert.hasPem) {
      issues.push({ lvl: 'info', msg: 'PEM not imported — certificate OID checks require a parsed certificate' });
    } else if (certOids.length === 0 && ccadbEvOids.length === 0) {
      issues.push({ lvl: 'info', msg: 'No policy OIDs present in either source' });
    } else {
      // Cert has OIDs but CCADB has none
      if (certOids.length > 0 && ccadbEvOids.length === 0) {
        issues.push({ lvl: 'warn', msg: 'Certificate declares policy OIDs not found in CCADB' });
      }
      // CCADB has OIDs but cert has none
      if (ccadbEvOids.length > 0 && certOids.length === 0) {
        issues.push({ lvl: 'error', msg: 'CCADB declares policy OIDs but certificate has none' });
      }
      // CCADB OIDs missing from cert
      if (ccadbEvOids.length > 0 && certOids.length > 0) {
        var missing = ccadbEvOids.filter(function(o) { return certOids.indexOf(o) === -1; });
        if (missing.length > 0) {
          issues.push({ lvl: 'error', msg: 'CCADB OID(s) not found in certificate: ' + missing.join(', ') });
        }
        var extra = certOids.filter(function(o) { return o !== '2.5.29.32.0' && ccadbEvOids.indexOf(o) === -1; });
        if (extra.length > 0) {
          issues.push({ lvl: 'warn', msg: 'Certificate OID(s) not declared in CCADB: ' + extra.join(', ') });
        }
      }
      // TLS EV capable but no EV OIDs
      var isTlsEv = f(fields, 'TLS EV Capable') === 'True';
      if (isTlsEv && ccadbEvOids.length === 0) {
        issues.push({ lvl: 'warn', msg: 'Marked TLS EV Capable in CCADB but no EV OIDs declared' });
      }
      if (isTlsEv && certOids.length === 0) {
        issues.push({ lvl: 'warn', msg: 'Marked TLS EV Capable in CCADB but certificate has no policy OIDs' });
      }
      // Duplicate OIDs in cert
      var seen = {};
      var hasDup = certOids.some(function(o) { if (seen[o]) { return true; } seen[o] = true; return false; });
      if (hasDup) {
        issues.push({ lvl: 'warn', msg: 'Certificate contains duplicate policy OIDs' });
      }
      // Hierarchy: child OID not in parent (parent lacks anyPolicy)
      if (cert.parentSha256 && ownerCerts && ownerCerts.length > 0) {
        var parentCert = null;
        for (var pi = 0; pi < ownerCerts.length; pi++) {
          if (ownerCerts[pi].sha256 === cert.parentSha256) { parentCert = ownerCerts[pi]; break; }
        }
        if (parentCert && Array.isArray(parentCert.policyOids) && parentCert.policyOids.length > 0) {
          var pOids       = parentCert.policyOids;
          var parentAny   = pOids.indexOf('2.5.29.32.0') !== -1;
          if (!parentAny && certOids.length > 0) {
            var notInParent = certOids.filter(function(o) { return o !== '2.5.29.32.0' && pOids.indexOf(o) === -1; });
            if (notInParent.length > 0) {
              issues.push({ lvl: 'error', msg: 'Child asserts OID(s) not permitted by parent (parent lacks anyPolicy): ' + notInParent.join(', ') });
            }
          }
        } else if (!parentCert) {
          issues.push({ lvl: 'info', msg: 'Parent certificate not in current view — hierarchy check skipped' });
        }
      }
      if (issues.length === 0) {
        issues.push({ lvl: 'ok', msg: 'No OID issues detected' });
      }
    }

    var icons = { ok: '✓', warn: '⚠', error: '✕', info: 'ℹ' };
    html += '<div class="oid-compare">'
      + '<div class="oid-compare-hd">Comparison</div>';
    issues.forEach(function(issue) {
      html += '<div class="oid-issue oid-' + issue.lvl + '">'
        + '<span class="oid-icon">' + (icons[issue.lvl] || '') + '</span>'
        + '<span class="oid-issue-text">' + esc(issue.msg) + '</span>'
        + '</div>';
    });
    html += '</div>';

    html += '</div>'; // cm-sect
    return html;
  }

  function buildChainLintSection(cert) {
    var html = '<div class="cm-sect">'
      + '<div class="cm-sect-title">Chain Validation</div>';
    if (!cert.hasPem) {
      html += '<div class="oid-empty">PEM not imported — run CCADB PEM sync</div>';
    } else if (!cert.parentSha256) {
      html += '<div class="oid-empty">No parent certificate in CCADB — chain lint requires issuer</div>';
    } else {
      html += '<div id="cmChainLintResults"><span class="cm-loading-inline">Running lint_pkix_signer_signee_cert_chain…</span></div>';
    }
    return html + '</div>';
  }

  function buildModalBody(cert, fields, pem, certPolicyOids, ownerCerts) {
    var html = '';

    // ① Browser trust
    var trustBitsHtml = '';
    var tbRoot    = f(fields,'Trust Bits for Root Cert');
    var tbDerived = f(fields,'Derived Trust Bits');
    if (tbRoot || tbDerived) {
      trustBitsHtml = '<dl class="cm-dl" style="margin-top:.65rem">'
        + (tbRoot    ? tagListRow('Trust Bits (root)',  tbRoot)    : '')
        + (tbDerived ? tagListRow('Derived Trust Bits', tbDerived) : '')
        + '</dl>';
    }
    html += '<div class="cm-sect">'
      + '<div class="cm-sect-title">Browser Trust</div>'
      + '<div class="cm-trust-grid">'
      + trustCard('Apple',     f(fields,'Apple Status'),     f(fields,'Apple EV Root Certificate Inclusion Status'))
      + trustCard('Chrome',    f(fields,'Chrome Status'),    '')
      + trustCard('Microsoft', f(fields,'Microsoft Status'), f(fields,'Microsoft EV Root Certificate Inclusion Status'))
      + trustCard('Mozilla',   f(fields,'Mozilla Status'),   f(fields,'Mozilla EV Root Certificate Inclusion Status'))
      + '</div>'
      + trustBitsHtml
      + '</div>';

    // ② Certificate details
    html += '<div class="cm-sect">'
      + '<div class="cm-sect-title">Certificate Details</div>'
      + '<dl class="cm-dl">'
      + dlRow('Record Type',      f(fields,'Certificate Record Type'))
      + dlRow('SHA-256',          f(fields,'SHA-256 Fingerprint'))
      + dlRow('Parent SHA-256',   f(fields,'Parent SHA-256 Fingerprint'))
      + dlRow('Valid From (GMT)', f(fields,'Valid From (GMT)'))
      + dlRow('Valid To (GMT)',   f(fields,'Valid To (GMT)'))
      + dlRow('AKI',              f(fields,'Authority Key Identifier'))
      + dlRow('SKI',              f(fields,'Subject Key Identifier'))
      + '<dt class="cm-dt">Constrained</dt><dd class="cm-dd">' + boolBadge(f(fields,'Technically Constrained')) + '</dd>'
      + '<dt class="cm-dt">Revocation</dt><dd class="cm-dd">' + revokBadge(f(fields,'Revocation Status')) + '</dd>'
      + dlRow('Salesforce ID',    f(fields,'Salesforce Record ID'))
      + '</dl></div>';

    // ③ Capabilities
    html += '<div class="cm-sect">'
      + '<div class="cm-sect-title">Capabilities</div>'
      + '<dl class="cm-dl">'
      + dlRow('EV OIDs',        f(fields,'EV OIDs for Root Cert'))
      + sorRow('Status of Root', f(fields,'Status of Root Cert'))
      + '</dl>'
      + '<div style="margin-top:.5rem">' + capRow(fields) + '</div>'
      + '</div>';

    // ④ Audit information
    var audits = [
      ['Standard',    'Standard Audit URL',       'Standard Audit Type',       'Standard Audit Statement Date',       'Standard Audit Period Start Date',       'Standard Audit Period End Date'],
      ['NetSec',      'NetSec Audit URL',          'NetSec Audit Type',         'NetSec Audit Statement Date',         'NetSec Audit Period Start Date',         'NetSec Audit Period End Date'],
      ['TLS BR',      'TLS BR Audit URL',          'TLS BR Audit Type',         'TLS BR Audit Statement Date',         'TLS BR Audit Period Start Date',         'TLS BR Audit Period End Date'],
      ['TLS EVG',     'TLS EVG Audit URL',         'TLS EVG Audit Type',        'TLS EVG Audit Statement Date',        'TLS EVG Audit Period Start Date',        'TLS EVG Audit Period End Date'],
      ['Code Signing','Code Signing Audit URL',    'Code Signing Audit Type',   'Code Signing Audit Statement Date',   'Code Signing Audit Period Start Date',   'Code Signing Audit Period End Date'],
      ['S/MIME BR',   'S/MIME BR Audit URL',       'S/MIME BR Audit Type',      'S/MIME BR Audit Statement Date',      'S/MIME BR Audit Period Start Date',      'S/MIME BR Audit Period End Date'],
      ['VMC',         'VMC Audit URL',             'VMC Audit Type',            'VMC Audit Statement Date',            'VMC Audit Period Start Date',            'VMC Audit Period End Date'],
    ];
    var auditHtml = '';
    audits.forEach(function(a) {
      auditHtml += auditBlock(a[0], f(fields,a[1]), f(fields,a[2]), f(fields,a[3]), f(fields,a[4]), f(fields,a[5]));
    });
    if (auditHtml) {
      html += '<div class="cm-sect">'
        + '<div class="cm-sect-title">Audit</div>'
        + '<dl class="cm-dl">'
        + dlRow('Audit Firm',          f(fields,'Audit Firm'))
        + dlRow('Firm Location',       f(fields,'Audit Firm Location'))
        + dlRow('Same as Parent',      f(fields,'Audits Same as Parent'))
        + '</dl>'
        + auditHtml
        + '</div>';
    }

    // ⑤ Policy & documentation
    html += '<div class="cm-sect">'
      + '<div class="cm-sect-title">Policy &amp; Documentation</div>'
      + '<dl class="cm-dl">'
      + multiLinkRow('Policy Docs',    f(fields,'Policy Documentation'))
      + multiLinkRow('Doc Repository', f(fields,'CA Document Repository'))
      + urlFieldRow('CP URL',         f(fields,'Certificate Policy (CP) URL'))
      + dlRow('CP Effective',         f(fields,'CP Effective Date'))
      + urlFieldRow('CPS URL',        f(fields,'Certificate Practice Statement (CPS) URL'))
      + dlRow('CPS Effective',        f(fields,'CPS Effective Date'))
      + urlFieldRow('CP/CPS Statement', f(fields,'Certificate Practice & Policy Statement'))
      + urlFieldRow('MD/AsciiDoc URL',  f(fields,'MD/AsciiDoc CP/CPS URL'))
      + '</dl></div>';

    // ⑥ Policy OIDs — cert-derived vs CCADB administrative declaration
    html += buildOidSection(cert, fields, certPolicyOids, ownerCerts);

    // ⑦ Chain validation — lint_pkix_signer_signee_cert_chain
    html += buildChainLintSection(cert);

    // ⑧ Infrastructure
    html += '<div class="cm-sect">'
      + '<div class="cm-sect-title">Infrastructure</div>'
      + '<dl class="cm-dl">'
      + dlRow('Country',       f(fields,'Country'))
      + dlRow('Sub CA Owner',  f(fields,'Subordinate CA Owner'))
      + crlRow('CRL (Full)',    f(fields,'JSON Array of All Full CRL URLs'))
      + crlRow('CRL (Parts)',   f(fields,'JSON Array of Partitioned CRLs'))
      + urlFieldRow('ACME DV',       f(fields,'DV ACME Directory URL(s)'))
      + urlFieldRow('ACME OV',       f(fields,'OV ACME Directory URL(s)'))
      + urlFieldRow('ACME EV',       f(fields,'EV ACME Directory URL(s)'))
      + urlFieldRow('Test (Valid)',   f(fields,'Test Website URL - Valid'))
      + urlFieldRow('Test (Expired)', f(fields,'Test Website URL - Expired'))
      + urlFieldRow('Test (Revoked)', f(fields,'Test Website URL - Revoked'))
      + '</dl></div>';

    // ⑦ PEM — always shown; buttons disabled when no PEM available
    var hasPemData = pem && pem.indexOf('CERTIFICATE') !== -1;
    var dis        = hasPemData ? '' : ' disabled';
    var pemContent = hasPemData
      ? '<textarea class="ap-embed-cert-pem" id="cmPemArea" readonly spellcheck="false" aria-label="Certificate PEM">'
          + esc(pem) + '</textarea>'
      : '<div class="ap-embed-cert-pem pem-empty" id="cmPemArea" role="status" aria-live="polite">'
          + 'PEM not yet imported — run the CCADB PEM sync'
          + '</div>';
    html += '<div class="cm-sect" id="cmPemSect">'
      + '<div class="cm-sect-title">Certificate (PEM)</div>'
      + pemContent
      + '<div class="ap-embed-cert-actions">'
      + '<button class="ap-embed-cert-btn ap-embed-cert-lint"  id="cmLint"' + dis + '>Run Linters</button>'
      + '<button class="ap-embed-cert-btn ap-embed-cert-parse" id="cmParse"' + dis + '>Parse Certificate</button>'
      + '<button class="ap-embed-cert-btn ap-embed-cert-copy"  id="cmCopy"' + dis + '>Copy PEM</button>'
      + '<button class="ap-embed-cert-btn ap-embed-cert-dl"    id="cmDl"'   + dis + '>Download .pem</button>'
      + '</div></div>';

    return html;
  }

  // ── Wire PEM buttons (after modal body is in DOM) ─────────────────────────
  function wirePemButtons(pem, cert) {
    var hasPemData = pem && pem.indexOf('CERTIFICATE') !== -1;
    var lint  = document.getElementById('cmLint');
    var parse = document.getElementById('cmParse');
    var copy  = document.getElementById('cmCopy');
    var dl    = document.getElementById('cmDl');
    // Buttons always rendered — only wire if PEM data is present
    if (!lint || !hasPemData) { return; }

    lint.addEventListener('click', function() {
      sessionStorage.setItem('pki_prefill_cert', pem);
      sessionStorage.removeItem('pki_prefill_issuer');

      var parentSha = (cert && cert.parentSha256) || '';
      var isRoot    = !parentSha || (cert.type || '').toLowerCase().indexOf('root') !== -1;

      if (isRoot) {
        // Self-signed root — no issuer to fetch
        window.open('/linters.php', '_blank');
        return;
      }

      // Show brief loading state while fetching parent PEM
      var origText = lint.textContent;
      lint.textContent = 'Loading…';
      lint.disabled = true;

      fetch('/ccadb.php?detail=' + encodeURIComponent(parentSha))
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (data.found && data.pemInfo && data.pemInfo.indexOf('CERTIFICATE') !== -1) {
            sessionStorage.setItem('pki_prefill_issuer', data.pemInfo);
          }
          // If parent PEM not in DB yet, issuer key stays absent — linters handles it gracefully
        })
        .catch(function() { /* network error — proceed without issuer */ })
        .finally(function() {
          lint.textContent = origText;
          lint.disabled = false;
          window.open('/linters.php', '_blank');
        });
    });
    parse.addEventListener('click', function() {
      sessionStorage.removeItem('mkt_eseal_cms');
      sessionStorage.removeItem('mkt_eseal_xades');
      sessionStorage.removeItem('meerkat_pem');
      sessionStorage.setItem('pki_prefill_cert', pem);
      window.open('/artifact_parser.php', '_blank');
    });
    copy.addEventListener('click', function() {
      navigator.clipboard.writeText(pem).then(function() {
        var orig = copy.textContent;
        copy.textContent = 'Copied!';
        setTimeout(function() { copy.textContent = orig; }, 1500);
      });
    });
    dl.addEventListener('click', function() {
      var blob = new Blob([pem], { type: 'application/x-pem-file' });
      var url  = URL.createObjectURL(blob);
      var a    = document.createElement('a');
      var name = (cert.sha256 || 'certificate').replace(/[^a-zA-Z0-9_-]/g,'').substring(0,40) || 'certificate';
      a.href = url; a.download = name + '.pem'; a.click();
      URL.revokeObjectURL(url);
    });
  }

  // ── Wire URL inputs/open buttons + Verify buttons ────────────────────────
  function wireVerifyButtons(container) {
    // Click on the input itself → open URL
    container.querySelectorAll('.cm-crl-input[data-href]').forEach(function(inp) {
      inp.addEventListener('click', function() {
        window.open(inp.getAttribute('data-href'), '_blank', 'noopener');
      });
      inp.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
          window.open(inp.getAttribute('data-href'), '_blank', 'noopener');
        }
      });
    });
    // Open icon button
    container.querySelectorAll('.cm-crl-open[data-href]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        window.open(btn.getAttribute('data-href'), '_blank', 'noopener');
      });
    });
    // Verify button
    container.querySelectorAll('.cm-crl-verify').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var url = btn.getAttribute('data-url');
        if (!url || btn.classList.contains('checking')) { return; }
        btn.classList.add('checking');
        btn.textContent = '…';
        function doVerify(token) {
          var body = 'verify_url=' + encodeURIComponent(url)
                   + '&g_recaptcha_token=' + encodeURIComponent(token || '');
          fetch('/ccadb.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body,
          })
            .then(function(r) { return r.json(); })
            .then(function(data) {
              btn.classList.remove('checking');
              if (data.ok) {
                btn.classList.add('ok');
                btn.textContent = '✓ ' + (data.status || 'OK');
              } else {
                btn.classList.add('broken');
                btn.textContent = '✗ ' + (data.status || 'Error');
              }
            })
            .catch(function() {
              btn.classList.remove('checking');
              btn.classList.add('broken');
              btn.textContent = '✗ Failed';
            });
        }
        if (typeof grecaptcha !== 'undefined' && RCAPTCHA_KEY && RCAPTCHA_KEY.indexOf('YOUR_') === -1) {
          grecaptcha.ready(function() {
            grecaptcha.execute(RCAPTCHA_KEY, { action: 'verify_url' })
              .then(function(token) { doVerify(token); })
              .catch(function() { doVerify(''); });
          });
        } else {
          doVerify('');
        }
      });
    });
  }

  // ── CPS OID verification ──────────────────────────────────────────────────

  function wireCpsVerifyButton(container) {
    var btn = container.querySelector('.oid-cps-btn');
    if (!btn) { return; }
    btn.addEventListener('click', function() {
      if (btn.disabled) { return; }
      btn.disabled = true;
      btn.textContent = 'Verifying…';
      var sha256   = btn.getAttribute('data-sha256');
      var oidsRaw  = btn.getAttribute('data-oids');
      var urlsRaw  = btn.getAttribute('data-cert-urls');
      var results  = document.getElementById('cmCpsResults');
      function doVerifyCps(token) {
        var body = 'verify_cps=1'
          + '&cert_sha256=' + encodeURIComponent(sha256)
          + '&cert_urls='   + encodeURIComponent(urlsRaw)
          + '&cert_oids='   + encodeURIComponent(oidsRaw)
          + '&g_recaptcha_token=' + encodeURIComponent(token || '');
        fetch('/ccadb.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: body,
        })
          .then(function(r) { return r.json(); })
          .then(function(data) {
            btn.disabled = false;
            btn.textContent = 'Re-verify OIDs in CPS';
            if (results) { renderCpsResults(results, data); }
          })
          .catch(function() {
            btn.disabled = false;
            btn.textContent = 'Verify OIDs in CPS';
            if (results) {
              results.innerHTML = '<div class="oid-cps-flag cps-err">Network error — could not reach server</div>';
              results.classList.add('visible');
            }
          });
      }
      if (typeof grecaptcha !== 'undefined' && RCAPTCHA_KEY && RCAPTCHA_KEY.indexOf('YOUR_') === -1) {
        grecaptcha.ready(function() {
          grecaptcha.execute(RCAPTCHA_KEY, { action: 'verify_cps' })
            .then(function(token) { doVerifyCps(token); })
            .catch(function() { doVerifyCps(''); });
        });
      } else {
        doVerifyCps('');
      }
    });
  }

  var CPS_STATUS_LABELS = {
    VERIFIED_IN_CPS:    { label: 'Verified',      cls: 'cps-s-verified'  },
    FOUND_ELSEWHERE:    { label: 'Found (other)',  cls: 'cps-s-elsewhere' },
    DIFFERENT_OIDS_FOUND: { label: 'Different',   cls: 'cps-s-different' },
    NOT_FOUND:          { label: 'Not found',      cls: 'cps-s-notfound'  },
    CPS_UNAVAILABLE:    { label: 'Unavailable',    cls: 'cps-s-unavail'   },
    CPS_PARSE_FAILED:   { label: 'Parse failed',   cls: 'cps-s-failed'    },
  };

  function renderCpsResults(container, data) {
    // Top-level error (e.g. reCAPTCHA failed, invalid params)
    if (data.error && !data.docs) {
      var lbl = CPS_STATUS_LABELS[data.status] || { label: data.status || 'Error', cls: 'cps-s-failed' };
      container.innerHTML = '<div class="oid-cps-flag cps-err">'
        + '<strong>' + esc(lbl.label) + '</strong>'
        + ' — ' + esc(data.error)
        + '</div>';
      container.classList.add('visible');
      return;
    }

    var html = '';
    var multiDoc = data.docs && data.docs.length > 1;

    // Overall flag
    if (data.ok) {
      html += '<div class="oid-cps-flag cps-ok">All OIDs verified in CP/CPS</div>';
    } else {
      html += '<div class="oid-cps-flag cps-warn">One or more OIDs could not be verified</div>';
    }

    // Summary table (best result per OID across all docs)
    if (data.summary && data.summary.length) {
      html += '<table class="oid-cps-table"><thead><tr>'
        + '<th>OID</th><th>Status</th>'
        + (multiDoc ? '<th>Document</th>' : '<th>Section</th>')
        + '<th>Notes / Snippet</th>'
        + '</tr></thead><tbody>';
      data.summary.forEach(function(r) {
        var si      = CPS_STATUS_LABELS[r.status] || { label: r.status, cls: 'cps-s-failed' };
        var docCell = multiDoc
          ? esc(r.docLabel || '—')
          : esc(r.section  || '—');
        var snippet = '';
        if (r.snippet) {
          var hi = r.snippet.replace(new RegExp('(' + escRe(r.oid) + ')', 'g'), '<mark>$1</mark>');
          snippet = '<div class="oid-cps-snippet">…' + hi + '…</div>';
        }
        html += '<tr>'
          + '<td>' + oidChip(r.oid) + '</td>'
          + '<td><span class="oid-cps-status ' + si.cls + '">' + esc(si.label) + '</span></td>'
          + '<td class="oid-cps-section">' + docCell + '</td>'
          + '<td>' + esc(r.notes || '') + snippet + '</td>'
          + '</tr>';
      });
      html += '</tbody></table>';
    }

    // Per-document metadata + all detected OIDs
    if (data.docs && data.docs.length) {
      data.docs.forEach(function(doc) {
        var meta = [];
        var docUrl = doc.cpsUrl || doc.url || '';
        if (docUrl) {
          var urlDisp = docUrl.length > 55 ? docUrl.substring(0, 52) + '…' : docUrl;
          meta.push('<span class="oid-cps-meta-item"><span class="oid-cps-meta-label">'
            + esc(doc.label || 'Doc') + '</span>'
            + '<a href="' + esc(docUrl) + '" target="_blank" rel="noopener noreferrer">' + esc(urlDisp) + '</a></span>');
        }
        if (doc.contentType) {
          meta.push('<span class="oid-cps-meta-item"><span class="oid-cps-meta-label">Type</span>' + esc(doc.contentType) + '</span>');
        }
        if (doc.downloadedAt) {
          var age = doc.fromCache
            ? ' (cached' + (doc.cacheAgeDays != null ? ', ' + doc.cacheAgeDays + 'd ago' : '') + ')'
            : ' (fresh)';
          meta.push('<span class="oid-cps-meta-item"><span class="oid-cps-meta-label">Downloaded</span>'
            + esc(doc.downloadedAt) + esc(age) + '</span>');
        }
        if (doc.error) {
          meta.push('<span class="oid-cps-meta-item"><span class="oid-cps-meta-label" style="color:var(--red)">Error</span>'
            + esc(doc.error) + '</span>');
        }
        if (meta.length) {
          html += '<div class="oid-cps-meta">' + meta.join('') + '</div>';
        }
        if (doc.allCpsOids && doc.allCpsOids.length) {
          html += '<div class="oid-cps-all-oids">'
            + '<div class="oid-cps-all-label">All OIDs detected in ' + esc(doc.label || 'document') + '</div>'
            + '<div class="oid-chips">' + doc.allCpsOids.map(oidChip).join('') + '</div>'
            + '</div>';
        }
      });
    }

    container.innerHTML = html;
    container.classList.add('visible');
  }

  function escRe(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // ── Chain lint ────────────────────────────────────────────────────────────

  function autoChainLint(cert, pem) {
    var results = document.getElementById('cmChainLintResults');
    if (!results) { return; }

    fetch('/ccadb.php?detail=' + encodeURIComponent(cert.parentSha256))
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d.found || !d.pemInfo || d.pemInfo.indexOf('CERTIFICATE') === -1) {
          results.innerHTML = '<div class="oid-cps-flag cps-err">Parent certificate PEM not available in database</div>';
          return;
        }
        runChainLint(pem, d.pemInfo, results);
      })
      .catch(function() {
        results.innerHTML = '<div class="oid-cps-flag cps-err">Failed to fetch parent certificate</div>';
      });
  }

  function runChainLint(certPem, parentPem, results) {
    function execute(token) {
      fetch('/ccadb.php', {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'chain_lint=1'
          + '&cert_pem='          + encodeURIComponent(certPem)
          + '&parent_pem='        + encodeURIComponent(parentPem)
          + '&g_recaptcha_token=' + encodeURIComponent(token || ''),
      })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          results.innerHTML = data.ok
            ? data.html
            : '<div class="oid-cps-flag cps-err">' + esc(data.error || 'Unknown error') + '</div>';
        })
        .catch(function() {
          results.innerHTML = '<div class="oid-cps-flag cps-err">Network error</div>';
        });
    }
    if (typeof grecaptcha !== 'undefined' && RCAPTCHA_KEY && RCAPTCHA_KEY.indexOf('YOUR_') === -1) {
      grecaptcha.ready(function() {
        grecaptcha.execute(RCAPTCHA_KEY, { action: 'chain_lint' })
          .then(function(token) { execute(token); })
          .catch(function() { execute(''); });
      });
    } else {
      execute('');
    }
  }

  // ── Initial render ────────────────────────────────────────────────────────
  searchQ = searchEl.value;
  if (initData) {
    renderTable(initData, false);
  } else {
    fetchPage(searchQ, 1, false);
  }

}());
</script>
</body>
</html>
