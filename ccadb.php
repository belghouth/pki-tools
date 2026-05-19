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
header("X-Frame-Options: SAMEORIGIN");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: "
    . "default-src 'self'; "
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    . "font-src https://fonts.gstatic.com; "
    . "script-src 'self' 'unsafe-inline'; "
    . "object-src 'none'; base-uri 'self'; form-action 'self';"
);

require_once __DIR__ . '/config.php';

const OWNERS_PER_PAGE = 25;

define('HDR_JSON', 'Content-Type: application/json; charset=utf-8');

// ── Input ─────────────────────────────────────────────────────────────────────

$search     = trim(substr($_GET['q']          ?? '', 0, 200));
$page       = max(1, (int)($_GET['p']         ?? 1));
$isJson     = isset($_GET['json'])   && $_GET['json']   === '1';
$detail     = trim($_GET['detail']   ?? '');
$verifyUrl  = trim($_GET['verify_url'] ?? '');

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

// ── ?verify_url= — HEAD-check a CRL / policy URL ─────────────────────────────

if ($verifyUrl !== '') {
    header(HDR_JSON);
    if (!preg_match('#^https?://#i', $verifyUrl)) {
        echo json_encode(['ok' => false, 'status' => 'Invalid URL']);
        exit;
    }
    $ch = curl_init($verifyUrl);
    curl_setopt_array($ch, [
        CURLOPT_NOBODY         => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERAGENT      => 'pki-tools/1.0 (URL verify)',
        CURLOPT_SSL_VERIFYPEER => false,
    ]);
    curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr  = curl_error($ch);
    curl_close($ch);
    if ($curlErr !== '') {
        $errLc = strtolower($curlErr);
        if (str_contains($errLc, 'ssl') || str_contains($errLc, 'tls') || str_contains($errLc, 'certificate')) {
            $friendly = 'SSL Error';
        } elseif (str_contains($errLc, 'timed out') || str_contains($errLc, 'timeout')) {
            $friendly = 'Timeout';
        } elseif (str_contains($errLc, 'could not resolve') || str_contains($errLc, 'name resolution')) {
            $friendly = 'DNS Error';
        } elseif (str_contains($errLc, 'connection refused')) {
            $friendly = 'Connection Refused';
        } else {
            $friendly = 'Network Error';
        }
        echo json_encode(['ok' => false, 'status' => $friendly]);
    } elseif ($httpCode >= 200 && $httpCode < 400) {
        echo json_encode(['ok' => true,  'status' => (string)$httpCode]);
    } else {
        echo json_encode(['ok' => false, 'status' => (string)($httpCode ?: 'No Response')]);
    }
    exit;
}

// ── ?detail=<sha256> — full cert data for modal ───────────────────────────────

if ($detail !== '' && $pdo) {
    header(HDR_JSON);
    try {
        $st = $pdo->prepare(
            "SELECT data_json, pem_info FROM ccadb_v5_certs WHERE sha256 = ? LIMIT 1"
        );
        $st->execute([$detail]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if ($row) {
            $fields = json_decode($row['data_json'], true) ?? [];
            echo json_encode([
                'found'   => true,
                'fields'  => $fields,
                'pemInfo' => $row['pem_info'],
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

function queryGrouped(PDO $pdo, string $search, int $page): array {
    $offset     = ($page - 1) * OWNERS_PER_PAGE;
    $hasSearch  = $search !== '';
    $ftsArg     = $hasSearch ? $search : null;

    // Phase 1: distinct CA owners matching the search, paginated
    if ($hasSearch) {
        $countSql = "SELECT COUNT(DISTINCT ca_owner) FROM ccadb_v5_certs
                     WHERE MATCH(search_text) AGAINST(? IN BOOLEAN MODE)";
        $ownerSql = "SELECT DISTINCT ca_owner FROM ccadb_v5_certs
                     WHERE MATCH(search_text) AGAINST(? IN BOOLEAN MODE)
                     ORDER BY ca_owner LIMIT " . OWNERS_PER_PAGE . " OFFSET $offset";
        $cSt = $pdo->prepare($countSql); $cSt->execute([$ftsArg]);
        $oSt = $pdo->prepare($ownerSql); $oSt->execute([$ftsArg]);
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
                valid_from, valid_to,
                status_apple, status_chrome, status_microsoft, status_mozilla,
                tls_capable, tls_ev_capable, code_sign_capable, smime_capable,
                country, subordinate_ca_owner,
                (pem_info IS NOT NULL AND pem_info != '') AS has_pem,
                data_json
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
        ];
    }

    return [
        'owners'      => array_values($grouped),
        'totalOwners' => $totalOwners,
        'page'        => $page,
        'pages'       => max(1, (int)ceil($totalOwners / OWNERS_PER_PAGE)),
    ];
}

?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
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
    .tbl-wrap{border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
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
    .br-badges{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    .br-badge{display:flex;flex-direction:column;align-items:center;gap:3px;flex-shrink:0}
    .br-badge svg{width:18px;height:18px;display:block;opacity:.75}
    .br-badge:hover svg{opacity:1}
    .br-dot{width:12px;height:12px;border-radius:50%;border:1px solid rgba(255,255,255,.12);flex-shrink:0}
    .br-dot.d-included{background:#00d4aa;border-color:rgba(0,212,170,.4);box-shadow:0 0 4px rgba(0,212,170,.35)}
    .br-dot.d-ev{background:#00b894;border-color:rgba(0,184,148,.4);box-shadow:0 0 4px rgba(0,184,148,.35)}
    .br-dot.d-pending{background:#f5a623;border-color:rgba(245,166,35,.4);box-shadow:0 0 4px rgba(245,166,35,.35)}
    .br-dot.d-removed{background:#e85555;border-color:rgba(232,85,85,.4);box-shadow:0 0 4px rgba(232,85,85,.35)}
    .br-dot.d-na{background:transparent;border-color:#2a3040}

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

    /* loading state */
    .cm-loading{text-align:center;padding:4rem 1rem;color:var(--muted);font-family:var(--mono);font-size:.82rem}

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
    .cm-crl-input{flex:1;font-family:var(--mono);font-size:.67rem;background:#0e1219;border:1px solid var(--border);border-radius:4px;color:var(--text);padding:.28rem .5rem;overflow-x:auto;white-space:nowrap;cursor:text;min-width:0}
    .cm-crl-verify{font-family:var(--mono);font-size:.62rem;padding:.2rem .55rem;border-radius:4px;border:1px solid rgba(0,212,170,.35);background:transparent;color:var(--green);cursor:pointer;white-space:nowrap;flex-shrink:0}
    .cm-crl-verify:hover{background:rgba(0,212,170,.08)}
    .cm-crl-verify.checking{color:var(--muted);border-color:var(--border);cursor:default}
    .cm-crl-verify.ok{color:var(--green);border-color:rgba(0,212,170,.5)}
    .cm-crl-verify.broken{color:var(--red);border-color:rgba(232,85,85,.4)}

    /* audit sub-block */
    .cm-audit-block{margin-bottom:.5rem;padding-bottom:.5rem;border-bottom:1px solid rgba(42,48,64,.6)}
    .cm-audit-block:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}
    .cm-audit-label{font-family:var(--mono);font-size:.62rem;font-weight:600;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;margin-bottom:.25rem}

    /* PEM + actions (same style as artifact_parser.php) */
    .ap-embed-cert-pem{
      display:block;width:100%;height:90px;resize:none;
      background:rgba(0,0,0,.3);color:#8a9ab8;
      border:1px solid var(--border);border-radius:4px;
      font-family:var(--mono);font-size:.6rem;line-height:1.45;
      padding:.4rem .6rem;outline:none;white-space:pre;overflow-y:auto;
      margin-bottom:.5rem
    }
    .ap-embed-cert-actions{display:flex;gap:.5rem;flex-wrap:wrap}
    .ap-embed-cert-btn{
      font-family:var(--mono);font-size:.65rem;text-transform:uppercase;
      letter-spacing:.07em;font-weight:600;cursor:pointer;
      border-radius:4px;padding:.3em .8em;background:none;
      transition:background .15s,border-color .15s
    }
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
          <th>SHA-256</th>
          <th><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody id="cTbody">
        <tr><td colspan="7" class="tbl-loading">Loading…</td></tr>
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
  var initData = <?= json_encode($initialData) ?>;

  // ── State ─────────────────────────────────────────────────────────────────
  var allOwners   = [];   // current page data
  var activeFilter= 'all';
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

  // ── Browser SVG logos ─────────────────────────────────────────────────────
  var BR_LOGOS = {
    apple: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.8-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/></svg>',
    chrome: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15.93V16c-2.76-.55-5-2.29-6.16-4.69L7.13 10c.96 1.96 2.78 3.4 5 3.87v-.01c.08.01.18.02.27.02 2.21 0 4-1.79 4-4s-1.79-4-4-4c-.69 0-1.34.18-1.9.5L8.7 4.74C9.73 4.27 10.83 4 12 4c4.41 0 8 3.59 8 8s-3.59 8-8 8c-.34 0-.67-.03-1-.07zM12 8c2.21 0 4 1.79 4 4s-1.79 4-4 4-4-1.79-4-4 1.79-4 4-4z"/></svg>',
    microsoft: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M11.5 2v9.5H2V2h9.5zm1 0H22v9.5h-9.5V2zM2 12.5h9.5V22H2v-9.5zm10.5 0H22V22h-9.5v-9.5z"/></svg>',
    mozilla: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 2c1.84 0 3.53.63 4.88 1.68L5.68 16.88A7.95 7.95 0 014 12c0-4.41 3.59-8 8-8zm0 16c-1.84 0-3.53-.63-4.88-1.68l11.2-11.2A7.95 7.95 0 0120 12c0 4.41-3.59 8-8 8z"/></svg>'
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
      var sc  = statusClass(p[2]);
      var tip = esc(p[1]) + ': ' + esc(p[2] || 'N/A');
      html += '<span class="br-badge" title="' + tip + '">'
            +   '<span style="color:' + (sc==='included'?'#00d4aa':sc==='ev'?'#00b894':sc==='pending'?'#f5a623':sc==='removed'?'#e85555':'#3a4055') + '">'
            +     BR_LOGOS[p[0]]
            +   '</span>'
            +   '<span class="br-dot d-' + sc + '"></span>'
            + '</span>';
    });
    return html + '</div>';
  }

  // ── Type badge ────────────────────────────────────────────────────────────
  function typeBadge(type) {
    var t = (type || '').toLowerCase();
    if (t.indexOf('root') !== -1) { return '<span class="cert-type-badge badge-root">Root</span>'; }
    if (t.indexOf('inter') !== -1) { return '<span class="cert-type-badge badge-inter">Intermediate</span>'; }
    if (t.indexOf('cross') !== -1) { return '<span class="cert-type-badge badge-cross">Cross</span>'; }
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

  // ── Fingerprint ───────────────────────────────────────────────────────────
  function shortFp(sha256) {
    if (!sha256) { return '<span style="color:var(--muted)">—</span>'; }
    return '<abbr title="' + esc(sha256) + '">' + sha256.replace(/:/g,'').toUpperCase().substring(0,16) + '…</abbr>';
  }

  // ── Filter predicate ─────────────────────────────────────────────────────
  function certMatchesFilter(cert) {
    if (activeFilter === 'all') { return true; }
    if (activeFilter === 'root') { return (cert.type || '').toLowerCase().indexOf('root') !== -1; }
    if (activeFilter === 'intermediate') { return (cert.type || '').toLowerCase().indexOf('inter') !== -1; }
    if (activeFilter === 'tls')   { return cert.tlsCap; }
    if (activeFilter === 'smime') { return cert.smimeCap; }
    if (activeFilter === 'cs')    { return cert.csCap; }
    return true;
  }

  // ── Render table ──────────────────────────────────────────────────────────
  function renderTable(data, expandAll) {
    allOwners   = data.owners   || [];
    totalOwners = data.totalOwners || 0;
    curPage     = data.page     || 1;
    totalPages  = data.pages    || 1;

    if (!allOwners.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="tbl-empty">'
        + (searchQ ? 'No results for &ldquo;' + esc(searchQ) + '&rdquo;.' : 'No data — run the sync cron to populate.')
        + '</td></tr>';
      metaEl.textContent = '';
      pagination.innerHTML = '';
      return;
    }

    var html = '';
    var totalCerts = 0;
    allOwners.forEach(function(owner, oi) {
      var visible = allOwners.length <= 3 || expandAll;
      var filtered = owner.certs.filter(certMatchesFilter);
      totalCerts += filtered.length;

      html += '<tr class="owner-row' + (visible ? ' expanded' : '') + '" data-oi="' + oi + '">'
        + '<td colspan="7">'
        + '<span class="owner-toggle" aria-hidden="true">›</span>'
        + '<span class="owner-name">' + esc(owner.name) + '</span>'
        + (owner.country ? '<span class="owner-meta">' + esc(owner.country) + '</span>' : '')
        + '<span class="owner-count">' + filtered.length + ' cert' + (filtered.length !== 1 ? 's' : '') + '</span>'
        + '</td></tr>';

      filtered.forEach(function(cert, ci) {
        html += '<tr class="cert-row' + (visible ? ' visible' : '') + '" data-oi="' + oi + '" data-ci="' + ci + '">'
          + '<td class="cert-name">' + esc(cert.name) + '</td>'
          + '<td>' + typeBadge(cert.type) + '</td>'
          + '<td>' + browserDots(cert) + '</td>'
          + '<td>' + capTags(cert) + '</td>'
          + '<td class="cert-valid">' + validUntil(cert.validTo) + '</td>'
          + '<td class="cert-fp">' + shortFp(cert.sha256) + '</td>'
          + '<td class="cert-chevron" aria-hidden="true">›</td>'
          + '</tr>';
      });
    });

    tbody.innerHTML = html || '<tr><td colspan="7" class="tbl-empty">No certs match the current filter.</td></tr>';

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
        tbody.innerHTML = '<tr><td colspan="7" class="tbl-empty">Request failed — please try again.</td></tr>';
      })
      .finally(function() { spinner.classList.remove('active'); });
  }

  // ── Search input ──────────────────────────────────────────────────────────
  searchEl.addEventListener('input', function() {
    var q = this.value;
    clearBtn.style.display = q ? '' : 'none';
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function() { fetchPage(q, 1, q !== ''); }, 320);
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
    fetchPage(searchQ, parseInt(a.dataset.p, 10), searchQ !== '');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  // ── Filter chips ──────────────────────────────────────────────────────────
  document.querySelectorAll('.chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.chip').forEach(function(c) { c.classList.remove('active'); });
      this.classList.add('active');
      activeFilter = this.dataset.filter;
      renderTable({ owners: allOwners, totalOwners: totalOwners, page: curPage, pages: totalPages }, searchQ !== '');
    });
  });

  // ── Owner row expand/collapse ─────────────────────────────────────────────
  tbody.addEventListener('click', function(e) {
    var ownerRow = e.target.closest('tr.owner-row');
    if (ownerRow) {
      var oi = ownerRow.dataset.oi;
      var expanded = ownerRow.classList.toggle('expanded');
      tbody.querySelectorAll('tr.cert-row[data-oi="' + oi + '"]').forEach(function(r) {
        r.classList.toggle('visible', expanded);
      });
      return;
    }
    var certRow = e.target.closest('tr.cert-row');
    if (certRow) {
      var oi2 = parseInt(certRow.dataset.oi, 10);
      var ci  = parseInt(certRow.dataset.ci, 10);
      var owner = allOwners[oi2];
      if (!owner) { return; }
      var filtered = owner.certs.filter(certMatchesFilter);
      var cert = filtered[ci];
      if (cert) { openModal(cert, owner.name); }
    }
  });
  tbody.addEventListener('keydown', function(e) {
    if (e.key !== 'Enter' && e.key !== ' ') { return; }
    var certRow = e.target.closest('tr.cert-row');
    if (!certRow) { return; }
    e.preventDefault();
    certRow.click();
  });

  // ══════════════════════════════════════════════════════════════════════════
  // Modal
  // ══════════════════════════════════════════════════════════════════════════

  function openModal(cert, ownerName) {
    activeCert = cert;
    cmEyebrow.textContent = cert.type || 'Certificate';
    cmTitle.textContent   = cert.name || ownerName;
    cmOwner.textContent   = 'CA Owner: ' + ownerName;
    cmBody.innerHTML      = '<div class="cm-loading">Loading…</div>';
    modal.showModal();

    fetch('/ccadb.php?detail=' + encodeURIComponent(cert.sha256))
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.found) {
          cmBody.innerHTML = buildModalBody(cert, data.fields, data.pemInfo);
          wirePemButtons(data.pemInfo, cert);
          wireVerifyButtons(cmBody);
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
      var id = 'url-verify-' + (++_crlVerifyId);
      if (/^https?:\/\//.test(u)) {
        rows += '<div class="cm-crl-row">'
              +   '<input class="cm-crl-input" type="text" readonly value="' + esc(u) + '" aria-label="' + esc(label) + '">'
              +   '<button class="cm-crl-verify" data-url="' + esc(u) + '" id="' + id + '">Verify</button>'
              + '</div>';
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
      var id = 'crl-verify-' + (++_crlVerifyId);
      rows += '<div class="cm-crl-row">'
            +   '<input class="cm-crl-input" type="text" readonly value="' + esc(url) + '" aria-label="' + esc(label) + ' URL">'
            +   '<button class="cm-crl-verify" data-url="' + esc(url) + '" id="' + id + '">Verify</button>'
            + '</div>';
    });
    return dt + '<dd class="cm-dd"><div class="cm-crl-list">' + rows + '</div></dd>';
  }

  // ── URL field row (non-truncated, scrollable) ─────────────────────────────
  function urlFieldRow(label, value) {
    var dt = '<dt class="cm-dt">' + esc(label) + '</dt>';
    if (!value || value === '-' || !/^https?:\/\//.test(value)) {
      return '<dt class="cm-dt">' + esc(label) + '</dt><dd class="cm-dd">'
           + (!value || value === '-' ? '<span class="cm-dd-muted">—</span>' : esc(value)) + '</dd>';
    }
    var id = 'url-verify-' + (++_crlVerifyId);
    return dt + '<dd class="cm-dd"><div class="cm-crl-row">'
         + '<input class="cm-crl-input" type="text" readonly value="' + esc(value) + '" aria-label="' + esc(label) + '">'
         + '<button class="cm-crl-verify" data-url="' + esc(value) + '" id="' + id + '">Verify</button>'
         + '</div></dd>';
  }

  function trustCard(browser, status, evStatus) {
    var sc  = statusClass(status);
    var cls = 'cm-tc tc-' + sc;
    var sCls= 's-' + sc;
    var ev  = evStatus ? '<div class="cm-tc-ev-lbl">EV: ' + esc(evStatus) + '</div>' : '';
    return '<div class="' + cls + '">'
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

  function buildModalBody(cert, fields, pem) {
    var html = '';

    // ① Browser trust
    html += '<div class="cm-sect">'
      + '<div class="cm-sect-title">Browser Trust</div>'
      + '<div class="cm-trust-grid">'
      + trustCard('Apple',     f(fields,'Apple Status'),     f(fields,'Apple EV Root Certificate Inclusion Status'))
      + trustCard('Chrome',    f(fields,'Chrome Status'),    '')
      + trustCard('Microsoft', f(fields,'Microsoft Status'), f(fields,'Microsoft EV Root Certificate Inclusion Status'))
      + trustCard('Mozilla',   f(fields,'Mozilla Status'),   f(fields,'Mozilla EV Root Certificate Inclusion Status'))
      + '</div></div>';

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

    // ③ Trust bits & capabilities
    html += '<div class="cm-sect">'
      + '<div class="cm-sect-title">Trust Bits &amp; Capabilities</div>'
      + '<dl class="cm-dl">'
      + tagListRow('Trust Bits (root)',  f(fields,'Trust Bits for Root Cert'))
      + tagListRow('Derived Trust Bits', f(fields,'Derived Trust Bits'))
      + dlRow('EV OIDs',            f(fields,'EV OIDs for Root Cert'))
      + sorRow('Status of Root',     f(fields,'Status of Root Cert'))
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

    // ⑥ Infrastructure
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

    // ⑦ PEM
    if (pem && pem.indexOf('CERTIFICATE') !== -1) {
      html += '<div class="cm-sect" id="cmPemSect">'
        + '<div class="cm-sect-title">Certificate (PEM)</div>'
        + '<textarea class="ap-embed-cert-pem" id="cmPemArea" readonly spellcheck="false">'
        + esc(pem)
        + '</textarea>'
        + '<div class="ap-embed-cert-actions">'
        + '<button class="ap-embed-cert-btn ap-embed-cert-lint"  id="cmLint">Lint</button>'
        + '<button class="ap-embed-cert-btn ap-embed-cert-parse" id="cmParse">Inspect</button>'
        + '<button class="ap-embed-cert-btn ap-embed-cert-copy"  id="cmCopy">Copy PEM</button>'
        + '<button class="ap-embed-cert-btn ap-embed-cert-dl"    id="cmDl">Download .pem</button>'
        + '</div></div>';
    }

    return html;
  }

  // ── Wire PEM buttons (after modal body is in DOM) ─────────────────────────
  function wirePemButtons(pem, cert) {
    var lint  = document.getElementById('cmLint');
    var parse = document.getElementById('cmParse');
    var copy  = document.getElementById('cmCopy');
    var dl    = document.getElementById('cmDl');
    if (!lint) { return; }

    lint.addEventListener('click', function() {
      sessionStorage.setItem('pki_prefill_cert', pem);
      window.open('/linters.php', '_blank', 'noopener');
    });
    parse.addEventListener('click', function() {
      sessionStorage.removeItem('mkt_eseal_cms');
      sessionStorage.removeItem('mkt_eseal_xades');
      sessionStorage.removeItem('meerkat_pem');
      sessionStorage.setItem('pki_prefill_cert', pem);
      window.open('/artifact_parser.php', '_blank', 'noopener');
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

  // ── Wire Verify buttons (CRL / URL fields) ───────────────────────────────
  function wireVerifyButtons(container) {
    container.querySelectorAll('.cm-crl-verify').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var url = btn.getAttribute('data-url');
        if (!url || btn.classList.contains('checking')) { return; }
        btn.classList.add('checking');
        btn.textContent = '…';
        fetch('/ccadb.php?verify_url=' + encodeURIComponent(url))
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
      });
    });
  }

  // ── Initial render ────────────────────────────────────────────────────────
  searchQ = searchEl.value;
  if (initData) {
    renderTable(initData, searchQ !== '');
  } else {
    fetchPage(searchQ, 1, false);
  }

}());
</script>
</body>
</html>
