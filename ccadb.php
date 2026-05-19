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

// ── Input ─────────────────────────────────────────────────────────────────────

$search   = trim(substr($_GET['q']      ?? '', 0, 200));
$page     = max(1, (int)($_GET['p']     ?? 1));
$isJson   = isset($_GET['json'])   && $_GET['json']   === '1';
$detail   = trim($_GET['detail']   ?? '');

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

// ── ?detail=<sha256> — full cert data for modal ───────────────────────────────

if ($detail !== '' && $pdo) {
    header('Content-Type: application/json; charset=utf-8');
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
    header('Content-Type: application/json; charset=utf-8');
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

    /* ── Browser dots ── */
    .br-dots{display:flex;gap:4px;align-items:center}
    .br-dot{width:9px;height:9px;border-radius:50%;border:1px solid rgba(255,255,255,.12);flex-shrink:0}
    .br-dot.d-included{background:#00d4aa;border-color:rgba(0,212,170,.4)}
    .br-dot.d-ev{background:#00b894;border-color:rgba(0,184,148,.4)}
    .br-dot.d-pending{background:#f5a623;border-color:rgba(245,166,35,.4)}
    .br-dot.d-removed{background:#e85555;border-color:rgba(232,85,85,.4)}
    .br-dot.d-na{background:transparent;border-color:#2a3040}
    .br-dot-row{display:flex;gap:3px;margin-top:2px}
    .br-dot-lbl{font-family:var(--mono);font-size:.54rem;color:var(--muted);width:9px;text-align:center}

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
    var lc = (s || '').toLowerCase();
    if (!lc || lc === '-') { return 'na'; }
    if (lc.indexOf('ev included') !== -1) { return 'ev'; }
    if (lc.indexOf('included') !== -1 || lc.indexOf('trusted') !== -1) { return 'included'; }
    if (lc.indexOf('pending') !== -1 || lc.indexOf('transitional') !== -1 || lc.indexOf('not yet') !== -1) { return 'pending'; }
    if (lc.indexOf('removed') !== -1 || lc.indexOf('rejected') !== -1 || lc.indexOf('not included') !== -1) { return 'removed'; }
    return 'na';
  }

  // ── Browser dots ─────────────────────────────────────────────────────────
  function browserDots(cert) {
    var pairs = [
      ['A', cert.statusApple],['C', cert.statusChrome],
      ['M', cert.statusMs],   ['Z', cert.statusMoz]
    ];
    var dots = '<div class="br-dots">';
    var lbls = '<div class="br-dot-row">';
    pairs.forEach(function(p) {
      var sc = statusClass(p[1]);
      dots += '<span class="br-dot d-' + sc + '" title="' + esc(p[0] === 'A' ? 'Apple' : p[0] === 'C' ? 'Chrome' : p[0] === 'M' ? 'Microsoft' : 'Mozilla') + ': ' + esc(p[1] || 'N/A') + '"></span>';
      lbls += '<span class="br-dot-lbl" aria-hidden="true">' + esc(p[0]) + '</span>';
    });
    return dots + '</div>' + lbls + '</div>';
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
    if (!value || value === '-') {
      return '<dt class="cm-dt">' + esc(label) + '</dt><dd class="cm-dd"><span class="cm-dd-muted">—</span></dd>';
    }
    var links = value.split(/[;\n]+/).map(function(u) {
      u = u.trim();
      if (!u) { return ''; }
      if (/^https?:\/\//.test(u)) {
        return '<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer">' + esc(u.length > 60 ? u.substring(0,57)+'…' : u) + '</a>';
      }
      return esc(u);
    }).filter(Boolean);
    return '<dt class="cm-dt">' + esc(label) + '</dt><dd class="cm-dd">' + links.join('<br>') + '</dd>';
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
    var rows = dlRow('Audit URL',   url,  true)
             + dlRow('Type',        type)
             + dlRow('Statement',   date)
             + dlRow('Period',      start && end ? start + ' – ' + end : (start || end || ''));
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
      + dlRow('Constrained',      f(fields,'Technically Constrained'))
      + dlRow('Revocation',       f(fields,'Revocation Status'))
      + dlRow('Salesforce ID',    f(fields,'Salesforce Record ID'))
      + '</dl></div>';

    // ③ Trust bits & capabilities
    html += '<div class="cm-sect">'
      + '<div class="cm-sect-title">Trust Bits &amp; Capabilities</div>'
      + '<dl class="cm-dl">'
      + dlRow('Trust Bits (root)',  f(fields,'Trust Bits for Root Cert'))
      + dlRow('Derived Trust Bits', f(fields,'Derived Trust Bits'))
      + dlRow('EV OIDs',            f(fields,'EV OIDs for Root Cert'))
      + dlRow('Status of Root',     f(fields,'Status of Root Cert'))
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
      + dlRow('CP URL',                f(fields,'Certificate Policy (CP) URL'),                  true)
      + dlRow('CP Effective',          f(fields,'CP Effective Date'))
      + dlRow('CPS URL',               f(fields,'Certificate Practice Statement (CPS) URL'),     true)
      + dlRow('CPS Effective',         f(fields,'CPS Effective Date'))
      + dlRow('CP/CPS Statement',      f(fields,'Certificate Practice & Policy Statement'),       true)
      + dlRow('MD/AsciiDoc URL',       f(fields,'MD/AsciiDoc CP/CPS URL'),                       true)
      + '</dl></div>';

    // ⑥ Infrastructure
    html += '<div class="cm-sect">'
      + '<div class="cm-sect-title">Infrastructure</div>'
      + '<dl class="cm-dl">'
      + dlRow('Country',       f(fields,'Country'))
      + dlRow('Sub CA Owner',  f(fields,'Subordinate CA Owner'))
      + dlRow('CRL (Full)',    f(fields,'JSON Array of All Full CRL URLs'))
      + dlRow('CRL (Parts)',   f(fields,'JSON Array of Partitioned CRLs'))
      + dlRow('ACME DV',       f(fields,'DV ACME Directory URL(s)'), true)
      + dlRow('ACME OV',       f(fields,'OV ACME Directory URL(s)'), true)
      + dlRow('ACME EV',       f(fields,'EV ACME Directory URL(s)'), true)
      + dlRow('Test (Valid)',   f(fields,'Test Website URL - Valid'),   true)
      + dlRow('Test (Expired)', f(fields,'Test Website URL - Expired'), true)
      + dlRow('Test (Revoked)', f(fields,'Test Website URL - Revoked'), true)
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
