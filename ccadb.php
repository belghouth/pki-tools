<?php
/**
 * ccadb.php — CCADB public resource browser
 *
 * Tabbed viewer for cached CCADB CSV data (All Certificate Records,
 * Included Root Certificates). Data is populated by cron/ccadb_sync.php.
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

const CCADB_RESOURCES = [
    'included_roots' => [
        'name'  => 'Included Root Certificates',
        'label' => 'Included Roots',
        'desc'  => 'Trust bit settings for all root certificates included in participating root stores.',
    ],
    'all_certs' => [
        'name'  => 'All Certificate Records',
        'label' => 'All Certs',
        'desc'  => 'All root and intermediate CA certificates disclosed in the CCADB (V5).',
    ],
];

const CCADB_PER_PAGE = 50;

// ── Input ─────────────────────────────────────────────────────────────────────

$validTabs = array_keys(CCADB_RESOURCES);
$tab       = in_array($_GET['tab'] ?? '', $validTabs, true) ? $_GET['tab'] : 'included_roots';
$search    = trim(substr($_GET['q'] ?? '', 0, 200));
$page      = max(1, (int)($_GET['p'] ?? 1));
$isJson    = isset($_GET['json']) && $_GET['json'] === '1';

// ── DB query ──────────────────────────────────────────────────────────────────

$pdo      = admin_pdo();
$rows     = [];
$total    = 0;
$syncInfo = null;
$dbError  = null;

if ($pdo) {
    try {
        $offset = ($page - 1) * CCADB_PER_PAGE;

        if ($search !== '') {
            $cs = $pdo->prepare(
                "SELECT COUNT(*) FROM ccadb_rows
                 WHERE resource_key = ? AND MATCH(search_text) AGAINST(? IN BOOLEAN MODE)"
            );
            $cs->execute([$tab, $search]);
            $total = (int)$cs->fetchColumn();

            $rs = $pdo->prepare(
                "SELECT data_json FROM ccadb_rows
                 WHERE resource_key = ? AND MATCH(search_text) AGAINST(? IN BOOLEAN MODE)
                 ORDER BY id LIMIT " . CCADB_PER_PAGE . " OFFSET $offset"
            );
            $rs->execute([$tab, $search]);
        } else {
            $cs = $pdo->prepare(
                "SELECT COUNT(*) FROM ccadb_rows WHERE resource_key = ?"
            );
            $cs->execute([$tab]);
            $total = (int)$cs->fetchColumn();

            $rs = $pdo->prepare(
                "SELECT data_json FROM ccadb_rows WHERE resource_key = ?
                 ORDER BY `row_number` LIMIT " . CCADB_PER_PAGE . " OFFSET $offset"
            );
            $rs->execute([$tab]);
        }

        foreach ($rs->fetchAll(PDO::FETCH_COLUMN) as $json) {
            $decoded = json_decode($json, true);
            if (is_array($decoded)) {
                $rows[] = $decoded;
            }
        }

        $si = $pdo->prepare(
            "SELECT synced_at, row_count FROM ccadb_sync_log
             WHERE resource_key = ? AND status = 'ok'
             ORDER BY synced_at DESC LIMIT 1"
        );
        $si->execute([$tab]);
        $syncInfo = $si->fetch() ?: null;
    } catch (Throwable $e) {
        $dbError = $e->getMessage();
    }
}

$pages   = $total > 0 ? (int)ceil($total / CCADB_PER_PAGE) : 1;
$page    = min($page, $pages);
$tabRes  = CCADB_RESOURCES[$tab];

// ── JSON endpoint (AJAX for included_roots) ───────────────────────────────────

if ($isJson && $tab === 'included_roots') {
    header('Content-Type: application/json; charset=utf-8');
    $out = [];
    foreach ($rows as $row) {
        $out[] = ccadbExtractIncludedRoot($row);
    }
    echo json_encode(['rows' => $out, 'total' => $total, 'pages' => $pages, 'page' => $page]);
    exit;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function ccadbPageUrl(int $p, string $tab, string $q): string {
    $params = ['tab' => $tab, 'p' => $p];
    if ($q !== '') {
        $params['q'] = $q;
    }
    return '/ccadb.php?' . http_build_query($params);
}

/**
 * Find a value in a CCADB row by exact then partial case-insensitive key match.
 */
function ccadbFindInRow(array $row, string ...$needles): string {
    foreach ($needles as $needle) {
        foreach ($row as $k => $v) {
            if (strcasecmp($k, $needle) === 0) {
                return (string)$v;
            }
        }
    }
    foreach ($needles as $needle) {
        foreach ($row as $k => $v) {
            if (stripos($k, $needle) !== false) {
                return (string)$v;
            }
        }
    }
    return '';
}

/**
 * Extract all structured fields from a raw CCADB included-roots row for both
 * the compact table row and the full detail modal.
 */
function ccadbExtractIncludedRoot(array $row): array {
    // Subject DN parts
    $subjectCN = ccadbFindInRow($row, 'Certificate Subject Common Name');
    $subjectO  = ccadbFindInRow($row, 'Certificate Subject Organization');
    $subjectOU = ccadbFindInRow($row, 'Certificate Subject Organizational Unit');
    $dnParts = [];
    if ($subjectCN !== '') {
        $dnParts[] = 'CN=' . $subjectCN;
    }
    if ($subjectOU !== '') {
        $dnParts[] = 'OU=' . $subjectOU;
    }
    if ($subjectO !== '') {
        $dnParts[] = 'O=' . $subjectO;
    }

    // PEM normalisation
    $pem = trim(trim(ccadbFindInRow($row, 'PEM Info', 'PEM'), '"\''));
    if ($pem !== '' && !str_contains($pem, '-----')) {
        $pem = "-----BEGIN CERTIFICATE-----\n"
             . wordwrap($pem, 64, "\n", true)
             . "\n-----END CERTIFICATE-----";
    }

    return [
        // ── compact table columns ──────────────────────────────────────────
        'caOwner'      => ccadbFindInRow($row, 'CA Owner'),
        'certName'     => ccadbFindInRow($row, 'Certificate Name', 'CA Owner/Certificate Name'),
        'subjectDN'    => implode(', ', $dnParts),
        'subjectCN'    => $subjectCN,
        'sha256'       => ccadbFindInRow($row, 'SHA-256 Fingerprint', 'SHA256 Fingerprint', 'Fingerprint'),
        'validFrom'    => ccadbFindInRow($row, 'Valid From [GMT]', 'Valid From', 'Not Before'),
        'validTo'      => ccadbFindInRow($row, 'Valid To [GMT]', 'Valid To', 'Not After'),
        // ── browser trust ──────────────────────────────────────────────────
        'mozStatus'    => ccadbFindInRow($row, 'Mozilla Status'),
        'mozEvStatus'  => ccadbFindInRow($row, 'Mozilla EV Root Certificate Inclusion Status'),
        'msStatus'     => ccadbFindInRow($row, 'Microsoft Status'),
        'msEvStatus'   => ccadbFindInRow($row, 'Microsoft EV Root Certificate Inclusion Status'),
        'appleStatus'  => ccadbFindInRow($row, 'Apple Root Certificate Status', 'Apple Status'),
        'appleEvStatus'=> ccadbFindInRow($row, 'Apple EV Root Certificate Inclusion Status'),
        'chromeStatus' => ccadbFindInRow($row, 'Google Chrome Inclusion Status', 'Chrome Status'),
        // ── capabilities / EKU ────────────────────────────────────────────
        'eku'          => ccadbFindInRow($row, 'Extended Key Usage'),
        'trustBits'    => ccadbFindInRow($row, 'Trust Bits'),
        'tlsCapable'   => ccadbFindInRow($row, 'TLS Capable'),
        'tlsEvCapable' => ccadbFindInRow($row, 'TLS EV Capable'),
        'evPolicies'   => ccadbFindInRow($row, 'TLS EV Policy OID(s)', 'EV Policy OID'),
        'codeSign'     => ccadbFindInRow($row, 'Code Signing Capable'),
        // ── identity / crypto ─────────────────────────────────────────────
        'subjectO'     => $subjectO,
        'subjectOU'    => $subjectOU,
        'issuerCN'     => ccadbFindInRow($row, 'Certificate Issuer Common Name'),
        'issuerO'      => ccadbFindInRow($row, 'Certificate Issuer Organization'),
        'issuerOU'     => ccadbFindInRow($row, 'Certificate Issuer Organizational Unit'),
        'serial'       => ccadbFindInRow($row, 'Certificate Serial Number'),
        'spkiSha256'   => ccadbFindInRow($row, 'Subject + SPKI SHA256'),
        'pubKeyAlgo'   => ccadbFindInRow($row, 'Public Key Algorithm'),
        'sigHash'      => ccadbFindInRow($row, 'Signature Hash Algorithm'),
        // ── compliance ────────────────────────────────────────────────────
        'cpsUri'       => ccadbFindInRow($row, 'CPS URI'),
        'testValid'    => ccadbFindInRow($row, 'Test Website - Valid'),
        'testRevoked'  => ccadbFindInRow($row, 'Test Website - Revoked'),
        'testExpired'  => ccadbFindInRow($row, 'Test Website - Expired'),
        // ── certificate ───────────────────────────────────────────────────
        'pem'          => $pem,
    ];
}

function renderCcadbCell(string $val): string {
    if ($val === '' || $val === '-') {
        return '<span style="color:var(--muted)">—</span>';
    }
    if (filter_var($val, FILTER_VALIDATE_URL) && str_starts_with($val, 'http')) {
        $display = strlen($val) > 60 ? substr($val, 0, 57) . '…' : $val;
        return '<a href="' . htmlspecialchars($val) . '" target="_blank" rel="noopener noreferrer">'
             . htmlspecialchars($display) . '</a>';
    }
    return htmlspecialchars($val);
}

// ── Initial data for included_roots JS renderer ───────────────────────────────

$irInitialData = null;
if ($tab === 'included_roots') {
    $irInitialData = [
        'rows'  => array_map('ccadbExtractIncludedRoot', $rows),
        'total' => $total,
        'pages' => $pages,
        'page'  => $page,
    ];
}

// ── Sync badge ────────────────────────────────────────────────────────────────

$syncClass = 'never';
$syncText  = 'Never synced';
if ($syncInfo) {
    $syncDate  = new DateTimeImmutable($syncInfo['synced_at'] . ' UTC');
    $now       = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    $ageDays   = (int)$now->diff($syncDate)->days;
    $syncClass = $ageDays > 10 ? 'stale' : '';
    $syncText  = 'Synced ' . $syncDate->format('Y-m-d') . ' · ' . number_format($syncInfo['row_count']) . ' rows';
}

$navLabel = 'CCADB Browser';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'CCADB Browser — Public CA Data | ' . SITE_DOMAIN,
    'description' => 'Browse cached CCADB public data: All Certificate Records and Included Root Certificates. Updated weekly.',
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
      --bg: #0e1014; --surface: #13171e; --border: #2a3040;
      --accent: #00d4aa; --text: #d4dae6; --muted: #6b7a90;
      --sans: 'IBM Plex Sans', sans-serif; --mono: 'IBM Plex Mono', monospace;
      --radius: 8px;
      --red: #e85555; --amber: #f5a623; --green: #00d4aa; --purple: #a78bfa;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; scroll-behavior: smooth; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.7; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }

    /* ── Layout ── */
    .page { max-width: 1400px; margin: 0 auto; padding: 2.5rem 1.5rem 6rem; }
    .page-hd { margin-bottom: 1.8rem; }
    .page-hd h1 { font-size: 1.75rem; font-weight: 600; color: #fff; margin-bottom: 0.25rem; }
    .page-hd p  { font-size: 0.85rem; color: var(--muted); }

    /* ── Tabs ── */
    .tab-nav {
      display: flex; align-items: center; gap: 0.25rem;
      border-bottom: 1px solid var(--border); margin-bottom: 1.5rem;
    }
    .tab-btn {
      font-family: var(--sans); font-size: 0.82rem; font-weight: 400;
      color: var(--muted); background: none; border: none;
      padding: 0.55rem 1rem; border-radius: 6px 6px 0 0;
      cursor: pointer; text-decoration: none; border-bottom: 2px solid transparent;
      transition: color 150ms, border-color 150ms; margin-bottom: -1px;
    }
    .tab-btn:hover  { color: var(--text); }
    .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 500; }

    /* ── Toolbar ── */
    .toolbar { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem; }
    .search-wrap { position: relative; flex: 0 0 360px; }
    .search-wrap input {
      width: 100%; background: var(--surface); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text); font-family: var(--mono);
      font-size: 0.8rem; padding: 0.45rem 2.2rem 0.45rem 0.75rem;
      outline: none; transition: border-color 150ms;
    }
    .search-wrap input:focus { border-color: var(--accent); }
    .search-wrap input::placeholder { color: var(--muted); }
    .search-clear {
      position: absolute; right: 0.5rem; top: 50%; transform: translateY(-50%);
      background: none; border: none; color: var(--muted); cursor: pointer;
      font-size: 1rem; line-height: 1; padding: 0;
    }
    .search-clear:hover { color: var(--text); }
    .toolbar-meta { font-size: 0.78rem; color: var(--muted); margin-left: auto; white-space: nowrap; }
    .search-spinner {
      display: none; width: 14px; height: 14px; border: 2px solid var(--border);
      border-top-color: var(--accent); border-radius: 50%;
      animation: spin 0.6s linear infinite; flex-shrink: 0;
    }
    .search-spinner.active { display: inline-block; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ── Table base ── */
    .tbl-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius); }
    table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
    thead th {
      background: #1a1f28; color: var(--muted);
      font-family: var(--mono); font-size: 0.68rem; font-weight: 600;
      letter-spacing: 0.05em; text-transform: uppercase;
      padding: 0.6rem 0.85rem; text-align: left;
      border-bottom: 1px solid var(--border); white-space: nowrap;
    }
    tbody tr { border-bottom: 1px solid #1e2430; transition: background 80ms; }
    tbody tr:last-child { border-bottom: none; }
    tbody td { padding: 0.5rem 0.85rem; vertical-align: middle; }
    tbody td a { color: var(--accent); }
    tbody td a:hover { color: #fff; text-decoration: underline; }

    /* ── Included-roots compact rows ── */
    tr.ir-row { cursor: pointer; }
    tr.ir-row:hover { background: rgba(0,212,170,0.04); }
    tr.ir-row:hover td.ir-owner { color: #fff; }
    .ir-owner { font-weight: 500; color: #e8edf7; max-width: 180px; }
    .ir-certname { color: var(--text); max-width: 200px; font-size: 0.76rem; line-height: 1.4; }
    .ir-subject { font-family: var(--mono); font-size: 0.68rem; color: var(--muted); max-width: 200px; word-break: break-word; }
    .ir-fp { font-family: var(--mono); font-size: 0.67rem; color: #8892a4; white-space: nowrap; }
    .ir-fp abbr { text-decoration: none; cursor: default; }
    .ir-valid { font-family: var(--mono); font-size: 0.68rem; color: var(--muted); white-space: nowrap; }
    .ir-valid .vto.expired { color: var(--red); }
    .ir-chevron { color: var(--muted); font-size: 0.75rem; opacity: 0.5; }
    tr.ir-row:hover .ir-chevron { opacity: 1; color: var(--accent); }

    /* ── Browser dots (compact, in table row) ── */
    .br-dots { display: flex; gap: 4px; align-items: center; }
    .br-dot {
      width: 9px; height: 9px; border-radius: 50%;
      border: 1px solid rgba(255,255,255,0.12); flex-shrink: 0;
    }
    .br-dot.d-included { background: #00d4aa; border-color: rgba(0,212,170,0.4); }
    .br-dot.d-pending  { background: #f5a623; border-color: rgba(245,166,35,0.4); }
    .br-dot.d-removed  { background: #e85555; border-color: rgba(232,85,85,0.4); }
    .br-dot.d-na       { background: transparent; border-color: #2a3040; }
    .br-dot-labels { display: flex; gap: 3px; margin-top: 3px; }
    .br-dot-label { font-family: var(--mono); font-size: 0.55rem; color: var(--muted); letter-spacing: 0; text-align: center; width: 9px; }

    /* ── Screen-reader only ── */
    .sr-only {
      position: absolute; width: 1px; height: 1px; padding: 0;
      margin: -1px; overflow: hidden; clip: rect(0,0,0,0);
      white-space: nowrap; border: 0;
    }

    /* ── Empty / loading ── */
    .tbl-empty    { text-align: center; padding: 4rem 1rem; color: var(--muted); font-family: var(--mono); font-size: 0.82rem; }
    .tbl-loading  { text-align: center; padding: 3rem 1rem; color: var(--muted); font-size: 0.82rem; }

    /* ── Pagination ── */
    .pagination {
      display: flex; align-items: center; justify-content: center;
      gap: 0.3rem; margin-top: 1.5rem; flex-wrap: wrap;
    }
    .pagination a, .pagination span {
      display: inline-flex; align-items: center; justify-content: center;
      min-width: 32px; height: 32px; padding: 0 0.5rem;
      border-radius: 5px; font-size: 0.78rem; font-family: var(--mono);
      border: 1px solid var(--border); color: var(--muted);
      text-decoration: none; transition: color 120ms, border-color 120ms, background 120ms;
    }
    .pagination a:hover { color: var(--text); border-color: #3a4458; background: rgba(255,255,255,0.04); }
    .pagination .cur  { color: var(--accent); border-color: rgba(0,212,170,0.35); background: rgba(0,212,170,0.07); }
    .pagination .dots { border: none; color: var(--muted); }

    /* ── Sync badge ── */
    .sync-badge {
      display: inline-flex; align-items: center; gap: 0.4rem;
      font-size: 0.72rem; font-family: var(--mono); color: var(--muted);
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 4px; padding: 0.25rem 0.6rem;
    }
    .sync-badge .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--accent); flex-shrink: 0; }
    .sync-badge.stale .dot { background: var(--amber); }
    .sync-badge.never .dot { background: var(--red); }

    /* ══════════════════════════════════════════════════════════════════════════
       ROOT DETAIL MODAL
    ══════════════════════════════════════════════════════════════════════════ */

    dialog.ir-modal {
      position: fixed; inset: 0;
      width: 100vw; height: 100vh;
      max-width: 100%; max-height: 100%;
      background: transparent; border: none; padding: 0;
      /* flex centering set inline when open; dialog default display is inline-block */
    }
    dialog.ir-modal[open] {
      display: flex; align-items: center; justify-content: center;
    }
    dialog.ir-modal::backdrop {
      background: rgba(0,0,0,0.78); backdrop-filter: blur(5px);
    }

    .ir-modal-box {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; width: min(860px, 96vw);
      max-height: min(88vh, 800px);
      display: flex; flex-direction: column;
      box-shadow: 0 32px 100px rgba(0,0,0,0.8);
      overflow: hidden;
    }

    /* header */
    .ir-modal-hd {
      display: flex; align-items: flex-start; gap: 1rem;
      padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border);
      flex-shrink: 0; background: #0f1318;
    }
    .ir-modal-hd-text { flex: 1; min-width: 0; }
    .ir-modal-eyebrow {
      font-family: var(--mono); font-size: 0.6rem; letter-spacing: 0.12em;
      text-transform: uppercase; color: var(--accent); margin-bottom: 0.2rem;
    }
    .ir-modal-title {
      font-size: 1rem; font-weight: 600; color: #fff;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .ir-modal-owner {
      font-size: 0.78rem; color: var(--muted); margin-top: 0.15rem;
    }
    .ir-modal-close {
      background: none; border: none; color: var(--muted); cursor: pointer;
      font-size: 1.4rem; line-height: 1; padding: 0.2rem 0.4rem;
      border-radius: 4px; flex-shrink: 0; transition: color 120ms, background 120ms;
    }
    .ir-modal-close:hover { color: var(--text); background: rgba(255,255,255,0.06); }

    /* scrollable body */
    .ir-modal-body { overflow-y: auto; flex: 1; padding: 0; }

    /* section blocks */
    .ir-modal-sect {
      padding: 1rem 1.5rem; border-bottom: 1px solid #1e2430;
    }
    .ir-modal-sect:last-of-type { border-bottom: none; }
    .ir-sect-title {
      font-family: var(--mono); font-size: 0.65rem; font-weight: 600;
      letter-spacing: 0.1em; text-transform: uppercase;
      color: var(--muted); margin-bottom: 0.75rem;
    }

    /* definition list rows */
    .ir-dl { display: grid; grid-template-columns: 160px 1fr; gap: 0.15rem 1rem; }
    .ir-dt {
      font-family: var(--mono); font-size: 0.68rem; color: var(--muted);
      padding: 0.2rem 0; align-self: start; white-space: nowrap;
    }
    .ir-dd {
      font-size: 0.78rem; color: var(--text); padding: 0.2rem 0;
      word-break: break-word; font-family: var(--mono);
    }
    .ir-dd a { color: var(--accent); }
    .ir-dd a:hover { color: #fff; }
    .ir-dd-muted { color: var(--muted); }

    /* browser trust cards */
    .ir-trust-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
      gap: 0.6rem;
    }
    .ir-trust-card {
      border: 1px solid var(--border); border-radius: 6px;
      padding: 0.65rem 0.85rem; background: rgba(255,255,255,0.02);
      border-left: 3px solid var(--border);
    }
    .ir-trust-card.tc-included { border-left-color: var(--green); background: rgba(0,212,170,0.04); }
    .ir-trust-card.tc-pending  { border-left-color: var(--amber); background: rgba(245,166,35,0.04); }
    .ir-trust-card.tc-removed  { border-left-color: var(--red);   background: rgba(232,85,85,0.04); }
    .ir-trust-card.tc-na       { opacity: 0.55; }
    .ir-tc-browser {
      font-family: var(--mono); font-size: 0.62rem; font-weight: 600;
      letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted);
      margin-bottom: 0.25rem;
    }
    .ir-tc-status {
      font-size: 0.8rem; font-weight: 500; color: var(--text); line-height: 1.3;
    }
    .ir-tc-status.s-included { color: var(--green); }
    .ir-tc-status.s-pending  { color: var(--amber); }
    .ir-tc-status.s-removed  { color: var(--red); }
    .ir-tc-ev {
      font-family: var(--mono); font-size: 0.65rem; color: var(--muted); margin-top: 0.2rem;
    }

    /* EKU tags */
    .ir-eku-tags { display: flex; flex-wrap: wrap; gap: 0.3rem; }
    .ir-eku-tag {
      font-size: 0.65rem; font-family: var(--mono);
      background: rgba(167,139,250,0.1); color: var(--purple);
      border: 1px solid rgba(167,139,250,0.3); border-radius: 3px;
      padding: 0.1rem 0.4rem; white-space: nowrap;
    }

    /* ── PEM section + action buttons (matching artifact_parser.php style) ── */
    .ap-embed-cert-pem {
      display: block; width: 100%; height: 90px; resize: none;
      background: rgba(0,0,0,0.3); color: #8a9ab8;
      border: 1px solid var(--border); border-radius: 4px;
      font-family: var(--mono); font-size: 0.6rem; line-height: 1.45;
      padding: 0.4rem 0.6rem; outline: none; white-space: pre; overflow-y: auto;
      margin-bottom: 0.5rem;
    }
    .ap-embed-cert-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .ap-embed-cert-btn {
      font-family: var(--mono); font-size: 0.65rem; text-transform: uppercase;
      letter-spacing: 0.07em; font-weight: 600; cursor: pointer;
      border-radius: 4px; padding: 0.3em 0.8em; background: none;
      transition: background 0.15s, border-color 0.15s;
    }
    .ap-embed-cert-lint  { color: var(--accent); border: 1px solid rgba(0,212,170,0.35); }
    .ap-embed-cert-lint:hover  { background: rgba(0,212,170,0.08); border-color: var(--accent); }
    .ap-embed-cert-parse { color: var(--purple); border: 1px solid rgba(167,139,250,0.35); }
    .ap-embed-cert-parse:hover { background: rgba(167,139,250,0.08); border-color: var(--purple); }
    .ap-embed-cert-copy  { color: var(--muted); border: 1px solid var(--border); }
    .ap-embed-cert-copy:hover  { color: var(--text); border-color: #3a4458; background: rgba(255,255,255,0.04); }
    .ap-embed-cert-dl    { color: var(--muted); border: 1px solid var(--border); }
    .ap-embed-cert-dl:hover    { color: var(--text); border-color: #3a4458; background: rgba(255,255,255,0.04); }

    @media (max-width: 640px) {
      .search-wrap { flex: 1 1 100%; }
      .toolbar-meta { margin-left: 0; width: 100%; }
      .ir-dl { grid-template-columns: 1fr; }
      .ir-dt { padding-bottom: 0; }
    }
  </style>
</head>
<body>
<?php require_once __DIR__ . '/includes/site_nav.php'; ?>

<div class="page">

  <div class="page-hd">
    <h1>CCADB Browser</h1>
    <p>Cached snapshots of CCADB public data, updated weekly via automated sync.</p>
  </div>

  <!-- ── Tabs ── -->
  <nav class="tab-nav" aria-label="CCADB data sets">
    <?php foreach (CCADB_RESOURCES as $key => $res): ?>
    <a href="/ccadb.php?tab=<?= urlencode($key) ?>"
       class="tab-btn<?= $tab === $key ? ' active' : '' ?>"
       aria-label="<?= htmlspecialchars($res['label']) ?>"><?= htmlspecialchars($res['label']) ?></a>
    <?php endforeach; ?>
  </nav>

  <!-- ── Tab description + sync badge ── -->
  <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;flex-wrap:wrap;">
    <p style="font-size:0.82rem;color:var(--muted);"><?= htmlspecialchars($tabRes['desc']) ?></p>
    <span class="sync-badge <?= $syncClass ?>"><span class="dot"></span><?= htmlspecialchars($syncText) ?></span>
  </div>

<?php if ($tab === 'included_roots'): ?>
  <!-- ══════════════════════════════════════════════════════════════════════════
       INCLUDED ROOTS — live-search AJAX table + detail modal
  ══════════════════════════════════════════════════════════════════════════ -->

  <div class="toolbar">
    <div class="search-wrap">
      <input type="search" id="irSearch" value="<?= htmlspecialchars($search) ?>"
             placeholder="Search CA owner, certificate name, DN…"
             autocomplete="off" spellcheck="false" aria-label="Search included roots">
      <button type="button" class="search-clear" id="irClear"
              style="<?= $search === '' ? 'display:none' : '' ?>"
              aria-label="Clear search">×</button>
    </div>
    <div class="search-spinner" id="irSpinner" aria-hidden="true"></div>
    <span class="toolbar-meta" id="irMeta" aria-live="polite"></span>
  </div>

  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>CA Owner</th>
          <th>Certificate Name</th>
          <th>Subject</th>
          <th title="Mozilla · Microsoft · Apple · Chrome">Trust</th>
          <th>Valid Until</th>
          <th>SHA-256</th>
          <th><span class="sr-only">Open detail</span></th>
        </tr>
      </thead>
      <tbody id="irTbody">
        <tr><td colspan="7" class="tbl-loading">Loading…</td></tr>
      </tbody>
    </table>
  </div>

  <nav class="pagination" id="irPagination" aria-label="Page navigation"></nav>

  <!-- ═══════════════════════════════════════════════════════════════════════
       ROOT DETAIL MODAL
  ═══════════════════════════════════════════════════════════════════════ -->
  <dialog class="ir-modal" id="irModal" aria-labelledby="irModalTitle">
    <div class="ir-modal-box">

      <!-- Header -->
      <div class="ir-modal-hd">
        <div class="ir-modal-hd-text">
          <div class="ir-modal-eyebrow">Root CA Certificate</div>
          <h2 class="ir-modal-title" id="irModalTitle">—</h2>
          <div class="ir-modal-owner" id="irModalOwner"></div>
        </div>
        <button class="ir-modal-close" id="irModalClose" aria-label="Close">×</button>
      </div>

      <!-- Scrollable body -->
      <div class="ir-modal-body" id="irModalBody">

        <!-- ① Browser Trust -->
        <div class="ir-modal-sect">
          <div class="ir-sect-title">Browser Trust</div>
          <div class="ir-trust-grid" id="irModalTrust"></div>
        </div>

        <!-- ② Identity -->
        <div class="ir-modal-sect">
          <div class="ir-sect-title">Identity</div>
          <dl class="ir-dl" id="irModalIdentity"></dl>
        </div>

        <!-- ③ Validity & Cryptography -->
        <div class="ir-modal-sect">
          <div class="ir-sect-title">Validity &amp; Cryptography</div>
          <dl class="ir-dl" id="irModalValidity"></dl>
        </div>

        <!-- ④ Capabilities & EKU -->
        <div class="ir-modal-sect">
          <div class="ir-sect-title">Capabilities &amp; Extended Key Usage</div>
          <dl class="ir-dl" id="irModalEku"></dl>
        </div>

        <!-- ⑤ Compliance -->
        <div class="ir-modal-sect" id="irModalComplianceSect">
          <div class="ir-sect-title">Compliance</div>
          <dl class="ir-dl" id="irModalCompliance"></dl>
        </div>

        <!-- ⑥ Certificate PEM -->
        <div class="ir-modal-sect" id="irModalPemSect" style="display:none">
          <div class="ir-sect-title">Certificate (PEM)</div>
          <textarea class="ap-embed-cert-pem" id="irModalPemArea" readonly spellcheck="false"></textarea>
          <div class="ap-embed-cert-actions">
            <button class="ap-embed-cert-btn ap-embed-cert-lint"  id="irModalLint">Lint</button>
            <button class="ap-embed-cert-btn ap-embed-cert-parse" id="irModalParse">Inspect</button>
            <button class="ap-embed-cert-btn ap-embed-cert-copy"  id="irModalCopy">Copy PEM</button>
            <button class="ap-embed-cert-btn ap-embed-cert-dl"    id="irModalDl">Download .pem</button>
          </div>
        </div>

      </div><!-- /.ir-modal-body -->
    </div><!-- /.ir-modal-box -->
  </dialog>

  <script>
  (function () {
    'use strict';

    var initData   = <?= json_encode($irInitialData) ?>;
    var irRows     = [];
    var irSearch   = '';
    var irPage     = 1;
    var irPages    = 1;
    var irTotal    = 0;
    var irTimer    = null;
    var activeRow  = null; // currently open row object

    // ── DOM refs ──────────────────────────────────────────────────────────────
    var searchEl   = document.getElementById('irSearch');
    var clearBtn   = document.getElementById('irClear');
    var spinner    = document.getElementById('irSpinner');
    var metaEl     = document.getElementById('irMeta');
    var tbody      = document.getElementById('irTbody');
    var pagination = document.getElementById('irPagination');

    var modal        = document.getElementById('irModal');
    var modalTitle   = document.getElementById('irModalTitle');
    var modalOwner   = document.getElementById('irModalOwner');
    var modalTrust   = document.getElementById('irModalTrust');
    var modalIdent   = document.getElementById('irModalIdentity');
    var modalValid   = document.getElementById('irModalValidity');
    var modalEku     = document.getElementById('irModalEku');
    var modalCompSect= document.getElementById('irModalComplianceSect');
    var modalComp    = document.getElementById('irModalCompliance');
    var modalPemSect = document.getElementById('irModalPemSect');
    var modalPemArea = document.getElementById('irModalPemArea');
    var modalLint    = document.getElementById('irModalLint');
    var modalParse   = document.getElementById('irModalParse');
    var modalCopy    = document.getElementById('irModalCopy');
    var modalDl      = document.getElementById('irModalDl');

    // ── Escape HTML ───────────────────────────────────────────────────────────
    function esc(s) {
      return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    // ── Classify a browser status string ─────────────────────────────────────
    function statusClass(s) {
      var lc = (s || '').toLowerCase();
      if (!lc || lc === '-') { return 'na'; }
      if (lc.indexOf('included') !== -1 || lc.indexOf('trusted') !== -1) { return 'included'; }
      if (lc.indexOf('pending')  !== -1 || lc.indexOf('transitional') !== -1) { return 'pending'; }
      if (lc.indexOf('removed')  !== -1 || lc.indexOf('rejected') !== -1
          || lc.indexOf('expired') !== -1 || lc.indexOf('not included') !== -1) { return 'removed'; }
      return 'na';
    }

    // ── Compact browser dots (table row) ─────────────────────────────────────
    function renderBrowserDots(row) {
      var browsers = [
        { label: 'Moz',    status: row.mozStatus    },
        { label: 'MS',     status: row.msStatus     },
        { label: 'Apple',  status: row.appleStatus  },
        { label: 'Chrome', status: row.chromeStatus },
      ];
      var dots   = '<div class="br-dots">';
      var labels = '<div class="br-dot-labels">';
      browsers.forEach(function (b) {
        var sc    = statusClass(b.status);
        var title = b.label + ': ' + (b.status || 'N/A');
        dots   += '<span class="br-dot d-' + sc + '" title="' + esc(title) + '"></span>';
        labels += '<span class="br-dot-label" aria-hidden="true">' + esc(b.label.substring(0,3)) + '</span>';
      });
      dots   += '</div>';
      labels += '</div>';
      return dots + labels;
    }

    // ── Render fingerprint (abbr with full value as tooltip) ──────────────────
    function renderFp(sha256) {
      if (!sha256) { return '<span style="color:var(--muted)">—</span>'; }
      var clean = sha256.replace(/:/g, '').toUpperCase();
      return '<abbr title="' + esc(sha256) + '">' + clean.substring(0, 16) + '…</abbr>';
    }

    // ── Render validity (valid-until only) ────────────────────────────────────
    function renderValidUntil(to) {
      if (!to) { return '<span style="color:var(--muted)">—</span>'; }
      var expired = to && (new Date(to)) < new Date();
      return '<span class="vto' + (expired ? ' expired' : '') + '">' + esc(to) + '</span>';
    }

    // ── Compact table row ─────────────────────────────────────────────────────
    function renderRow(row, idx) {
      return '<tr class="ir-row" tabindex="0" role="button" aria-label="View details for '
        + esc(row.certName || row.caOwner) + '" data-idx="' + idx + '">'
        + '<td class="ir-owner">'   + esc(row.caOwner || '—') + '</td>'
        + '<td class="ir-certname">'+ esc(row.certName || '—') + '</td>'
        + '<td class="ir-subject">' + esc(row.subjectCN || row.subjectDN || '—') + '</td>'
        + '<td>' + renderBrowserDots(row) + '</td>'
        + '<td class="ir-valid">'   + renderValidUntil(row.validTo) + '</td>'
        + '<td class="ir-fp">'      + renderFp(row.sha256) + '</td>'
        + '<td class="ir-chevron" aria-hidden="true">›</td>'
        + '</tr>';
    }

    // ── Render table ──────────────────────────────────────────────────────────
    function renderTable(data) {
      irRows  = data.rows  || [];
      irTotal = data.total || 0;
      irPages = data.pages || 1;
      irPage  = data.page  || 1;

      if (!irRows.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="tbl-empty">'
          + (irSearch ? 'No results for &ldquo;' + esc(irSearch) + '&rdquo;.' : 'No rows.')
          + '</td></tr>';
      } else {
        var html = '';
        irRows.forEach(function (row, idx) { html += renderRow(row, idx); });
        tbody.innerHTML = html;
      }

      var unit   = irSearch ? 'result' : 'row';
      var plural = irTotal !== 1 ? 's' : '';
      metaEl.textContent = irTotal.toLocaleString() + ' ' + unit + plural
        + (irPages > 1 ? ' · page ' + irPage + ' of ' + irPages : '');

      renderPagination();
    }

    // ── Pagination ────────────────────────────────────────────────────────────
    function renderPagination() {
      if (irPages <= 1) { pagination.innerHTML = ''; return; }
      var html = '';
      var prev = irPage > 1;
      var next = irPage < irPages;
      html += prev ? '<a href="#" data-p="1" aria-label="First">&laquo;</a>'
                   : '<span aria-disabled="true">&laquo;</span>';
      html += prev ? '<a href="#" data-p="' + (irPage-1) + '" aria-label="Previous">&lsaquo;</a>'
                   : '<span aria-disabled="true">&lsaquo;</span>';
      var s = Math.max(1, irPage - 2), e = Math.min(irPages, irPage + 2);
      if (s > 1) { html += '<span class="dots">&hellip;</span>'; }
      for (var i = s; i <= e; i++) {
        if (i === irPage) { html += '<span class="cur" aria-current="page">' + i + '</span>'; }
        else { html += '<a href="#" data-p="' + i + '" aria-label="Page ' + i + '">' + i + '</a>'; }
      }
      if (e < irPages) { html += '<span class="dots">&hellip;</span>'; }
      html += next ? '<a href="#" data-p="' + (irPage+1) + '" aria-label="Next">&rsaquo;</a>'
                   : '<span aria-disabled="true">&rsaquo;</span>';
      html += next ? '<a href="#" data-p="' + irPages + '" aria-label="Last">&raquo;</a>'
                   : '<span aria-disabled="true">&raquo;</span>';
      pagination.innerHTML = html;
    }

    // ── AJAX fetch ────────────────────────────────────────────────────────────
    function fetchPage(q, page) {
      irSearch = q;
      spinner.classList.add('active');
      var url = '/ccadb.php?tab=included_roots&json=1&q=' + encodeURIComponent(q) + '&p=' + page;
      fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function (r) { return r.json(); })
        .then(function (data) { renderTable(data); })
        .catch(function () {
          tbody.innerHTML = '<tr><td colspan="7" class="tbl-empty">Request failed — please try again.</td></tr>';
        })
        .finally(function () { spinner.classList.remove('active'); });
    }

    // ── Search ────────────────────────────────────────────────────────────────
    searchEl.addEventListener('input', function () {
      var q = this.value;
      clearBtn.style.display = q ? '' : 'none';
      clearTimeout(irTimer);
      irTimer = setTimeout(function () { fetchPage(q, 1); }, 320);
    });

    clearBtn.addEventListener('click', function () {
      searchEl.value = '';
      clearBtn.style.display = 'none';
      fetchPage('', 1);
      searchEl.focus();
    });

    // ── Pagination clicks ─────────────────────────────────────────────────────
    pagination.addEventListener('click', function (e) {
      var a = e.target.closest('a[data-p]');
      if (!a) { return; }
      e.preventDefault();
      fetchPage(irSearch, parseInt(a.dataset.p, 10));
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    // ── Row click (open modal) ────────────────────────────────────────────────
    tbody.addEventListener('click', function (e) {
      var row = e.target.closest('tr.ir-row');
      if (!row) { return; }
      openModal(parseInt(row.dataset.idx, 10));
    });
    tbody.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') { return; }
      var row = e.target.closest('tr.ir-row');
      if (!row) { return; }
      e.preventDefault();
      openModal(parseInt(row.dataset.idx, 10));
    });

    // ── Modal helpers ─────────────────────────────────────────────────────────
    function dlRow(label, value, isLink) {
      var valHtml;
      if (!value || value === '-') {
        valHtml = '<span class="ir-dd-muted">—</span>';
      } else if (isLink && value.match(/^https?:\/\//)) {
        valHtml = '<a href="' + esc(value) + '" target="_blank" rel="noopener noreferrer">'
                + esc(value.length > 60 ? value.substring(0, 57) + '…' : value) + '</a>';
      } else {
        valHtml = esc(value);
      }
      return '<dt class="ir-dt">' + esc(label) + '</dt><dd class="ir-dd">' + valHtml + '</dd>';
    }

    function trustCardHtml(browser, status, evStatus) {
      var sc  = statusClass(status);
      var cardCls = 'ir-trust-card tc-' + sc;
      var statCls = 's-' + sc;
      var ev = evStatus ? '<div class="ir-tc-ev">EV: ' + esc(evStatus) + '</div>' : '';
      return '<div class="' + cardCls + '">'
           + '<div class="ir-tc-browser">' + esc(browser) + '</div>'
           + '<div class="ir-tc-status ' + statCls + '">' + esc(status || 'Not listed') + '</div>'
           + ev
           + '</div>';
    }

    function ekuTagsHtml(src) {
      if (!src || src === '-') { return '<span class="ir-dd-muted" style="font-family:var(--mono);font-size:.75rem">—</span>'; }
      var tags = '';
      src.split(/[;,]+/).forEach(function (item) {
        item = item.trim();
        if (item) { tags += '<span class="ir-eku-tag">' + esc(item) + '</span>'; }
      });
      return '<div class="ir-eku-tags">' + tags + '</div>';
    }

    // ── Open modal ────────────────────────────────────────────────────────────
    function openModal(idx) {
      var r = irRows[idx];
      if (!r) { return; }
      activeRow = r;

      // Header
      modalTitle.textContent = r.certName || r.caOwner || 'Certificate';
      modalOwner.textContent = r.caOwner ? 'CA Owner: ' + r.caOwner : '';

      // ① Browser trust cards
      modalTrust.innerHTML =
        trustCardHtml('Mozilla',   r.mozStatus,    r.mozEvStatus)
      + trustCardHtml('Microsoft', r.msStatus,     r.msEvStatus)
      + trustCardHtml('Apple',     r.appleStatus,  r.appleEvStatus)
      + trustCardHtml('Chrome',    r.chromeStatus, '');

      // ② Identity
      modalIdent.innerHTML =
          dlRow('Certificate Name', r.certName)
        + dlRow('Subject CN',       r.subjectCN)
        + dlRow('Subject O',        r.subjectO)
        + dlRow('Subject OU',       r.subjectOU)
        + dlRow('Issuer CN',        r.issuerCN)
        + dlRow('Issuer O',         r.issuerO)
        + dlRow('Issuer OU',        r.issuerOU)
        + dlRow('Serial Number',    r.serial)
        + dlRow('SHA-256',          r.sha256)
        + dlRow('Subject+SPKI SHA-256', r.spkiSha256);

      // ③ Validity & Crypto
      var expired = r.validTo && (new Date(r.validTo)) < new Date();
      var toHtml  = r.validTo
        ? '<span style="' + (expired ? 'color:var(--red)' : '') + '">' + esc(r.validTo) + (expired ? ' (expired)' : '') + '</span>'
        : '<span class="ir-dd-muted">—</span>';
      modalValid.innerHTML =
          dlRow('Valid From', r.validFrom)
        + '<dt class="ir-dt">Valid To</dt><dd class="ir-dd">' + toHtml + '</dd>'
        + dlRow('Public Key Algo', r.pubKeyAlgo)
        + dlRow('Sig Hash Algo',   r.sigHash);

      // ④ Capabilities / EKU
      modalEku.innerHTML =
          '<dt class="ir-dt">Extended Key Usage</dt><dd class="ir-dd">' + ekuTagsHtml(r.eku || r.trustBits) + '</dd>'
        + dlRow('Trust Bits',       r.trustBits)
        + dlRow('TLS Capable',      r.tlsCapable)
        + dlRow('TLS EV Capable',   r.tlsEvCapable)
        + dlRow('EV Policy OIDs',   r.evPolicies)
        + dlRow('Code Signing',     r.codeSign);

      // ⑤ Compliance
      var compRows = dlRow('CPS URI', r.cpsUri, true)
        + dlRow('Test Website (Valid)',   r.testValid,   true)
        + dlRow('Test Website (Revoked)', r.testRevoked, true)
        + dlRow('Test Website (Expired)', r.testExpired, true);
      modalComp.innerHTML = compRows;

      // ⑥ PEM
      if (r.pem && r.pem.indexOf('CERTIFICATE') !== -1) {
        modalPemArea.value = r.pem;
        modalPemSect.style.display = '';
      } else {
        modalPemSect.style.display = 'none';
      }

      // Scroll body to top
      document.getElementById('irModalBody').scrollTop = 0;
      modal.showModal();
    }

    // ── Close modal ───────────────────────────────────────────────────────────
    function closeModal() {
      modal.close();
      activeRow = null;
    }

    document.getElementById('irModalClose').addEventListener('click', closeModal);
    // Clicks on backdrop (the dialog element itself, outside the box)
    modal.addEventListener('click', function (e) {
      if (e.target === this) { closeModal(); }
    });
    modal.addEventListener('cancel', function (e) { e.preventDefault(); closeModal(); });

    // ── PEM actions ───────────────────────────────────────────────────────────
    modalLint.addEventListener('click', function () {
      if (!activeRow || !activeRow.pem) { return; }
      sessionStorage.setItem('pki_prefill_cert', activeRow.pem);
      window.open('/linters.php', '_blank', 'noopener');
    });

    modalParse.addEventListener('click', function () {
      if (!activeRow || !activeRow.pem) { return; }
      sessionStorage.removeItem('mkt_eseal_cms');
      sessionStorage.removeItem('mkt_eseal_xades');
      sessionStorage.removeItem('meerkat_pem');
      sessionStorage.setItem('pki_prefill_cert', activeRow.pem);
      window.open('/artifact_parser.php', '_blank', 'noopener');
    });

    modalCopy.addEventListener('click', function () {
      if (!activeRow || !activeRow.pem) { return; }
      navigator.clipboard.writeText(activeRow.pem).then(function () {
        var orig = modalCopy.textContent;
        modalCopy.textContent = 'Copied!';
        setTimeout(function () { modalCopy.textContent = orig; }, 1500);
      });
    });

    modalDl.addEventListener('click', function () {
      if (!activeRow || !activeRow.pem) { return; }
      var blob = new Blob([activeRow.pem], { type: 'application/x-pem-file' });
      var url  = URL.createObjectURL(blob);
      var a    = document.createElement('a');
      var name = (activeRow.sha256 || 'certificate').replace(/[^a-zA-Z0-9_-]/g, '').substring(0, 40) || 'certificate';
      a.href = url; a.download = name + '.pem'; a.click();
      URL.revokeObjectURL(url);
    });

    // ── Initial render ────────────────────────────────────────────────────────
    irSearch = searchEl.value;
    if (initData) {
      renderTable(initData);
    } else {
      fetchPage(irSearch, 1);
    }

  }());
  </script>

<?php else: ?>
  <!-- ══════════════════════════════════════════════════════════════════════════
       ALL CERTS — server-side paginated table
  ══════════════════════════════════════════════════════════════════════════ -->

  <?php $colKeys = $rows ? array_keys($rows[0]) : []; ?>

  <form method="GET" action="/ccadb.php" class="toolbar">
    <input type="hidden" name="tab" value="<?= htmlspecialchars($tab) ?>">
    <div class="search-wrap">
      <input type="search" name="q" value="<?= htmlspecialchars($search) ?>"
             placeholder="Search…" autocomplete="off" spellcheck="false">
      <?php if ($search !== ''): ?>
      <button type="button" class="search-clear"
              onclick="this.closest('form').q.value='';this.closest('form').submit();"
              aria-label="Clear search">×</button>
      <?php endif; ?>
    </div>
    <button type="submit" style="display:none;">Search</button>
    <?php if ($total > 0): ?>
    <span class="toolbar-meta">
      <?php
      $unit   = $search !== '' ? 'result' : 'row';
      $plural = $total !== 1 ? 's' : '';
      echo number_format($total) . ' ' . $unit . $plural . ' · page ' . $page . ' of ' . $pages;
      ?>
    </span>
    <?php endif; ?>
  </form>

  <?php if (!$pdo): ?>
  <div class="tbl-empty">Database unavailable.</div>
  <?php elseif ($dbError !== null): ?>
  <div class="tbl-empty">Query error — try again shortly.</div>
  <?php elseif ($syncInfo === null && $total === 0): ?>
  <div class="tbl-empty">No data yet — run <code>cron/ccadb_sync.php</code> to populate.</div>
  <?php elseif (empty($rows)): ?>
  <div class="tbl-empty">
    <?= $search !== '' ? 'No results for &ldquo;' . htmlspecialchars($search) . '&rdquo;.' : 'No rows.' ?>
  </div>
  <?php else: ?>
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <?php foreach ($colKeys as $col): ?>
          <th><?= htmlspecialchars($col) ?></th>
          <?php endforeach; ?>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($rows as $row): ?>
        <tr>
          <?php foreach ($colKeys as $col): ?>
          <td><?= renderCcadbCell((string)($row[$col] ?? '')) ?></td>
          <?php endforeach; ?>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <?php if ($pages > 1): ?>
  <nav class="pagination" aria-label="Page navigation">
    <?php if ($page > 1): ?>
    <a href="<?= htmlspecialchars(ccadbPageUrl(1, $tab, $search)) ?>" aria-label="First">&laquo;</a>
    <a href="<?= htmlspecialchars(ccadbPageUrl($page - 1, $tab, $search)) ?>" aria-label="Previous">&lsaquo;</a>
    <?php else: ?>
    <span aria-disabled="true">&laquo;</span>
    <span aria-disabled="true">&lsaquo;</span>
    <?php endif; ?>

    <?php
    $window = 2;
    $start  = max(1, $page - $window);
    $end    = min($pages, $page + $window);
    if ($start > 1) {
        echo '<span class="dots">…</span>';
    }
    for ($i = $start; $i <= $end; $i++) {
        if ($i === $page) {
            echo '<span class="cur" aria-current="page">' . $i . '</span>';
        } else {
            echo '<a href="' . htmlspecialchars(ccadbPageUrl($i, $tab, $search)) . '" aria-label="Page ' . $i . '">' . $i . '</a>';
        }
    }
    if ($end < $pages) {
        echo '<span class="dots">…</span>';
    }
    ?>

    <?php if ($page < $pages): ?>
    <a href="<?= htmlspecialchars(ccadbPageUrl($page + 1, $tab, $search)) ?>" aria-label="Next">&rsaquo;</a>
    <a href="<?= htmlspecialchars(ccadbPageUrl($pages, $tab, $search)) ?>" aria-label="Last">&raquo;</a>
    <?php else: ?>
    <span aria-disabled="true">&rsaquo;</span>
    <span aria-disabled="true">&raquo;</span>
    <?php endif; ?>
  </nav>
  <?php endif; ?>
  <?php endif; ?>

<?php endif; ?>

</div><!-- /.page -->
</body>
</html>
