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
 * Find a value in a row by trying exact then partial key matches (case-insensitive).
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
 * Extract structured fields from a raw CCADB included-roots row.
 * Column names are matched case-insensitively to cope with CSV header variations.
 */
function ccadbExtractIncludedRoot(array $row): array {
    $cn = ccadbFindInRow($row, 'Certificate Subject Common Name');
    $o  = ccadbFindInRow($row, 'Certificate Subject Organization');
    $ou = ccadbFindInRow($row, 'Certificate Subject Organizational Unit');
    $dnParts = [];
    if ($cn !== '') {
        $dnParts[] = 'CN=' . $cn;
    }
    if ($ou !== '') {
        $dnParts[] = 'OU=' . $ou;
    }
    if ($o !== '') {
        $dnParts[] = 'O=' . $o;
    }

    $pem = trim(trim(ccadbFindInRow($row, 'PEM Info', 'PEM'), '"\''));
    if ($pem !== '' && !str_contains($pem, '-----')) {
        $pem = "-----BEGIN CERTIFICATE-----\n" . wordwrap($pem, 64, "\n", true) . "\n-----END CERTIFICATE-----";
    }

    return [
        'caOwner'      => ccadbFindInRow($row, 'CA Owner'),
        'certName'     => ccadbFindInRow($row, 'Certificate Name', 'CA Owner/Certificate Name'),
        'subjectDN'    => implode(', ', $dnParts),
        'sha256'       => ccadbFindInRow($row, 'SHA-256 Fingerprint', 'SHA256 Fingerprint', 'Fingerprint'),
        'validFrom'    => ccadbFindInRow($row, 'Valid From [GMT]', 'Valid From', 'Not Before'),
        'validTo'      => ccadbFindInRow($row, 'Valid To [GMT]', 'Valid To', 'Not After'),
        'eku'          => ccadbFindInRow($row, 'Extended Key Usage'),
        'trustBits'    => ccadbFindInRow($row, 'Trust Bits'),
        'mozStatus'    => ccadbFindInRow($row, 'Mozilla Status'),
        'msStatus'     => ccadbFindInRow($row, 'Microsoft Status'),
        'appleStatus'  => ccadbFindInRow($row, 'Apple Root Certificate Status', 'Apple Status'),
        'chromeStatus' => ccadbFindInRow($row, 'Google Chrome Inclusion Status', 'Chrome Status'),
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
    .page { max-width: 1600px; margin: 0 auto; padding: 2.5rem 1.5rem 6rem; }
    .page-hd { margin-bottom: 1.8rem; }
    .page-hd h1 { font-size: 1.75rem; font-weight: 600; color: #fff; margin-bottom: 0.25rem; }
    .page-hd p  { font-size: 0.85rem; color: var(--muted); }

    /* ── Tabs ── */
    .tab-nav {
      display: flex; align-items: center; gap: 0.25rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1.5rem;
    }
    .tab-btn {
      font-family: var(--sans); font-size: 0.82rem; font-weight: 400;
      color: var(--muted); background: none; border: none;
      padding: 0.55rem 1rem; border-radius: 6px 6px 0 0;
      cursor: pointer; text-decoration: none; border-bottom: 2px solid transparent;
      transition: color 150ms, border-color 150ms;
      margin-bottom: -1px;
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
      font-family: var(--mono); font-size: 0.7rem; font-weight: 600;
      letter-spacing: 0.05em; text-transform: uppercase;
      padding: 0.6rem 0.85rem; text-align: left;
      border-bottom: 1px solid var(--border); white-space: nowrap;
    }
    tbody tr { border-bottom: 1px solid #1e2430; transition: background 80ms; }
    tbody tr:last-child { border-bottom: none; }
    tbody tr:hover { background: rgba(255,255,255,0.03); }
    tbody td { padding: 0.5rem 0.85rem; vertical-align: top; }
    tbody td a { color: var(--accent); }
    tbody td a:hover { color: #fff; text-decoration: underline; }

    /* ── Included-roots specific ── */
    .ir-owner { font-weight: 500; color: #e8edf7; max-width: 200px; word-break: break-word; }
    .ir-certname { color: var(--text); max-width: 220px; word-break: break-word; font-size: 0.76rem; }
    .ir-dn {
      font-family: var(--mono); font-size: 0.68rem; color: var(--muted);
      max-width: 280px; word-break: break-all; line-height: 1.5;
    }
    .ir-fp {
      font-family: var(--mono); font-size: 0.68rem; color: #8892a4;
      white-space: nowrap;
    }
    .ir-fp abbr { text-decoration: none; cursor: default; }
    .ir-valid { font-family: var(--mono); font-size: 0.68rem; color: var(--muted); white-space: nowrap; }
    .ir-valid .valid-to.expired { color: var(--red); }
    .ir-trust { max-width: 260px; }

    /* ── Browser status pills ── */
    .br-pills { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-bottom: 0.4rem; }
    .br-pill {
      display: inline-flex; align-items: center; gap: 0.25rem;
      font-size: 0.65rem; font-family: var(--mono);
      border: 1px solid; border-radius: 3px;
      padding: 0.1rem 0.4rem; white-space: nowrap; line-height: 1.5;
    }
    .br-pill.pill-included { color: #00d4aa; border-color: rgba(0,212,170,0.4); background: rgba(0,212,170,0.06); }
    .br-pill.pill-pending  { color: #f5a623; border-color: rgba(245,166,35,0.4);  background: rgba(245,166,35,0.06); }
    .br-pill.pill-removed  { color: #e85555; border-color: rgba(232,85,85,0.4);   background: rgba(232,85,85,0.06); }
    .br-pill.pill-other    { color: var(--muted); border-color: var(--border); }
    .br-label { font-weight: 600; opacity: 0.75; }

    /* ── EKU tags ── */
    .eku-tags { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-top: 0.2rem; }
    .eku-tag {
      font-size: 0.63rem; font-family: var(--mono);
      background: rgba(167,139,250,0.1); color: var(--purple);
      border: 1px solid rgba(167,139,250,0.3); border-radius: 3px;
      padding: 0.05rem 0.35rem; white-space: nowrap;
    }

    /* ── Action buttons ── */
    .ir-actions { white-space: nowrap; }
    .ir-btn {
      display: inline-flex; align-items: center; justify-content: center;
      font-family: var(--mono); font-size: 0.65rem; font-weight: 600;
      border-radius: 4px; border: 1px solid; cursor: pointer;
      padding: 0.18rem 0.5rem; line-height: 1.4;
      background: none; transition: background 120ms, border-color 120ms, color 120ms;
      margin: 0.15rem 0.1rem 0 0;
    }
    .ir-btn-dl    { color: #8892a4; border-color: #2a3040; }
    .ir-btn-dl:hover    { color: var(--text); border-color: #3a4458; background: rgba(255,255,255,0.04); }
    .ir-btn-view  { color: #8892a4; border-color: #2a3040; }
    .ir-btn-view:hover  { color: var(--text); border-color: #3a4458; background: rgba(255,255,255,0.04); }
    .ir-btn-lint  { color: var(--accent); border-color: rgba(0,212,170,0.35); }
    .ir-btn-lint:hover  { background: rgba(0,212,170,0.08); border-color: var(--accent); }
    .ir-btn-parse { color: var(--purple); border-color: rgba(167,139,250,0.35); }
    .ir-btn-parse:hover { background: rgba(167,139,250,0.08); border-color: var(--purple); }

    /* ── Empty / loading ── */
    .tbl-empty { text-align: center; padding: 4rem 1rem; color: var(--muted); font-family: var(--mono); font-size: 0.82rem; }
    .tbl-loading { text-align: center; padding: 3rem 1rem; color: var(--muted); font-size: 0.82rem; }

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

    /* ── Certificate Modal ── */
    dialog.cert-modal-box {
      background: #13171e; border: 1px solid #2a3040;
      border-radius: 10px; width: min(800px, 95vw);
      max-height: 90vh; display: flex; flex-direction: column;
      box-shadow: 0 24px 80px rgba(0,0,0,0.7);
      padding: 0; color: var(--text);
    }
    dialog.cert-modal-box::backdrop {
      background: rgba(0,0,0,0.75); backdrop-filter: blur(4px);
    }
    .cert-modal-hd {
      display: flex; align-items: center; gap: 0.75rem;
      padding: 1rem 1.25rem; border-bottom: 1px solid #2a3040; flex-shrink: 0;
    }
    .cert-modal-hd h2 { font-size: 0.9rem; font-weight: 600; color: #fff; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .cert-modal-close {
      background: none; border: none; color: var(--muted); cursor: pointer;
      font-size: 1.3rem; line-height: 1; padding: 0.2rem;
      border-radius: 4px; flex-shrink: 0;
    }
    .cert-modal-close:hover { color: var(--text); background: rgba(255,255,255,0.06); }
    .cert-modal-body { overflow-y: auto; padding: 1rem 1.25rem; flex: 1; }
    .cert-modal-pem {
      font-family: var(--mono); font-size: 0.72rem; color: #a8b8cc;
      line-height: 1.6; white-space: pre-wrap; word-break: break-all;
      background: #0b0e14; border: 1px solid #1e2430; border-radius: 6px;
      padding: 1rem; margin-bottom: 0.75rem;
    }
    .cert-modal-ft {
      display: flex; gap: 0.6rem; flex-wrap: wrap;
      padding: 0.75rem 1.25rem; border-top: 1px solid #1e2430; flex-shrink: 0;
    }
    .cert-modal-btn {
      font-family: var(--mono); font-size: 0.72rem; border-radius: 5px;
      border: 1px solid; cursor: pointer; padding: 0.3rem 0.75rem;
      background: none; transition: background 120ms;
    }
    .cert-modal-btn-copy  { color: var(--accent); border-color: rgba(0,212,170,0.35); }
    .cert-modal-btn-copy:hover  { background: rgba(0,212,170,0.08); }
    .cert-modal-btn-lint  { color: var(--accent); border-color: rgba(0,212,170,0.35); }
    .cert-modal-btn-lint:hover  { background: rgba(0,212,170,0.08); }
    .cert-modal-btn-parse { color: var(--purple); border-color: rgba(167,139,250,0.35); }
    .cert-modal-btn-parse:hover { background: rgba(167,139,250,0.08); }

    @media (max-width: 640px) {
      .search-wrap { flex: 1 1 100%; }
      .toolbar-meta { margin-left: 0; width: 100%; }
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
       INCLUDED ROOTS — live-search AJAX table
  ══════════════════════════════════════════════════════════════════════════ -->

  <div class="toolbar">
    <div class="search-wrap">
      <input type="search" id="irSearch" value="<?= htmlspecialchars($search) ?>"
             placeholder="Search CA owner, certificate name, DN…"
             autocomplete="off" spellcheck="false" aria-label="Search">
      <button type="button" class="search-clear" id="irClear" style="<?= $search === '' ? 'display:none' : '' ?>"
              aria-label="Clear search">×</button>
    </div>
    <div class="search-spinner" id="irSpinner"></div>
    <span class="toolbar-meta" id="irMeta"></span>
  </div>

  <div class="tbl-wrap" id="irTableWrap">
    <table id="irTable">
      <thead>
        <tr>
          <th>CA Owner</th>
          <th>Certificate Name</th>
          <th>Subject DN</th>
          <th>SHA-256</th>
          <th>Validity</th>
          <th>Trust &amp; EKU</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="irTbody">
        <tr><td colspan="7" class="tbl-loading">Loading…</td></tr>
      </tbody>
    </table>
  </div>

  <nav class="pagination" id="irPagination" aria-label="Page navigation"></nav>

  <!-- ── Certificate Modal ── -->
  <dialog class="cert-modal-box" id="certModal" aria-labelledby="certModalTitle">
    <div class="cert-modal-hd">
      <h2 id="certModalTitle">Certificate</h2>
      <button class="cert-modal-close" id="certModalClose" aria-label="Close">×</button>
    </div>
    <div class="cert-modal-body">
      <pre class="cert-modal-pem" id="certModalPem"></pre>
    </div>
    <div class="cert-modal-ft">
      <button class="cert-modal-btn cert-modal-btn-copy" id="certModalCopy">Copy PEM</button>
      <button class="cert-modal-btn cert-modal-btn-lint" id="certModalLint">Open in Linters</button>
      <button class="cert-modal-btn cert-modal-btn-parse" id="certModalParse">Open in Artifact Parser</button>
    </div>
  </dialog>

  <script>
  (function () {
    'use strict';

    // ── Initial data injected by PHP ──────────────────────────────────────────
    var initData = <?= json_encode($irInitialData) ?>;
    var irRows   = [];   // current page row objects
    var irPage   = 1;
    var irPages  = 1;
    var irTotal  = 0;
    var irSearch = '';
    var irTimer  = null;
    var modalPem = '';

    // ── DOM refs ──────────────────────────────────────────────────────────────
    var searchEl   = document.getElementById('irSearch');
    var clearBtn   = document.getElementById('irClear');
    var spinner    = document.getElementById('irSpinner');
    var metaEl     = document.getElementById('irMeta');
    var tbody      = document.getElementById('irTbody');
    var pagination = document.getElementById('irPagination');
    var modal      = document.getElementById('certModal');
    var modalTitle = document.getElementById('certModalTitle');
    var modalPemEl = document.getElementById('certModalPem');
    var modalCopy  = document.getElementById('certModalCopy');
    var modalLint  = document.getElementById('certModalLint');
    var modalParse = document.getElementById('certModalParse');

    // ── Escape HTML ───────────────────────────────────────────────────────────
    function esc(s) {
      return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    // ── Browser status pill class ─────────────────────────────────────────────
    function pillClass(status) {
      var lc = (status || '').toLowerCase();
      if (!lc || lc === '-') return '';
      if (lc.indexOf('included') !== -1 || lc.indexOf('trusted') !== -1 || lc.indexOf('approved') !== -1) return 'pill-included';
      if (lc.indexOf('pending') !== -1 || lc.indexOf('transitional') !== -1) return 'pill-pending';
      if (lc.indexOf('removed') !== -1 || lc.indexOf('rejected') !== -1 || lc.indexOf('expired') !== -1 || lc.indexOf('not included') !== -1) return 'pill-removed';
      return 'pill-other';
    }

    // ── Render browser status + EKU cell ─────────────────────────────────────
    function renderTrustCell(row) {
      var html = '<div class="br-pills">';
      var browsers = [
        ['Moz', row.mozStatus],
        ['MS',  row.msStatus],
        ['Apple', row.appleStatus],
        ['Chrome', row.chromeStatus],
      ];
      var anyBrowser = false;
      browsers.forEach(function(b) {
        var name = b[0], status = b[1] || '';
        if (!status || status === '-' || status === '') return;
        var cls = pillClass(status);
        if (!cls) return;
        anyBrowser = true;
        html += '<span class="br-pill ' + cls + '"><span class="br-label">' + esc(name) + '</span> ' + esc(status) + '</span>';
      });
      if (!anyBrowser) html += '<span style="color:var(--muted);font-size:0.7rem">—</span>';
      html += '</div>';

      // EKU tags
      var ekuSrc = row.eku || row.trustBits || '';
      if (ekuSrc && ekuSrc !== '-') {
        var items = ekuSrc.split(/[;,]+/);
        html += '<div class="eku-tags">';
        items.forEach(function(item) {
          item = item.trim();
          if (item) html += '<span class="eku-tag">' + esc(item) + '</span>';
        });
        html += '</div>';
      }
      return html;
    }

    // ── Render fingerprint (truncated with tooltip) ───────────────────────────
    function renderFp(sha256) {
      if (!sha256) return '<span style="color:var(--muted)">—</span>';
      var short = sha256.replace(/:/g, '').substring(0, 16).toUpperCase();
      return '<abbr title="' + esc(sha256) + '">' + esc(short) + '…</abbr>';
    }

    // ── Render validity dates ─────────────────────────────────────────────────
    function renderValidity(from, to) {
      var now  = new Date();
      var toDate = to ? new Date(to) : null;
      var expiredClass = (toDate && toDate < now) ? ' expired' : '';
      var f = from || '—';
      var t = to   || '—';
      return '<span style="display:block">' + esc(f) + '</span>'
           + '<span class="valid-to' + expiredClass + '">' + esc(t) + '</span>';
    }

    // ── Render one table row ──────────────────────────────────────────────────
    function renderRow(row, idx) {
      var hasPem = !!(row.pem && row.pem.indexOf('CERTIFICATE') !== -1);
      var actions = '';
      if (hasPem) {
        actions += '<button class="ir-btn ir-btn-dl"   onclick="irDownload(' + idx + ')" title="Download certificate">↓ DL</button>';
        actions += '<button class="ir-btn ir-btn-view" onclick="irModal(' + idx + ')"    title="View certificate PEM">⊕ View</button>';
        actions += '<button class="ir-btn ir-btn-lint" onclick="irLint(' + idx + ')"    title="Lint in linters.php">Lint</button>';
        actions += '<button class="ir-btn ir-btn-parse" onclick="irParse(' + idx + ')"  title="Inspect in Artifact Parser">Parse</button>';
      }
      return '<tr>'
        + '<td class="ir-owner">'    + esc(row.caOwner)   + '</td>'
        + '<td class="ir-certname">' + esc(row.certName)  + '</td>'
        + '<td class="ir-dn">'       + esc(row.subjectDN) + '</td>'
        + '<td class="ir-fp">'       + renderFp(row.sha256) + '</td>'
        + '<td class="ir-valid">'    + renderValidity(row.validFrom, row.validTo) + '</td>'
        + '<td class="ir-trust">'    + renderTrustCell(row) + '</td>'
        + '<td class="ir-actions">'  + actions + '</td>'
        + '</tr>';
    }

    // ── Render table body ─────────────────────────────────────────────────────
    function renderTable(data) {
      irRows  = data.rows  || [];
      irTotal = data.total || 0;
      irPages = data.pages || 1;
      irPage  = data.page  || 1;

      if (!irRows.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="tbl-empty">'
          + (irSearch ? 'No results for &ldquo;' + esc(irSearch) + '&rdquo;.' : 'No rows.') + '</td></tr>';
      } else {
        var html = '';
        irRows.forEach(function(row, idx) { html += renderRow(row, idx); });
        tbody.innerHTML = html;
      }

      // Meta
      var unit   = irSearch ? 'result' : 'row';
      var plural = irTotal !== 1 ? 's' : '';
      metaEl.textContent = irTotal.toLocaleString() + ' ' + unit + plural
        + (irPages > 1 ? ' · page ' + irPage + ' of ' + irPages : '');

      renderPagination();
    }

    // ── Render pagination ─────────────────────────────────────────────────────
    function renderPagination() {
      if (irPages <= 1) { pagination.innerHTML = ''; return; }

      var html = '';
      var prev = irPage > 1;
      var next = irPage < irPages;

      html += prev ? '<a href="#" data-p="1" aria-label="First">&laquo;</a>'
                   : '<span aria-disabled="true">&laquo;</span>';
      html += prev ? '<a href="#" data-p="' + (irPage - 1) + '" aria-label="Previous">&lsaquo;</a>'
                   : '<span aria-disabled="true">&lsaquo;</span>';

      var win = 2;
      var s   = Math.max(1, irPage - win);
      var e   = Math.min(irPages, irPage + win);
      if (s > 1) html += '<span class="dots">&hellip;</span>';
      for (var i = s; i <= e; i++) {
        if (i === irPage) html += '<span class="cur" aria-current="page">' + i + '</span>';
        else html += '<a href="#" data-p="' + i + '" aria-label="Page ' + i + '">' + i + '</a>';
      }
      if (e < irPages) html += '<span class="dots">&hellip;</span>';

      html += next ? '<a href="#" data-p="' + (irPage + 1) + '" aria-label="Next">&rsaquo;</a>'
                   : '<span aria-disabled="true">&rsaquo;</span>';
      html += next ? '<a href="#" data-p="' + irPages + '" aria-label="Last">&raquo;</a>'
                   : '<span aria-disabled="true">&raquo;</span>';

      pagination.innerHTML = html;
    }

    // ── Fetch from server ─────────────────────────────────────────────────────
    function fetchPage(q, page) {
      irSearch = q;
      spinner.classList.add('active');
      var url = '/ccadb.php?tab=included_roots&json=1&q=' + encodeURIComponent(q) + '&p=' + page;
      fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function(r) { return r.json(); })
        .then(function(data) { renderTable(data); })
        .catch(function() {
          tbody.innerHTML = '<tr><td colspan="7" class="tbl-empty">Request failed — please try again.</td></tr>';
        })
        .finally(function() { spinner.classList.remove('active'); });
    }

    // ── Search input handler ──────────────────────────────────────────────────
    searchEl.addEventListener('input', function() {
      var q = this.value;
      clearBtn.style.display = q ? '' : 'none';
      clearTimeout(irTimer);
      irTimer = setTimeout(function() { fetchPage(q, 1); }, 320);
    });

    clearBtn.addEventListener('click', function() {
      searchEl.value = '';
      clearBtn.style.display = 'none';
      fetchPage('', 1);
      searchEl.focus();
    });

    // ── Pagination click ──────────────────────────────────────────────────────
    pagination.addEventListener('click', function(e) {
      var a = e.target.closest('a[data-p]');
      if (!a) return;
      e.preventDefault();
      fetchPage(irSearch, parseInt(a.dataset.p, 10));
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    // ── Action: download ──────────────────────────────────────────────────────
    window.irDownload = function(idx) {
      var row = irRows[idx];
      if (!row || !row.pem) return;
      var blob = new Blob([row.pem], { type: 'application/x-pem-file' });
      var url  = URL.createObjectURL(blob);
      var a    = document.createElement('a');
      var name = (row.sha256 || 'certificate').replace(/[^a-zA-Z0-9_-]/g, '').substring(0, 40) || 'certificate';
      a.href = url; a.download = name + '.pem'; a.click();
      URL.revokeObjectURL(url);
    };

    // ── Action: modal ─────────────────────────────────────────────────────────
    window.irModal = function(idx) {
      var row = irRows[idx];
      if (!row || !row.pem) { return; }
      modalPem = row.pem;
      modalTitle.textContent = row.certName || row.caOwner || 'Certificate';
      modalPemEl.textContent = row.pem;
      modal.showModal();
    };

    function closeModal() {
      modal.close();
    }

    document.getElementById('certModalClose').addEventListener('click', closeModal);
    modal.addEventListener('click', function(e) { if (e.target === modal) { closeModal(); } });
    // <dialog> handles Escape natively; this listener is a belt-and-suspenders fallback.
    modal.addEventListener('cancel', function(e) { e.preventDefault(); closeModal(); });

    modalCopy.addEventListener('click', function() {
      if (!modalPem) return;
      navigator.clipboard.writeText(modalPem).then(function() {
        var orig = modalCopy.textContent;
        modalCopy.textContent = 'Copied!';
        setTimeout(function() { modalCopy.textContent = orig; }, 1500);
      });
    });

    modalLint.addEventListener('click', function() {
      if (!modalPem) return;
      sessionStorage.setItem('pki_prefill_cert', modalPem);
      window.open('/linters.php', '_blank', 'noopener');
      closeModal();
    });

    modalParse.addEventListener('click', function() {
      if (!modalPem) return;
      sessionStorage.setItem('pki_prefill_cert', modalPem);
      window.open('/artifact_parser.php', '_blank', 'noopener');
      closeModal();
    });

    // ── Action: lint (direct) ─────────────────────────────────────────────────
    window.irLint = function(idx) {
      var row = irRows[idx];
      if (!row || !row.pem) return;
      sessionStorage.setItem('pki_prefill_cert', row.pem);
      window.open('/linters.php', '_blank', 'noopener');
    };

    // ── Action: parse (direct) ────────────────────────────────────────────────
    window.irParse = function(idx) {
      var row = irRows[idx];
      if (!row || !row.pem) return;
      sessionStorage.setItem('pki_prefill_cert', row.pem);
      window.open('/artifact_parser.php', '_blank', 'noopener');
    };

    // ── Initial render from PHP data ──────────────────────────────────────────
    if (initData) {
      irSearch = searchEl.value;
      renderTable(initData);
    } else {
      fetchPage(searchEl.value, 1);
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
  <div class="tbl-empty"><?= $search !== '' ? 'No results for &ldquo;' . htmlspecialchars($search) . '&rdquo;.' : 'No rows.' ?></div>
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

  <!-- ── Pagination ── -->
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
