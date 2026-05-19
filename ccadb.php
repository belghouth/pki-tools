<?php
/**
 * ccadb.php — CCADB public resource browser
 *
 * Tabbed viewer for cached CCADB CSV data (CAA Identifiers, Problem Reporting
 * Mechanisms, All Certificate Records). Data is populated by cron/ccadb_sync.php.
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
    'caa' => [
        'name'  => 'CAA Identifiers',
        'label' => 'CAA',
        'desc'  => 'Authorized CA DNS names from CA entries in the CCADB.',
    ],
    'problem_reporting' => [
        'name'  => 'Problem Reporting Mechanisms',
        'label' => 'Problem Reporting',
        'desc'  => 'Mechanisms CAs provide for reporting certificate problems.',
    ],
    'all_certs' => [
        'name'  => 'All Certificate Records',
        'label' => 'All Certs',
        'desc'  => 'All CA certificates disclosed in the CCADB (v2 format).',
    ],
];

const CCADB_PER_PAGE = 50;

// ── Input ─────────────────────────────────────────────────────────────────────

$validTabs = array_keys(CCADB_RESOURCES);
$tab       = in_array($_GET['tab'] ?? '', $validTabs, true) ? $_GET['tab'] : 'caa';
$search    = trim(substr($_GET['q'] ?? '', 0, 200));
$page      = max(1, (int)($_GET['p'] ?? 1));

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

$pages     = $total > 0 ? (int)ceil($total / CCADB_PER_PAGE) : 1;
$page      = min($page, $pages);
$colKeys   = $rows ? array_keys($rows[0]) : [];
$tabRes    = CCADB_RESOURCES[$tab];

// ── Pagination helper ─────────────────────────────────────────────────────────

function ccadbPageUrl(int $p, string $tab, string $q): string {
    $params = ['tab' => $tab, 'p' => $p];
    if ($q !== '') {
        $params['q'] = $q;
    }
    return '/ccadb.php?' . http_build_query($params);
}

// ── HTML ──────────────────────────────────────────────────────────────────────

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
    'description' => 'Browse cached CCADB public data: CAA Identifiers, Problem Reporting Mechanisms, and All Certificate Records. Updated weekly.',
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
      border-bottom: 1px solid var(--border);
      margin-bottom: 1.5rem; padding-bottom: 0;
    }
    .tab-btn {
      font-family: var(--sans); font-size: 0.82rem; font-weight: 400;
      color: var(--muted); background: none; border: none;
      padding: 0.55rem 1rem; border-radius: 6px 6px 0 0;
      cursor: pointer; text-decoration: none; border-bottom: 2px solid transparent;
      transition: color 150ms ease, border-color 150ms ease;
      margin-bottom: -1px;
    }
    .tab-btn:hover   { color: var(--text); }
    .tab-btn.active  { color: var(--accent); border-bottom-color: var(--accent); font-weight: 500; }

    /* ── Toolbar ── */
    .toolbar {
      display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;
      margin-bottom: 1rem;
    }
    .search-wrap { position: relative; flex: 0 0 320px; }
    .search-wrap input {
      width: 100%; background: var(--surface); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text); font-family: var(--mono);
      font-size: 0.8rem; padding: 0.45rem 2.2rem 0.45rem 0.75rem;
      outline: none;
      transition: border-color 150ms ease;
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

    /* ── Table ── */
    .tbl-wrap {
      overflow-x: auto;
      border: 1px solid var(--border); border-radius: var(--radius);
    }
    table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
    thead th {
      background: #1a1f28; color: var(--muted);
      font-family: var(--mono); font-size: 0.7rem; font-weight: 600;
      letter-spacing: 0.05em; text-transform: uppercase;
      padding: 0.6rem 0.85rem; text-align: left;
      border-bottom: 1px solid var(--border); white-space: nowrap;
    }
    tbody tr { border-bottom: 1px solid #1e2430; }
    tbody tr:last-child { border-bottom: none; }
    tbody tr:hover { background: rgba(255,255,255,0.025); }
    tbody td { padding: 0.5rem 0.85rem; vertical-align: top; max-width: 420px; word-break: break-word; }
    tbody td a { color: var(--accent); }
    tbody td a:hover { color: #fff; text-decoration: underline; }

    /* empty / loading states */
    .tbl-empty {
      text-align: center; padding: 4rem 1rem;
      color: var(--muted); font-family: var(--mono); font-size: 0.82rem;
    }

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
    .sync-badge.stale .dot { background: #f5a623; }
    .sync-badge.never .dot { background: #e85555; }

    @media (max-width: 600px) {
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
  <nav class="tab-nav" role="tablist">
    <?php foreach (CCADB_RESOURCES as $key => $res): ?>
    <a href="/ccadb.php?tab=<?= urlencode($key) ?>"
       class="tab-btn<?= $tab === $key ? ' active' : '' ?>"
       role="tab"
       aria-selected="<?= $tab === $key ? 'true' : 'false' ?>"><?= htmlspecialchars($res['label']) ?></a>
    <?php endforeach; ?>
  </nav>

  <!-- ── Tab description + sync info ── -->
  <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;flex-wrap:wrap;">
    <p style="font-size:0.82rem;color:var(--muted);"><?= htmlspecialchars($tabRes['desc']) ?></p>
    <?php
    $syncClass = 'never';
    $syncText  = 'Never synced';
    if ($syncInfo) {
        $syncDate = new DateTimeImmutable($syncInfo['synced_at'] . ' UTC');
        $now      = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $ageDays  = (int)$now->diff($syncDate)->days;
        $syncClass = $ageDays > 10 ? 'stale' : '';
        $syncText  = 'Synced ' . $syncDate->format('Y-m-d') . ' · ' . number_format($syncInfo['row_count']) . ' rows';
    }
    ?>
    <span class="sync-badge <?= $syncClass ?>"><span class="dot"></span><?= htmlspecialchars($syncText) ?></span>
  </div>

  <!-- ── Search + meta toolbar ── -->
  <form method="GET" action="/ccadb.php" class="toolbar">
    <input type="hidden" name="tab" value="<?= htmlspecialchars($tab) ?>">
    <div class="search-wrap">
      <input type="search" name="q" value="<?= htmlspecialchars($search) ?>"
             placeholder="Search…" autocomplete="off" spellcheck="false">
      <?php if ($search !== ''): ?>
      <button type="button" class="search-clear" onclick="this.closest('form').q.value='';this.closest('form').submit();" aria-label="Clear search">×</button>
      <?php endif; ?>
    </div>
    <button type="submit" style="display:none;">Search</button>
    <?php if ($total > 0): ?>
    <span class="toolbar-meta">
      <?= number_format($total) ?> <?= $search !== '' ? 'result' . ($total !== 1 ? 's' : '') : 'row' . ($total !== 1 ? 's' : '') ?>
      · page <?= $page ?> of <?= $pages ?>
    </span>
    <?php endif; ?>
  </form>

  <!-- ── Table ── -->
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
          <?php $val = $row[$col] ?? ''; ?>
          <td><?= renderCcadbCell($val) ?></td>
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
    <a href="<?= htmlspecialchars(ccadbPageUrl(1, $tab, $search)) ?>" aria-label="First page">&laquo;</a>
    <a href="<?= htmlspecialchars(ccadbPageUrl($page - 1, $tab, $search)) ?>" aria-label="Previous page">&lsaquo;</a>
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
    <a href="<?= htmlspecialchars(ccadbPageUrl($page + 1, $tab, $search)) ?>" aria-label="Next page">&rsaquo;</a>
    <a href="<?= htmlspecialchars(ccadbPageUrl($pages, $tab, $search)) ?>" aria-label="Last page">&raquo;</a>
    <?php else: ?>
    <span aria-disabled="true">&rsaquo;</span>
    <span aria-disabled="true">&raquo;</span>
    <?php endif; ?>
  </nav>
  <?php endif; ?>

  <?php endif; ?>

</div><!-- /.page -->

</body>
</html>
<?php

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
