<?php
define('ADMIN_NO_LOG', true);
require_once __DIR__ . '/config.php';

$email = admin_auth_check();
if (!$email) { header('Location: ' . ADMIN_LOGIN_URL, true, 302); exit; }

$pdo = admin_pdo();

// ── Helpers ───────────────────────────────────────────────────────────────────
$TOOL_NAMES = [
    'index.php'              => 'Home',
    'x509parse.php'          => 'X.509 Parser',
    'cert_factory.php'       => 'TLS Cert Factory',
    'mpca_factory.php'       => 'MPCA Factory',
    'linters.php'            => 'Multi-Linter',
    'artifact_parser.php'    => 'Artifact Parser',
    'cps_to_br_assessor.php' => 'CPS-to-BR Assessor',
    'csr_generator.php'      => 'CSR Generator',
    'ct_log.php'             => 'CT Log API',
    'ct_log_doc.php'         => 'CT Log Docs',
    'tsa.php'                => 'TSA API',
    'tsa_doc.php'            => 'TSA Docs',
    'timestamp_it.php'       => 'TimeStampIt',
    'eseal.php'              => 'e-Seal API',
    'eseal_doc.php'          => 'e-Seal Docs',
    'eseal_signer.php'       => 'e-Seal Signer',
    'acme-endpoint.php'      => 'ACME Endpoint',
    'acme_tester.php'        => 'ACME Tester',
    'revocation.php'         => 'Revocation',
    'feed.php'               => 'News Feed',
    'community_tools.php'    => 'Community Tools',
    'references.php'         => 'References',
    'privacy.php'            => 'Privacy',
];
$tool_name = fn(string $s) => $TOOL_NAMES[$s] ?? $s;

function status_badge(int $s): string {
    $c = match(true) { $s < 300 => 'ok', $s < 400 => 'redir', $s < 500 => 'warn', default => 'err' };
    return "<span class=\"badge badge--$c\">$s</span>";
}
function method_badge(string $m): string {
    $c = match($m) { 'GET' => 'get', 'POST' => 'post', default => 'oth' };
    return "<span class=\"badge badge--$c\">$m</span>";
}
function ua_label(string $ua): string {
    if ($ua === '') return '<span class="muted">—</span>';
    if (preg_match('/bot|crawl|spider|slurp|python|curl|wget|go-http|libwww|java|scrapy|zgrab|nuclei/i', $ua))
        return '<span class="ua-bot" title="'.htmlspecialchars($ua).'">bot</span>';
    if (preg_match('/(Edg|OPR|Firefox|Chrome|Safari)\b/i', $ua, $m))
        return '<span class="ua-browser" title="'.htmlspecialchars($ua).'">'.htmlspecialchars($m[1]).'</span>';
    return '<span class="muted" title="'.htmlspecialchars($ua).'">'.htmlspecialchars(substr($ua, 0, 20)).'…</span>';
}
function rel_time(string $dt): string {
    $d = time() - strtotime($dt . ' UTC');
    if ($d < 60)    return $d . 's ago';
    if ($d < 3600)  return floor($d/60) . 'm ago';
    if ($d < 86400) return floor($d/3600) . 'h ago';
    return floor($d/86400) . 'd ago';
}
function q(array $over = [], array $drop = []): string {
    $p = array_filter($_GET, fn($v) => $v !== '');
    foreach ($drop as $k) unset($p[$k]);
    unset($p['page']);
    return '?' . http_build_query(array_merge($p, $over));
}
function pg_url(int $p): string {
    return '?' . http_build_query(array_merge(array_filter($_GET, fn($v) => $v !== ''), ['page' => $p]));
}

// ── Filters ───────────────────────────────────────────────────────────────────
$period  = in_array($_GET['period'] ?? '24h', ['24h', '7d', '30d']) ? $_GET['period'] : '24h';
$fip     = preg_replace('/[^\d\.:a-fA-F]/', '', $_GET['ip']     ?? '');
$fstatus = $_GET['status'] ?? '';
$fmethod = strtoupper(preg_replace('/[^A-Za-z]/', '', $_GET['method'] ?? ''));
$page    = max(1, (int)($_GET['page'] ?? 1));
$pp      = 50;

if (!in_array($fmethod, ['', 'GET', 'POST', 'DELETE', 'PUT', 'HEAD', 'OPTIONS'])) $fmethod = '';
if (!preg_match('/^(\d{3}|\dxx)$/', $fstatus)) $fstatus = '';

$pstart = match($period) {
    '7d'  => 'DATE_SUB(NOW(), INTERVAL 7 DAY)',
    '30d' => 'DATE_SUB(NOW(), INTERVAL 30 DAY)',
    default => 'DATE_SUB(NOW(), INTERVAL 24 HOUR)',
};

$w = ["created_at >= $pstart"]; $bp = [];
if ($fip)     { $w[] = 'ip = ?';     $bp[] = $fip; }
if ($fmethod) { $w[] = 'method = ?'; $bp[] = $fmethod; }
if ($fstatus !== '') {
    if (preg_match('/^(\d)xx$/', $fstatus, $m)) {
        $lo = (int)$m[1] * 100; $hi = $lo + 99;
        $w[] = 'status BETWEEN ? AND ?'; $bp[] = $lo; $bp[] = $hi;
    } else { $w[] = 'status = ?'; $bp[] = (int)$fstatus; }
}
$wsql = implode(' AND ', $w);

// ── Data ──────────────────────────────────────────────────────────────────────
$stats      = ['total' => 0, 'uniq' => 0, 'errs' => 0, 'epct' => 0, 'top_tool' => '—', 'top_cnt' => 0];
$rows       = [];
$total_rows = 0;
$tool_usage = [];
$top_ips    = [];
$err_rows   = [];

if ($pdo) {
    // Stats (always full period, ignore column filters)
    $r = $pdo->query("SELECT COUNT(*) AS t, COUNT(DISTINCT ip) AS u FROM visits WHERE created_at >= $pstart")->fetch();
    $stats['total'] = (int)$r['t']; $stats['uniq'] = (int)$r['u'];

    $r = $pdo->query("SELECT COUNT(*) AS c FROM visits WHERE created_at >= $pstart AND status >= 400")->fetch();
    $stats['errs'] = (int)$r['c'];
    $stats['epct'] = $stats['total'] > 0 ? round($stats['errs'] / $stats['total'] * 100, 1) : 0;

    $r = $pdo->query("SELECT script_name, COUNT(*) AS c FROM visits WHERE created_at >= $pstart AND script_name NOT IN ('','index.php') GROUP BY script_name ORDER BY c DESC LIMIT 1")->fetch();
    if ($r) { $stats['top_tool'] = $r['script_name']; $stats['top_cnt'] = (int)$r['c']; }

    // Activity table
    $st = $pdo->prepare("SELECT COUNT(*) FROM visits WHERE $wsql"); $st->execute($bp);
    $total_rows = (int)$st->fetchColumn();
    $st = $pdo->prepare("SELECT created_at,ip,method,uri,query_string,status,user_agent,referer,script_name FROM visits WHERE $wsql ORDER BY created_at DESC LIMIT $pp OFFSET " . (($page-1)*$pp));
    $st->execute($bp); $rows = $st->fetchAll();

    // Tool usage
    $tool_usage = $pdo->query("SELECT script_name, COUNT(*) AS c FROM visits WHERE created_at >= $pstart AND script_name != '' GROUP BY script_name ORDER BY c DESC LIMIT 15")->fetchAll();

    // Top IPs
    $top_ips = $pdo->query("SELECT ip, COUNT(*) AS c, MAX(created_at) AS last, ROUND(SUM(status>=400)/COUNT(*)*100) AS epct FROM visits WHERE created_at >= $pstart GROUP BY ip ORDER BY c DESC LIMIT 12")->fetchAll();

    // Errors
    $err_rows = $pdo->query("SELECT created_at,ip,uri,error_type,error_msg,error_file,error_line FROM errors ORDER BY created_at DESC LIMIT 25")->fetchAll();
}

$total_pages = max(1, (int)ceil($total_rows / $pp));
$tool_max    = $tool_usage ? (int)$tool_usage[0]['c'] : 1;
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Activity — <?= SITE_DOMAIN ?></title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,600;1,300&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:      #0e1014; --surface: #13171e; --surface2: #181d26;
      --border:  #2a3040; --border2: #3a4458;
      --accent:  #00d4aa; --accent2: #0099ff;
      --text:    #d4dae6; --muted:   #6b7a90;
      --ok:      #22c55e; --redir: #0099ff; --warn: #f59e0b; --err: #ef4444;
      --mono: 'IBM Plex Mono', monospace; --sans: 'IBM Plex Sans', sans-serif;
      --radius: 6px; --tr: 160ms ease;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 14px; overflow-x: hidden; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.6; min-height: 100vh; }
    a { color: var(--accent); text-decoration: none; transition: color var(--tr); }
    a:hover { color: #fff; }

    /* admin bar */
    .admin-bar { background: rgba(18,22,28,.98); border-bottom: 1px solid #1a2030; padding: 0 1.75rem; height: 34px; display: flex; align-items: center; justify-content: space-between; font-family: var(--mono); font-size: .68rem; letter-spacing: .04em; }
    .admin-bar-user { color: #4a5a70; } .admin-bar-user span { color: var(--accent); }
    .admin-bar-logout { color: #4a5a70; transition: color var(--tr); } .admin-bar-logout:hover { color: #fca5a5; }

    /* layout */
    .wrap { max-width: 1360px; margin: 0 auto; padding: 2rem 1.5rem; }

    /* page header */
    .page-hd { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: .75rem; margin-bottom: 1.75rem; }
    .page-hd h1 { font-size: 1.15rem; font-weight: 600; color: #fff; }
    .period-tabs { display: flex; gap: .25rem; }
    .period-tabs a { font-family: var(--mono); font-size: .68rem; letter-spacing: .08em; text-transform: uppercase; padding: .3rem .75rem; border-radius: var(--radius); border: 1px solid var(--border2); color: var(--muted); transition: all var(--tr); }
    .period-tabs a:hover { color: var(--text); border-color: var(--accent); }
    .period-tabs a.active { background: rgba(0,212,170,.1); border-color: var(--accent); color: var(--accent); }

    /* stat cards */
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.75rem; }
    @media(max-width:760px) { .stats-grid { grid-template-columns: repeat(2,1fr); } }
    .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.1rem 1.25rem; }
    .stat-val { font-family: var(--mono); font-size: 1.5rem; font-weight: 600; color: #fff; line-height: 1.1; }
    .stat-val.warn { color: var(--warn); } .stat-val.err { color: var(--err); }
    .stat-lbl { font-size: .73rem; color: var(--muted); margin-top: .3rem; }
    .stat-sub { font-family: var(--mono); font-size: .65rem; color: #3d4f68; margin-top: .15rem; }

    /* dashboard columns */
    .dash-row { display: grid; grid-template-columns: 1fr 320px; gap: 1.5rem; align-items: start; }
    @media(max-width:1040px) { .dash-row { grid-template-columns: 1fr; } }

    /* cards */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 1.25rem; }
    .card-hd { padding: .75rem 1.1rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
    .card-hd h2 { font-family: var(--mono); font-size: .7rem; letter-spacing: .1em; text-transform: uppercase; color: var(--accent); }
    .card-hd .card-meta { font-family: var(--mono); font-size: .65rem; color: #3d4f68; }
    .card-body { padding: 1rem; }

    /* filter bar */
    .filter-bar { display: flex; flex-wrap: wrap; gap: .6rem; align-items: flex-end; margin-bottom: 1rem; }
    .flt { display: flex; flex-direction: column; gap: .3rem; }
    .flt label { font-family: var(--mono); font-size: .62rem; letter-spacing: .08em; text-transform: uppercase; color: #3d4f68; }
    .flt input, .flt select { background: var(--surface2); border: 1px solid var(--border2); border-radius: 4px; color: var(--text); font-family: var(--mono); font-size: .75rem; padding: .35rem .6rem; outline: none; transition: border-color var(--tr); }
    .flt input:focus, .flt select:focus { border-color: var(--accent); }
    .flt input { width: 140px; } .flt select { width: 100px; }
    .btn-sm { padding: .35rem .85rem; background: rgba(0,212,170,.12); border: 1px solid rgba(0,212,170,.3); border-radius: 4px; color: var(--accent); font-family: var(--mono); font-size: .72rem; cursor: pointer; transition: all var(--tr); }
    .btn-sm:hover { background: rgba(0,212,170,.2); } .btn-sm.clear { background: transparent; border-color: var(--border2); color: var(--muted); }
    .btn-sm.clear:hover { border-color: var(--border2); color: var(--text); }

    /* result meta */
    .result-meta { font-family: var(--mono); font-size: .68rem; color: #3d4f68; margin-bottom: .6rem; }
    .result-meta span { color: var(--muted); }

    /* table */
    .tbl-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: .78rem; }
    th { font-family: var(--mono); font-size: .62rem; letter-spacing: .08em; text-transform: uppercase; color: #3d4f68; padding: .5rem .75rem; border-bottom: 1px solid var(--border); text-align: left; white-space: nowrap; }
    td { padding: .45rem .75rem; border-bottom: 1px solid rgba(42,48,64,.6); vertical-align: middle; white-space: nowrap; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,.02); }
    .ts { font-family: var(--mono); font-size: .68rem; color: var(--muted); }
    .uri { font-family: var(--mono); font-size: .72rem; color: var(--text); max-width: 260px; overflow: hidden; text-overflow: ellipsis; }
    .ip-link { font-family: var(--mono); font-size: .72rem; color: var(--accent2); }
    .ip-link:hover { color: #fff; }
    .muted { color: var(--muted); font-size: .68rem; }
    .referer { max-width: 140px; overflow: hidden; text-overflow: ellipsis; font-size: .68rem; color: var(--muted); }

    /* badges */
    .badge { font-family: var(--mono); font-size: .63rem; padding: .15rem .45rem; border-radius: 3px; display: inline-block; font-weight: 600; }
    .badge--ok   { background: rgba(34,197,94,.12);  color: var(--ok);   border: 1px solid rgba(34,197,94,.25); }
    .badge--redir{ background: rgba(0,153,255,.12);  color: var(--redir);border: 1px solid rgba(0,153,255,.25); }
    .badge--warn { background: rgba(245,158,11,.12); color: var(--warn); border: 1px solid rgba(245,158,11,.25); }
    .badge--err  { background: rgba(239,68,68,.12);  color: var(--err);  border: 1px solid rgba(239,68,68,.25); }
    .badge--get  { background: rgba(0,153,255,.08);  color: var(--accent2); border: 1px solid rgba(0,153,255,.2); }
    .badge--post { background: rgba(245,158,11,.08); color: var(--warn);    border: 1px solid rgba(245,158,11,.2); }
    .badge--oth  { background: rgba(255,255,255,.04); color: var(--muted);  border: 1px solid var(--border); }
    .ua-bot     { font-family: var(--mono); font-size: .65rem; color: var(--err);  background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.2); border-radius: 3px; padding: .1rem .35rem; }
    .ua-browser { font-family: var(--mono); font-size: .65rem; color: var(--muted); }

    /* pagination */
    .pager { display: flex; gap: .35rem; flex-wrap: wrap; margin-top: .85rem; align-items: center; }
    .pager a, .pager span { font-family: var(--mono); font-size: .68rem; padding: .3rem .6rem; border-radius: 4px; border: 1px solid var(--border); color: var(--muted); transition: all var(--tr); }
    .pager a:hover { border-color: var(--accent); color: var(--accent); }
    .pager span.cur { border-color: var(--accent); color: var(--accent); background: rgba(0,212,170,.08); }
    .pager .ellipsis { border: none; color: #3d4f68; padding: .3rem .2rem; }

    /* tool usage bars */
    .tool-row { display: flex; align-items: center; gap: .6rem; margin-bottom: .5rem; }
    .tool-row:last-child { margin-bottom: 0; }
    .tool-lbl { font-family: var(--mono); font-size: .68rem; color: var(--muted); width: 130px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tool-bar-bg { flex: 1; height: 6px; background: var(--surface2); border-radius: 3px; overflow: hidden; }
    .tool-bar-fill { height: 100%; background: var(--accent); border-radius: 3px; transition: width .4s ease; }
    .tool-cnt { font-family: var(--mono); font-size: .65rem; color: #3d4f68; width: 40px; text-align: right; flex-shrink: 0; }

    /* errors table */
    .err-msg { font-family: var(--mono); font-size: .68rem; color: var(--text); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .err-file { font-family: var(--mono); font-size: .63rem; color: #3d4f68; max-width: 200px; overflow: hidden; text-overflow: ellipsis; }
    .empty-state { padding: 2rem; text-align: center; font-family: var(--mono); font-size: .72rem; color: #3d4f68; }

    /* IP table side */
    .ip-table td:first-child { font-family: var(--mono); font-size: .72rem; }
    .epct-warn { color: var(--warn); }
  </style>
</head>
<body>

<?php $navLabel = 'Admin Panel'; require __DIR__ . '/includes/site_nav.php'; ?>
<div class="admin-bar">
  <span class="admin-bar-user">Signed in as <span><?= htmlspecialchars($email) ?></span></span>
  <a href="<?= ADMIN_LOGIN_URL ?>?logout=1" class="admin-bar-logout">Sign out</a>
</div>

<div class="wrap">

  <!-- ── Header ──────────────────────────────────────────────────────────────── -->
  <div class="page-hd">
    <h1>Site Activity</h1>
    <div class="period-tabs">
      <?php foreach (['24h' => 'Last 24 h', '7d' => '7 days', '30d' => '30 days'] as $k => $lbl): ?>
      <a href="<?= q(['period' => $k]) ?>" class="<?= $period === $k ? 'active' : '' ?>"><?= $lbl ?></a>
      <?php endforeach; ?>
    </div>
  </div>

  <!-- ── Stats ───────────────────────────────────────────────────────────────── -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-val"><?= number_format($stats['total']) ?></div>
      <div class="stat-lbl">Requests</div>
    </div>
    <div class="stat-card">
      <div class="stat-val"><?= number_format($stats['uniq']) ?></div>
      <div class="stat-lbl">Unique IPs</div>
    </div>
    <div class="stat-card">
      <div class="stat-val <?= $stats['epct'] > 10 ? 'err' : ($stats['epct'] > 3 ? 'warn' : '') ?>">
        <?= $stats['epct'] ?>%
      </div>
      <div class="stat-lbl">Error rate (4xx+5xx)</div>
      <div class="stat-sub"><?= number_format($stats['errs']) ?> requests</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="font-size:1rem;line-height:1.4"><?= htmlspecialchars($tool_name($stats['top_tool'])) ?></div>
      <div class="stat-lbl">Top tool</div>
      <div class="stat-sub"><?= number_format($stats['top_cnt']) ?> requests</div>
    </div>
  </div>

  <!-- ── Main columns ────────────────────────────────────────────────────────── -->
  <div class="dash-row">

    <!-- Left: filters + activity table -->
    <div>
      <div class="card">
        <div class="card-hd">
          <h2>Activity Feed</h2>
          <span class="card-meta"><?= number_format($total_rows) ?> rows matched</span>
        </div>
        <div class="card-body">

          <!-- Filters -->
          <form method="GET" class="filter-bar">
            <input type="hidden" name="period" value="<?= htmlspecialchars($period) ?>">
            <div class="flt">
              <label>IP</label>
              <input type="text" name="ip" value="<?= htmlspecialchars($fip) ?>" placeholder="1.2.3.4">
            </div>
            <div class="flt">
              <label>Status</label>
              <select name="status">
                <option value="">All</option>
                <?php foreach (['2xx','3xx','4xx','5xx'] as $opt): ?>
                <option value="<?= $opt ?>" <?= $fstatus === $opt ? 'selected' : '' ?>><?= $opt ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="flt">
              <label>Method</label>
              <select name="method">
                <option value="">All</option>
                <?php foreach (['GET','POST','HEAD','OPTIONS','DELETE','PUT'] as $m): ?>
                <option value="<?= $m ?>" <?= $fmethod === $m ? 'selected' : '' ?>><?= $m ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="flt" style="flex-direction:row;gap:.4rem;align-items:flex-end">
              <button type="submit" class="btn-sm">Filter</button>
              <a href="<?= q([], ['ip','status','method','page']) ?>" class="btn-sm clear">Clear</a>
            </div>
          </form>

          <!-- Table -->
          <?php if ($rows): ?>
          <div class="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th><th>IP</th><th>M</th><th>Path</th>
                  <th>Status</th><th>Tool</th><th>UA</th><th>Referer</th>
                </tr>
              </thead>
              <tbody>
              <?php foreach ($rows as $r): ?>
              <tr>
                <td><span class="ts" title="<?= htmlspecialchars($r['created_at']) ?> UTC"><?= rel_time($r['created_at']) ?></span></td>
                <td><a href="<?= q(['ip' => $r['ip']]) ?>" class="ip-link"><?= htmlspecialchars($r['ip']) ?></a></td>
                <td><?= method_badge($r['method']) ?></td>
                <td><span class="uri" title="<?= htmlspecialchars($r['uri'] . ($r['query_string'] ? '?'.$r['query_string'] : '')) ?>">
                  <?= htmlspecialchars($r['uri']) ?>
                </span></td>
                <td><?= status_badge((int)$r['status']) ?></td>
                <td><span class="muted"><?= htmlspecialchars($tool_name($r['script_name'])) ?></span></td>
                <td><?= ua_label($r['user_agent']) ?></td>
                <td><span class="referer" title="<?= htmlspecialchars($r['referer']) ?>"><?= $r['referer'] ? htmlspecialchars($r['referer']) : '<span class="muted">—</span>' ?></span></td>
              </tr>
              <?php endforeach; ?>
              </tbody>
            </table>
          </div>
          <?php else: ?>
          <div class="empty-state">No activity found for this filter.</div>
          <?php endif; ?>

          <!-- Pagination -->
          <?php if ($total_pages > 1): ?>
          <div class="pager">
            <?php if ($page > 1): ?><a href="<?= pg_url($page-1) ?>">← Prev</a><?php endif; ?>
            <?php
              $pages_to_show = [];
              for ($i = 1; $i <= $total_pages; $i++) {
                if ($i === 1 || $i === $total_pages || abs($i - $page) <= 2) $pages_to_show[] = $i;
              }
              $prev = null;
              foreach ($pages_to_show as $pn):
                if ($prev !== null && $pn - $prev > 1): ?><span class="ellipsis">…</span><?php endif;
                $prev = $pn;
            ?>
            <?php if ($pn === $page): ?><span class="cur"><?= $pn ?></span>
            <?php else: ?><a href="<?= pg_url($pn) ?>"><?= $pn ?></a><?php endif; ?>
            <?php endforeach; ?>
            <?php if ($page < $total_pages): ?><a href="<?= pg_url($page+1) ?>">Next →</a><?php endif; ?>
          </div>
          <?php endif; ?>

        </div>
      </div>
    </div>

    <!-- Right: tool usage + top IPs -->
    <div>

      <div class="card">
        <div class="card-hd"><h2>Tool Usage</h2></div>
        <div class="card-body">
          <?php if ($tool_usage): ?>
          <?php foreach ($tool_usage as $t): ?>
          <div class="tool-row">
            <span class="tool-lbl" title="<?= htmlspecialchars($t['script_name']) ?>"><?= htmlspecialchars($tool_name($t['script_name'])) ?></span>
            <div class="tool-bar-bg"><div class="tool-bar-fill" style="width:<?= round($t['c']/$tool_max*100) ?>%"></div></div>
            <span class="tool-cnt"><?= number_format($t['c']) ?></span>
          </div>
          <?php endforeach; ?>
          <?php else: ?><div class="empty-state">No data yet.</div><?php endif; ?>
        </div>
      </div>

      <div class="card">
        <div class="card-hd"><h2>Top IPs</h2></div>
        <div class="tbl-wrap">
          <table class="ip-table">
            <thead><tr><th>IP</th><th>Req</th><th>Err%</th><th>Last seen</th></tr></thead>
            <tbody>
            <?php if ($top_ips): ?>
            <?php foreach ($top_ips as $row): ?>
            <tr>
              <td><a href="<?= q(['ip' => $row['ip']]) ?>" class="ip-link"><?= htmlspecialchars($row['ip']) ?></a></td>
              <td><?= number_format($row['c']) ?></td>
              <td class="<?= (int)$row['epct'] > 30 ? 'epct-warn' : '' ?> muted"><?= (int)$row['epct'] ?>%</td>
              <td class="muted"><?= rel_time($row['last']) ?></td>
            </tr>
            <?php endforeach; ?>
            <?php else: ?><tr><td colspan="4" class="empty-state">No data yet.</td></tr><?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>

    </div>
  </div><!-- .dash-row -->

  <!-- ── Errors ──────────────────────────────────────────────────────────────── -->
  <div class="card">
    <div class="card-hd">
      <h2>PHP Errors</h2>
      <span class="card-meta">latest 25</span>
    </div>
    <?php if ($err_rows): ?>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Time</th><th>IP</th><th>Type</th><th>URI</th><th>Message</th><th>File : line</th></tr></thead>
        <tbody>
        <?php foreach ($err_rows as $e): ?>
        <tr>
          <td><span class="ts" title="<?= htmlspecialchars($e['created_at']) ?> UTC"><?= rel_time($e['created_at']) ?></span></td>
          <td><a href="<?= q(['ip' => $e['ip']]) ?>" class="ip-link"><?= htmlspecialchars($e['ip']) ?></a></td>
          <td><span class="badge badge--warn"><?= htmlspecialchars($e['error_type']) ?></span></td>
          <td><span class="uri"><?= htmlspecialchars($e['uri']) ?></span></td>
          <td><span class="err-msg" title="<?= htmlspecialchars($e['error_msg']) ?>"><?= htmlspecialchars($e['error_msg']) ?></span></td>
          <td><span class="err-file"><?= htmlspecialchars(basename($e['error_file'])) ?> : <?= (int)$e['error_line'] ?></span></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php else: ?>
    <div class="empty-state">No PHP errors logged.</div>
    <?php endif; ?>
  </div>

</div><!-- .wrap -->

<script>
// Convert UTC timestamps to local time on hover title
document.querySelectorAll('.ts').forEach(function(el) {
  var utc = el.title;
  if (!utc) return;
  var d = new Date(utc.replace(' ', 'T') + 'Z');
  el.title = d.toLocaleString();
});
// Auto-submit selects
document.querySelectorAll('.filter-bar select').forEach(function(s) {
  s.addEventListener('change', function() { this.closest('form').submit(); });
});
</script>

</body>
</html>
