<?php
$navLabel  = 'PKI News';
$cacheFile = __DIR__ . '/includes/feed_cache.json';

$cache   = [];
$items   = [];
$sources = [];

if (file_exists($cacheFile)) {
    $decoded = @json_decode(file_get_contents($cacheFile), true);
    if ($decoded) {
        $cache   = $decoded;
        $items   = $cache['items']   ?? [];
        $sources = $cache['sources'] ?? [];
    }
}
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'PKI News — Daily WebPKI & CA/Browser Forum Updates | thameur.org',
    'description' => "Daily PKI news aggregated from mozilla.dev.security.policy, CA/Browser Forum GitHub, IETF LAMPS WG, Mozilla Security Blog, Let's Encrypt, and more. Refreshed every 24 hours.",
    'url'         => 'https://thameur.org/feed.php',
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
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }

    /* ── Layout ── */
    .feed-page { max-width: 860px; margin: 0 auto; padding: 3.5rem 2rem 6rem; }

    .feed-header { margin-bottom: 2rem; }
    .feed-header h1 { font-size: 2rem; font-weight: 600; color: #fff; margin-bottom: 0.3rem; }
    .feed-meta {
      font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
      letter-spacing: 0.05em; display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;
    }
    .feed-meta-dot { color: var(--border); }

    /* ── Filters ── */
    .filter-bar {
      display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 2rem;
    }
    .filter-btn {
      font-family: var(--mono); font-size: 0.7rem; letter-spacing: 0.06em; text-transform: uppercase;
      border: 1px solid var(--border); background: none; color: var(--muted);
      border-radius: 4px; padding: 0.3em 0.75em; cursor: pointer; transition: all 0.15s;
    }
    .filter-btn:hover { border-color: var(--muted); color: var(--text); }
    .filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(0,212,170,0.06); }

    /* ── Feed cards ── */
    .feed-list { display: flex; flex-direction: column; gap: 1px; }

    .feed-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.2rem 1.4rem;
      margin-bottom: 0.75rem;
      transition: border-color 0.15s;
    }
    .feed-card:hover { border-color: #3d4f68; }

    .feed-card-meta {
      display: flex; align-items: center; gap: 0.75rem;
      flex-wrap: wrap; margin-bottom: 0.5rem;
    }
    .feed-source {
      font-family: var(--mono); font-size: 0.68rem; text-transform: uppercase;
      letter-spacing: 0.07em; font-weight: 600;
      padding: 0.15em 0.55em; border-radius: 3px;
      border: 1px solid color-mix(in srgb, var(--src-color) 35%, transparent);
      background: color-mix(in srgb, var(--src-color) 8%, transparent);
      color: var(--src-color);
    }
    .feed-date {
      font-family: var(--mono); font-size: 0.68rem; color: var(--muted);
    }

    .feed-card-title {
      font-size: 0.95rem; font-weight: 600; line-height: 1.45; margin-bottom: 0.4rem;
    }
    .feed-card-title a { color: var(--text); }
    .feed-card-title a:hover { color: #fff; }

    .feed-card-summary {
      font-size: 0.82rem; color: var(--muted); line-height: 1.6;
      display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden;
    }

    /* ── Pagination ── */
    .pagination {
      display: flex; align-items: center; justify-content: center;
      gap: 0.5rem; margin-top: 2rem; flex-wrap: wrap;
    }
    .page-btn {
      font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.04em;
      border: 1px solid var(--border); background: none; color: var(--muted);
      border-radius: 4px; padding: 0.35em 0.75em; cursor: pointer; transition: all 0.15s;
      min-width: 2.2rem; text-align: center;
    }
    .page-btn:hover:not(:disabled) { border-color: var(--muted); color: var(--text); }
    .page-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(0,212,170,0.06); }
    .page-btn:disabled { opacity: 0.3; cursor: not-allowed; }
    .page-info {
      font-family: var(--mono); font-size: 0.68rem; color: var(--muted);
      padding: 0 0.4rem;
    }

    /* ── Empty / not-yet-fetched state ── */
    .feed-empty {
      background: var(--surface); border: 1px dashed var(--border);
      border-radius: var(--radius); padding: 3rem 2rem; text-align: center;
    }
    .feed-empty h2 { font-size: 1rem; font-weight: 600; color: var(--text); margin-bottom: 0.5rem; }
    .feed-empty p { font-size: 0.85rem; color: var(--muted); margin-bottom: 0.5rem; }
    .feed-empty code {
      font-family: var(--mono); font-size: 0.78rem;
      background: rgba(255,255,255,0.05); padding: 0.2em 0.5em; border-radius: 3px;
    }

    /* ── Footer ── */
    .feed-footer-note {
      margin-top: 2.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border);
      font-family: var(--mono); font-size: 0.7rem; color: var(--muted);
    }
    .site-footer {
      border-top: 1px solid var(--border); padding: 1.4rem 2rem;
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
    }
    .site-footer a { color: var(--muted); text-decoration: none; }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }

    @media (max-width: 600px) {
      .feed-card { padding: 1rem; }
    }
  </style>
  <?php require __DIR__ . '/includes/adsense_head.php'; ?>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<main class="feed-page">

  <div class="feed-header">
    <h1>PKI News</h1>
    <div class="feed-meta">
      <?php if (!empty($cache['fetched_at_fmt'])): ?>
        <span>Updated <?= htmlspecialchars($cache['fetched_at_fmt']) ?></span>
        <span class="feed-meta-dot">·</span>
        <span><?= (int)($cache['total'] ?? 0) ?> items from <?= count($sources) ?> sources</span>
        <span class="feed-meta-dot">·</span>
        <span>Refreshed daily at 06:00 UTC</span>
      <?php else: ?>
        <span>Feed not yet populated — run the cron script to fetch items</span>
      <?php endif; ?>
    </div>
  </div>

  <?php if (empty($items)): ?>

    <div class="feed-empty">
      <h2>No feed data yet</h2>
      <p>Run the cron script to populate the feed:</p>
      <p><code>php cron/fetch_feeds.php</code></p>
      <p style="margin-top:1rem;">Then schedule it for daily refresh — see the cron comment at the top of the script.</p>
    </div>

  <?php else: ?>

    <!-- Source filter buttons -->
    <div class="filter-bar" id="filterBar" role="group" aria-label="Filter by source">
      <button class="filter-btn active" data-src="all">All</button>
      <?php foreach ($sources as $src): ?>
      <button class="filter-btn" data-src="<?= htmlspecialchars($src['id']) ?>"
              style="--src-color: <?= htmlspecialchars($src['color']) ?>">
        <?= htmlspecialchars($src['label']) ?>
        <span style="opacity:0.55;margin-left:0.35em"><?= $src['count'] ?></span>
      </button>
      <?php endforeach; ?>
    </div>

    <?php require __DIR__ . '/includes/adsense_unit.php'; ?>

    <!-- Feed items -->
    <div class="feed-list" id="feedList">
      <?php foreach ($items as $item): ?>
      <article class="feed-card" data-src="<?= htmlspecialchars($item['source_id']) ?>">
        <div class="feed-card-meta">
          <span class="feed-source" style="--src-color: <?= htmlspecialchars($item['source_color']) ?>">
            <?= htmlspecialchars($item['source_label']) ?>
          </span>
          <?php if ($item['date_fmt']): ?>
          <time class="feed-date" datetime="<?= htmlspecialchars($item['date_iso']) ?>">
            <?= htmlspecialchars($item['date_fmt']) ?>
          </time>
          <?php endif; ?>
        </div>
        <h2 class="feed-card-title">
          <a href="<?= htmlspecialchars($item['url']) ?>" target="_blank" rel="noopener noreferrer">
            <?= htmlspecialchars($item['title']) ?>
          </a>
        </h2>
        <?php if ($item['summary']): ?>
        <p class="feed-card-summary"><?= htmlspecialchars($item['summary']) ?></p>
        <?php endif; ?>
      </article>
      <?php endforeach; ?>
    </div>

    <div class="pagination" id="pagination" hidden></div>

    <p id="noResults" hidden style="color:var(--muted);font-size:0.85rem;margin-top:2rem;">No items for this source.</p>

  <?php endif; ?>

  <div class="feed-footer-note">
    Sources: mozilla.dev.security.policy &nbsp;·&nbsp; CA/Browser Forum (TLS, S/MIME, Code Signing) &nbsp;·&nbsp;
    IETF LAMPS WG &nbsp;·&nbsp; Mozilla Security Blog &nbsp;·&nbsp; Let's Encrypt Blog &nbsp;·&nbsp; Mozilla CA Incidents
  </div>

</main>

<footer class="site-footer">
  <span>&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="/">Home</a>
    <a href="/references.php">PKI References</a>
    <a href="/privacy.php">Privacy Policy</a>
    <a href="mailto:me@thameur.org">me@thameur.org</a>
  </div>
</footer>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>

<script>
(function () {
  var PAGE_SIZE   = 25;
  var currentPage = 1;
  var currentSrc  = 'all';

  var filterBtns  = document.querySelectorAll('.filter-btn');
  var allCards    = Array.from(document.querySelectorAll('.feed-card'));
  var noRes       = document.getElementById('noResults');
  var pagination  = document.getElementById('pagination');

  function filteredCards() {
    return currentSrc === 'all'
      ? allCards
      : allCards.filter(function (c) { return c.dataset.src === currentSrc; });
  }

  function applyView() {
    var visible = filteredCards();
    var total   = visible.length;
    var pages   = Math.max(1, Math.ceil(total / PAGE_SIZE));

    if (currentPage > pages) currentPage = pages;

    var start = (currentPage - 1) * PAGE_SIZE;
    var end   = start + PAGE_SIZE;

    // hide all, show the current page slice
    allCards.forEach(function (c) { c.hidden = true; });
    visible.slice(start, end).forEach(function (c) { c.hidden = false; });

    if (noRes) noRes.hidden = total > 0;

    renderPagination(currentPage, pages, total);
  }

  function renderPagination(page, pages, total) {
    if (!pagination) return;

    if (pages <= 1) {
      pagination.hidden = true;
      return;
    }
    pagination.hidden = false;

    var html = '';

    // Prev
    html += '<button class="page-btn" id="pgPrev"' + (page <= 1 ? ' disabled' : '') + '>&#8592;</button>';

    // Page numbers — show at most 7 slots with ellipsis
    var nums = pageNumbers(page, pages);
    nums.forEach(function (n) {
      if (n === '…') {
        html += '<span class="page-info">…</span>';
      } else {
        html += '<button class="page-btn' + (n === page ? ' active' : '') + '" data-pg="' + n + '">' + n + '</button>';
      }
    });

    // Next
    html += '<button class="page-btn" id="pgNext"' + (page >= pages ? ' disabled' : '') + '>&#8594;</button>';

    // Summary
    var s = (page - 1) * PAGE_SIZE + 1;
    var e = Math.min(page * PAGE_SIZE, total);
    html += '<span class="page-info">' + s + '–' + e + ' of ' + total + '</span>';

    pagination.innerHTML = html;

    var prev = document.getElementById('pgPrev');
    var next = document.getElementById('pgNext');
    if (prev) prev.addEventListener('click', function () { currentPage--; applyView(); scrollToList(); });
    if (next) next.addEventListener('click', function () { currentPage++; applyView(); scrollToList(); });

    pagination.querySelectorAll('[data-pg]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        currentPage = parseInt(btn.dataset.pg, 10);
        applyView();
        scrollToList();
      });
    });
  }

  function pageNumbers(current, total) {
    if (total <= 7) {
      var arr = [];
      for (var i = 1; i <= total; i++) arr.push(i);
      return arr;
    }
    var nums = [1];
    if (current > 3)          nums.push('…');
    for (var p = Math.max(2, current - 1); p <= Math.min(total - 1, current + 1); p++) nums.push(p);
    if (current < total - 2)  nums.push('…');
    nums.push(total);
    return nums;
  }

  function scrollToList() {
    var list = document.getElementById('feedList');
    if (list) list.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Filter buttons
  filterBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      currentSrc  = btn.dataset.src;
      currentPage = 1;
      filterBtns.forEach(function (b) { b.classList.toggle('active', b === btn); });
      applyView();
    });
  });

  // Initial render
  applyView();
}());
</script>
</body>
</html>
