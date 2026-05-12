<?php
/**
 * Shared site navigation bar.
 *
 * Usage — include near the top of <body>, before any page content:
 *   <?php
 *   $navLabel = 'Certificate Linters'; // optional page label shown centred
 *   require __DIR__ . '/includes/site_nav.php';
 *   ?>
 *
 * If $navLabel is not set the centre slot is empty.
 */
$_navLabel = $navLabel ?? '';
?>
<style>
/* ── Shared site nav ─────────────────────────────────────────────────────── */
.snav {
  position: sticky; top: 0; z-index: 100;
  background: rgba(14,16,20,0.94);
  backdrop-filter: blur(12px) saturate(1.4);
  -webkit-backdrop-filter: blur(12px) saturate(1.4);
  border-bottom: 1px solid #2a3040;
  padding: 0 1.75rem;
  display: flex; align-items: center;
  height: 52px; gap: 1rem;
}
.snav-home {
  display: flex; align-items: center; gap: 0.5rem;
  text-decoration: none; flex-shrink: 0;
}
.snav-home img {
  width: 26px; height: 26px; object-fit: contain;
  filter: drop-shadow(0 0 5px rgba(0,212,170,0.3));
  transition: filter 150ms ease;
}
.snav-home:hover img { filter: drop-shadow(0 0 10px rgba(0,212,170,0.65)); }
.snav-wordmark {
  font-family: 'IBM Plex Mono', 'JetBrains Mono', monospace;
  font-size: 0.8rem; font-weight: 600;
  letter-spacing: 0.1em; text-transform: uppercase;
  color: #00d4aa; text-decoration: none;
}
.snav-label {
  flex: 1; text-align: center;
  font-family: 'IBM Plex Mono', 'JetBrains Mono', monospace;
  font-size: 0.72rem; letter-spacing: 0.08em;
  color: #6b7a90; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.snav-links {
  display: flex; gap: 1.6rem; flex-shrink: 0;
}
.snav-links a {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.75rem; font-weight: 400;
  letter-spacing: 0.05em; text-transform: uppercase;
  color: #6b7a90; text-decoration: none;
  transition: color 150ms ease;
}
.snav-links a:hover { color: #d4dae6; }
@media (max-width: 600px) {
  .snav { padding: 0 1rem; }
  .snav-label { display: none; }
  .snav-links { gap: 1rem; }
}
</style>

<nav class="snav">
  <a href="/" class="snav-home">
    <img src="/img/meerkat_120.png" alt="Meerkat">
    <span class="snav-wordmark">thameur.org</span>
  </a>
  <?php if ($_navLabel !== ''): ?>
  <span class="snav-label"><?= htmlspecialchars($_navLabel) ?></span>
  <?php else: ?>
  <span class="snav-label"></span>
  <?php endif; ?>
  <div class="snav-links">
    <a href="/#about">About</a>
    <a href="/#tools">Tools</a>
    <a href="/feed.php">News</a>
    <a href="/references.php">References</a>
    <a href="mailto:me@thameur.org">Contact</a>
  </div>
</nav>
