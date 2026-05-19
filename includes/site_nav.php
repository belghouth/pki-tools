<?php
/**
 * Shared site navigation bar.
 *
 * Set $navLabel before including to show the current page name in the bar.
 *   $navLabel = 'Certificate Linters';
 *   require_once __DIR__ . '/includes/site_nav.php';
 */
$_navLabel = $navLabel ?? '';
?>
<script>
/* Restore theme before first paint to avoid flash */
(function(){
  try {
    var t = localStorage.getItem('theme');
    if (t === 'light') document.documentElement.setAttribute('data-theme', 'light');
  } catch(e) {}
})();
</script>
<style>
@media (pointer: coarse) { body { overscroll-behavior-y: none; } }

/* ── Light theme: invert everything, then restore media to original ── */
html[data-theme="light"] {
  filter: invert(1) hue-rotate(180deg);
}
html[data-theme="light"] img,
html[data-theme="light"] video,
html[data-theme="light"] iframe,
html[data-theme="light"] canvas {
  filter: invert(1) hue-rotate(180deg);
}

/* ── Shared site nav ──────────────────────────────────────────────────────── */
body { padding-top: 56px; }
.snav {
  position: fixed; top: 0; left: 0; right: 0; z-index: 100;
  background: rgba(13,15,20,0.96);
  backdrop-filter: blur(14px) saturate(1.6);
  -webkit-backdrop-filter: blur(14px) saturate(1.6);
  border-bottom: 1px solid #1e2535;
  height: 56px;
  padding: 0 1.75rem;
  display: flex; align-items: center; gap: 1rem;
}

/* ── Logo ── */
.snav-home {
  display: flex; align-items: center; gap: 0.55rem;
  text-decoration: none; flex-shrink: 0;
}
.snav-home img {
  width: 28px; height: 28px; object-fit: contain;
  filter: drop-shadow(0 0 6px rgba(0,212,170,0.35));
  transition: filter 180ms ease;
}
.snav-home:hover img { filter: drop-shadow(0 0 12px rgba(0,212,170,0.75)); }
.snav-wordmark {
  font-family: 'IBM Plex Mono', 'JetBrains Mono', monospace;
  font-size: 0.85rem; font-weight: 600;
  letter-spacing: 0.1em; text-transform: uppercase;
  color: #00d4aa; text-decoration: none;
}

/* ── Page label (centre slot) ── */
.snav-label {
  flex: 1; text-align: center;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.7rem; letter-spacing: 0.1em; text-transform: uppercase;
  color: #3d4f68; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  pointer-events: none;
}

/* ── Desktop links ── */
.snav-links {
  display: flex; align-items: center; gap: 0.25rem; flex-shrink: 0;
}

.snav-link {
  display: flex; align-items: center; gap: 0.38rem;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.8rem; font-weight: 400;
  color: #8a9ab8;
  text-decoration: none;
  padding: 0.35rem 0.65rem;
  border-radius: 5px;
  border: 1px solid transparent;
  transition: color 150ms ease, background 150ms ease, border-color 150ms ease;
  white-space: nowrap;
}
.snav-link svg { flex-shrink: 0; opacity: 0.75; transition: opacity 150ms ease; }
.snav-link:hover {
  color: #e8edf5;
  background: rgba(255,255,255,0.05);
  border-color: rgba(255,255,255,0.07);
}
.snav-link:hover svg { opacity: 1; }

/* active page highlight */
.snav-link[aria-current="page"] {
  color: #00d4aa;
  background: rgba(0,212,170,0.08);
  border-color: rgba(0,212,170,0.18);
}
.snav-link[aria-current="page"] svg { opacity: 1; }

/* ── Theme toggle button ── */
.snav-theme-btn {
  display: flex; align-items: center; justify-content: center;
  width: 34px; height: 34px; flex-shrink: 0;
  background: transparent;
  border: 1px solid #1e2535;
  border-radius: 6px; cursor: pointer;
  color: #8a9ab8;
  transition: color 150ms ease, border-color 150ms ease, background 150ms ease;
  padding: 0;
}
.snav-theme-btn:hover { color: #e8edf5; border-color: #3a4458; background: rgba(255,255,255,0.04); }
/* Show moon in dark mode (→ switch to light), sun in light mode (→ switch to dark) */
.snav-theme-btn .icon-sun  { display: none; }
.snav-theme-btn .icon-moon { display: block; }
html[data-theme="light"] .snav-theme-btn .icon-moon { display: none; }
html[data-theme="light"] .snav-theme-btn .icon-sun  { display: block; }

/* ── Hamburger button (mobile only) ── */
.snav-burger {
  display: none;
  flex-direction: column; justify-content: center; align-items: center;
  gap: 5px;
  width: 38px; height: 38px;
  background: transparent; border: 1px solid #1e2535;
  border-radius: 6px; cursor: pointer;
  padding: 0; flex-shrink: 0;
  transition: border-color 150ms ease, background 150ms ease;
}
.snav-burger:hover { border-color: #3a4458; background: rgba(255,255,255,0.04); }
.snav-burger span {
  display: block; width: 18px; height: 1.5px;
  background: #8a9ab8; border-radius: 2px;
  transition: transform 220ms ease, opacity 220ms ease, background 150ms ease;
  transform-origin: center;
}
.snav-burger:hover span { background: #c8d4e6; }

/* animated X when open */
.snav--open .snav-burger span:nth-child(1) { transform: rotate(45deg) translate(3px, 4.5px); }
.snav--open .snav-burger span:nth-child(2) { opacity: 0; transform: scaleX(0); }
.snav--open .snav-burger span:nth-child(3) { transform: rotate(-45deg) translate(3px, -4.5px); }

/* ── Mobile layout ── */
@media (max-width: 820px) {
  .snav { padding: 0 1.1rem; }
  .snav-burger { display: flex; margin-left: auto; }
  .snav-label  { display: none; }

  .snav-links {
    display: none;
    position: absolute;
    top: 56px; left: 0; right: 0;
    flex-direction: column; align-items: stretch;
    gap: 0;
    background: #0d0f14;
    border-bottom: 1px solid #1e2535;
    padding: 0.5rem 0.75rem 0.75rem;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5);
  }
  .snav--open .snav-links { display: flex; }

  .snav-link {
    padding: 0.65rem 0.75rem;
    font-size: 0.88rem;
    border-radius: 6px;
  }
}

</style>

<nav class="snav" id="siteNav">

  <a href="/" class="snav-home">
    <img src="/img/meerkat_120.png" alt="">
    <span class="snav-wordmark"><?= SITE_DOMAIN ?></span>
  </a>

  <?php if ($_navLabel !== ''): ?>
  <span class="snav-label"><?= htmlspecialchars($_navLabel) ?></span>
  <?php else: ?>
  <span class="snav-label"></span>
  <?php endif; ?>

  <button class="snav-theme-btn" id="snavThemeBtn" aria-label="Toggle light/dark theme" title="Toggle theme">
    <!-- Moon: shown in dark mode — click to switch to light -->
    <svg class="icon-moon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d="M21 12.79A9 9 0 1111.21 3a7 7 0 009.79 9.79z"/>
    </svg>
    <!-- Sun: shown in light mode — click to switch to dark -->
    <svg class="icon-sun" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="5"/>
      <line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
      <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
    </svg>
  </button>

  <button class="snav-burger" id="snavBurger" aria-label="Toggle navigation" aria-expanded="false" aria-controls="snavLinks">
    <span></span><span></span><span></span>
  </button>

  <div class="snav-links" id="snavLinks" role="menubar">

    <a href="/#about" class="snav-link" role="menuitem">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
      </svg>
      About
    </a>

    <a href="/#tools" class="snav-link" role="menuitem">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/>
      </svg>
      Tools
    </a>

    <a href="/feed.php" class="snav-link" role="menuitem">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M4 11a9 9 0 019 9"/><path d="M4 4a16 16 0 0116 16"/><circle cx="5" cy="19" r="1" fill="currentColor" stroke="none"/>
      </svg>
      News
    </a>

    <a href="/community_tools.php" class="snav-link" role="menuitem">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/>
        <path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/>
      </svg>
      Community
    </a>

    <a href="/references.php" class="snav-link" role="menuitem">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M4 19.5A2.5 2.5 0 016.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/>
      </svg>
      References
    </a>

    <a href="/ccadb.php" class="snav-link" role="menuitem">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="3"/>
      </svg>
      CCADB
    </a>

    <a href="/#contact" class="snav-link" role="menuitem">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>
      </svg>
      Contact
    </a>

  </div>
</nav>

<script>
(function () {
  var nav    = document.getElementById('siteNav');
  var burger = document.getElementById('snavBurger');
  var links  = document.getElementById('snavLinks');
  var themeBtn = document.getElementById('snavThemeBtn');

  function open()  { nav.classList.add('snav--open');    burger.setAttribute('aria-expanded', 'true');  }
  function close() { nav.classList.remove('snav--open'); burger.setAttribute('aria-expanded', 'false'); }
  function toggle(){ nav.classList.contains('snav--open') ? close() : open(); }

  burger.addEventListener('click', function (e) { e.stopPropagation(); toggle(); });

  document.addEventListener('click', function (e) {
    if (!nav.contains(e.target)) close();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') close();
  });

  // ── Theme toggle ──────────────────────────────────────────────────────────
  themeBtn.addEventListener('click', function () {
    var isLight = document.documentElement.getAttribute('data-theme') === 'light';
    if (isLight) {
      document.documentElement.removeAttribute('data-theme');
      try { localStorage.setItem('theme', 'dark'); } catch(e) {}
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
      try { localStorage.setItem('theme', 'light'); } catch(e) {}
    }
  });

  // ── Mark current page link ────────────────────────────────────────────────
  var cur = location.pathname;
  links.querySelectorAll('a.snav-link').forEach(function (a) {
    var href = a.getAttribute('href');
    if (!href || href.startsWith('mailto:')) return;
    var hrefPath = href.split('#')[0];
    if (hrefPath && hrefPath !== '/' && hrefPath === cur) {
      a.setAttribute('aria-current', 'page');
    }
  });
})();
</script>
