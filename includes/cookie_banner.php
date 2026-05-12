<?php
/**
 * GDPR / cookie consent banner.
 * Include once, just before </body>.
 */
?>
<style>
/* ── Cookie banner ───────────────────────────────────────────────────────── */
.ck-banner {
  position: fixed; bottom: 0; left: 0; right: 0; z-index: 9000;
  background: #13171e;
  border-top: 1px solid #2a3040;
  padding: 1rem 2rem;
  display: flex; align-items: center; justify-content: space-between;
  gap: 1.2rem; flex-wrap: wrap;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.82rem; color: #6b7a90;
  box-shadow: 0 -4px 20px rgba(0,0,0,0.4);
  transition: transform 320ms ease, opacity 320ms ease;
}
.ck-banner.ck-hidden {
  transform: translateY(110%);
  opacity: 0;
  pointer-events: none;
}
.ck-banner p { margin: 0; line-height: 1.6; }
.ck-banner a { color: #00d4aa; text-decoration: none; }
.ck-banner a:hover { text-decoration: underline; }
.ck-actions { display: flex; gap: 0.6rem; flex-shrink: 0; }
.ck-btn {
  padding: 0.45rem 1.1rem;
  border-radius: 4px; border: none; cursor: pointer;
  font-size: 0.78rem; font-family: inherit;
  transition: all 150ms ease; white-space: nowrap;
}
.ck-accept { background: #00d4aa; color: #0a1210; }
.ck-accept:hover { background: #00f0c0; }
.ck-reject {
  background: transparent;
  border: 1px solid #2a3040;
  color: #6b7a90;
}
.ck-reject:hover { border-color: #6b7a90; color: #d4dae6; }
</style>

<div class="ck-banner ck-hidden" id="ck-banner" role="dialog" aria-label="Cookie consent">
  <p>
    We use cookies to serve ads (Google AdSense) and analyse traffic.
    See our <a href="/privacy.php">Privacy Policy</a> for details.
    You can opt out at any time via your browser settings or
    <a href="https://adssettings.google.com/" target="_blank" rel="noopener">Google's Ad Settings</a>.
  </p>
  <div class="ck-actions">
    <button class="ck-btn ck-reject" id="ck-reject">Reject Non-Essential</button>
    <button class="ck-btn ck-accept" id="ck-accept">Accept All</button>
  </div>
</div>

<script>
(function () {
  var KEY    = 'ck_consent_v1';
  var banner = document.getElementById('ck-banner');
  var stored = localStorage.getItem(KEY);

  function dismiss(val) {
    localStorage.setItem(KEY, val);
    banner.classList.add('ck-hidden');
  }

  if (!stored) {
    // Small delay so page feels loaded before banner slides in.
    setTimeout(function () { banner.classList.remove('ck-hidden'); }, 900);
  }

  document.getElementById('ck-accept').addEventListener('click', function () { dismiss('accepted'); });
  document.getElementById('ck-reject').addEventListener('click', function () { dismiss('rejected'); });
})();
</script>
