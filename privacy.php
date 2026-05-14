<?php
$navLabel = 'Privacy Policy';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'Privacy Policy — ' . SITE_DOMAIN,
    'description' => 'Privacy policy for ' . SITE_DOMAIN . ' — how we handle cookies, Google AdSense advertising, and your data.',
    'url'         => SITE_BASE_URL . '/privacy.php',
    'robots'      => 'noindex, follow',
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
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); }
    a:hover { color: #fff; }
    code { font-family: var(--mono); font-size: 0.85em; background: rgba(255,255,255,0.05); padding: 0.1em 0.35em; border-radius: 3px; }

    .prose { max-width: 780px; margin: 0 auto; padding: 4rem 2rem 6rem; }
    .prose h1 { font-size: 2rem; font-weight: 600; color: #fff; margin-bottom: 0.4rem; }
    .prose .meta { font-family: var(--mono); font-size: 0.72rem; color: var(--muted); letter-spacing: 0.06em; margin-bottom: 3rem; }
    .prose h2 { font-size: 1.05rem; font-weight: 600; color: #fff; margin: 2.5rem 0 0.6rem; padding-bottom: 0.4rem; border-bottom: 1px solid var(--border); }
    .prose p { color: var(--muted); margin-bottom: 0.9rem; font-size: 0.9rem; }
    .prose ul { color: var(--muted); font-size: 0.9rem; padding-left: 1.4rem; margin-bottom: 0.9rem; }
    .prose ul li { margin-bottom: 0.35rem; }
    .prose strong { color: var(--text); font-weight: 400; }
    .prose-footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border); font-size: 0.8rem; color: var(--muted); }

    .site-footer {
      border-top: 1px solid var(--border); padding: 1.4rem 2rem;
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
    }
    .site-footer a { color: var(--muted); text-decoration: none; }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }
  </style>
  <?php require __DIR__ . '/includes/adsense_head.php'; ?>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<div class="prose">
  <h1>Privacy Policy</h1>
  <p class="meta">Effective date: <?= date('d F Y') ?> &nbsp;·&nbsp; <?= SITE_DOMAIN ?></p>

  <h2>1. Who We Are</h2>
  <p>This website (<strong><?= SITE_DOMAIN ?></strong>) is operated by Thameur Belghith. Questions about this policy can be directed to <a href="<?= 'mailto:' . CONTACT_EMAIL ?>"><?= CONTACT_EMAIL ?></a>.</p>

  <h2>2. Information We Collect</h2>
  <p>We collect limited data in the following ways:</p>
  <ul>
    <li><strong>Contact form submissions</strong> — name, email address, and message content you voluntarily submit. This data is emailed directly to us and is not stored in a database.</li>
    <li><strong>Server logs</strong> — standard web-server access logs (IP address, browser user agent, referring URL, page visited, timestamp). Logs are retained for up to 30 days for security and diagnostics.</li>
    <li><strong>Cookies</strong> — see Section 4 below.</li>
  </ul>
  <p>We do not collect sensitive personal data, and we do not sell, rent, or share personal information with third parties except as described in this policy.</p>

  <h2>3. How We Use Your Information</h2>
  <ul>
    <li>To respond to enquiries submitted via the contact form.</li>
    <li>To monitor and maintain the security and performance of the site.</li>
    <li>To serve relevant advertisements through Google AdSense.</li>
  </ul>

  <h2>4. Cookies</h2>
  <p>This website uses the following categories of cookies:</p>
  <ul>
    <li><strong>Functional cookies</strong> — used to remember your cookie consent preference (stored in <code>localStorage</code> under the key <code>ck_consent_v1</code>). These do not leave your device.</li>
    <li><strong>Advertising cookies</strong> — set by Google AdSense to serve personalised advertisements based on your browsing activity. Google may use these cookies to show ads on other sites you visit.</li>
  </ul>
  <p>You can control or delete cookies at any time through your browser settings. Rejecting advertising cookies will not affect your ability to use the tools on this site.</p>

  <h2>5. Google AdSense &amp; Third-Party Advertising</h2>
  <p>We use <strong>Google AdSense</strong> to display advertisements. Google uses cookies (including the DoubleClick cookie) to serve ads based on your prior visits to this site and other sites on the internet.</p>
  <p>You can opt out of personalised advertising at any time by visiting <a href="https://adssettings.google.com/" target="_blank" rel="noopener">Google's Ad Settings</a>. Google's use of advertising cookies is governed by <a href="https://policies.google.com/privacy" target="_blank" rel="noopener">Google's Privacy Policy</a>.</p>

  <h2>6. Data Retention</h2>
  <ul>
    <li>Contact form emails are retained in our inbox until manually deleted.</li>
    <li>Server access logs are purged after 30 days.</li>
    <li>Cookie consent preferences are stored locally in your browser and are not transmitted to our servers.</li>
  </ul>

  <h2>7. Your Rights (GDPR)</h2>
  <p>If you are located in the European Economic Area you have the right to access, rectify, or erase personal data we hold about you, object to or restrict its processing, and lodge a complaint with a supervisory authority. To exercise these rights, contact us at <a href="<?= 'mailto:' . CONTACT_EMAIL ?>"><?= CONTACT_EMAIL ?></a>.</p>

  <h2>8. Children's Privacy</h2>
  <p>This site is not directed at children under the age of 13. We do not knowingly collect personal information from children.</p>

  <h2>9. Changes to This Policy</h2>
  <p>We may update this policy periodically. The effective date at the top of the page reflects the most recent revision. Continued use of the site constitutes acceptance of the updated policy.</p>

  <h2>10. Contact</h2>
  <p>For privacy-related questions or requests: <a href="<?= 'mailto:' . CONTACT_EMAIL ?>"><?= CONTACT_EMAIL ?></a></p>

  <div class="prose-footer">
    &copy; <?= date('Y') ?> Thameur Belghith &nbsp;·&nbsp; <a href="/"><?= SITE_DOMAIN ?></a>
  </div>
</div>

<footer class="site-footer">
  <span>&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="/">Home</a>
    <a href="/privacy.php">Privacy Policy</a>
    <a href="<?= 'mailto:' . CONTACT_EMAIL ?>"><?= CONTACT_EMAIL ?></a>
  </div>
</footer>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>
</body>
</html>
