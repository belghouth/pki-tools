<?php
// ── Contact form AJAX handler ───────────────────────────────────────────────
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/recaptcha.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'contact') {
    header('Content-Type: application/json');

    $name    = trim(strip_tags($_POST['name']    ?? ''));
    $email   = trim(strip_tags($_POST['email']   ?? ''));
    $subject = trim(strip_tags($_POST['subject'] ?? ''));
    $message = trim(strip_tags($_POST['message'] ?? ''));

    if (!$name || !$email || !$message) {
        echo json_encode(['error' => 'Name, email, and message are required.']);
        exit;
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['error' => 'Please enter a valid email address.']);
        exit;
    }
    if (strlen($message) > 4000) {
        echo json_encode(['error' => 'Message is too long (max 4 000 characters).']);
        exit;
    }

    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'contact')) {
            echo json_encode(['error' => 'reCAPTCHA verification failed. Please try again.']);
            exit;
        }
    }

    $to       = CONTACT_EMAIL;
    $mailSubj = $subject !== ''
        ? '[' . SITE_DOMAIN . '] ' . mb_substr($subject, 0, 100)
        : '[' . SITE_DOMAIN . '] Message from ' . $name;
    $body     = "Name:    {$name}\nEmail:   {$email}\n\n" . wordwrap($message, 72);
    $headers  = implode("\r\n", [
        'From: ' . NOREPLY_EMAIL,
        'Reply-To: ' . $email,
        'Content-Type: text/plain; charset=UTF-8',
        'X-Mailer: ' . SITE_DOMAIN . '/contact',
    ]);

    $sent = @mail($to, $mailSubj, $body, $headers);
    echo json_encode($sent
        ? ['ok' => true, 'message' => "Thanks {$name} — I'll be in touch."]
        : ['error' => 'Mail could not be sent. Please email me directly at ' . CONTACT_EMAIL]
    );
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'Thameur Belghith — PKI & Trust Services Engineer',
    'description' => 'Free browser-based PKI tools for WebPKI compliance, certificate linting, CPS analysis, and CA audit support. Built by Thameur Belghith, PKI & Trust Services Engineer.',
    'url'         => SITE_BASE_URL . '/',
    'jsonld'      => json_encode([
      '@context' => 'https://schema.org',
      '@graph'   => [
        [
          '@type'    => 'Person',
          '@id'      => SITE_BASE_URL . '/#person',
          'name'     => 'Thameur Belghith',
          'jobTitle' => 'PKI & Trust Services Engineer',
          'url'      => SITE_BASE_URL . '/',
          'email'    => 'mailto:' . CONTACT_EMAIL,
          'sameAs'   => [
            'https://github.com/belghouth',
            'https://www.linkedin.com/in/belghouth/',
          ],
        ],
        [
          '@type'       => 'WebSite',
          '@id'         => SITE_BASE_URL . '/#website',
          'url'         => SITE_BASE_URL . '/',
          'name'        => SITE_DOMAIN,
          'description' => 'Free PKI tools and resources for WebPKI practitioners and CA auditors.',
          'author'      => ['@id' => SITE_BASE_URL . '/#person'],
        ],
      ],
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
  ]);
  ?>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">
  <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,600;1,300&display=swap" rel="stylesheet">

  <?php require __DIR__ . '/includes/adsense_head.php'; ?>

  <?php if (recaptcha_configured()): ?>
  <?= recaptcha_head() ?>
  <script>window.RECAPTCHA_SITE_KEY = <?= json_encode(RECAPTCHA_SITE_KEY) ?>;</script>
  <?php endif; ?>

  <style>
    /* ── Tokens ─────────────────────────────────────────────────────────────── */
    :root {
      --bg:        #0e1014;
      --surface:   #13171e;
      --surface2:  #181d26;
      --border:    #2a3040;
      --border2:   #3a4458;
      --accent:    #00d4aa;
      --accent2:   #0099ff;
      --text:      #d4dae6;
      --muted:     #6b7a90;
      --mono:      'IBM Plex Mono', monospace;
      --sans:      'IBM Plex Sans', sans-serif;
      --radius:    6px;
      --tr:        160ms ease;
      --max:       1140px;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; font-size: 15px; overflow-x: hidden; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-weight: 300;
      line-height: 1.7;
      min-height: 100vh;
      overflow-x: hidden;
    }

    a { color: var(--accent); text-decoration: none; transition: color var(--tr); }
    a:hover { color: #fff; }

    /* ── Header ─────────────────────────────────────────────────────────────── */
    .site-header {
      position: sticky; top: 0; z-index: 20;
      background: rgba(14,16,20,0.88);
      backdrop-filter: blur(10px);
      border-bottom: 1px solid var(--border);
      padding: 0 2rem;
      display: flex; align-items: center; justify-content: space-between;
      height: 54px;
    }

    .header-logo {
      font-family: var(--mono);
      font-size: 0.9rem; font-weight: 600;
      letter-spacing: 0.08em; text-transform: uppercase;
      color: var(--accent);
    }

    .site-nav { display: flex; gap: 2rem; }
    .site-nav a {
      font-size: 0.82rem; font-weight: 400;
      color: var(--muted); letter-spacing: 0.04em; text-transform: uppercase;
    }
    .site-nav a:hover { color: var(--text); }

    /* ── Hero ───────────────────────────────────────────────────────────────── */
    .hero {
      min-height: 80vh;
      display: flex; align-items: center; justify-content: center;
      text-align: center;
      padding: 4.5rem 2rem;
      background:
        radial-gradient(ellipse 800px 600px at 50% 30%, rgba(0,212,170,0.05) 0%, transparent 70%),
        var(--bg);
      border-bottom: 1px solid var(--border);
      position: relative; overflow: hidden;
    }

    .hero::before {
      content: '';
      position: absolute; inset: 0;
      background-image:
        linear-gradient(var(--border) 1px, transparent 1px),
        linear-gradient(90deg, var(--border) 1px, transparent 1px);
      background-size: 60px 60px;
      opacity: 0.18;
      pointer-events: none;
    }

    .hero-inner { position: relative; max-width: 780px; }

    .hero-meerkat {
      width: 140px; height: 140px;
      object-fit: contain;
      margin-bottom: 1.6rem;
      filter: drop-shadow(0 0 28px rgba(0,212,170,0.35));
      animation: meerkat-float 4s ease-in-out infinite;
    }
    @keyframes meerkat-float {
      0%, 100% { transform: translateY(0); }
      50%       { transform: translateY(-8px); }
    }

    .header-meerkat {
      width: 28px; height: 28px;
      object-fit: contain;
      filter: drop-shadow(0 0 6px rgba(0,212,170,0.3));
    }

    .hero-byline {
      font-family: var(--mono);
      font-size: 0.72rem; letter-spacing: 0.16em; text-transform: uppercase;
      color: #3d4f68; margin-bottom: 1.1rem;
    }

    .hero-headline {
      font-size: clamp(1.7rem, 4.5vw, 3rem);
      font-weight: 600; letter-spacing: -0.02em; line-height: 1.15;
      color: #fff; margin-bottom: 0.9rem;
    }

    .hero-tagline {
      font-size: 1.05rem; color: var(--muted);
      max-width: 540px; margin: 0 auto 0.55rem;
      line-height: 1.65;
    }

    .hero-subline {
      font-family: var(--mono);
      font-size: 0.75rem; color: #3d4f68;
      margin-bottom: 1.8rem;
      letter-spacing: 0.02em;
    }

    .hero-badges {
      display: flex; flex-wrap: wrap; gap: 0.45rem;
      justify-content: center;
      margin-bottom: 2.2rem;
    }
    .hero-badge {
      font-family: var(--mono);
      font-size: 0.68rem; letter-spacing: 0.06em;
      color: #5a7090;
      border: 1px solid #1e2d40;
      border-radius: 4px;
      padding: 0.25rem 0.6rem;
      background: rgba(0,212,170,0.03);
      transition: color 150ms ease, border-color 150ms ease;
    }
    .hero-badge:hover { color: var(--accent); border-color: rgba(0,212,170,0.3); }

    .hero-actions { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }

    .btn {
      display: inline-flex; align-items: center; gap: 0.4rem;
      padding: 0.65rem 1.5rem;
      border-radius: var(--radius);
      font-size: 0.85rem; font-weight: 400; letter-spacing: 0.03em;
      transition: all var(--tr); cursor: pointer; border: none;
      text-decoration: none;
    }
    .btn--primary {
      background: var(--accent); color: #0a1210;
    }
    .btn--primary:hover { background: #00f0c0; color: #0a1210; }
    .btn--outline {
      background: transparent;
      border: 1px solid var(--border2);
      color: var(--text);
    }
    .btn--outline:hover { border-color: var(--accent); color: var(--accent); }

    /* ── Sections ───────────────────────────────────────────────────────────── */
    .section { padding: 5rem 2rem; }
    .section--alt { background: var(--surface); }

    .container { max-width: var(--max); margin: 0 auto; }
    .container--sm { max-width: 680px; margin: 0 auto; }

    .section-eyebrow {
      font-family: var(--mono);
      font-size: 0.72rem; letter-spacing: 0.18em; text-transform: uppercase;
      color: var(--accent); margin-bottom: 0.6rem;
    }

    .section-heading {
      font-size: clamp(1.5rem, 3vw, 2.2rem);
      font-weight: 600; letter-spacing: -0.01em; color: #fff;
      margin-bottom: 0.5rem;
    }

    .section-sub {
      color: var(--muted); font-size: 0.95rem;
      margin-bottom: 3rem;
    }

    /* ── About ──────────────────────────────────────────────────────────────── */
    .about-grid {
      display: grid;
      grid-template-columns: 1fr minmax(0, 320px);
      gap: 4rem; align-items: start;
      width: 100%;
    }

    .about-body p { color: var(--muted); margin-bottom: 1rem; font-size: 0.95rem; }
    .about-body p:last-of-type { margin-bottom: 0; }
    .about-body .about-lead-label {
      font-family: var(--mono);
      font-size: 0.68rem; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase;
      color: var(--accent); margin-bottom: 0.5rem;
    }

    .about-links { display: flex; gap: 0.75rem; margin-top: 1.8rem; flex-wrap: wrap; }
    .pill-link {
      display: inline-block;
      padding: 0.35rem 0.9rem;
      border: 1px solid var(--border2);
      border-radius: 100px;
      font-size: 0.78rem; color: var(--muted);
      transition: all var(--tr);
    }
    .pill-link:hover { border-color: var(--accent); color: var(--accent); }

    /* LinkedIn card */
    .li-card {
      display: flex; align-items: center; gap: 0.9rem;
      margin-top: 1.4rem; padding: 0.9rem 1.1rem;
      background: rgba(10,102,194,0.07);
      border: 1px solid rgba(10,102,194,0.3);
      border-radius: var(--radius);
      text-decoration: none;
      transition: border-color var(--tr), background var(--tr);
    }
    .li-card:hover { border-color: rgba(10,102,194,0.7); background: rgba(10,102,194,0.12); }
    .li-card-logo { color: #0a66c2; flex-shrink: 0; }
    .li-card-body { flex: 1; min-width: 0; }
    .li-card-name { font-size: 0.88rem; font-weight: 600; color: #fff; }
    .li-card-title { font-size: 0.75rem; color: var(--muted); margin-top: 0.1rem; }
    .li-card-cta { font-family: var(--mono); font-size: 0.72rem; color: #0a66c2; flex-shrink: 0; }

    .about-focus {
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.6rem;
    }

    .about-focus h3 {
      font-family: var(--mono);
      font-size: 0.75rem; letter-spacing: 0.12em; text-transform: uppercase;
      color: var(--accent); margin-bottom: 1rem;
    }

    .focus-list { list-style: none; }
    .focus-list li {
      font-size: 0.85rem; color: var(--muted);
      padding: 0.45rem 0;
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 0.6rem;
    }
    .focus-list li:last-child { border-bottom: none; }
    .focus-list li::before {
      content: '';
      display: inline-block; width: 6px; height: 6px;
      border-radius: 50%; background: var(--accent);
      flex-shrink: 0;
    }

    /* ── Tools grid ─────────────────────────────────────────────────────────── */
    .tools-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
      gap: 1.25rem;
    }

    .tool-card {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
      transition: border-color var(--tr), transform var(--tr);
      display: flex; flex-direction: column;
    }
    .tool-card:hover {
      border-color: var(--border2);
      transform: translateY(-2px);
    }

    .tool-card-bar { height: 3px; }
    .tool-card-bar--teal    { background: var(--accent); }
    .tool-card-bar--blue    { background: var(--accent2); }
    .tool-card-bar--purple  { background: #a78bfa; }
    .tool-card-bar--amber   { background: #f59e0b; }
    .tool-card-bar--orange  { background: #f97316; }
    .tool-card-bar--green   { background: #22c55e; }

    .tool-card-body { padding: 1.4rem; flex: 1; display: flex; flex-direction: column; }

    .tool-card-icon {
      font-size: 1.5rem; margin-bottom: 0.8rem;
      line-height: 1;
    }

    .tool-card-name {
      font-size: 1rem; font-weight: 600; color: #fff;
      margin-bottom: 0.4rem;
    }

    .tool-card-desc {
      font-size: 0.83rem; color: var(--muted);
      flex: 1; margin-bottom: 1.2rem; line-height: 1.6;
    }

    .tool-card-tags {
      display: flex; gap: 0.4rem; flex-wrap: wrap;
      margin-bottom: 1.2rem;
    }

    .tag {
      font-family: var(--mono);
      font-size: 0.68rem; padding: 0.2rem 0.5rem;
      border-radius: 3px;
      background: rgba(255,255,255,0.04);
      border: 1px solid var(--border);
      color: var(--muted);
    }
    .tag--experimental {
      background: rgba(245,158,11,0.12);
      border-color: rgba(245,158,11,0.4);
      color: #f59e0b;
    }

    .tool-card-link {
      font-family: var(--mono);
      font-size: 0.78rem; color: var(--accent);
      display: flex; align-items: center; gap: 0.3rem;
      transition: gap var(--tr);
    }
    .tool-card-link:hover { color: #fff; gap: 0.5rem; }

    /* ── AdSense strip ──────────────────────────────────────────────────────── */
    .ad-strip {
      padding: 2rem;
      background: var(--bg);
      border-top: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
      text-align: center;
    }
    .ad-strip .ad-label {
      font-family: var(--mono);
      font-size: 0.65rem; color: var(--border2);
      letter-spacing: 0.1em; text-transform: uppercase;
      margin-bottom: 0.5rem;
    }

    /* ── Contact (email card) ───────────────────────────────────────────────── */
    .contact-email-card {
      display: inline-flex; align-items: center; gap: 0.75rem;
      margin: 0 auto 1.6rem;
      padding: 1rem 2rem;
      background: var(--surface);
      border: 1px solid var(--border2);
      border-radius: var(--radius);
      color: var(--accent); text-decoration: none;
      font-size: 1.05rem;
      transition: border-color var(--tr), background var(--tr);
    }
    .contact-email-card:hover { border-color: var(--accent); background: rgba(0,212,170,0.06); color: var(--accent); }
    .contact-note { font-size: 0.82rem; color: var(--muted); margin-top: 0.5rem; line-height: 1.8; }
    .coming-soon-badge {
      display: inline-block;
      font-family: var(--mono); font-size: 0.68rem;
      letter-spacing: 0.08em; text-transform: uppercase;
      padding: 0.2rem 0.65rem;
      border-radius: 100px;
      border: 1px solid var(--border2);
      color: var(--muted);
    }

    /* ── Footer ─────────────────────────────────────────────────────────────── */
    .site-footer {
      border-top: 1px solid var(--border);
      padding: 1.6rem 2rem;
      display: flex; align-items: center; justify-content: space-between;
      flex-wrap: wrap; gap: 1rem;
    }
    .site-footer-left {
      font-family: var(--mono);
      font-size: 0.75rem; color: var(--muted);
    }
    .site-footer-links {
      display: flex; gap: 1.5rem;
      font-size: 0.78rem; color: var(--muted);
    }
    .site-footer-links a:hover { color: var(--accent); }

    /* ── Responsive ─────────────────────────────────────────────────────────── */
    @media (max-width: 820px) {
      .about-grid { grid-template-columns: 1fr; gap: 2.5rem; }
      .form-row   { grid-template-columns: 1fr; }
      .site-nav   { gap: 1.2rem; }
    }
    @media (max-width: 520px) {
      .site-header { padding: 0 1rem; }
      .section     { padding: 3.5rem 1.25rem; }
      .hero        { padding: 3rem 1.25rem; min-height: 0; }
      .hero-meerkat { width: 96px; height: 96px; margin-bottom: 1.1rem; }
      .hero-headline { font-size: clamp(1.35rem, 6vw, 2rem); }
      .hero-byline  { font-size: 0.65rem; }
      .hero-tagline { font-size: 0.92rem; }
      .hero-subline { font-size: 0.7rem; }
      .hero-badges  { gap: 0.35rem; }
      .site-nav a:not(:first-child):not(:last-child) { display: none; }
    }

    /* ── Back-to-top button (mobile only) ── */
    .back-top {
      display: none;
    }
    @media (max-width: 820px) {
      .back-top {
        display: flex;
        align-items: center; justify-content: center;
        position: fixed;
        top: 68px; right: 1rem;
        z-index: 90;
        width: 36px; height: 36px;
        background: rgba(13,15,20,0.88);
        border: 1px solid rgba(0,212,170,0.35);
        border-radius: 8px;
        color: var(--accent);
        cursor: pointer;
        opacity: 0;
        pointer-events: none;
        transform: translateY(-6px);
        transition: opacity 220ms ease, transform 220ms ease, background 150ms ease, border-color 150ms ease;
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
      }
      .back-top--visible {
        opacity: 1;
        pointer-events: auto;
        transform: translateY(0);
      }
      .back-top:active {
        background: rgba(0,212,170,0.12);
        border-color: rgba(0,212,170,0.7);
      }
    }
  </style>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<main>

  <!-- ── Hero ───────────────────────────────────────────────────────────────── -->
  <section class="hero">
    <div class="hero-inner">
      <img src="/img/meerkat_240.png" alt="Meerkat mascot" class="hero-meerkat">
      <p class="hero-byline">by Thameur Belghith &mdash; PKI &amp; Trust Services Engineer</p>
      <h1 class="hero-headline">WebPKI Tools, Compliance &amp; Certificate Engineering</h1>
      <p class="hero-tagline">Tools for people who would rather catch problems before Chrome does.</p>
      <p class="hero-subline">Built with enough vigilance to survive Bugzilla.</p>
      <div class="hero-badges">
        <span class="hero-badge">zlint</span>
        <span class="hero-badge">pkilint</span>
        <span class="hero-badge">x509lint</span>
        <span class="hero-badge">ACME</span>
        <span class="hero-badge">CT</span>
        <span class="hero-badge">RFC 5280</span>
        <span class="hero-badge">CABF BRs</span>
      </div>
      <div class="hero-actions">
        <a href="#tools" class="btn btn--primary">Explore Tools</a>
        <a href="#about" class="btn btn--outline">About</a>
      </div>
    </div>
  </section>

  <!-- ── About ──────────────────────────────────────────────────────────────── -->
  <section class="section" id="about">
    <div class="container">
      <h2 class="section-heading">About</h2>
      <div class="about-grid">
        <div class="about-body">

          <p class="about-lead-label">What this site is</p>
          <p>A free, no-account resource for PKI practitioners — certificates, compliance, and the full toolbox in one place. It hosts tools I built to cover gaps I kept running into: a multi-linter that runs zlint, pkilint, and x509lint in a single shot; a CPS-to-BR coverage checker; a universal artifact parser that handles anything from a certificate to a timestamp token; and a live ACME endpoint demo. Next to those, there is a curated directory of the best open-source testing tools the community produces — ASN.1 decoders, TLS analysers, digital signature validators, CT log search, and more. One place, everything PKI.</p>

          <p class="about-lead-label" style="margin-top:1.6rem">Who built it</p>
          <p>I work in PKI and Trust Services. Day-to-day: certificate profile engineering, CA system design, CPS/CP authoring, compliance against the CA/Browser Forum Baseline Requirements, audit support. These tools started as internal utilities for problems I kept running into. I open-sourced them because the gap between what the BRs require and what most teams have available to check against it is real — and not worth solving from scratch every time.</p>

          <div class="about-links">
            <a href="https://github.com/belghouth" class="pill-link" target="_blank" rel="noopener">GitHub</a>
            <a href="https://www.linkedin.com/in/belghouth/" class="pill-link" target="_blank" rel="noopener">LinkedIn</a>
            <a href="<?= 'mailto:' . CONTACT_EMAIL ?>" class="pill-link">Email</a>
          </div>

          <a href="https://www.linkedin.com/in/belghouth/" class="li-card" target="_blank" rel="noopener" aria-label="LinkedIn profile">
            <div class="li-card-logo">
              <svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>
            </div>
            <div class="li-card-body">
              <div class="li-card-name">Thameur Belghith</div>
              <div class="li-card-title">PKI &amp; Trust Services Engineer</div>
            </div>
            <div class="li-card-cta">Connect ↗</div>
          </a>
        </div>
        <div class="about-focus">
          <h3>Areas of Focus</h3>
          <ul class="focus-list">
            <li>WebPKI &amp; CA/Browser Forum Compliance</li>
            <li>X.509 Certificate Engineering</li>
            <li>CPS / CP Authoring &amp; Audit Support</li>
            <li>Certificate Transparency (CT Logs)</li>
            <li>ACME &amp; Automated Certificate Management</li>
            <li>Revocation Infrastructure (OCSP / CRL)</li>
            <li>Multi-Perspective Issuance Corroboration</li>
          </ul>
        </div>
      </div>
    </div>
  </section>

  <!-- ── Tools ──────────────────────────────────────────────────────────────── -->
  <section class="section section--alt" id="tools">
    <div class="container">
      <h2 class="section-heading">PKI Tools</h2>
      <p class="section-sub">Free, browser-based tools for PKI practitioners, CA auditors, and security engineers.</p>

      <div class="tools-grid">

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--blue"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">🧾</div>
            <div class="tool-card-name">Meerkat Multi-Linter</div>
            <div class="tool-card-desc">Run a certificate through zlint, pkilint, and x509lint simultaneously. Flags policy violations and RFC 5280 issues with direct references to the failing requirements.</div>
            <div class="tool-card-tags">
              <span class="tag">zlint</span>
              <span class="tag">pkilint</span>
              <span class="tag">x509lint</span>
            </div>
            <a href="/linters.php" class="tool-card-link">Open Tool →</a>
          </div>
        </div>

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--teal"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">⚡</div>
            <div class="tool-card-name">ACME Automation Testing Endpoint</div>
            <div class="tool-card-desc">A live reference implementation of an automated certificate renewal endpoint as required by the Chrome Root Program and validated by Mozilla. Demonstrates RFC 8555 renewal verification in a production environment.</div>
            <div class="tool-card-tags">
              <span class="tag">ACME</span>
              <span class="tag">RFC 8555</span>
              <span class="tag">Chrome Root</span>
            </div>
            <a href="/acme-endpoint.php" class="tool-card-link">View Demo →</a>
          </div>
        </div>

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--teal"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">🔬</div>
            <div class="tool-card-name">ACME Endpoint Tester</div>
            <div class="tool-card-desc">Validate any RFC 8555 ACME endpoint end-to-end: directory field checks, account creation (with optional EAB), order placement, http-01 and dns-01 challenges, certificate issuance, revocation, and ARI. Captures all raw protocol exchanges for a downloadable evidence report.</div>
            <div class="tool-card-tags">
              <span class="tag">ACME</span>
              <span class="tag">RFC 8555</span>
              <span class="tag">http-01</span>
              <span class="tag">dns-01</span>
              <span class="tag">ARI</span>
            </div>
            <a href="/acme_tester.php" class="tool-card-link">Open Tool →</a>
          </div>
        </div>

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--amber"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">🔍</div>
            <div class="tool-card-name">Meerkat Artifact Parser</div>
            <div class="tool-card-desc">Paste or upload any PKI artifact — certificate, CSR, CRL, OCSP response, public key, PKCS#7, or timestamp token — and get an instant structured breakdown. Supports PEM and DER. Private key material is detected and rejected server-side.</div>
            <div class="tool-card-tags">
              <span class="tag">X.509</span>
              <span class="tag">CSR</span>
              <span class="tag">CRL</span>
              <span class="tag">PKCS#7</span>
              <span class="tag">RFC 3161</span>
            </div>
            <a href="/artifact_parser.php" class="tool-card-link">Open Tool →</a>
          </div>
        </div>

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--teal"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">🔑</div>
            <div class="tool-card-name">CSR Generator</div>
            <div class="tool-card-desc">Build a Certificate Signing Request with full control over the key algorithm (RSA, ECDSA, Ed25519), curve or key size, and signature hash. Compose the Subject DN field-by-field from a complete OID-annotated list — deprecated attributes flagged — with SAN support for DNS, IP, email, and URI. UTF-8 encoding enabled throughout for international characters.</div>
            <div class="tool-card-tags">
              <span class="tag">CSR</span>
              <span class="tag">RSA</span>
              <span class="tag">ECDSA</span>
              <span class="tag">Ed25519</span>
              <span class="tag">SAN</span>
            </div>
            <a href="/csr_generator.php" class="tool-card-link">Open Tool →</a>
          </div>
        </div>

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--orange"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">🏭</div>
            <div class="tool-card-name">Meerkat TLS Test Certificate Factory</div>
            <div class="tool-card-desc">Issue BR-compliant DV TLS certificates from the Meerkat Test CA. Accepts a CSR or generates one on-the-fly from a list of domains. Only DNS SANs accepted — no IPs, no email. Subject CN is derived from the first SAN; all other CSR fields are stripped.</div>
            <div class="tool-card-tags">
              <span class="tag">Test CA</span>
              <span class="tag">BR Compliance</span>
              <span class="tag">DV</span>
              <span class="tag">RSA</span>
            </div>
            <a href="/cert_factory.php" class="tool-card-link">Open Tool →</a>
          </div>
        </div>

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--green"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">🌳</div>
            <div class="tool-card-name">Meerkat Testing CT Log</div>
            <div class="tool-card-desc">An RFC 6962-compliant Certificate Transparency log for testing. Accepts precertificate chains and returns cryptographically valid SCTs signed by one of 8 randomised fake log identities. Ephemeral — no entries are stored. Includes full API reference and integration guide.</div>
            <div class="tool-card-tags">
              <span class="tag">RFC 6962</span>
              <span class="tag">CT Log</span>
              <span class="tag">SCT</span>
              <span class="tag">Precertificate</span>
            </div>
            <a href="/ct_log_doc.php" class="tool-card-link">Open Tool →</a>
          </div>
        </div>

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--amber"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">⏱</div>
            <div class="tool-card-name">Meerkat Testing TSA</div>
            <div class="tool-card-desc">A fully RFC 3161-compliant Time Stamping Authority for testing. Submit a DER-encoded timestamp request and receive a cryptographically valid TimeStampResp signed by the Meerkat TSA. Supports SHA-256, SHA-384, and SHA-512. Includes integration guide and verification instructions.</div>
            <div class="tool-card-tags">
              <span class="tag">RFC 3161</span>
              <span class="tag">TSA</span>
              <span class="tag">IETF</span>
              <span class="tag">Timestamp</span>
            </div>
            <a href="/tsa_doc.php" class="tool-card-link">Open Tool →</a>
          </div>
        </div>

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--purple"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">🏛️</div>
            <div class="tool-card-name">Meerkat MPCA Factory</div>
            <div class="tool-card-desc">Issue multi-purpose test certificates from the Meerkat private CA hierarchy. Supports S/MIME (MV Multipurpose &amp; Signing), Client Authentication, Document Signing (AdES/RFC 9336), and Code Signing OV. Profile-driven — extensions, policies, and validity are enforced per CA/B Forum requirements.</div>
            <div class="tool-card-tags">
              <span class="tag">S/MIME</span>
              <span class="tag">Code Signing</span>
              <span class="tag">Client Auth</span>
              <span class="tag">AdES</span>
            </div>
            <a href="/mpca_factory.php" class="tool-card-link">Open Tool →</a>
          </div>
        </div>

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--purple"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">📋</div>
            <div class="tool-card-name">CPS-to-BR Assessor</div>
            <div class="tool-card-desc">Upload or link to a CP/CPS document and get an automated section-by-section coverage analysis against the CA/Browser Forum Baseline Requirements.</div>
            <div class="tool-card-tags">
              <span class="tag tag--experimental">Experimental</span>
              <span class="tag">CPS</span>
              <span class="tag">BR</span>
              <span class="tag">CABF</span>
            </div>
            <a href="/cps_to_br_assessor.php" class="tool-card-link">Open Tool →</a>
          </div>
        </div>

      </div>
    </div>
  </section>

  <?php require __DIR__ . '/includes/adsense_unit.php'; ?>

  <!-- ── Contact ────────────────────────────────────────────────────────────── -->
  <section class="section" id="contact">
    <div class="container--sm" style="text-align:center;">
      <h2 class="section-heading">Get in Touch</h2>
      <p class="section-sub">Questions about the tools, PKI consulting, or just want to connect.</p>

      <a href="<?= 'mailto:' . CONTACT_EMAIL ?>" class="contact-email-card">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="28" height="28"><path d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
        <span><?= CONTACT_EMAIL ?></span>
      </a>

      <p class="contact-note">
        <span class="coming-soon-badge">Contact form coming soon</span>
      </p>
    </div>
  </section>

</main>

<!-- ── Footer ─────────────────────────────────────────────────────────────── -->
<footer class="site-footer">
  <span class="site-footer-left">&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="https://github.com/belghouth" target="_blank" rel="noopener">GitHub</a>
    <a href="https://www.linkedin.com/in/belghouth/" target="_blank" rel="noopener">LinkedIn</a>
    <a href="/feed.php">PKI News</a>
    <a href="/community_tools.php">Community Tools</a>
    <a href="/references.php">References</a>
    <a href="/privacy.php">Privacy</a>
    <a href="<?= 'mailto:' . CONTACT_EMAIL ?>"><?= CONTACT_EMAIL ?></a>
  </div>
</footer>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>

<button class="back-top" id="backTop" aria-label="Back to top">
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <polyline points="18 15 12 9 6 15"/>
  </svg>
</button>

<script>
(function () {
  var btn = document.getElementById('backTop');
  var threshold = document.getElementById('about');

  function update() {
    var show = threshold
      ? window.scrollY >= threshold.offsetTop - 80
      : window.scrollY > 400;
    btn.classList.toggle('back-top--visible', show);
  }

  window.addEventListener('scroll', update, { passive: true });
  btn.addEventListener('click', function () {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
})();
</script>

</body>
</html>
