<?php
// ── Contact form AJAX handler ───────────────────────────────────────────────
define('ADMIN_NO_LOG', true);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/recaptcha.php';

const CONTACT_TOPICS = [
    'bug_report'      => 'Bug Report',
    'wrong_result'    => 'Wrong Result / False Positive',
    'feature_request' => 'Feature Request / Suggestion',
    'pki_question'    => 'PKI / Compliance Question',
    'tool_feedback'   => 'Tool Feedback',
    'consulting'      => 'Consulting Inquiry',
    'other'           => 'Other',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'contact') {
    header('Content-Type: application/json');

    $name    = mb_substr(trim(strip_tags($_POST['name']    ?? '')), 0, 120);
    $email   = mb_substr(trim(strip_tags($_POST['email']   ?? '')), 0, 254);
    $topic   = trim($_POST['topic'] ?? '');
    $message = mb_substr(trim(strip_tags($_POST['message'] ?? '')), 0, 4000);
    $postUri = '/index.php';

    if (!$name || !$email || !$message) {
        logPostPayload($postUri, $_POST, 200, 'missing_fields');
        echo json_encode(['error' => 'Name, email, and message are required.']);
        exit;
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        logPostPayload($postUri, $_POST, 200, 'invalid_email');
        echo json_encode(['error' => 'Please enter a valid email address.']);
        exit;
    }
    if (!isset(CONTACT_TOPICS[$topic])) {
        logPostPayload($postUri, $_POST, 200, 'invalid_topic');
        echo json_encode(['error' => 'Please select a topic.']);
        exit;
    }

    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'contact')) {
            logPostPayload($postUri, $_POST, 200, 'recaptcha_fail');
            echo json_encode(['error' => 'reCAPTCHA verification failed. Please try again.']);
            exit;
        }
    }

    $ip = substr(trim(explode(',',
        $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_REAL_IP'] ??
        $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '')[0]), 0, 45);
    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 300);

    $pdo = admin_pdo();
    if ($pdo) {
        $pdo->prepare(
            "INSERT INTO contact_messages (name, email, topic, message, ip, user_agent)
             VALUES (?, ?, ?, ?, ?, ?)"
        )->execute([$name, $email, $topic, $message, $ip, $ua]);
    }

    $topicLabel = CONTACT_TOPICS[$topic];
    $mailSubj   = '[' . SITE_DOMAIN . '] ' . $topicLabel . ' from ' . $name;
    $mailBody   = "Topic  : {$topicLabel}\nName   : {$name}\nEmail  : {$email}\nIP     : {$ip}\n\n"
                . wordwrap($message, 72);
    $headers = implode("\r\n", [
        'From: '       . SITE_DOMAIN . ' Contact <' . NOREPLY_EMAIL . '>',
        'Reply-To: '   . $email,
        'Content-Type: text/plain; charset=UTF-8',
        'X-Mailer: '   . SITE_DOMAIN . '/contact',
    ]);
    @mail(ADMIN_ALLOWED_EMAIL, $mailSubj, $mailBody, $headers);

    logPostPayload($postUri, $_POST, 200, 'success');
    echo json_encode(['ok' => true, 'message' => "Thanks {$name}, your message was received."]);
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
          'sameAs'   => [
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

  <?php require_once __DIR__ . '/includes/adsense_head.php'; ?>

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
    .tool-group { margin-bottom: 3rem; }
    .tool-group:last-child { margin-bottom: 0; }

    .tool-group-header {
      padding: 0.85rem 1.25rem;
      background: var(--surface2);
      border: 1px solid var(--border2);
      border-left: 3px solid var(--accent);
      border-radius: var(--radius);
      margin-bottom: 1.25rem;
    }
    .tool-group-label {
      font-size: 0.95rem;
      font-weight: 600;
      color: #fff;
      letter-spacing: -0.01em;
    }

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

    /* ── Contact form ───────────────────────────────────────────────────────── */
    .contact-form { text-align: left; max-width: 540px; margin: 0 auto; }
    .cf-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
    .cf-field { display: flex; flex-direction: column; gap: 0.35rem; margin-bottom: 1rem; }
    .cf-field label { font-size: 0.78rem; color: var(--muted); font-family: var(--mono); }
    .cf-field input,
    .cf-field select,
    .cf-field textarea {
      background: var(--surface); border: 1px solid var(--border2);
      border-radius: 6px; color: var(--text);
      font-family: var(--sans); font-size: 0.92rem;
      padding: 0.55rem 0.75rem; width: 100%; box-sizing: border-box;
      transition: border-color var(--tr);
    }
    .cf-field input:focus,
    .cf-field select:focus,
    .cf-field textarea:focus {
      outline: none; border-color: var(--accent);
    }
    .cf-field select { appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%238b949e' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 0.75rem center; padding-right: 2rem; }
    .cf-field textarea { resize: vertical; min-height: 130px; line-height: 1.55; }
    .cf-error { font-size: 0.82rem; color: #f85149; margin-bottom: 0.75rem; min-height: 1.2em; }
    .cf-success { font-size: 1rem; color: var(--accent); padding: 2rem 0; text-align: center; }
    .cf-submit { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.6rem 1.5rem; background: var(--accent); color: #0d1117; border: none; border-radius: 6px; font-size: 0.9rem; font-weight: 600; cursor: pointer; transition: opacity var(--tr); }
    .cf-submit:disabled { opacity: 0.5; cursor: default; }
    @media (max-width: 520px) { .cf-row { grid-template-columns: 1fr; } }

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

<?php require_once __DIR__ . '/includes/site_nav.php'; ?>

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
          <p>A free, no-account toolbox for PKI practitioners and CA auditors. It covers certificate linting (pkilint, zlint, x509lint in one shot), CPS-to-BR compliance mapping, a universal artifact parser for certificates, CRLs, OCSP, timestamp tokens, and more. It also provides a live ACME endpoint for testing, a CCADB browser with browser trust status and inline chain linting, an e-seal signer, and a curated directory of the best community tools. Built to close the gap between what the BRs require and what most teams have to check against it.</p>

          <p class="about-lead-label" style="margin-top:1.6rem">Who built it</p>
          <p>I work in PKI and Trust Services. Day-to-day: certificate profile engineering, CA system design, CPS/CP authoring, compliance against the CA/Browser Forum Baseline Requirements, audit support. These tools started as internal utilities for problems I kept running into. I open-sourced them because the gap between what the BRs require and what most teams have available to check against it is real — and not worth solving from scratch every time.</p>

          <div class="about-links">
            <a href="https://www.linkedin.com/in/belghouth/" class="pill-link" target="_blank" rel="noopener">LinkedIn</a>
            <a href="#contact" class="pill-link">Contact</a>
          </div>

        </div>
        <div class="about-focus">
          <h3>Areas of Focus</h3>
          <ul class="focus-list">
            <li>WebPKI &amp; CA/Browser Forum Compliance</li>
            <li>X.509 Certificate Profile Engineering</li>
            <li>CPS / CP Authoring &amp; Audit Support</li>
            <li>CCADB &amp; Root Program Management</li>
            <li>Certificate Transparency (CT Logs)</li>
            <li>ACME &amp; Automated Certificate Management</li>
            <li>Revocation Infrastructure (OCSP / CRL)</li>
            <li>eIDAS / EU Trust Services (eSeals, TSA)</li>
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

      <!-- ── Certificate Issuance & Test CAs ──────────────────────────────── -->
      <div class="tool-group">
        <div class="tool-group-header">
          <span class="tool-group-label">Certificate Issuance &amp; Test CAs</span>
        </div>
        <div class="tools-grid">

          <div class="tool-card">
            <div class="tool-card-bar tool-card-bar--teal"></div>
            <div class="tool-card-body">
              <div class="tool-card-icon">🔑</div>
              <div class="tool-card-name">CSR Generator</div>
              <div class="tool-card-desc">Build a Certificate Signing Request with full control over the key algorithm (RSA, ECDSA, Ed25519), curve or key size, and signature hash. Compose the Subject DN field-by-field from a complete OID-annotated list — deprecated attributes flagged — with SAN support for DNS, IP, email, and URI.</div>
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
              <div class="tool-card-name">Meerkat TLS Certificate Factory</div>
              <div class="tool-card-desc">Issue BR-compliant DV TLS certificates from the Meerkat Test CA. Accepts a CSR or generates one on-the-fly from a list of domains. Only DNS SANs accepted — no IPs, no email. Subject CN is derived from the first SAN; all other CSR fields are stripped.</div>
              <div class="tool-card-tags">
                <span class="tag">Test CA</span>
                <span class="tag">BR Compliance</span>
                <span class="tag">DV TLS</span>
                <span class="tag">RSA</span>
              </div>
              <a href="/cert_factory.php" class="tool-card-link">Open Tool →</a>
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

        </div>
      </div>

      <!-- ── Trust Service Endpoints ───────────────────────────────────────── -->
      <div class="tool-group">
        <div class="tool-group-header">
          <span class="tool-group-label">Trust Service Endpoints</span>
        </div>
        <div class="tools-grid">

          <div class="tool-card">
            <div class="tool-card-bar tool-card-bar--teal"></div>
            <div class="tool-card-body">
              <div class="tool-card-icon">⚡</div>
              <div class="tool-card-name">Meerkat ACME Endpoint</div>
              <div class="tool-card-desc">A live reference implementation of an automated certificate renewal endpoint as required by the Chrome Root Program and validated by Mozilla. Demonstrates RFC 8555 renewal verification in a production environment.</div>
              <div class="tool-card-tags">
                <span class="tag">ACME</span>
                <span class="tag">RFC 8555</span>
                <span class="tag">Chrome Root</span>
              </div>
              <a href="/acme-endpoint.php" class="tool-card-link">View Endpoint →</a>
            </div>
          </div>

          <div class="tool-card">
            <div class="tool-card-bar tool-card-bar--green"></div>
            <div class="tool-card-body">
              <div class="tool-card-icon">🌳</div>
              <div class="tool-card-name">Meerkat CT Log</div>
              <div class="tool-card-desc">An RFC 6962-compliant Certificate Transparency log for testing. Accepts precertificate chains and returns cryptographically valid SCTs signed by one of 8 randomised fake log identities. Ephemeral — no entries are stored. Includes full API reference and integration guide.</div>
              <div class="tool-card-tags">
                <span class="tag">RFC 6962</span>
                <span class="tag">CT Log</span>
                <span class="tag">SCT</span>
                <span class="tag">Precertificate</span>
              </div>
              <a href="/ct_log_doc.php" class="tool-card-link">View Endpoint →</a>
            </div>
          </div>

          <div class="tool-card">
            <div class="tool-card-bar tool-card-bar--amber"></div>
            <div class="tool-card-body">
              <div class="tool-card-icon">⏱</div>
              <div class="tool-card-name">Meerkat TSA</div>
              <div class="tool-card-desc">A fully RFC 3161-compliant Time Stamping Authority for testing. Submit a DER-encoded timestamp request and receive a cryptographically valid TimeStampResp signed by the Meerkat TSA. Supports SHA-256, SHA-384, and SHA-512. Includes integration guide and verification instructions.</div>
              <div class="tool-card-tags">
                <span class="tag">RFC 3161</span>
                <span class="tag">TSA</span>
                <span class="tag">SHA-256</span>
                <span class="tag">SHA-512</span>
              </div>
              <a href="/tsa_doc.php" class="tool-card-link">View Endpoint →</a>
            </div>
          </div>

          <div class="tool-card">
            <div class="tool-card-bar tool-card-bar--purple"></div>
            <div class="tool-card-body">
              <div class="tool-card-icon">🖊️</div>
              <div class="tool-card-name">Meerkat e-Seal API</div>
              <div class="tool-card-desc">REST signing endpoint issuing CAdES (CMS) or XAdES (XML) signatures from the Meerkat e-Seal authority (eIDAS / ETSI EN 319 412-3). Optional RFC 3161 timestamp for T-level. Includes curl, Python, and JavaScript integration examples.</div>
              <div class="tool-card-tags">
                <span class="tag">eIDAS</span>
                <span class="tag">CAdES</span>
                <span class="tag">XAdES</span>
                <span class="tag">ETSI</span>
              </div>
              <a href="/eseal_doc.php" class="tool-card-link">View Endpoint →</a>
            </div>
          </div>

        </div>
      </div>

      <!-- ── Service Clients & Signers ─────────────────────────────────────── -->
      <div class="tool-group">
        <div class="tool-group-header">
          <span class="tool-group-label">Service Clients &amp; Signers</span>
        </div>
        <div class="tools-grid">

          <div class="tool-card">
            <div class="tool-card-bar tool-card-bar--amber"></div>
            <div class="tool-card-body">
              <div class="tool-card-icon">🕰️</div>
              <div class="tool-card-name">Meerkat TimeStampIt</div>
              <div class="tool-card-desc">Upload any file or paste text to receive a cryptographically signed RFC 3161 timestamp token from the Meerkat TSA. Download the signed <code>.tsr</code> and inspect the full timestamp response inline — no CLI required.</div>
              <div class="tool-card-tags">
                <span class="tag">RFC 3161</span>
                <span class="tag">TSA</span>
                <span class="tag">Timestamp</span>
                <span class="tag">IETF</span>
              </div>
              <a href="/timestamp_it.php" class="tool-card-link">Open Tool →</a>
            </div>
          </div>

          <div class="tool-card">
            <div class="tool-card-bar tool-card-bar--purple"></div>
            <div class="tool-card-body">
              <div class="tool-card-icon">🔏</div>
              <div class="tool-card-name">Meerkat e-Seal Signer</div>
              <div class="tool-card-desc">Paste a hash digest to receive a CAdES (CMS) or XAdES (XML) e-Seal signature, with or without an RFC 3161 timestamp (T level). Download the token and inspect it inline or send it to the Artifact Parser.</div>
              <div class="tool-card-tags">
                <span class="tag">eIDAS</span>
                <span class="tag">CAdES</span>
                <span class="tag">XAdES</span>
                <span class="tag">ETSI</span>
              </div>
              <a href="/eseal_signer.php" class="tool-card-link">Open Tool →</a>
            </div>
          </div>

        </div>
      </div>

      <!-- ── Inspection & Compliance ────────────────────────────────────────── -->
      <div class="tool-group">
        <div class="tool-group-header">
          <span class="tool-group-label">Inspection &amp; Compliance</span>
        </div>
        <div class="tools-grid">

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

          <div class="tool-card">
            <div class="tool-card-bar tool-card-bar--green"></div>
            <div class="tool-card-body">
              <div class="tool-card-icon">🗄️</div>
              <div class="tool-card-name">CCADB Browser</div>
              <div class="tool-card-desc">Browse all CCADB root and intermediate CA certificates grouped by CA owner. Shows browser trust status (Chrome, Mozilla, Apple, Microsoft), audit info, EKU capabilities, and policy OIDs. Includes inline chain linting. Updated weekly.</div>
              <div class="tool-card-tags">
                <span class="tag">CCADB</span>
                <span class="tag">Root Programs</span>
                <span class="tag">Browser Trust</span>
                <span class="tag">Chain Lint</span>
              </div>
              <a href="/ccadb.php" class="tool-card-link">Open Tool →</a>
            </div>
          </div>

        </div>
      </div>

    </div>
  </section>

  <?php require_once __DIR__ . '/includes/adsense_unit.php'; ?>

  <!-- ── Contact ────────────────────────────────────────────────────────────── -->
  <section class="section" id="contact">
    <div class="container--sm" style="text-align:center;">
      <h2 class="section-heading">Get in Touch</h2>
      <p class="section-sub">Questions about the tools, a result that looks wrong, PKI consulting, or just want to connect.</p>

      <form id="contact-form" class="contact-form" novalidate>
        <input type="hidden" name="action" value="contact">
        <input type="hidden" name="g_recaptcha_token" id="g_recaptcha_token">

        <div class="cf-row">
          <div class="cf-field">
            <label for="cf-name">Your name <span style="color:var(--err)">*</span></label>
            <input type="text" id="cf-name" name="name" maxlength="120" autocomplete="name" required>
          </div>
          <div class="cf-field">
            <label for="cf-email">Your email <span style="color:var(--err)">*</span></label>
            <input type="email" id="cf-email" name="email" maxlength="254" autocomplete="email" required>
          </div>
        </div>

        <div class="cf-field">
          <label for="cf-topic">Topic <span style="color:var(--err)">*</span></label>
          <select id="cf-topic" name="topic" required>
            <option value="">— Select a topic —</option>
            <?php foreach (CONTACT_TOPICS as $val => $lbl): ?>
            <option value="<?= htmlspecialchars($val) ?>"><?= htmlspecialchars($lbl) ?></option>
            <?php endforeach; ?>
          </select>
        </div>

        <div class="cf-field">
          <label for="cf-message">Message <span style="color:var(--err)">*</span></label>
          <textarea id="cf-message" name="message" maxlength="4000" required></textarea>
        </div>

        <div class="cf-error" id="cf-error" aria-live="polite"></div>

        <button type="submit" class="cf-submit" id="cf-submit">Send Message</button>
      </form>
    </div>
  </section>

</main>

<!-- ── Footer ─────────────────────────────────────────────────────────────── -->
<footer class="site-footer">
  <span class="site-footer-left">&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="https://www.linkedin.com/in/belghouth/" target="_blank" rel="noopener">LinkedIn</a>
    <a href="/feed.php">PKI News</a>
    <a href="/community_tools.php">Community Tools</a>
    <a href="/references.php">References</a>
    <a href="/privacy.php">Privacy</a>
    <a href="#contact">Contact</a>
  </div>
</footer>

<?php require_once __DIR__ . '/includes/cookie_banner.php'; ?>

<button class="back-top" id="backTop" aria-label="Back to top">
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <polyline points="18 15 12 9 6 15"/>
  </svg>
</button>

<script>
// ── Contact form ──────────────────────────────────────────────────────────────
(function () {
  var form  = document.getElementById('contact-form');
  if (!form) return;
  var errEl = document.getElementById('cf-error');
  var btnEl = document.getElementById('cf-submit');

  function doPost(token) {
    var fd = new FormData(form);
    fd.set('g_recaptcha_token', token || '');
    fetch('/', { method: 'POST', body: fd })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.ok) {
          form.innerHTML = '<p class="cf-success">' + d.message + '</p>';
        } else {
          errEl.textContent = d.error || 'Something went wrong.';
          btnEl.disabled = false;
          btnEl.textContent = 'Send Message';
        }
      })
      .catch(function () {
        errEl.textContent = 'Network error — please try again.';
        btnEl.disabled = false;
        btnEl.textContent = 'Send Message';
      });
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    errEl.textContent = '';
    btnEl.disabled = true;
    btnEl.textContent = 'Sending…';
    if (typeof grecaptcha !== 'undefined' && window.RECAPTCHA_SITE_KEY) {
      grecaptcha.ready(function () {
        grecaptcha.execute(window.RECAPTCHA_SITE_KEY, { action: 'contact' })
          .then(doPost);
      });
    } else {
      doPost('');
    }
  });
})();

// ── Back-to-top ───────────────────────────────────────────────────────────────
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
