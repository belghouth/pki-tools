<?php
// ── Contact form AJAX handler ───────────────────────────────────────────────
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

    $to       = 'me@thameur.org';
    $mailSubj = $subject !== ''
        ? '[thameur.org] ' . mb_substr($subject, 0, 100)
        : '[thameur.org] Message from ' . $name;
    $body     = "Name:    {$name}\nEmail:   {$email}\n\n" . wordwrap($message, 72);
    $headers  = implode("\r\n", [
        'From: no-reply@thameur.org',
        'Reply-To: ' . $email,
        'Content-Type: text/plain; charset=UTF-8',
        'X-Mailer: thameur.org/contact',
    ]);

    $sent = @mail($to, $mailSubj, $body, $headers);
    echo json_encode($sent
        ? ['ok' => true, 'message' => "Thanks {$name} — I'll be in touch."]
        : ['error' => 'Mail could not be sent. Please email me directly at me@thameur.org']
    );
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Thameur Belghith — PKI &amp; Trust Services Engineer</title>
  <meta name="description" content="PKI and Trust Services Engineer building open tools for WebPKI compliance, certificate linting, and CA audit support.">
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">
  <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,600;1,300&display=swap" rel="stylesheet">

  <!-- Google AdSense -->
  <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-7400730223763810" crossorigin="anonymous"></script>

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
    html { scroll-behavior: smooth; font-size: 15px; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-weight: 300;
      line-height: 1.7;
      min-height: 100vh;
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
      min-height: 90vh;
      display: flex; align-items: center; justify-content: center;
      text-align: center;
      padding: 5rem 2rem;
      background:
        radial-gradient(ellipse 800px 600px at 50% 30%, rgba(0,212,170,0.04) 0%, transparent 70%),
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

    .hero-inner { position: relative; max-width: 760px; }

    .hero-meerkat {
      width: 96px; height: 96px;
      object-fit: contain;
      margin-bottom: 1.4rem;
      filter: drop-shadow(0 0 18px rgba(0,212,170,0.28));
      animation: meerkat-float 4s ease-in-out infinite;
    }
    @keyframes meerkat-float {
      0%, 100% { transform: translateY(0); }
      50%       { transform: translateY(-6px); }
    }

    .header-meerkat {
      width: 28px; height: 28px;
      object-fit: contain;
      filter: drop-shadow(0 0 6px rgba(0,212,170,0.3));
    }

    .hero-eyebrow {
      font-family: var(--mono);
      font-size: 0.8rem; letter-spacing: 0.18em; text-transform: uppercase;
      color: var(--accent); margin-bottom: 1rem;
    }

    .hero-name {
      font-size: clamp(2.4rem, 6vw, 4.2rem);
      font-weight: 600; letter-spacing: -0.02em; line-height: 1.1;
      color: #fff; margin-bottom: 0.6rem;
    }

    .hero-role {
      font-family: var(--mono);
      font-size: clamp(0.85rem, 2vw, 1.05rem);
      color: var(--accent2); margin-bottom: 1.6rem;
    }

    .hero-tagline {
      font-size: 1.05rem; color: var(--muted);
      max-width: 520px; margin: 0 auto 2.4rem;
    }

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
      grid-template-columns: 1fr 320px;
      gap: 4rem; align-items: start;
    }

    .about-body p { color: var(--muted); margin-bottom: 1rem; font-size: 0.95rem; }
    .about-body p:last-of-type { margin-bottom: 0; }

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
    .contact-form { display: flex; flex-direction: column; gap: 1rem; }

    .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }

    .form-group { display: flex; flex-direction: column; gap: 0.35rem; }

    .form-group label {
      font-family: var(--mono);
      font-size: 0.72rem; letter-spacing: 0.08em; text-transform: uppercase;
      color: var(--muted);
    }

    .form-group input,
    .form-group textarea {
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text);
      font-family: var(--sans);
      font-size: 0.9rem;
      padding: 0.65rem 0.85rem;
      transition: border-color var(--tr);
      width: 100%;
    }
    .form-group input:focus,
    .form-group textarea:focus {
      outline: none;
      border-color: var(--accent);
    }
    .form-group input::placeholder,
    .form-group textarea::placeholder { color: var(--border2); }
    .form-group textarea { resize: vertical; min-height: 130px; }

    #contact-status {
      font-size: 0.85rem; padding: 0.7rem 1rem;
      border-radius: var(--radius);
      display: none;
    }
    #contact-status.ok  { background: rgba(0,212,170,0.1); border: 1px solid rgba(0,212,170,0.3); color: var(--accent); }
    #contact-status.err { background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.3); color: #f87171; }

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
      .hero        { padding: 4rem 1.25rem; }
      .site-nav a:not(:first-child):not(:last-child) { display: none; }
    }
  </style>
</head>
<body>

<!-- ── Header ─────────────────────────────────────────────────────────────── -->
<header class="site-header">
  <span class="header-logo">thameur.org</span>
  <img src="/img/meerkat_120.png" alt="Meerkat" class="header-meerkat">
  <nav class="site-nav">
    <a href="#about">About</a>
    <a href="#tools">Tools</a>
    <a href="#contact">Contact</a>
  </nav>
</header>

<main>

  <!-- ── Hero ───────────────────────────────────────────────────────────────── -->
  <section class="hero">
    <div class="hero-inner">
      <img src="/img/meerkat_240.png" alt="Meerkat" class="hero-meerkat">
      <p class="hero-eyebrow">Hello, I'm</p>
      <h1 class="hero-name">Thameur Belghith</h1>
      <p class="hero-role">PKI &amp; Trust Services Engineer</p>
      <p class="hero-tagline">Building open tools for WebPKI compliance, certificate management, and CA audit support.</p>
      <div class="hero-actions">
        <a href="#tools" class="btn btn--primary">Explore Tools</a>
        <a href="#contact" class="btn btn--outline">Get in Touch</a>
      </div>
    </div>
  </section>

  <!-- ── About ──────────────────────────────────────────────────────────────── -->
  <section class="section" id="about">
    <div class="container">
      <p class="section-eyebrow">Background</p>
      <h2 class="section-heading">About Me</h2>
      <div class="about-grid">
        <div class="about-body">
          <p>I work at the intersection of cryptography, web security, and standards compliance, with a focus on Public Key Infrastructure and the WebPKI ecosystem. My day-to-day spans everything from certificate profile engineering and CA system design to audit preparation and compliance tooling.</p>
          <p>The CA/Browser Forum Baseline Requirements define the ground rules every publicly-trusted CA must follow. I actively study and implement those requirements — the tools on this site were born from real gaps I encountered while doing that work, and I open them up so the wider PKI community can benefit.</p>
          <p>I'm also interested in automated certificate lifecycle management (ACME protocol), multi-perspective issuance corroboration, and making PKI tooling more accessible to practitioners who aren't full-time cryptographers.</p>
          <div class="about-links">
            <a href="https://github.com/belghouth" class="pill-link" target="_blank" rel="noopener">GitHub</a>
            <a href="mailto:me@thameur.org" class="pill-link">Email</a>
          </div>
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
      <p class="section-eyebrow">Open Source</p>
      <h2 class="section-heading">PKI Tools</h2>
      <p class="section-sub">Free, browser-based tools for PKI practitioners, CA auditors, and security engineers.</p>

      <div class="tools-grid">

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--blue"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">🧾</div>
            <div class="tool-card-name">Certificate Linters</div>
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
          <div class="tool-card-bar tool-card-bar--purple"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">📋</div>
            <div class="tool-card-name">CPS-to-BR Assessor</div>
            <div class="tool-card-desc">Upload or link to a CP/CPS document and get an automated section-by-section coverage analysis against the CA/Browser Forum Baseline Requirements.</div>
            <div class="tool-card-tags">
              <span class="tag">CPS</span>
              <span class="tag">BR</span>
              <span class="tag">CABF</span>
            </div>
            <a href="/cps_to_br_assessor.php" class="tool-card-link">Open Tool →</a>
          </div>
        </div>

        <div class="tool-card">
          <div class="tool-card-bar tool-card-bar--teal"></div>
          <div class="tool-card-body">
            <div class="tool-card-icon">⚡</div>
            <div class="tool-card-name">ACME Automation Endpoint</div>
            <div class="tool-card-desc">A live reference implementation of an automated certificate renewal endpoint as required by the Chrome Root Program and validated by Mozilla. Demonstrates RFC 8555 renewal verification in a production environment.</div>
            <div class="tool-card-tags">
              <span class="tag">ACME</span>
              <span class="tag">RFC 8555</span>
              <span class="tag">Chrome Root</span>
            </div>
            <a href="/acme-endpoint.php" class="tool-card-link">View Demo →</a>
          </div>
        </div>

      </div>
    </div>
  </section>

  <!-- ── AdSense ────────────────────────────────────────────────────────────── -->
  <div class="ad-strip">
    <p class="ad-label">Sponsored</p>
    <!-- Replace data-ad-slot value with your actual AdSense slot ID -->
    <ins class="adsbygoogle"
         style="display:block"
         data-ad-client="ca-pub-7400730223763810"
         data-ad-slot="0000000000"
         data-ad-format="auto"
         data-full-width-responsive="true"></ins>
    <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
  </div>

  <!-- ── Contact ────────────────────────────────────────────────────────────── -->
  <section class="section" id="contact">
    <div class="container--sm">
      <p class="section-eyebrow">Say Hello</p>
      <h2 class="section-heading">Get in Touch</h2>
      <p class="section-sub">Questions about the tools, PKI consulting, or just want to connect — drop me a line.</p>

      <form class="contact-form" id="contact-form" novalidate>
        <div class="form-row">
          <div class="form-group">
            <label for="cf-name">Name</label>
            <input type="text" id="cf-name" name="name" placeholder="Your name" required>
          </div>
          <div class="form-group">
            <label for="cf-email">Email</label>
            <input type="email" id="cf-email" name="email" placeholder="you@example.com" required>
          </div>
        </div>
        <div class="form-group">
          <label for="cf-subject">Subject <span style="color:var(--border2)">(optional)</span></label>
          <input type="text" id="cf-subject" name="subject" placeholder="What's this about?">
        </div>
        <div class="form-group">
          <label for="cf-message">Message</label>
          <textarea id="cf-message" name="message" placeholder="Your message…" required></textarea>
        </div>

        <div id="contact-status" role="alert"></div>

        <button type="submit" class="btn btn--primary" id="cf-submit">Send Message</button>
      </form>
    </div>
  </section>

</main>

<!-- ── Footer ─────────────────────────────────────────────────────────────── -->
<footer class="site-footer">
  <span class="site-footer-left">&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="https://github.com/belghouth" target="_blank" rel="noopener">GitHub</a>
    <a href="mailto:me@thameur.org">me@thameur.org</a>
  </div>
</footer>

<script>
(function () {
  'use strict';

  const form      = document.getElementById('contact-form');
  const statusEl  = document.getElementById('contact-status');
  const submitBtn = document.getElementById('cf-submit');

  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    submitBtn.disabled = true;
    submitBtn.textContent = 'Sending…';
    statusEl.style.display = 'none';
    statusEl.className = '';

    const fd = new FormData(form);
    fd.set('action', 'contact');

    // Attach reCAPTCHA v3 token if available.
    if (window.RECAPTCHA_SITE_KEY && window.grecaptcha) {
      try {
        const token = await new Promise((resolve, reject) => {
          grecaptcha.ready(() => {
            grecaptcha.execute(window.RECAPTCHA_SITE_KEY, { action: 'contact' })
              .then(resolve).catch(reject);
          });
        });
        fd.set('g_recaptcha_token', token);
      } catch { /* server will handle missing token */ }
    }

    try {
      const resp = await fetch(window.location.href, { method: 'POST', body: fd });
      const data = await resp.json();

      if (data.error) {
        statusEl.textContent = data.error;
        statusEl.className   = 'err';
      } else {
        statusEl.textContent = data.message || 'Message sent — thank you!';
        statusEl.className   = 'ok';
        form.reset();
      }
    } catch {
      statusEl.textContent = 'Network error. Please email me directly at me@thameur.org';
      statusEl.className   = 'err';
    } finally {
      statusEl.style.display = 'block';
      submitBtn.disabled     = false;
      submitBtn.textContent  = 'Send Message';
    }
  });
})();
</script>

</body>
</html>
