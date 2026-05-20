<?php
require_once __DIR__ . '/config.php';
$navLabel = 'ACME Web Service';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title' => 'Meerkat ACME Web Service - RFC 8555 Test CA | ' . SITE_DOMAIN,
    'description' => 'RFC 8555 ACME endpoint for issuing 90-day DV TLS test certificates from the Meerkat Test CA with http-01, dns-01, CT submission, and revocation.',
    'url' => SITE_BASE_URL . '/acmews.php',
  ]);
  ?>
  <style>
    :root { --bg:#0a0e14; --surface:#111820; --line:#263444; --text:#dbe7f3; --muted:#8ca0b4; --accent:#00d4aa; --blue:#55a7ff; --warn:#ffcc66; --mono:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace; --sans:Inter,system-ui,sans-serif; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); line-height:1.55; }
    main { width:min(1080px, calc(100% - 32px)); margin:0 auto; padding:42px 0 64px; }
    .hero { display:grid; grid-template-columns:1.15fr .85fr; gap:28px; align-items:end; padding:36px 0 28px; border-bottom:1px solid var(--line); }
    h1 { margin:0 0 14px; font-size:clamp(2.2rem, 5vw, 4.4rem); line-height:.94; letter-spacing:0; }
    h2 { margin:34px 0 12px; font-size:1.15rem; color:#fff; }
    p { margin:0 0 14px; color:var(--muted); }
    code, pre { font-family:var(--mono); }
    pre { margin:0; padding:16px; overflow:auto; background:#071018; border:1px solid var(--line); border-radius:6px; color:#c7f7ea; font-size:.86rem; }
    .panel { background:var(--surface); border:1px solid var(--line); border-radius:8px; padding:18px; }
    .grid { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:16px; margin-top:18px; }
    .kv { display:grid; grid-template-columns:170px 1fr; gap:10px; padding:10px 0; border-bottom:1px solid rgba(255,255,255,.07); }
    .kv:last-child { border-bottom:0; }
    .key { color:var(--muted); font-family:var(--mono); font-size:.82rem; }
    .val { color:var(--text); font-family:var(--mono); font-size:.86rem; word-break:break-word; }
    .tagrow { display:flex; flex-wrap:wrap; gap:8px; margin-top:18px; }
    .tag { border:1px solid rgba(0,212,170,.35); color:var(--accent); border-radius:999px; padding:5px 9px; font-family:var(--mono); font-size:.75rem; }
    a { color:var(--blue); }
    ul { color:var(--muted); padding-left:20px; }
    li { margin:6px 0; }
    @media (max-width: 760px) { .hero, .grid { grid-template-columns:1fr; } .kv { grid-template-columns:1fr; gap:2px; } }
  </style>
</head>
<body>
<?php require_once __DIR__ . '/includes/site_nav.php'; ?>
<main>
  <section class="hero">
    <div>
      <h1>Meerkat ACME Web Service</h1>
      <p>RFC 8555 test endpoint for issuing short-lived DV TLS certificates from the Meerkat issuing CA. It supports standard ACME clients, account creation with terms acceptance, new orders, http-01 and dns-01 validation, finalization, certificate download, and revocation.</p>
      <div class="tagrow">
        <span class="tag">RFC 8555</span>
        <span class="tag">90 days</span>
        <span class="tag">http-01</span>
        <span class="tag">dns-01</span>
        <span class="tag">No EAB</span>
        <span class="tag">CT embedded</span>
      </div>
    </div>
    <div class="panel">
      <div class="kv"><div class="key">Directory</div><div class="val"><?= htmlspecialchars(SITE_BASE_URL . '/acme/directory') ?></div></div>
      <div class="kv"><div class="key">Issuer</div><div class="val">Meerkat Test Issuing CA 1 / ECC Issuing CA 1</div></div>
      <div class="kv"><div class="key">Validity</div><div class="val"><?= (int)CERT_DAYS ?> days</div></div>
      <div class="kv"><div class="key">External Account Binding</div><div class="val">Not required</div></div>
    </div>
  </section>

  <section>
    <h2>Client Configuration</h2>
    <pre>server = <?= htmlspecialchars(SITE_BASE_URL . "/acme/directory") ?></pre>
  </section>

  <section class="grid">
    <div>
      <h2>Implemented</h2>
      <ul>
        <li>Directory, nonce, account, order, authorization, challenge, finalize, certificate, and revoke resources.</li>
        <li>HTTP-01 at <code>/.well-known/acme-challenge/&lt;token&gt;</code> and DNS-01 at <code>_acme-challenge</code>.</li>
        <li>RSA and P-256 account keys, RSA and ECDSA subscriber CSRs, one matching CA tree per issued certificate.</li>
        <li>CAA checks, reserved-name rejection, rate limiting, and embedded SCTs from the local CT test log.</li>
      </ul>
    </div>
    <div id="renewal">
      <h2>Renewal</h2>
      <p>Renewal is normal ACME re-issuance: the client creates a fresh order, validates control again, finalizes with a CSR, and receives a new certificate. The renewalInfo resource returns a suggested window for clients that probe ARI-style metadata.</p>
    </div>
  </section>

  <section>
    <h2>Testing</h2>
    <p>Use the local <a href="/acme_tester.php">ACME Endpoint Tester</a> with the directory URL above to inspect every request and response, including raw JWS exchanges and revocation.</p>
  </section>
</main>
</body>
</html>
