<?php
require_once __DIR__ . '/config.php';

define('ESEAL_SIGN_DIR',   MPCA_CA_DIR   . '/eseal_sign');
define('ESEAL_CERT_PATH',  ESEAL_SIGN_DIR . '/eseal_signing.crt');
define('ESEAL_CA_CRT_URL', MPCA_BASE_URL  . '/eseal_ca.crt');
define('ESEAL_CHAIN_URL',  PKI_BASE_URL   . '/mpca/eseal_chain.pem');

$esealInfo = null;
if (file_exists(ESEAL_CERT_PATH)) {
    $pem  = (string) file_get_contents(ESEAL_CERT_PATH);
    $cert = openssl_x509_read($pem);
    if ($cert !== false) {
        $p = openssl_x509_parse($cert, false);
        $esealInfo = [
            'subject'    => $p['name'] ?? 'N/A',
            'not_before' => isset($p['validFrom_time_t']) ? date('Y-m-d', $p['validFrom_time_t']) : 'N/A',
            'not_after'  => isset($p['validTo_time_t'])   ? date('Y-m-d', $p['validTo_time_t'])   : 'N/A',
            'serial'     => $p['serialNumberHex'] ?? ($p['serialNumber'] ?? 'N/A'),
        ];
    }
}

$navLabel = 'Meerkat e-Seal';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'Meerkat e-Seal — CMS / CAdES-B Signing Authority | ' . SITE_DOMAIN,
    'description' => 'A testing e-Seal authority based on eIDAS/ETSI EN 319 412-3. Submit a hash digest and receive a cryptographically valid CMS SignedData signed by the Meerkat e-Seal certificate. Supports SHA-256, SHA-384, and SHA-512.',
    'url'         => SITE_BASE_URL . '/eseal_doc.php',
    'jsonld'      => json_encode([
      '@context'            => 'https://schema.org',
      '@type'               => 'WebApplication',
      'name'                => 'Meerkat e-Seal',
      'url'                 => SITE_BASE_URL . '/eseal_doc.php',
      'description'         => 'Testing e-Seal authority. Returns CMS SignedData tokens. Supports SHA-256/384/512 hash inputs.',
      'applicationCategory' => 'SecurityApplication',
      'operatingSystem'     => 'Any',
      'isAccessibleForFree' => true,
      'keywords'            => 'eIDAS, e-Seal, CMS, CAdES-B, ETSI EN 319 412-3, PKI, testing, digital signature',
      'author'              => ['@id' => SITE_BASE_URL . '/#person', 'name' => 'Thameur Belghith'],
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
  ]);
  ?>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0e1014; --surface: #13171e; --surface2: #181d26; --border: #2a3040;
      --accent: #00d4aa; --text: #d4dae6; --muted: #6b7a90; --danger: #f87171;
      --amber: #f59e0b; --green: #22c55e; --purple: #a78bfa;
      --sans: 'IBM Plex Sans', sans-serif; --mono: 'IBM Plex Mono', monospace;
      --radius: 8px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; scroll-behavior: smooth; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }
    code { font-family: var(--mono); font-size: 0.82em; background: rgba(255,255,255,0.06); padding: 0.1em 0.35em; border-radius: 3px; }

    .doc-wrap { max-width: 900px; margin: 0 auto; padding: 3.5rem 2rem 6rem; }

    .page-header { margin-bottom: 2.5rem; }
    .page-header h1 { font-size: 1.9rem; font-weight: 600; color: #fff; margin-bottom: 0.4rem; }
    .page-header .sub { font-size: 0.88rem; color: var(--muted); max-width: 680px; }
    .eseal-badge {
      display: inline-flex; align-items: center; gap: 0.5rem;
      background: rgba(167,139,250,0.1); border: 1px solid rgba(167,139,250,0.3);
      border-radius: 4px; padding: 0.3em 0.8em; font-family: var(--mono);
      font-size: 0.72rem; color: var(--purple); margin-bottom: 1rem;
    }

    .notice {
      display: flex; gap: 0.8rem;
      border: 1px solid rgba(245,158,11,0.35); background: rgba(245,158,11,0.07);
      border-radius: 6px; padding: 0.9rem 1.1rem; margin-bottom: 2rem;
      font-size: 0.84rem; color: #fcd34d;
    }
    .notice-icon { flex-shrink: 0; font-size: 1rem; }

    .doc-section { margin-bottom: 3rem; }
    .doc-section h2 {
      font-size: 1.1rem; font-weight: 600; color: #fff;
      border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 1.2rem;
    }
    .doc-section h3 { font-size: 0.95rem; font-weight: 600; color: var(--accent); margin: 1.4rem 0 0.6rem; }
    .doc-section p { font-size: 0.88rem; color: var(--text); margin-bottom: 0.8rem; }
    .doc-section ul { font-size: 0.88rem; padding-left: 1.4rem; margin-bottom: 0.8rem; }
    .doc-section li { margin-bottom: 0.3rem; }

    .id-table {
      width: 100%; border-collapse: collapse; font-size: 0.82rem; margin-bottom: 1rem;
    }
    .id-table th {
      text-align: left; color: var(--muted); font-weight: 400;
      font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em;
      border-bottom: 1px solid var(--border); padding: 0.5rem 0.8rem;
    }
    .id-table td {
      padding: 0.55rem 0.8rem; border-bottom: 1px solid rgba(42,48,64,0.5);
      font-family: var(--mono); font-size: 0.76rem; vertical-align: top;
    }
    .id-table tr:last-child td { border-bottom: none; }
    .id-table .label { color: var(--muted); font-family: var(--sans); font-size: 0.82rem; width: 160px; }
    .id-table .val   { color: var(--text); }
    .id-table .oid   { color: var(--amber); }
    .id-table .uninit { color: rgba(107,122,144,0.5); font-style: italic; font-family: var(--sans); }

    .code-block {
      background: #0a0c10; border: 1px solid var(--border); border-radius: 6px;
      padding: 1rem 1.2rem; margin: 0.8rem 0 1.2rem;
      font-family: var(--mono); font-size: 0.72rem; line-height: 1.8;
      color: var(--text); overflow-x: auto; white-space: pre;
    }
    .code-block .comment { color: var(--muted); }
    .code-block .key    { color: #93c5fd; }
    .code-block .val    { color: #86efac; }
    .code-block .cmd    { color: var(--accent); }
    .code-block .str    { color: #fde68a; }

    .ep-table {
      width: 100%; border-collapse: collapse; font-size: 0.82rem;
    }
    .ep-table th {
      text-align: left; color: var(--muted); font-size: 0.65rem;
      text-transform: uppercase; letter-spacing: 0.1em;
      border-bottom: 1px solid var(--border); padding: 0.5rem 0.8rem;
    }
    .ep-table td { padding: 0.6rem 0.8rem; border-bottom: 1px solid rgba(42,48,64,0.4); vertical-align: top; }
    .ep-table tr:last-child td { border-bottom: none; }
    .method-post { color: #f59e0b; font-family: var(--mono); font-size: 0.72rem; font-weight: 600; }
    .method-get  { color: var(--accent); font-family: var(--mono); font-size: 0.72rem; font-weight: 600; }
    .ep-path { font-family: var(--mono); font-size: 0.78rem; }

    .field-table {
      width: 100%; border-collapse: collapse; font-size: 0.8rem; margin: 0.6rem 0 1rem;
    }
    .field-table th {
      text-align: left; color: var(--muted); font-size: 0.63rem;
      text-transform: uppercase; letter-spacing: 0.1em;
      border-bottom: 1px solid var(--border); padding: 0.45rem 0.7rem;
    }
    .field-table td { padding: 0.5rem 0.7rem; border-bottom: 1px solid rgba(42,48,64,0.4); font-family: var(--mono); font-size: 0.72rem; }
    .field-table td:last-child { font-family: var(--sans); font-size: 0.8rem; }
    .field-table tr:last-child td { border-bottom: none; }
    .required { color: var(--danger); font-size: 0.65rem; }
    .optional  { color: var(--muted); font-size: 0.65rem; }

    .err-code { color: var(--danger); font-family: var(--mono); font-weight: 600; }

    .badge-test {
      display: inline-block; font-family: var(--mono); font-size: 0.65rem;
      background: rgba(245,158,11,0.12); border: 1px solid rgba(245,158,11,0.3);
      color: var(--amber); border-radius: 3px; padding: 0.1em 0.5em;
    }

    .tool-cta {
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      background: rgba(167,139,250,0.07); border: 1px solid rgba(167,139,250,0.25);
      border-radius: 6px; padding: 0.9rem 1.2rem; margin-bottom: 2rem;
      font-size: 0.84rem;
    }
    .tool-cta-text { color: var(--text); }
    .tool-cta-text strong { color: #fff; }
    .tool-cta-btn {
      display: inline-flex; align-items: center; gap: 0.4rem;
      font-family: var(--mono); font-size: 0.72rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.07em; white-space: nowrap;
      background: var(--purple); color: #0e1014; border-radius: 4px;
      padding: 0.45em 1.1em; text-decoration: none; transition: opacity 0.15s;
    }
    .tool-cta-btn:hover { opacity: 0.85; color: #0e1014; }

    .inline-cta {
      display: inline-flex; align-items: center; gap: 0.4rem;
      font-family: var(--mono); font-size: 0.72rem; font-weight: 600;
      letter-spacing: 0.06em; color: var(--purple); text-decoration: none;
      border: 1px solid rgba(167,139,250,0.35); border-radius: 4px;
      padding: 0.3em 0.8em; transition: background 0.15s;
    }
    .inline-cta:hover { background: rgba(167,139,250,0.08); color: var(--purple); }

    .site-footer {
      border-top: 1px solid var(--border); padding: 1.4rem 2rem;
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
    }
    .site-footer a { color: var(--muted); }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }

    @media (max-width: 640px) {
      .doc-wrap { padding: 2rem 1rem 4rem; }
      .ep-table, .field-table, .id-table { font-size: 0.7rem; }
    }
  </style>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<main class="doc-wrap">

  <div class="page-header">
    <div class="eseal-badge">🔏 e-Seal Authority — eIDAS / ETSI EN 319 412-3</div>
    <h1>Meerkat e-Seal</h1>
    <p class="sub">
      A testing e-Seal signing service based on eIDAS and ETSI EN 319 412-3.
      Submit a hash digest and receive a <strong>CAdES</strong> (CMS) or <strong>XAdES</strong> (XML) signature
      from the Meerkat e-Seal authority, with or without an RFC 3161 timestamp (T level).
      Supports SHA-256, SHA-384, and SHA-512.
    </p>
  </div>

  <div class="tool-cta">
    <span class="tool-cta-text">
      <strong>Want to e-seal a file directly?</strong>
      Use <strong>Meerkat e-Seal Signer</strong> — paste a hash, choose CAdES or XAdES format, and get a signed token with optional timestamp. This page documents the raw HTTP API.
    </span>
    <a href="/eseal_signer.php" class="tool-cta-btn">🔏 Open e-Seal Signer →</a>
  </div>

  <div class="notice">
    <span class="notice-icon">⚠</span>
    <span>
      <strong>Testing only — do not use in production documents.</strong>
      The Meerkat e-Seal is not a qualified or accredited trust service. Signatures issued here carry no legal
      weight and must not be embedded in documents intended for production use. The e-Seal signing certificate
      is issued under a private, untrusted CA hierarchy that is not recognized by any public root store.
    </span>
  </div>

  <!-- ── e-Seal Identity ───────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>e-Seal Identity</h2>

    <table class="id-table">
      <tbody>
        <tr>
          <td class="label">Endpoint URL</td>
          <td class="val"><?= htmlspecialchars(MPCA_ESEAL_URL) ?></td>
        </tr>
        <tr>
          <td class="label">Signing Certificate</td>
          <td>
            <?php if ($esealInfo): ?>
            <span class="val"><?= htmlspecialchars($esealInfo['subject']) ?></span>
            <?php else: ?>
            <span class="uninit">not yet initialized — run scripts/mpca_init.sh</span>
            <?php endif; ?>
          </td>
        </tr>
        <tr>
          <td class="label">Valid From</td>
          <td class="val"><?= $esealInfo ? htmlspecialchars($esealInfo['not_before']) : '—' ?></td>
        </tr>
        <tr>
          <td class="label">Valid Until</td>
          <td class="val"><?= $esealInfo ? htmlspecialchars($esealInfo['not_after']) : '—' ?></td>
        </tr>
        <tr>
          <td class="label">Policy OID</td>
          <td class="oid">2.16.788.1.99.1.60</td>
        </tr>
        <tr>
          <td class="label">Key Usage</td>
          <td class="val">digitalSignature, nonRepudiation (critical)</td>
        </tr>
        <tr>
          <td class="label">Signing Key</td>
          <td class="val">ECDSA P-256</td>
        </tr>
        <tr>
          <td class="label">Hash Algorithms</td>
          <td class="val">SHA-256 &nbsp;·&nbsp; SHA-384 &nbsp;·&nbsp; SHA-512</td>
        </tr>
        <tr>
          <td class="label">e-Seal CA Certificate</td>
          <td class="val"><a href="<?= htmlspecialchars(ESEAL_CA_CRT_URL) ?>"><?= htmlspecialchars(ESEAL_CA_CRT_URL) ?></a></td>
        </tr>
        <tr>
          <td class="label">Chain (CA + Root)</td>
          <td class="val"><a href="<?= htmlspecialchars(ESEAL_CHAIN_URL) ?>"><?= htmlspecialchars(ESEAL_CHAIN_URL) ?></a></td>
        </tr>
        <tr>
          <td class="label">Standard</td>
          <td class="val">eIDAS, ETSI EN 319 412-3, ETSI EN 319 122-1 (CAdES)</td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- ── API Endpoint ──────────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>API Endpoint</h2>

    <table class="ep-table">
      <thead>
        <tr><th>Method</th><th>URL</th><th>Description</th></tr>
      </thead>
      <tbody>
        <tr>
          <td><span class="method-post">POST</span></td>
          <td class="ep-path"><?= htmlspecialchars(MPCA_ESEAL_URL) ?></td>
          <td>Submit a JSON request with a hash digest. Returns a <code>CMS SignedData</code> (CAdES) or XML <code>ds:Signature</code> (XAdES) based on the <code>format</code> parameter. <strong>Primary endpoint.</strong></td>
        </tr>
        <tr>
          <td><span class="method-get">GET</span></td>
          <td class="ep-path"><?= htmlspecialchars(MPCA_ESEAL_URL) ?></td>
          <td>Redirects to this documentation page.</td>
        </tr>
      </tbody>
    </table>

    <h3>Request</h3>
    <table class="field-table">
      <thead><tr><th>Header / Body field</th><th>Presence</th><th>Notes</th></tr></thead>
      <tbody>
        <tr>
          <td>Content-Type</td>
          <td><span class="required">required</span></td>
          <td>Must be <code>application/json</code></td>
        </tr>
        <tr>
          <td><code>hash</code></td>
          <td><span class="required">required</span></td>
          <td>Hex or base64-encoded digest of the document to seal. The algorithm is inferred from the byte length (32 → SHA-256, 48 → SHA-384, 64 → SHA-512). Spaces, colons, and dashes are stripped automatically.</td>
        </tr>
        <tr>
          <td><code>alg</code></td>
          <td><span class="optional">optional</span></td>
          <td>Hint for the hash algorithm (<code>sha256</code>, <code>sha384</code>, <code>sha512</code>). Ignored — algorithm is always inferred from hash length.</td>
        </tr>
        <tr>
          <td><code>format</code></td>
          <td><span class="optional">optional</span></td>
          <td><code>cms</code> (default) for CAdES/CMS SignedData output, or <code>xades</code> for XAdES XML output.</td>
        </tr>
        <tr>
          <td><code>ts</code></td>
          <td><span class="optional">optional</span></td>
          <td>Boolean. <code>true</code> (default) to embed an RFC 3161 SignatureTimeStamp (T level); <code>false</code> for baseline level only (B level). If the TSA is unavailable, the timestamp is silently omitted regardless of this flag.</td>
        </tr>
      </tbody>
    </table>

    <h3>Request Body Examples</h3>
    <div class="code-block"><span class="comment">// CAdES-T (default — CMS + timestamp)</span>
{
  <span class="key">"hash"</span>: <span class="str">"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"</span>
}

<span class="comment">// XAdES-B-T (XML + timestamp)</span>
{
  <span class="key">"hash"</span>:   <span class="str">"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"</span>,
  <span class="key">"format"</span>: <span class="str">"xades"</span>,
  <span class="key">"ts"</span>:     <span class="val">true</span>
}

<span class="comment">// CAdES-B (no timestamp)</span>
{
  <span class="key">"hash"</span>:   <span class="str">"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"</span>,
  <span class="key">"format"</span>: <span class="str">"cms"</span>,
  <span class="key">"ts"</span>:     <span class="val">false</span>
}</div>

    <h3>Success Response — CAdES (HTTP 200)</h3>
    <table class="field-table">
      <thead><tr><th>Header / Body</th><th>Value</th></tr></thead>
      <tbody>
        <tr>
          <td>Content-Type</td>
          <td><code>application/cms</code></td>
        </tr>
        <tr>
          <td>X-Eseal-Format</td>
          <td><code>cms</code></td>
        </tr>
        <tr>
          <td>X-Eseal-Level</td>
          <td><code>CAdES-T</code> if timestamped; <code>CAdES-B</code> if the TSA was unavailable or <code>ts</code> was <code>false</code>.</td>
        </tr>
        <tr>
          <td>Body</td>
          <td>DER-encoded <code>CMS SignedData</code> (RFC 5652). The signed content (hash bytes) is embedded (<code>eContent</code> — non-detached). When <code>X-Eseal-Level: CAdES-T</code>, an <code>id-aa-signatureTimeStampToken</code> unsigned attribute (OID <code>1.2.840.113549.1.9.16.2.14</code>) is included per ETSI EN 319 122-1 §5.3.3.</td>
        </tr>
      </tbody>
    </table>

    <h3>Success Response — XAdES (HTTP 200)</h3>
    <table class="field-table">
      <thead><tr><th>Header / Body</th><th>Value</th></tr></thead>
      <tbody>
        <tr>
          <td>Content-Type</td>
          <td><code>application/xml; charset=utf-8</code></td>
        </tr>
        <tr>
          <td>Content-Disposition</td>
          <td><code>attachment; filename="eseal.xades"</code></td>
        </tr>
        <tr>
          <td>X-Eseal-Format</td>
          <td><code>xades</code></td>
        </tr>
        <tr>
          <td>X-Eseal-Level</td>
          <td><code>XAdES-B-T</code> if timestamped; <code>XAdES-B-B</code> if <code>ts</code> was <code>false</code> or the TSA was unavailable.</td>
        </tr>
        <tr>
          <td>Body</td>
          <td>UTF-8 XML document containing a detached <code>ds:Signature</code> per W3C XMLDSig + ETSI EN 319 132-2. The document digest is referenced via a <code>ds:Reference</code> (not embedded). When <code>X-Eseal-Level: XAdES-B-T</code>, a <code>xades:SignatureTimeStamp</code> unsigned attribute is present in <code>xades:UnsignedSignatureProperties</code> per ETSI EN 319 132-1 §5.3.4.</td>
        </tr>
      </tbody>
    </table>

    <h3>Error Response (JSON)</h3>
    <div class="code-block">{ <span class="key">"error"</span>: <span class="str">"human-readable error message"</span> }</div>
  </div>

  <!-- ── Integration Guide ─────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>Integration Guide</h2>

    <p>
      If you just want to e-seal a file without writing any code,
      use <a href="/eseal_signer.php" class="inline-cta">🔏 Meerkat e-Seal Signer</a> —
      it handles the hash computation and API call for you and lets you download the token directly.
      The steps below are for integrating the e-Seal endpoint into your own tooling.
    </p>

    <h3>Step 1 — Compute the hash of your document</h3>
    <div class="code-block"><span class="comment"># SHA-256 (most common)</span>
<span class="cmd">sha256sum myfile.pdf | awk '{print $1}'</span>

<span class="comment"># SHA-384</span>
<span class="cmd">sha384sum myfile.pdf | awk '{print $1}'</span>

<span class="comment"># SHA-512</span>
<span class="cmd">sha512sum myfile.pdf | awk '{print $1}'</span>

<span class="comment"># On macOS (use openssl)</span>
<span class="cmd">openssl dgst -sha256 myfile.pdf | awk '{print $2}'</span></div>

    <h3>Step 2 — Send the hash to the e-Seal endpoint</h3>
    <div class="code-block"><span class="comment"># Store the hash</span>
<span class="cmd">HASH=$(sha256sum myfile.pdf | awk '{print $1}')</span>

<span class="comment"># Send to e-Seal endpoint</span>
<span class="cmd">curl -s -X POST <?= htmlspecialchars(MPCA_ESEAL_URL) ?> \
  -H 'Content-Type: application/json' \
  -d "{\"hash\": \"$HASH\"}" \
  -o signature.cms</span>

<span class="comment"># Inspect the CMS structure</span>
<span class="cmd">openssl asn1parse -inform DER -in signature.cms | head -40</span></div>

    <h3>Step 3 — Verify the e-Seal signature</h3>
    <div class="code-block"><span class="comment"># Download the e-Seal CA chain</span>
<span class="cmd">curl -s -o eseal_chain.pem <?= htmlspecialchars(ESEAL_CHAIN_URL) ?></span>

<span class="comment"># Verify the CMS signature (content is embedded — no -content flag needed).
# -purpose any is required: the e-Seal cert carries id-kp-documentSigning
# (RFC 9336 OID 1.3.6.1.5.5.7.3.36), not emailProtection; OpenSSL's default
# smimesign purpose would reject it as "unsuitable certificate purpose".</span>
<span class="cmd">openssl cms -verify -inform DER -in signature.cms \
  -CAfile eseal_chain.pem -purpose any -noout</span>

<span class="comment"># Extract the signed content (should match your original hash bytes)</span>
<span class="cmd">openssl cms -verify -inform DER -in signature.cms \
  -CAfile eseal_chain.pem -purpose any | xxd</span></div>

    <h3>One-liner (hash + e-seal in one step)</h3>
    <div class="code-block"><span class="cmd">curl -s -X POST <?= htmlspecialchars(MPCA_ESEAL_URL) ?> \
  -H 'Content-Type: application/json' \
  -d "{\"hash\": \"$(openssl dgst -sha256 myfile.pdf | awk '{print $2}')\"}" \
  -o signature.cms \
  &amp;&amp; openssl asn1parse -inform DER -in signature.cms | head -30</span></div>

    <h3>Python (using the requests library)</h3>
    <div class="code-block">import hashlib, requests

<span class="comment"># Compute SHA-256 hash</span>
with open(<span class="str">'myfile.pdf'</span>, <span class="str">'rb'</span>) as f:
    digest = hashlib.sha256(f.read()).hexdigest()

<span class="comment"># Send to e-Seal endpoint</span>
resp = requests.post(
    <span class="str">'<?= htmlspecialchars(MPCA_ESEAL_URL) ?>'</span>,
    json={<span class="str">'hash'</span>: digest},
)
resp.raise_for_status()

with open(<span class="str">'signature.cms'</span>, <span class="str">'wb'</span>) as f:
    f.write(resp.content)</div>

    <h3>JavaScript (Node.js)</h3>
    <div class="code-block">const crypto = require(<span class="str">'crypto'</span>);
const fs     = require(<span class="str">'fs'</span>);

const hash = crypto.createHash(<span class="str">'sha256'</span>)
  .update(fs.readFileSync(<span class="str">'myfile.pdf'</span>))
  .digest(<span class="str">'hex'</span>);

const response = await fetch(<span class="str">'<?= htmlspecialchars(MPCA_ESEAL_URL) ?>'</span>, {
  method:  <span class="str">'POST'</span>,
  headers: { <span class="str">'Content-Type'</span>: <span class="str">'application/json'</span> },
  body:    JSON.stringify({ hash }),
});

fs.writeFileSync(<span class="str">'signature.cms'</span>, Buffer.from(await response.arrayBuffer()));</div>
  </div>

  <!-- ── CMS Structure ─────────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>CMS SignedData Structure (RFC 5652)</h2>

    <table class="field-table">
      <thead><tr><th>Field</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>contentType</td><td><code>id-signedData (1.2.840.113549.1.7.2)</code></td></tr>
        <tr><td>version</td><td><code>v1 (1)</code></td></tr>
        <tr><td>digestAlgorithms</td><td>Hash algorithm inferred from the input (SHA-256, SHA-384, or SHA-512).</td></tr>
        <tr><td>encapContentInfo.eContentType</td><td><code>id-data (1.2.840.113549.1.7.1)</code></td></tr>
        <tr><td>encapContentInfo.eContent</td><td>The raw hash bytes submitted in the request (embedded, non-detached).</td></tr>
        <tr><td>certificates</td><td>e-Seal signing certificate + e-Seal CA + Root CA (full chain).</td></tr>
        <tr><td>signerInfo.digestAlgorithm</td><td>Same as <code>digestAlgorithms</code>.</td></tr>
        <tr><td>signerInfo.signatureAlgorithm</td><td>ECDSA with the matching SHA algorithm (e.g. <code>ecdsa-with-SHA256</code>).</td></tr>
        <tr><td>signerInfo.signature</td><td>DER-encoded ECDSA signature over the signed attributes (which include the message digest of the content).</td></tr>
        <tr><td>signerInfo.unsignedAttrs[0]</td><td><code>id-aa-signatureTimeStampToken</code> (OID <code>1.2.840.113549.1.9.16.2.14</code>) — RFC 3161 TimeStampToken covering SHA-256(signatureValue). Sourced from the Meerkat TSA at signing time. This is the CAdES-T extension.</td></tr>
      </tbody>
    </table>

    <p>
      The signed content is the hash bytes you supplied, not your original document.
      This means the CMS token proves that the e-Seal signing key operated on those specific bytes —
      to tie it back to your document, you must independently verify that the hash bytes match
      the expected digest of your document.
    </p>
  </div>

  <!-- ── XAdES Signature Structure ──────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>XAdES Signature Structure (ETSI EN 319 132-2)</h2>

    <p>
      When <code>format=xades</code>, the response is an XML document containing a detached
      <code>ds:Signature</code> element with XAdES qualifying properties.
      The signature covers the document's hash digest — the original document is not embedded.
    </p>

    <table class="field-table">
      <thead><tr><th>Element</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>ds:Signature</td><td>Root W3C XMLDSig signature element. Carries Id for internal cross-references.</td></tr>
        <tr><td>ds:SignedInfo / ds:CanonicalizationMethod</td><td><code>http://www.w3.org/TR/2001/REC-xml-c14n-20010315</code> (inclusive C14N).</td></tr>
        <tr><td>ds:SignedInfo / ds:SignatureMethod</td><td>ECDSA with the hash algorithm matching the input length (e.g. <code>ecdsa-sha256</code>).</td></tr>
        <tr><td>ds:Reference[@Id="Ref-Content"]</td><td>References the signed document by digest only (detached, <code>URI=""</code>). <code>ds:DigestValue</code> is the base64-encoded hash bytes from the request.</td></tr>
        <tr><td>ds:Reference[@Id="Ref-SignedProperties"]</td><td>References the <code>xades:SignedProperties</code> element after C14N. The DigestValue covers the canonicalized SignedProperties XML.</td></tr>
        <tr><td>ds:SignatureValue</td><td>Raw ECDSA signature (r||s concatenation, 64 bytes for P-256) over the canonicalized <code>ds:SignedInfo</code>, base64-encoded.</td></tr>
        <tr><td>ds:KeyInfo / ds:X509Data</td><td>Full DER of the e-Seal signing certificate (base64), embedded for offline verification.</td></tr>
        <tr><td>xades:SignedProperties</td><td>Contains <code>xades:SigningTime</code> and <code>xades:SigningCertificateV2</code> (SHA-256 digest of the signing certificate for binding).</td></tr>
        <tr><td>xades:UnsignedSignatureProperties / xades:SignatureTimeStamp</td><td>(B-T only) Contains <code>xades:EncapsulatedTimeStamp</code>: base64-encoded DER of an RFC 3161 TimeStampToken covering SHA-256 of the canonicalized <code>ds:SignatureValue</code> element. Per ETSI EN 319 132-1 §5.3.4.</td></tr>
      </tbody>
    </table>

    <h3>Verify with xmlsec1</h3>
    <div class="code-block"><span class="comment"># Download the e-Seal chain</span>
<span class="cmd">curl -s -o eseal_chain.pem <?= htmlspecialchars(ESEAL_CHAIN_URL) ?></span>

<span class="comment"># Request an XAdES-B-T signature</span>
<span class="cmd">curl -s -X POST <?= htmlspecialchars(MPCA_ESEAL_URL) ?> \
  -H 'Content-Type: application/json' \
  -d '{"hash":"'"$(openssl dgst -sha256 myfile.pdf | awk '{print $2}')"'","format":"xades"}' \
  -o eseal.xades</span>

<span class="comment"># Verify the XMLDSig signature (requires xmlsec1)</span>
<span class="cmd">xmlsec1 --verify --trusted-pem eseal_chain.pem eseal.xades</span>

<span class="comment"># Inspect the XAdES XML</span>
<span class="cmd">xmllint --format eseal.xades</span></div>

    <h3>XAdES vs CAdES — when to choose which</h3>
    <table class="field-table">
      <thead><tr><th>Criterion</th><th>CAdES (CMS)</th><th>XAdES (XML)</th></tr></thead>
      <tbody>
        <tr><td>Output format</td><td>Binary DER (<code>.cms</code>)</td><td>UTF-8 XML (<code>.xades</code>)</td></tr>
        <tr><td>Content embedding</td><td>Hash bytes embedded in <code>eContent</code></td><td>Detached — only digest referenced</td></tr>
        <tr><td>Verification tooling</td><td><code>openssl cms -verify</code></td><td><code>xmlsec1 --verify</code></td></tr>
        <tr><td>Common use cases</td><td>Binary document signing, email, S/MIME</td><td>XML documents, EU eIDAS, web services</td></tr>
        <tr><td>Human-readable</td><td>No (ASN.1/DER)</td><td>Yes (XML)</td></tr>
      </tbody>
    </table>
  </div>

  <!-- ── Error Responses ───────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>Error Responses</h2>
    <p>Errors return JSON <code>{"error": "..."}</code> with the matching HTTP status code.</p>

    <table class="ep-table">
      <thead><tr><th>HTTP</th><th>Cause</th></tr></thead>
      <tbody>
        <tr><td class="err-code">400</td><td>Missing or unparseable <code>hash</code> field, or hash decodes to wrong byte length (not 32, 48, or 64 bytes).</td></tr>
        <tr><td class="err-code">405</td><td>Wrong HTTP method (only GET and POST are accepted).</td></tr>
        <tr><td class="err-code">415</td><td>Wrong <code>Content-Type</code> — must be <code>application/json</code>.</td></tr>
        <tr><td class="err-code">500</td><td>OpenSSL <code>cms -sign</code> failed — internal error. The error message contains the OpenSSL stderr output.</td></tr>
        <tr><td class="err-code">503</td><td>e-Seal not initialized — the signing key or certificate is missing. Run <code>scripts/mpca_init.sh</code>.</td></tr>
      </tbody>
    </table>
  </div>

  <!-- ── Technical Notes ───────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>Technical Notes</h2>
    <ul>
      <li><strong>CAdES format:</strong> The CMS output is a <strong>CAdES-T</strong> (by default) or <strong>CAdES-B</strong> (when <code>ts=false</code>) token per ETSI EN 319 122-1. The RFC 3161 signature timestamp (<code>id-aa-signatureTimeStampToken</code>, OID <code>1.2.840.113549.1.9.16.2.14</code>) is embedded as an unsigned attribute in the SignerInfo, covering the SHA-256 hash of the ECDSA signature value.</li>
      <li><strong>XAdES format:</strong> The XML output follows ETSI EN 319 132-2 (XAdES baseline profile). At B-B level it contains only signed qualifying properties. At B-T level it adds a <code>xades:SignatureTimeStamp</code> unsigned attribute per ETSI EN 319 132-1 §5.3.4. The signature is detached — only the document's digest is referenced, not the document itself. The ECDSA signature value is raw r||s (not DER), base64-encoded, as required by the W3C XMLDSig specification.</li>
      <li><strong>Standard basis:</strong> The e-Seal signing certificate conforms to ETSI EN 319 412-3 (Certificate Profiles for Legal Persons). Key Usage is <code>digitalSignature + nonRepudiation</code> (critical). The subject includes <code>organizationIdentifier</code> in the ETSI-defined format.</li>
      <li><strong>eIDAS scope:</strong> Under eIDAS Regulation (EU) 910/2014, an e-Seal is the legal-person equivalent of an e-Signature. This testing service mimics the structure but is <span class="badge-test">not qualified</span> and has no legal standing.</li>
      <li><strong>CMS format:</strong> The response is a non-detached CMS SignedData (the hash bytes are embedded inside the token). This simplifies verification — you do not need the original hash separately to verify the signature, but you do need it to confirm the token covers your document.</li>
      <li><strong>Hash-only input:</strong> The endpoint accepts only a pre-computed hash, not the document itself. This keeps your document data off the server and matches the architecture of the RFC 3161 TSA endpoint.</li>
      <li><strong>Policy OID <code>2.16.788.1.99.1.60</code>:</strong> A private OID registered under the Meerkat test PKI namespace (<code>2.16.788.1.99</code>). It has no meaning outside of this testing environment.</li>
      <li><strong>Signing key:</strong> ECDSA P-256. The signing certificate is issued by the Meerkat MPCA e-Seal CA (P-384), which chains to the Meerkat MPCA Root CA. None of these CAs are trusted by any public root store.</li>
      <li><strong>CORS:</strong> The endpoint responds with <code>Access-Control-Allow-Origin: *</code> to allow browser-based testing tools to call it directly.</li>
    </ul>
  </div>

</main>

<footer class="site-footer">
  <span>&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="/">Home</a>
    <a href="/references.php">PKI References</a>
    <a href="/privacy.php">Privacy Policy</a>
    <a href="<?= 'mailto:' . CONTACT_EMAIL ?>"><?= CONTACT_EMAIL ?></a>
  </div>
</footer>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>
</body>
</html>
