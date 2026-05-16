<?php
require_once __DIR__ . '/config.php';

define('TSA_SIGN_DIR',  MPCA_CA_DIR  . '/tsa_sign');
define('TSA_CERT_PATH', TSA_SIGN_DIR . '/tsa_signing.crt');
define('TSA_CA_CRT_URL',   MPCA_BASE_URL . '/tsa_ca.crt');
define('TSA_CHAIN_URL',    PKI_BASE_URL  . '/mpca/tsa_chain.pem');

// ── Read TSA signing certificate details (if initialized) ─────────────────────
$tsaInfo = null;
if (file_exists(TSA_CERT_PATH)) {
    $pem  = (string) file_get_contents(TSA_CERT_PATH);
    $cert = openssl_x509_read($pem);
    if ($cert !== false) {
        $p = openssl_x509_parse($cert, false);
        $tsaInfo = [
            'subject'    => $p['name'] ?? 'N/A',
            'not_before' => isset($p['validFrom_time_t']) ? date('Y-m-d', $p['validFrom_time_t']) : 'N/A',
            'not_after'  => isset($p['validTo_time_t'])   ? date('Y-m-d', $p['validTo_time_t'])   : 'N/A',
            'serial'     => $p['serialNumberHex'] ?? ($p['serialNumber'] ?? 'N/A'),
        ];
    }
}

$navLabel = 'Meerkat TSA';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'Meerkat Testing TSA — RFC 3161 Time Stamping Authority | ' . SITE_DOMAIN,
    'description' => 'A fully RFC 3161-compliant testing Time Stamping Authority. Submit a timestamp request and receive a cryptographically valid TimeStampResp signed by the Meerkat TSA. Supports SHA-256, SHA-384, and SHA-512. Includes integration guide and openssl verification commands.',
    'url'         => SITE_BASE_URL . '/tsa_doc.php',
    'jsonld'      => json_encode([
      '@context'            => 'https://schema.org',
      '@type'               => 'WebApplication',
      'name'                => 'Meerkat Testing TSA',
      'url'                 => SITE_BASE_URL . '/tsa_doc.php',
      'description'         => 'RFC 3161-compliant testing TSA. Returns cryptographically signed TimeStampResp tokens. Supports SHA-256/384/512 message imprints.',
      'applicationCategory' => 'SecurityApplication',
      'operatingSystem'     => 'Any',
      'isAccessibleForFree' => true,
      'keywords'            => 'RFC 3161, TSA, Time Stamping Authority, timestamp, PKI, testing',
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
      --amber: #f59e0b; --green: #22c55e;
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

    /* ── Header ── */
    .page-header { margin-bottom: 2.5rem; }
    .page-header h1 { font-size: 1.9rem; font-weight: 600; color: #fff; margin-bottom: 0.4rem; }
    .page-header .sub { font-size: 0.88rem; color: var(--muted); max-width: 680px; }
    .tsa-badge {
      display: inline-flex; align-items: center; gap: 0.5rem;
      background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3);
      border-radius: 4px; padding: 0.3em 0.8em; font-family: var(--mono);
      font-size: 0.72rem; color: var(--amber); margin-bottom: 1rem;
    }

    /* ── Notice banner ── */
    .notice {
      display: flex; gap: 0.8rem;
      border: 1px solid rgba(245,158,11,0.35); background: rgba(245,158,11,0.07);
      border-radius: 6px; padding: 0.9rem 1.1rem; margin-bottom: 2rem;
      font-size: 0.84rem; color: #fcd34d;
    }
    .notice-icon { flex-shrink: 0; font-size: 1rem; }

    /* ── Section ── */
    .doc-section { margin-bottom: 3rem; }
    .doc-section h2 {
      font-size: 1.1rem; font-weight: 600; color: #fff;
      border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 1.2rem;
    }
    .doc-section h3 { font-size: 0.95rem; font-weight: 600; color: var(--accent); margin: 1.4rem 0 0.6rem; }
    .doc-section p { font-size: 0.88rem; color: var(--text); margin-bottom: 0.8rem; }
    .doc-section ul { font-size: 0.88rem; padding-left: 1.4rem; margin-bottom: 0.8rem; }
    .doc-section li { margin-bottom: 0.3rem; }

    /* ── Identity table ── */
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

    /* ── Code block ── */
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

    /* ── Endpoint table ── */
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

    /* ── Field table ── */
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

    /* ── Error table ── */
    .err-code { color: var(--danger); font-family: var(--mono); font-weight: 600; }

    /* ── Inline badge ── */
    .badge-test {
      display: inline-block; font-family: var(--mono); font-size: 0.65rem;
      background: rgba(245,158,11,0.12); border: 1px solid rgba(245,158,11,0.3);
      color: var(--amber); border-radius: 3px; padding: 0.1em 0.5em;
    }

    /* ── Tool CTA banner ── */
    .tool-cta {
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      background: rgba(245,158,11,0.07); border: 1px solid rgba(245,158,11,0.25);
      border-radius: 6px; padding: 0.9rem 1.2rem; margin-bottom: 2rem;
      font-size: 0.84rem;
    }
    .tool-cta-text { color: var(--text); }
    .tool-cta-text strong { color: #fff; }
    .tool-cta-btn {
      display: inline-flex; align-items: center; gap: 0.4rem;
      font-family: var(--mono); font-size: 0.72rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.07em; white-space: nowrap;
      background: var(--amber); color: #0e1014; border-radius: 4px;
      padding: 0.45em 1.1em; text-decoration: none; transition: opacity 0.15s;
    }
    .tool-cta-btn:hover { opacity: 0.85; color: #0e1014; }

    /* ── Inline CTA (inside sections) ── */
    .inline-cta {
      display: inline-flex; align-items: center; gap: 0.4rem;
      font-family: var(--mono); font-size: 0.72rem; font-weight: 600;
      letter-spacing: 0.06em; color: var(--amber); text-decoration: none;
      border: 1px solid rgba(245,158,11,0.35); border-radius: 4px;
      padding: 0.3em 0.8em; transition: background 0.15s;
    }
    .inline-cta:hover { background: rgba(245,158,11,0.08); color: var(--amber); }

    /* ── Footer ── */
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
    <div class="tsa-badge">⏱ Time Stamping Authority — RFC 3161</div>
    <h1>Meerkat Testing TSA</h1>
    <p class="sub">
      A fully RFC 3161-compliant Time Stamping Authority for testing.
      Submit a DER-encoded <code>TimeStampReq</code> and receive a cryptographically valid
      <code>TimeStampResp</code> signed by the Meerkat TSA signing certificate.
      Supports SHA-256, SHA-384, and SHA-512 message imprints.
    </p>
  </div>

  <div class="tool-cta">
    <span class="tool-cta-text">
      <strong>Want to timestamp a file or text?</strong>
      Use <strong>Meerkat TimeStampIt</strong> —  paste the hash of your document and get a signed <code>.tsr</code> token, and inspect it inline.
      This page documents the raw HTTP API.
    </span>
    <a href="/timestamp_it.php" class="tool-cta-btn">🕰️ Open TimeStampIt →</a>
  </div>

  <div class="notice">
    <span class="notice-icon">⚠</span>
    <span>
      <strong>Testing only — do not use in production documents.</strong>
      The Meerkat TSA is not a qualified or accredited TSA. Timestamps issued here carry no legal
      weight and must not be embedded in documents, code signatures, or archives intended for
      production use. The TSA signing certificate is issued under a private, untrusted CA hierarchy.
    </span>
  </div>

  <!-- ── TSA Identity ──────────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>TSA Identity</h2>

    <table class="id-table">
      <tbody>
        <tr>
          <td class="label">Endpoint URL</td>
          <td class="val"><?= htmlspecialchars(MPCA_TSA_URL) ?></td>
        </tr>
        <tr>
          <td class="label">Signing Certificate</td>
          <td>
            <?php if ($tsaInfo): ?>
            <span class="val"><?= htmlspecialchars($tsaInfo['subject']) ?></span>
            <?php else: ?>
            <span class="uninit">not yet initialized — run scripts/mpca_init.sh</span>
            <?php endif; ?>
          </td>
        </tr>
        <tr>
          <td class="label">Valid From</td>
          <td class="val"><?= $tsaInfo ? htmlspecialchars($tsaInfo['not_before']) : '—' ?></td>
        </tr>
        <tr>
          <td class="label">Valid Until</td>
          <td class="val"><?= $tsaInfo ? htmlspecialchars($tsaInfo['not_after']) : '—' ?></td>
        </tr>
        <tr>
          <td class="label">Policy OID</td>
          <td class="oid">2.16.788.1.99.1.40</td>
        </tr>
        <tr>
          <td class="label">Hash Algorithms</td>
          <td class="val">SHA-256 &nbsp;·&nbsp; SHA-384 &nbsp;·&nbsp; SHA-512</td>
        </tr>
        <tr>
          <td class="label">TSA CA Certificate</td>
          <td class="val"><a href="<?= htmlspecialchars(TSA_CA_CRT_URL) ?>"><?= htmlspecialchars(TSA_CA_CRT_URL) ?></a></td>
        </tr>
        <tr>
          <td class="label">Chain (CA + Root)</td>
          <td class="val"><a href="<?= htmlspecialchars(TSA_CHAIN_URL) ?>"><?= htmlspecialchars(TSA_CHAIN_URL) ?></a></td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- ── Endpoint ──────────────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>API Endpoint</h2>

    <table class="ep-table">
      <thead>
        <tr><th>Method</th><th>URL</th><th>Description</th></tr>
      </thead>
      <tbody>
        <tr>
          <td><span class="method-post">POST</span></td>
          <td class="ep-path"><?= htmlspecialchars(MPCA_TSA_URL) ?></td>
          <td>Submit a DER-encoded <code>TimeStampReq</code>. Returns a DER-encoded <code>TimeStampResp</code>. <strong>Primary endpoint.</strong></td>
        </tr>
        <tr>
          <td><span class="method-get">GET</span></td>
          <td class="ep-path"><?= htmlspecialchars(MPCA_TSA_URL) ?></td>
          <td>Redirects to this documentation page.</td>
        </tr>
      </tbody>
    </table>

    <h3>Request</h3>
    <table class="field-table">
      <thead><tr><th>Header / Body</th><th>Value</th><th>Notes</th></tr></thead>
      <tbody>
        <tr>
          <td>Content-Type</td>
          <td><span class="required">required</span></td>
          <td>Must be <code>application/timestamp-query</code></td>
        </tr>
        <tr>
          <td>Body</td>
          <td><span class="required">required</span></td>
          <td>DER-encoded <code>TimeStampReq</code> (RFC 3161 §2.4.1). Maximum size: 64 KB.</td>
        </tr>
      </tbody>
    </table>

    <h3>Success Response (HTTP 200)</h3>
    <table class="field-table">
      <thead><tr><th>Header / Body</th><th>Value</th></tr></thead>
      <tbody>
        <tr>
          <td>Content-Type</td>
          <td><code>application/timestamp-reply</code></td>
        </tr>
        <tr>
          <td>Body</td>
          <td>DER-encoded <code>TimeStampResp</code> (RFC 3161 §2.4.2). Contains <code>PKIStatusInfo</code> (granted) + <code>TimeStampToken</code> (CMS SignedData).</td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- ── Request / Response Structure ─────────────────────────────────────── -->
  <div class="doc-section">
    <h2>TimeStampReq Structure (RFC 3161 §2.4.1)</h2>

    <table class="field-table">
      <thead><tr><th>ASN.1 Field</th><th>Presence</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>version</td><td><span class="required">required</span></td><td>Must be <code>v1 (1)</code>.</td></tr>
        <tr><td>messageImprint.hashAlgorithm</td><td><span class="required">required</span></td><td>OID of the digest algorithm. Accepted: SHA-256 (<code>2.16.840.1.101.3.4.2.1</code>), SHA-384, SHA-512.</td></tr>
        <tr><td>messageImprint.hashedMessage</td><td><span class="required">required</span></td><td>Raw digest bytes of the data being timestamped.</td></tr>
        <tr><td>reqPolicy</td><td><span class="optional">optional</span></td><td>OID of the requested policy. If supplied, must be <code>2.16.788.1.99.1.40</code>.</td></tr>
        <tr><td>nonce</td><td><span class="optional">optional</span></td><td>Random integer for replay protection. Included verbatim in the response.</td></tr>
        <tr><td>certReq</td><td><span class="optional">optional</span></td><td>If <code>TRUE</code>, the TSA signing certificate is embedded in the response token.</td></tr>
      </tbody>
    </table>

    <h2>TimeStampResp Structure (RFC 3161 §2.4.2)</h2>

    <table class="field-table">
      <thead><tr><th>ASN.1 Field</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>status.status</td><td><code>granted (0)</code> on success. <code>rejection (2)</code> on failure — check <code>statusString</code> for the reason.</td></tr>
        <tr><td>timeStampToken</td><td>CMS <code>SignedData</code> containing a <code>TSTInfo</code> (RFC 3161 §2.4.2). Present only when status is <code>granted</code>.</td></tr>
        <tr><td>TSTInfo.version</td><td><code>v1 (1)</code></td></tr>
        <tr><td>TSTInfo.policy</td><td><code>2.16.788.1.99.1.40</code></td></tr>
        <tr><td>TSTInfo.messageImprint</td><td>Echo of the request's <code>messageImprint</code>.</td></tr>
        <tr><td>TSTInfo.serialNumber</td><td>Monotonically incrementing integer per token.</td></tr>
        <tr><td>TSTInfo.genTime</td><td>UTC time the token was generated (GeneralizedTime).</td></tr>
        <tr><td>TSTInfo.nonce</td><td>Echo of the request nonce, if present.</td></tr>
        <tr><td>SignerInfo.signatureAlgorithm</td><td>ECDSA with SHA-256 (P-256 key).</td></tr>
      </tbody>
    </table>
  </div>

  <!-- ── Integration Guide ─────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>Integration Guide</h2>

    <p>
      If you just want to timestamp a file without writing any code,
      use <a href="/timestamp_it.php" class="inline-cta">🕰️ Meerkat TimeStampIt</a> —
      it handles the TSQ/TSR flow for you and lets you download the token directly.
      The steps below are for integrating the TSA endpoint into your own tooling or pipeline.
    </p>

    <h3>Step 1 — Create a timestamp request with openssl</h3>
    <div class="code-block"><span class="comment"># Hash your file and create a TimeStampReq (nonce + certReq included)</span>
<span class="cmd">openssl ts -query -data myfile.pdf -sha256 -no_nonce -cert -out request.tsq</span>

<span class="comment"># Or with a nonce for replay protection (recommended)</span>
<span class="cmd">openssl ts -query -data myfile.pdf -sha256 -cert -out request.tsq</span>

<span class="comment"># Inspect the request</span>
<span class="cmd">openssl ts -query -in request.tsq -text</span></div>

    <h3>Step 2 — Send the request to the TSA</h3>
    <div class="code-block"><span class="cmd">curl -s -X POST <?= htmlspecialchars(MPCA_TSA_URL) ?> \
  -H 'Content-Type: application/timestamp-query' \
  --data-binary @request.tsq \
  -o response.tsr</span>

<span class="comment"># Inspect the raw response</span>
<span class="cmd">openssl ts -reply -in response.tsr -text</span></div>

    <h3>Step 3 — Verify the timestamp token</h3>
    <div class="code-block"><span class="comment"># Download the TSA chain (TSA CA + Meerkat Root CA)</span>
<span class="cmd">curl -s -o tsa_chain.pem <?= htmlspecialchars(TSA_CHAIN_URL) ?></span>

<span class="comment"># Verify the token against the original file</span>
<span class="cmd">openssl ts -verify -in response.tsr -data myfile.pdf -CAfile tsa_chain.pem</span>

<span class="comment"># Or using the query file if you kept it</span>
<span class="cmd">openssl ts -verify -in response.tsr -queryfile request.tsq -CAfile tsa_chain.pem</span></div>

    <h3>One-liner (request + timestamp in a single command)</h3>
    <div class="code-block"><span class="cmd">openssl ts -query -data myfile.pdf -sha256 -cert \
  | curl -s -X POST <?= htmlspecialchars(MPCA_TSA_URL) ?> \
      -H 'Content-Type: application/timestamp-query' \
      --data-binary @- \
      -o response.tsr \
  &amp;&amp; openssl ts -reply -in response.tsr -text</span></div>

    <h3>Python (using the requests library)</h3>
    <div class="code-block"><span class="comment">import</span> <span class="val">subprocess</span>, <span class="val">requests</span>

<span class="comment"># Create the TimeStampReq</span>
tsq = subprocess.check_output([<span class="str">'openssl'</span>, <span class="str">'ts'</span>, <span class="str">'-query'</span>, <span class="str">'-data'</span>, <span class="str">'myfile.pdf'</span>, <span class="str">'-sha256'</span>, <span class="str">'-cert'</span>])

<span class="comment"># Send to TSA</span>
resp = requests.post(
    <span class="str">'<?= htmlspecialchars(MPCA_TSA_URL) ?>'</span>,
    data=tsq,
    headers={<span class="str">'Content-Type'</span>: <span class="str">'application/timestamp-query'</span>},
)
resp.raise_for_status()

with open(<span class="str">'response.tsr'</span>, <span class="str">'wb'</span>) as f:
    f.write(resp.content)</div>

    <h3>Java (Apache HttpClient)</h3>
    <div class="code-block">HttpPost post = <span class="val">new</span> HttpPost(<span class="str">"<?= htmlspecialchars(MPCA_TSA_URL) ?>"</span>);
post.setHeader(<span class="str">"Content-Type"</span>, <span class="str">"application/timestamp-query"</span>);
post.setEntity(<span class="val">new</span> ByteArrayEntity(tsqDerBytes));
CloseableHttpResponse response = httpClient.execute(post);
<span class="comment">// response body is the DER-encoded TimeStampResp</span>
byte[] tsr = EntityUtils.toByteArray(response.getEntity());</div>
  </div>

  <!-- ── Error Responses ────────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>Error Responses</h2>
    <p>Errors return plain text with the matching HTTP status code.</p>

    <table class="ep-table">
      <thead><tr><th>HTTP</th><th>Cause</th></tr></thead>
      <tbody>
        <tr><td class="err-code">400</td><td>Empty request body — no DER data received.</td></tr>
        <tr><td class="err-code">405</td><td>Wrong HTTP method (only GET and POST are accepted).</td></tr>
        <tr><td class="err-code">415</td><td>Wrong <code>Content-Type</code> — must be <code>application/timestamp-query</code>.</td></tr>
        <tr><td class="err-code">500</td><td>OpenSSL <code>ts -reply</code> failed — malformed TSQ, unsupported hash algorithm, or internal error. The error message contains the OpenSSL stderr output.</td></tr>
        <tr><td class="err-code">503</td><td>TSA not initialized — the signing certificate or config file is missing. Run <code>scripts/mpca_init.sh</code>.</td></tr>
      </tbody>
    </table>
  </div>

  <!-- ── Technical Notes ─────────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>Technical Notes</h2>
    <ul>
      <li><strong>Implementation:</strong> The TSA backend calls <code>openssl ts -reply</code> with a dedicated signing key and certificate. No external network access is required per request.</li>
      <li><strong>Policy OID <code>2.16.788.1.99.1.40</code>:</strong> A private OID registered under the Meerkat test PKI namespace (<code>2.16.788.1.99</code>). It has no meaning outside of this testing environment.</li>
      <li><strong>Signing key:</strong> ECDSA P-256. The signing certificate is issued by the Meerkat MPCA TSA CA (P-384), which chains to the Meerkat MPCA Root CA. None of these CAs are trusted by any public root store.</li>
      <li><strong>Serial numbers:</strong> Incrementing integer stored in <code>tsaserial</code> on the server. Resets if the TSA is re-initialized.</li>
      <li><strong>Nonce:</strong> If the request includes a nonce, it is echoed verbatim in the <code>TSTInfo</code>. Use a nonce to prevent replay attacks when the timestamp is used in a protocol.</li>
      <li><strong>certReq:</strong> When set to <code>TRUE</code> in the request, the TSA signing certificate is included in the <code>SignedData.certificates</code> field of the response token, enabling offline verification without fetching the certificate separately.</li>
      <li><strong>Accepted digest algorithms:</strong> SHA-256 (<code>2.16.840.1.101.3.4.2.1</code>), SHA-384 (<code>2.16.840.1.101.3.4.2.2</code>), SHA-512 (<code>2.16.840.1.101.3.4.2.3</code>). MD5 and SHA-1 are rejected.</li>
      <li><strong>RFC 3161 §2.1 compliance:</strong> The TSA sets <code>tsa_name = yes</code>, so the <code>tsa</code> field in <code>TSTInfo</code> identifies the TSA by its distinguished name.</li>
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
