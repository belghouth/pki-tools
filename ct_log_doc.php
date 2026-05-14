<?php
// ── Read log identities (if keys have been generated) ─────────────────────────
const CT_DOC_KEYS_DIR = '/var/www/thameur.org/pki-ca/ct-log-keys/';
const CT_DOC_LOG_META = [
    'kablouti'    => ['Meerkat Kablouti CT 2025h1',   'Kablouti Certificate Services'],
    'karkoub'  => ['Meerkat Karkoub CT 2025h2',  'Karkoub Trust Infrastructure'],
    'sal7ouf' => ['Meerkat Sal7ouf CT 2026h1', 'Sal7ouf Digital Logs'],
    'farhoud'  => ['Meerkat Farhoud CT 2025',    'Farhoud CT Authority'],
    'habhoub' => ['Meerkat Habhoub CT 2026',   'Habhoub Certificate Logs'],
    'sardouk'  => ['Meerkat Sardouk CT 2025h2',  'Sardouk Log Services'],
    'dhibi'    => ['Meerkat Dhibi CT 2026h1',    'Dhibi Digital Trust'],
    'bousannoun'    => ['Meerkat Bousannoun CT 2025',      'Bousannoun Certificate Transparency'],
];

$log_identities = [];
foreach (CT_DOC_LOG_META as $slug => [$desc, $operator]) {
    $id_file = CT_DOC_KEYS_DIR . $slug . '.id';
    $log_id  = file_exists($id_file) ? trim((string) file_get_contents($id_file)) : null;
    $log_identities[] = [
        'slug'     => $slug,
        'desc'     => $desc,
        'operator' => $operator,
        'log_id'   => $log_id,
        'log_id_b64' => $log_id ? base64_encode(hex2bin($log_id)) : null,
        'url'      => 'https://thameur.org/ct/v1/',
    ];
}

$navLabel = 'Meerkat CT Log';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'Meerkat Testing CT Log — RFC 6962 Ephemeral Certificate Transparency | thameur.org',
    'description' => 'A RFC 6962-compliant testing Certificate Transparency log. Accepts precertificate chains and returns signed SCTs. Ephemeral — no entries are persisted. Randomises log identity across 8 fake CT operators for realistic testing.',
    'url'         => 'https://thameur.org/ct_log_doc.php',
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
    .ct-badge {
      display: inline-flex; align-items: center; gap: 0.5rem;
      background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3);
      border-radius: 4px; padding: 0.3em 0.8em; font-family: var(--mono);
      font-size: 0.72rem; color: var(--green); margin-bottom: 1rem;
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

    /* ── Log identities table ── */
    .logs-table {
      width: 100%; border-collapse: collapse; font-size: 0.78rem;
      font-family: var(--mono); margin-bottom: 1rem;
    }
    .logs-table th {
      text-align: left; color: var(--muted); font-weight: 400;
      font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em;
      border-bottom: 1px solid var(--border); padding: 0.5rem 0.8rem;
    }
    .logs-table td {
      padding: 0.55rem 0.8rem; border-bottom: 1px solid rgba(42,48,64,0.5);
      vertical-align: top;
    }
    .logs-table tr:last-child td { border-bottom: none; }
    .logs-table .log-name { color: var(--accent); font-weight: 600; }
    .logs-table .log-id { font-size: 0.65rem; color: var(--muted); word-break: break-all; }
    .logs-table .log-id-missing { color: rgba(107,122,144,0.5); font-style: italic; }
    .logs-table .operator { color: var(--text); font-size: 0.72rem; }

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
    .badge-ephemeral {
      display: inline-block; font-family: var(--mono); font-size: 0.65rem;
      background: rgba(245,158,11,0.12); border: 1px solid rgba(245,158,11,0.3);
      color: var(--amber); border-radius: 3px; padding: 0.1em 0.5em;
    }

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
      .logs-table, .ep-table, .field-table { font-size: 0.7rem; }
    }
  </style>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<main class="doc-wrap">

  <div class="page-header">
    <div class="ct-badge">🌳 Certificate Transparency — RFC 6962</div>
    <h1>Meerkat Testing CT Log</h1>
    <p class="sub">
      A fully RFC 6962-compliant Certificate Transparency log for testing.
      Accepts precertificate chains and returns cryptographically valid Signed Certificate Timestamps (SCTs).
      Each request is served by a randomly selected identity from a pool of 8 fake log operators —
      so SCTs look like they came from different logs.
    </p>
  </div>

  <div class="notice">
    <span class="notice-icon">⚠</span>
    <span>
      <strong>Ephemeral log — no entries are stored.</strong>
      SCTs are signed and valid but the corresponding tree entries are never persisted.
      Proof endpoints (<code>get-proof-by-hash</code>, <code>get-consistency-proof</code>) return 400.
      Log IDs and keys are stable per deployment; do not submit to real browsers or CT monitors.
    </span>
  </div>

  <!-- ── Available Log Identities ──────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>Available Log Identities</h2>
    <p>
      One identity is selected at random per <code>add-pre-chain</code> request.
      The returned SCT's <code>id</code> field identifies which log "signed" it.
      All identities share a single API endpoint.
    </p>

    <table class="logs-table">
      <thead>
        <tr>
          <th>Log Name</th>
          <th>Operator</th>
          <th>Log ID (base64)</th>
          <th>MMD</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($log_identities as $l): ?>
        <tr>
          <td class="log-name"><?= htmlspecialchars($l['desc']) ?></td>
          <td class="operator"><?= htmlspecialchars($l['operator']) ?></td>
          <td>
            <?php if ($l['log_id_b64']): ?>
            <span class="log-id"><?= htmlspecialchars($l['log_id_b64']) ?></span>
            <?php else: ?>
            <span class="log-id-missing">not yet generated — run gen_ct_log_keys.php</span>
            <?php endif; ?>
          </td>
          <td style="color:var(--muted)">24 h</td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
    <p style="font-size:0.78rem;color:var(--muted)">
      API Base URL: <code>https://thameur.org/ct/v1/</code> &nbsp;·&nbsp;
      Log ID = SHA-256(SubjectPublicKeyInfo DER of the log's ECDSA P-256 public key)
    </p>
  </div>

  <!-- ── Endpoints ─────────────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>API Endpoints</h2>

    <table class="ep-table">
      <thead>
        <tr><th>Method</th><th>Path</th><th>Description</th></tr>
      </thead>
      <tbody>
        <tr>
          <td><span class="method-post">POST</span></td>
          <td class="ep-path">/ct/v1/add-pre-chain</td>
          <td>Submit a precertificate chain. Returns a signed SCT. <strong>Primary endpoint.</strong></td>
        </tr>
        <tr>
          <td><span class="method-get">GET</span></td>
          <td class="ep-path">/ct/v1/get-sth</td>
          <td>Returns a signed tree head for the empty tree. Timestamp is the current UTC millisecond.</td>
        </tr>
        <tr>
          <td><span class="method-get">GET</span></td>
          <td class="ep-path">/ct/v1/get-roots</td>
          <td>Returns base64 DER of accepted root and issuing CA certificates.</td>
        </tr>
        <tr>
          <td><span class="method-get">GET</span></td>
          <td class="ep-path">/ct/v1/get-entries</td>
          <td>Always returns an empty list. Log is ephemeral — no entries are stored. <span class="badge-ephemeral">ephemeral</span></td>
        </tr>
        <tr>
          <td><span class="method-get">GET</span></td>
          <td class="ep-path">/ct/v1/get-proof-by-hash</td>
          <td>Returns HTTP 400 — proof endpoints require persistence. <span class="badge-ephemeral">not supported</span></td>
        </tr>
      </tbody>
    </table>

    <!-- add-pre-chain -->
    <h3>POST /ct/v1/add-pre-chain</h3>
    <p>
      Accepts a JSON body containing the precertificate chain (RFC 6962 §4.1).
      Validates the CT poison extension, strips it from the TBSCertificate,
      computes the issuer key hash, selects a random log identity, and returns a signed SCT.
    </p>

    <p><strong>Request body:</strong></p>
    <div class="code-block"><span class="comment">// Content-Type: application/json</span>
{
  <span class="key">"chain"</span>: [
    <span class="str">"&lt;base64-DER-precertificate&gt;"</span>,   <span class="comment">// required — must contain OID 1.3.6.1.4.1.11129.2.4.3</span>
    <span class="str">"&lt;base64-DER-issuing-CA-cert&gt;"</span>   <span class="comment">// optional — falls back to Meerkat Issuing CA if omitted</span>
  ]
}</div>

    <p><strong>Request fields:</strong></p>
    <table class="field-table">
      <thead><tr><th>Field</th><th>Type</th><th>Notes</th></tr></thead>
      <tbody>
        <tr>
          <td>chain[0]</td>
          <td><span class="required">required</span></td>
          <td>Base64-encoded DER precertificate. Must contain the CT poison extension (OID 1.3.6.1.4.1.11129.2.4.3, critical).</td>
        </tr>
        <tr>
          <td>chain[1]</td>
          <td><span class="optional">optional</span></td>
          <td>Base64-encoded DER issuing CA certificate. Used to compute the issuer_key_hash. If absent, the Meerkat Issuing CA cert is used.</td>
        </tr>
        <tr>
          <td>chain[2…N]</td>
          <td><span class="optional">optional</span></td>
          <td>Additional intermediate CA certificates up to the accepted root (max 10 total). Not used in SCT computation.</td>
        </tr>
      </tbody>
    </table>

    <p><strong>Success response (HTTP 200):</strong></p>
    <div class="code-block">{
  <span class="key">"sct_version"</span>: <span class="val">0</span>,                      <span class="comment">// always 0 (v1)</span>
  <span class="key">"id"</span>:          <span class="str">"&lt;base64 32-byte log ID&gt;"</span>,  <span class="comment">// SHA-256(SPKI) of this request's log identity</span>
  <span class="key">"timestamp"</span>:   <span class="val">1747217000000</span>,             <span class="comment">// Unix milliseconds (uint64)</span>
  <span class="key">"extensions"</span>:  <span class="str">""</span>,                         <span class="comment">// always empty (base64 of zero bytes)</span>
  <span class="key">"signature"</span>:   <span class="str">"&lt;base64 DigitallySigned&gt;"</span>  <span class="comment">// see SCT Structure below</span>
}</div>

    <!-- get-sth -->
    <h3>GET /ct/v1/get-sth</h3>
    <p>Returns a freshly signed Signed Tree Head for the empty tree (tree_size = 0). A new timestamp and a randomly selected log key are used on each call.</p>

    <div class="code-block">{
  <span class="key">"tree_size"</span>:           <span class="val">0</span>,
  <span class="key">"timestamp"</span>:           <span class="val">1747217000000</span>,
  <span class="key">"sha256_root_hash"</span>:    <span class="str">"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="</span>,  <span class="comment">// SHA-256("")</span>
  <span class="key">"tree_head_signature"</span>: <span class="str">"&lt;base64 DigitallySigned&gt;"</span>
}</div>

    <!-- get-roots -->
    <h3>GET /ct/v1/get-roots</h3>
    <div class="code-block">{
  <span class="key">"certificates"</span>: [
    <span class="str">"&lt;base64 DER Meerkat Root CA&gt;"</span>,
    <span class="str">"&lt;base64 DER Meerkat Issuing CA&gt;"</span>
  ]
}</div>
  </div>

  <!-- ── SCT Structure ──────────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>SCT &amp; Signed Data Structure</h2>
    <p>
      The <code>signature</code> field contains a base64-encoded <strong>DigitallySigned</strong> struct (RFC 6962 §3.2).
      The data signed by the log for a precertificate entry (<code>precert_entry = 1</code>):
    </p>

    <table class="field-table">
      <thead><tr><th>Field</th><th>Size</th><th>Value</th></tr></thead>
      <tbody>
        <tr><td>version</td><td>1 byte</td><td><code>0x00</code> (v1)</td></tr>
        <tr><td>signature_type</td><td>1 byte</td><td><code>0x00</code> (certificate_timestamp)</td></tr>
        <tr><td>timestamp</td><td>8 bytes</td><td>uint64 big-endian milliseconds since epoch</td></tr>
        <tr><td>entry_type</td><td>2 bytes</td><td><code>0x00 0x01</code> (precert_entry)</td></tr>
        <tr><td>issuer_key_hash</td><td>32 bytes</td><td>SHA-256 of issuer SubjectPublicKeyInfo DER</td></tr>
        <tr><td>tbs_certificate length</td><td>3 bytes</td><td>uint24 big-endian byte count of the TBS</td></tr>
        <tr><td>tbs_certificate</td><td>variable</td><td>DER TBSCertificate with CT poison extension removed</td></tr>
        <tr><td>extensions length</td><td>2 bytes</td><td><code>0x00 0x00</code> (no extensions)</td></tr>
      </tbody>
    </table>

    <p>The <strong>DigitallySigned</strong> encoding:</p>
    <table class="field-table">
      <thead><tr><th>Byte(s)</th><th>Field</th><th>Value</th></tr></thead>
      <tbody>
        <tr><td><code>0x04</code></td><td>hash_algorithm</td><td>SHA-256</td></tr>
        <tr><td><code>0x03</code></td><td>signature_algorithm</td><td>ECDSA</td></tr>
        <tr><td>2 bytes</td><td>signature length (uint16 big-endian)</td><td>DER ECDSA signature byte count</td></tr>
        <tr><td>variable</td><td>signature</td><td>DER-encoded ECDSA signature over the signed data above (P-256 + SHA-256)</td></tr>
      </tbody>
    </table>
  </div>

  <!-- ── Error codes ────────────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>Error Responses</h2>
    <p>All errors return JSON with <code>error_code</code> (HTTP status) and <code>error_message</code>.</p>

    <table class="ep-table">
      <thead><tr><th>HTTP</th><th>Cause</th></tr></thead>
      <tbody>
        <tr><td class="err-code">400</td><td>Missing or malformed <code>chain</code> field; base64 decode failure; <code>chain[0]</code> is not a valid X.509 certificate; CT poison extension not present; proof endpoint requested.</td></tr>
        <tr><td class="err-code">405</td><td>Wrong HTTP method (e.g. GET on <code>add-pre-chain</code>).</td></tr>
        <tr><td class="err-code">404</td><td>Unknown endpoint.</td></tr>
        <tr><td class="err-code">500</td><td>DER parsing failure; ECDSA signing error; log keys not yet generated.</td></tr>
      </tbody>
    </table>
  </div>

  <!-- ── Integration Guide ─────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>Integration Guide</h2>

    <h3>Step 1 — Issue a precertificate</h3>
    <p>
      Use the <a href="/cert_factory.php">Meerkat Certificate Factory</a> "Issue Precertificate" button,
      or issue one via your own CA pipeline with the CT poison extension
      (OID <code>1.3.6.1.4.1.11129.2.4.3</code>, critical, value = ASN.1 NULL <code>05 00</code>).
    </p>

    <h3>Step 2 — Encode the chain as base64 DER</h3>
    <div class="code-block"><span class="comment"># Convert PEM precert to base64 DER (single line, no headers)</span>
<span class="cmd">openssl x509 -in precert.pem -outform DER | base64 -w0</span>

<span class="comment"># Same for the issuing CA cert</span>
<span class="cmd">openssl x509 -in issuing-ca.pem -outform DER | base64 -w0</span></div>

    <h3>Step 3 — Submit to add-pre-chain</h3>
    <div class="code-block"><span class="cmd">curl -s -X POST https://thameur.org/ct/v1/add-pre-chain \
  -H 'Content-Type: application/json' \
  -d '{
    "chain": [
      "'"$(openssl x509 -in precert.pem -outform DER | base64 -w0)"'",
      "'"$(openssl x509 -in issuing-ca.pem -outform DER | base64 -w0)"'"
    ]
  }' | jq .</span></div>

    <h3>Step 4 — Example SCT response</h3>
    <div class="code-block">{
  <span class="key">"sct_version"</span>: <span class="val">0</span>,
  <span class="key">"id"</span>:          <span class="str">"r8US3L7lnpBxpHNH08p3DbqEP6r7VIGpHqCbLTNLkJo="</span>,
  <span class="key">"timestamp"</span>:   <span class="val">1747217284391</span>,
  <span class="key">"extensions"</span>:  <span class="str">""</span>,
  <span class="key">"signature"</span>:   <span class="str">"BAMARzBFAiEAx9kB0...RGQ4AiAjK2XhN..."</span>
}</div>

    <h3>Verify the SCT signature (OpenSSL)</h3>
    <div class="code-block"><span class="comment"># 1. Decode the log ID to find which key signed it</span>
<span class="cmd">echo -n '&lt;base64-id&gt;' | base64 -d | xxd | head -2</span>

<span class="comment"># 2. Export the log's public key from the SPKI</span>
<span class="cmd">openssl ec -in /path/to/ct-log-keys/&lt;name&gt;.pem -pubout -out log_pub.pem</span>

<span class="comment"># 3. Reconstruct the signed blob and verify — see RFC 6962 §3.2</span></div>

    <h3>Embed the SCT in a certificate extension</h3>
    <p>
      The SCT can be embedded in the final certificate as a
      <code>SignedCertificateTimestampList</code> (OID <code>1.3.6.1.4.1.11129.2.4.2</code>),
      or delivered via a TLS extension, or via OCSP stapling.
      Encoding of the SCT list is described in RFC 6962 §3.3.
    </p>
  </div>

  <!-- ── Notes ─────────────────────────────────────────────────────────────── -->
  <div class="doc-section">
    <h2>Technical Notes</h2>
    <ul>
      <li><strong>Randomisation:</strong> Each request picks one of 8 ECDSA P-256 key pairs at random. The <code>id</code> in the SCT uniquely identifies which log "signed" it. This prevents issued test certs from appearing to always submit to a single log.</li>
      <li><strong>No persistence:</strong> The Merkle tree is never built. <code>get-entries</code> always returns an empty list. SCTs are produced on-the-fly — there is no audit trail.</li>
      <li><strong>Poison stripping:</strong> The TBSCertificate submitted in the chain has the CT poison extension (OID 1.3.6.1.4.1.11129.2.4.3) removed before it is hashed into the signed data, per RFC 6962 §3.2. Extensions are re-encoded in-place; no other fields are modified.</li>
      <li><strong>IssuerKeyHash:</strong> Computed as SHA-256 of the SubjectPublicKeyInfo DER of the issuing CA certificate (chain[1], or the Meerkat Issuing CA if absent).</li>
      <li><strong>Accepted roots:</strong> Meerkat Root CA and Meerkat Test Issuing CA 1. Submit the chain up to one of these two.</li>
      <li><strong>CORS:</strong> All endpoints respond with <code>Access-Control-Allow-Origin: *</code> for browser-based testing.</li>
      <li><strong>RFC 6962 §4.1 chain requirement:</strong> The chain must chain to an accepted root. Full path verification is not enforced in this testing implementation.</li>
    </ul>
  </div>

</main>

<footer class="site-footer">
  <span>&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="/">Home</a>
    <a href="/references.php">PKI References</a>
    <a href="/privacy.php">Privacy Policy</a>
    <a href="mailto:me@thameur.org">me@thameur.org</a>
  </div>
</footer>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>
</body>
</html>
