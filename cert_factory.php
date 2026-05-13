<?php
// ── Server-side config ────────────────────────────────────────────────────────
const OPENSSL        = '/usr/bin/openssl';
const ISSUING_CRT    = '/var/www/pki.thameur.org/meerkat-issuing.crt';
const ISSUING_KEY    = '/var/www/thameur.org/pki-ca/private/issuing.key';
const ISSUING_DB_CNF = '/var/www/thameur.org/pki-ca/issuing-db/openssl.cnf';
const ISSUING_LOCK   = '/var/www/thameur.org/pki-ca/issuing-db/factory.lock';
const ISSUING_DB_SRL = '/var/www/thameur.org/pki-ca/issuing-db/cert.srl';
const CERT_DAYS      = 90;
const MAX_CSR_BYTES  = 65536;
const MAX_SANS       = 100;
const AIA_URL        = 'http://pki.thameur.org/meerkat-issuing.crt';
const CDP_URL        = 'http://pki.thameur.org/meerkat-issuing.crl';

// ── API ───────────────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(handle_issue(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function handle_issue(): array
{
    // Collect CSR PEM
    $csrPem = '';
    if (!empty($_POST['csr'])) {
        $csrPem = trim($_POST['csr']);
    } elseif (isset($_FILES['csr_file']) && $_FILES['csr_file']['error'] === UPLOAD_ERR_OK) {
        if ($_FILES['csr_file']['size'] > MAX_CSR_BYTES) {
            return ['error' => 'File exceeds 64 KB limit'];
        }
        $csrPem = trim((string) file_get_contents($_FILES['csr_file']['tmp_name']));
    }

    if (!$csrPem) {
        return ['error' => 'No CSR provided'];
    }
    if (strlen($csrPem) > MAX_CSR_BYTES) {
        return ['error' => 'CSR exceeds 64 KB limit'];
    }

    // Validate PEM header before touching the filesystem
    if (!preg_match('/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/i', $csrPem)) {
        return ['error' => 'Invalid format — expected a PEM CERTIFICATE REQUEST block'];
    }

    // Check CA is initialised
    if (!file_exists(ISSUING_DB_CNF)) {
        return ['error' => 'The issuing CA is not yet initialised — please check back shortly.'];
    }

    $tmpCsr = sys_get_temp_dir() . '/cf_csr_' . bin2hex(random_bytes(8)) . '.pem';
    file_put_contents($tmpCsr, $csrPem . "\n");

    try {
        return process_csr($tmpCsr);
    } finally {
        @unlink($tmpCsr);
    }
}

function process_csr(string $csrFile): array
{
    // 1. Parse (also validates PEM structure)
    $r = run_cmd([OPENSSL, 'req', '-in', $csrFile, '-noout', '-text']);
    if (!$r['ok']) {
        return ['error' => 'Failed to parse CSR — check the PEM encoding'];
    }
    $text = $r['out'];

    // 2. Signature self-check
    $r = run_cmd([OPENSSL, 'req', '-verify', '-in', $csrFile, '-noout']);
    if (!$r['ok'] && !str_contains($r['err'], 'verify OK')) {
        return ['error' => 'CSR self-signature verification failed'];
    }

    // 3. Key type — RSA only
    if (!preg_match('/Public Key Algorithm:\s*rsaEncryption/i', $text)) {
        return ['error' => 'Only RSA keys are accepted (EC, DSA and other types are not supported)'];
    }

    // 4. Key size — ≥ 2048 bits
    if (!preg_match('/Public[-\s]Key:\s*\((\d+)\s*bit\)/i', $text, $m)) {
        return ['error' => 'Could not determine RSA key size'];
    }
    $keyBits = (int) $m[1];
    if ($keyBits < 2048) {
        return ['error' => "RSA key is {$keyBits} bits — minimum accepted is 2048 bits"];
    }

    // 5. Extract DNS SANs from requested extensions
    $sans = extract_dns_sans($text);

    // 6. Fall back to CN when no SAN extension is present
    if (empty($sans)) {
        $cn = extract_cn($text);
        if ($cn !== '' && is_valid_dns($cn)) {
            $sans[] = $cn;
        }
    }

    if (empty($sans)) {
        return ['error' => 'No valid DNS SANs found. Add a Subject Alternative Name extension to your CSR, or set a valid FQDN as the Common Name.'];
    }

    // 7. Validate each DNS name
    foreach ($sans as $san) {
        if (!is_valid_dns($san)) {
            return ['error' => "Invalid DNS name: \"$san\""];
        }
    }

    // 8. Sign — serialised through a lock file (openssl ca is not re-entrant)
    $lock = fopen(ISSUING_LOCK, 'w');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
        if ($lock) fclose($lock);
        return ['error' => 'Another issuance is in progress — please retry in a moment'];
    }

    $extFile  = sys_get_temp_dir() . '/cf_ext_'  . bin2hex(random_bytes(8)) . '.cnf';
    $certFile = sys_get_temp_dir() . '/cf_cert_' . bin2hex(random_bytes(8)) . '.pem';

    try {
        // Random 128-bit serial — written before each signing so every cert
        // gets fresh entropy (BR §7.1.2.4 requires ≥64 bits; 128 is standard)
        file_put_contents(ISSUING_DB_SRL, strtoupper(bin2hex(random_bytes(16))) . "\n");

        $firstSan = $sans[0];
        $sanStr   = implode(', ', array_map(fn($s) => 'DNS:' . $s, $sans));

        file_put_contents($extFile, implode("\n", [
            '[ v3_ee ]',
            // critical — required by BR §7.1.2.7.6 and zlint e_sub_cert_basic_constraints_not_critical
            'basicConstraints       = critical, CA:FALSE',
            // keyEncipherment removed — discouraged per BR §7.1.2.7.11 for modern TLS
            'keyUsage               = critical, digitalSignature',
            'extendedKeyUsage       = serverAuth, clientAuth',
            // SKI omitted — discouraged in subscriber certs per BR §7.1.2.7
            'authorityKeyIdentifier = keyid:always',
            'certificatePolicies    = 2.23.140.1.2.1',
            'authorityInfoAccess    = caIssuers;URI:' . AIA_URL,
            'crlDistributionPoints  = URI:' . CDP_URL,
            'subjectAltName         = ' . $sanStr,
        ]));

        $r = run_cmd([
            OPENSSL, 'ca',
            '-config',     ISSUING_DB_CNF,
            '-in',         $csrFile,
            '-out',        $certFile,
            '-subj',       '/CN=' . $firstSan,
            '-extfile',    $extFile,
            '-extensions', 'v3_ee',
            '-days',       (string) CERT_DAYS,
            '-notext',
            '-batch',
        ]);

        if (!$r['ok']) {
            return ['error' => 'Signing failed: ' . trim($r['err'] ?: $r['out'])];
        }

        $certPem = (string) file_get_contents($certFile);
        if (!str_contains($certPem, '-----BEGIN CERTIFICATE-----')) {
            return ['error' => 'Signing produced no output'];
        }

        $info = parse_cert($certFile);

        return [
            'ok'         => true,
            'certificate'=> trim($certPem),
            'subject'    => 'CN=' . $firstSan,
            'sans'       => $sans,
            'key_bits'   => $keyBits,
            'issuer'     => $info['issuer']     ?? 'CN=Meerkat Test Issuing CA 1',
            'not_before' => $info['not_before'] ?? '',
            'not_after'  => $info['not_after']  ?? '',
            'serial'     => $info['serial']     ?? '',
        ];

    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
        @unlink($extFile);
        @unlink($certFile);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function extract_dns_sans(string $text): array
{
    $sans = [];
    // Capture everything after "Subject Alternative Name:" until the next blank/non-indented line
    if (preg_match('/Subject Alternative Name:\s*\n((?:[ \t]+[^\n]+\n?)+)/m', $text, $m)) {
        preg_match_all('/DNS:([^\s,]+)/i', $m[1], $dm);
        foreach ($dm[1] as $name) {
            if (count($sans) >= MAX_SANS) break;
            $sans[] = trim($name);
        }
    }
    return $sans;
}

function extract_cn(string $text): string
{
    if (preg_match('/Subject:.*?\bCN\s*=\s*([^\s,\/\n]+)/i', $text, $m)) {
        return trim($m[1]);
    }
    return '';
}

function is_valid_dns(string $name): bool
{
    if (strlen($name) === 0 || strlen($name) > 253) return false;
    if (str_starts_with($name, '*')) return false;   // no wildcards without DCV
    $labels = explode('.', $name);
    if (count($labels) < 2) return false;            // require at least one dot (FQDN)
    foreach ($labels as $label) {
        if ($label === '' || strlen($label) > 63) return false;
        if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$/', $label)) return false;
    }
    return true;
}

function parse_cert(string $certFile): array
{
    $r = run_cmd([OPENSSL, 'x509', '-in', $certFile, '-noout', '-text']);
    if (!$r['ok']) return [];
    $t   = $r['out'];
    $out = [];
    if (preg_match('/Issuer:\s*(.+)/i',          $t, $m)) $out['issuer']     = trim($m[1]);
    if (preg_match('/Not Before:\s*(.+)/i',      $t, $m)) $out['not_before'] = trim($m[1]);
    if (preg_match('/Not After\s*:\s*(.+)/i',    $t, $m)) $out['not_after']  = trim($m[1]);
    if (preg_match('/Serial Number:\s*\n?\s*([0-9a-f:]+)/i', $t, $m)) $out['serial'] = trim($m[1]);
    return $out;
}

function run_cmd(array $cmd): array
{
    $proc = proc_open($cmd, [
        0 => ['file', '/dev/null', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes);
    if (!$proc) return ['ok' => false, 'out' => '', 'err' => 'proc_open failed', 'code' => -1];
    $out  = stream_get_contents($pipes[1]);
    $err  = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return ['ok' => $code === 0, 'out' => (string) $out, 'err' => (string) $err, 'code' => $code];
}

// ── Page ──────────────────────────────────────────────────────────────────────
$navLabel = 'Test CA';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'Test Certificate Factory — BR-Compliant TLS Cert Issuance | thameur.org',
    'description' => 'Submit a CSR and receive a BR-compliant DV TLS certificate signed by the Meerkat Test Issuing CA. RSA ≥ 2048 only. For linter testing and local chain validation.',
    'url'         => 'https://thameur.org/cert_factory.php',
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
      --sans: 'IBM Plex Sans', sans-serif; --mono: 'IBM Plex Mono', monospace;
      --radius: 8px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; scroll-behavior: smooth; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans);
           font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }

    /* ── Layout ── */
    .factory-wrap { max-width: 820px; margin: 0 auto; padding: 3.5rem 2rem 6rem; }

    /* ── Page header ── */
    .page-header { margin-bottom: 2rem; }
    .page-header h1 { font-size: 1.9rem; font-weight: 600; color: #fff; margin-bottom: 0.3rem; }
    .page-header p  { font-size: 0.88rem; color: var(--muted); max-width: 600px; }

    /* ── Warning banner ── */
    .warn-banner {
      display: flex; align-items: center; gap: 0.6rem;
      border: 1px solid #7c2d12; background: rgba(124,45,18,0.1);
      border-radius: 6px; padding: 0.7rem 1rem; margin-bottom: 1.8rem;
      font-size: 0.82rem; color: #fca5a5;
    }

    /* ── Card ── */
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 1.6rem;
      margin-bottom: 1.5rem;
    }

    /* ── Input tabs ── */
    .input-tabs { display: flex; gap: 0; margin-bottom: 1.2rem; border-bottom: 1px solid var(--border); }
    .input-tab {
      font-family: var(--mono); font-size: 0.72rem; text-transform: uppercase;
      letter-spacing: 0.07em; background: none; border: none; color: var(--muted);
      padding: 0.55em 1.1em; cursor: pointer; border-bottom: 2px solid transparent;
      margin-bottom: -1px; transition: color 0.15s, border-color 0.15s;
    }
    .input-tab:hover { color: var(--text); }
    .input-tab.active { color: var(--accent); border-bottom-color: var(--accent); }

    .tab-pane { display: none; }
    .tab-pane.active { display: block; }

    /* ── CSR textarea ── */
    .csr-area {
      width: 100%; background: var(--bg); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text); font-family: var(--mono);
      font-size: 0.72rem; line-height: 1.6; padding: 0.9rem 1rem;
      resize: vertical; min-height: 200px;
      transition: border-color 0.15s;
    }
    .csr-area:focus { outline: none; border-color: var(--accent); }
    .csr-area::placeholder { color: var(--muted); }

    /* ── File drop zone ── */
    .file-drop {
      border: 1px dashed var(--border); border-radius: 6px;
      padding: 2.5rem 1rem; text-align: center; cursor: pointer;
      transition: border-color 0.15s, background 0.15s;
      position: relative;
    }
    .file-drop:hover, .file-drop.drag-over {
      border-color: var(--accent); background: rgba(0,212,170,0.04);
    }
    .file-drop input[type=file] {
      position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%;
    }
    .file-drop p { font-size: 0.85rem; color: var(--muted); pointer-events: none; }
    .file-drop .drop-icon { font-size: 1.6rem; margin-bottom: 0.4rem; }
    .file-selected {
      font-family: var(--mono); font-size: 0.72rem; color: var(--accent);
      margin-top: 0.7rem; padding: 0.4rem 0.7rem;
      background: rgba(0,212,170,0.06); border-radius: 4px;
    }

    /* ── Submit row ── */
    .submit-row {
      display: flex; align-items: center; gap: 1rem; margin-top: 1.2rem;
    }
    .btn-primary {
      font-family: var(--mono); font-size: 0.78rem; letter-spacing: 0.05em;
      text-transform: uppercase; background: var(--accent); color: #0e1014;
      border: none; border-radius: 5px; padding: 0.55em 1.4em;
      cursor: pointer; font-weight: 600; transition: opacity 0.15s;
    }
    .btn-primary:hover:not(:disabled) { opacity: 0.85; }
    .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }

    .btn-ghost {
      font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.05em;
      text-transform: uppercase; background: none;
      border: 1px solid var(--border); border-radius: 5px;
      padding: 0.45em 1em; cursor: pointer; color: var(--muted);
      transition: border-color 0.15s, color 0.15s;
    }
    .btn-ghost:hover { border-color: var(--accent); color: var(--accent); }

    .spinner {
      width: 18px; height: 18px; border: 2px solid var(--border);
      border-top-color: var(--accent); border-radius: 50%;
      animation: spin 0.7s linear infinite; flex-shrink: 0;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ── Error box ── */
    .error-box {
      display: flex; align-items: flex-start; gap: 0.6rem;
      background: rgba(248,113,113,0.08); border: 1px solid rgba(248,113,113,0.3);
      border-radius: 6px; padding: 0.8rem 1rem; margin-top: 1rem;
      font-size: 0.83rem; color: var(--danger);
    }
    .error-box .err-icon { flex-shrink: 0; margin-top: 0.1rem; }

    /* ── Result card ── */
    .result-header {
      display: flex; align-items: center; justify-content: space-between;
      flex-wrap: wrap; gap: 0.8rem; margin-bottom: 1.2rem;
    }
    .result-header h2 { font-size: 1rem; font-weight: 600; color: var(--accent); }
    .result-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }

    /* ── Cert info grid ── */
    .cert-info {
      display: grid; grid-template-columns: max-content 1fr;
      gap: 0.3rem 1rem; font-family: var(--mono); font-size: 0.72rem;
      margin-bottom: 1.2rem;
    }
    .ci-key   { color: var(--muted); white-space: nowrap; }
    .ci-val   { color: var(--text); word-break: break-all; }
    .san-list { display: flex; flex-wrap: wrap; gap: 0.3rem; }
    .san-tag  {
      display: inline-block; font-family: var(--mono); font-size: 0.68rem;
      padding: 0.15em 0.5em; border-radius: 3px;
      border: 1px solid rgba(0,212,170,0.3); background: rgba(0,212,170,0.07);
      color: var(--accent);
    }

    /* ── PEM output ── */
    .pem-wrap { position: relative; margin-bottom: 1rem; }
    .pem-output {
      width: 100%; background: var(--bg); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text); font-family: var(--mono);
      font-size: 0.7rem; line-height: 1.6; padding: 0.9rem 1rem;
      resize: vertical; min-height: 180px; cursor: default;
    }
    .pem-output:focus { outline: none; }

    /* ── Chain note ── */
    .chain-note {
      font-size: 0.78rem; color: var(--muted); margin-top: 0.6rem;
      padding-top: 1rem; border-top: 1px solid var(--border);
    }

    /* ── Footer ── */
    .site-footer {
      border-top: 1px solid var(--border); padding: 1.4rem 2rem;
      display: flex; align-items: center; justify-content: space-between;
      flex-wrap: wrap; gap: 1rem;
      font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
    }
    .site-footer a { color: var(--muted); }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }

    @media (max-width: 600px) {
      .factory-wrap { padding: 2rem 1rem 4rem; }
      .cert-info { grid-template-columns: 1fr; }
      .ci-key { color: var(--accent); font-size: 0.65rem; }
    }
  </style>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<main class="factory-wrap">

  <div class="page-header">
    <h1>Test Certificate Factory</h1>
    <p>Submit a CSR to receive a BR-compliant DV TLS certificate signed by the Meerkat Test Issuing CA.
       RSA ≥ 2048 only. Subject is rebuilt from the first SAN — all other CSR fields are stripped.</p>
  </div>

  <div class="warn-banner">
    <span class="err-icon">⚠</span>
    <span><strong>Test use only.</strong> Certificates from this CA are not trusted by any browser or OS
    and must never be used to secure real services.</span>
  </div>

  <!-- Input card -->
  <div class="card">
    <div class="input-tabs" role="tablist">
      <button class="input-tab active" role="tab" data-tab="paste">Paste CSR</button>
      <button class="input-tab"        role="tab" data-tab="upload">Upload File</button>
    </div>

    <form id="issueForm" enctype="multipart/form-data" novalidate>

      <div class="tab-pane active" id="pane-paste">
        <textarea class="csr-area" id="csrText" name="csr"
                  placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;MIIByjCCAT...&#10;-----END CERTIFICATE REQUEST-----"
                  spellcheck="false" autocomplete="off"></textarea>
      </div>

      <div class="tab-pane" id="pane-upload">
        <div class="file-drop" id="fileDrop">
          <div class="drop-icon">📄</div>
          <p>Drop a .pem or .csr file here, or click to browse</p>
          <input type="file" id="csrFile" name="csr_file" accept=".pem,.csr,.txt">
        </div>
        <div class="file-selected" id="fileSelected" hidden></div>
      </div>

      <div class="submit-row">
        <button class="btn-primary" type="submit" id="btnIssue">Issue Certificate</button>
        <div class="spinner" id="spinner" hidden></div>
      </div>

    </form>

    <div class="error-box" id="errorBox" hidden>
      <span class="err-icon">✕</span>
      <span id="errorMsg"></span>
    </div>
  </div>

  <!-- Result card (hidden until a cert is issued) -->
  <div class="card" id="resultCard" hidden>
    <div class="result-header">
      <h2>✔ Certificate Issued</h2>
      <div class="result-actions">
        <button class="btn-ghost" id="btnCopy">Copy PEM</button>
        <button class="btn-ghost" id="btnDl">Download .crt</button>
      </div>
    </div>

    <div class="cert-info" id="certInfo"></div>

    <div class="pem-wrap">
      <textarea class="pem-output" id="pemOutput" readonly spellcheck="false"></textarea>
    </div>

    <p class="chain-note">
      Chain: <a href="https://pki.thameur.org/meerkat-root.crt">Meerkat Root CA</a>
      → <a href="https://pki.thameur.org/meerkat-issuing.crt">Meerkat Test Issuing CA 1</a>
      → this certificate<br>
      Install the Root CA to trust this cert locally for linter testing.
    </p>
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

<script>
(function () {
  'use strict';

  // ── Tab switching ────────────────────────────────────────────────────────────
  var tabs  = document.querySelectorAll('.input-tab');
  var panes = document.querySelectorAll('.tab-pane');
  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      tabs.forEach(function (t) { t.classList.remove('active'); });
      panes.forEach(function (p) { p.classList.remove('active'); });
      tab.classList.add('active');
      var pane = document.getElementById('pane-' + tab.dataset.tab);
      if (pane) pane.classList.add('active');
    });
  });

  // ── File drop zone ───────────────────────────────────────────────────────────
  var fileDrop     = document.getElementById('fileDrop');
  var fileInput    = document.getElementById('csrFile');
  var fileSelected = document.getElementById('fileSelected');

  ['dragenter', 'dragover'].forEach(function (ev) {
    fileDrop.addEventListener(ev, function (e) {
      e.preventDefault();
      fileDrop.classList.add('drag-over');
    });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    fileDrop.addEventListener(ev, function (e) {
      e.preventDefault();
      fileDrop.classList.remove('drag-over');
    });
  });
  fileDrop.addEventListener('drop', function (e) {
    var f = e.dataTransfer && e.dataTransfer.files[0];
    if (f) handleFile(f);
  });
  fileInput.addEventListener('change', function () {
    if (fileInput.files[0]) handleFile(fileInput.files[0]);
  });

  function handleFile(file) {
    var reader = new FileReader();
    reader.onload = function (e) {
      fileSelected.hidden   = false;
      fileSelected.textContent = '📄 ' + file.name + ' (' + Math.ceil(file.size / 1024) + ' KB)';
    };
    reader.readAsText(file);
  }

  // ── Form submission ──────────────────────────────────────────────────────────
  var form       = document.getElementById('issueForm');
  var btnIssue   = document.getElementById('btnIssue');
  var spinner    = document.getElementById('spinner');
  var errorBox   = document.getElementById('errorBox');
  var errorMsg   = document.getElementById('errorMsg');
  var resultCard = document.getElementById('resultCard');
  var certInfo   = document.getElementById('certInfo');
  var pemOutput  = document.getElementById('pemOutput');

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    doIssue();
  });

  async function doIssue() {
    setLoading(true);
    hideError();
    resultCard.hidden = true;

    // Client-side: require something in the active tab
    var activeTab = document.querySelector('.input-tab.active');
    var method = activeTab ? activeTab.dataset.tab : 'paste';

    if (method === 'paste') {
      var txt = document.getElementById('csrText').value.trim();
      if (!txt) { showError('Please paste a PEM CSR.'); setLoading(false); return; }
      if (!txt.includes('CERTIFICATE REQUEST')) {
        showError('Not a valid PEM CERTIFICATE REQUEST block.');
        setLoading(false); return;
      }
    } else {
      if (!fileInput.files[0]) { showError('Please select a file.'); setLoading(false); return; }
    }

    var fd = new FormData(form);
    if (method === 'paste') fd.delete('csr_file');
    else                    fd.delete('csr');

    try {
      var resp = await fetch(window.location.href, { method: 'POST', body: fd });
      if (!resp.ok) throw new Error('Server returned ' + resp.status);
      var data = await resp.json();
      if (data.error) { showError(data.error); return; }
      renderResult(data);
    } catch (err) {
      showError('Request failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  }

  // ── Render result ────────────────────────────────────────────────────────────
  function renderResult(data) {
    // PEM
    pemOutput.value = data.certificate;

    // Info table
    var sanHtml = (data.sans || []).map(function (s) {
      return '<span class="san-tag">' + esc(s) + '</span>';
    }).join('');

    certInfo.innerHTML = [
      row('Subject',    esc(data.subject    || '—')),
      row('SANs',       '<div class="san-list">' + (sanHtml || '—') + '</div>'),
      row('Key',        'RSA ' + (data.key_bits || '—') + ' bit'),
      row('Issuer',     esc(data.issuer     || '—')),
      row('Not Before', esc(data.not_before || '—')),
      row('Not After',  esc(data.not_after  || '—')),
      row('Serial',     esc(data.serial     || '—')),
    ].join('');

    resultCard.hidden = false;
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function row(key, val) {
    return '<span class="ci-key">' + key + '</span><span class="ci-val">' + val + '</span>';
  }

  // ── Copy / Download ──────────────────────────────────────────────────────────
  document.getElementById('btnCopy').addEventListener('click', function () {
    if (!pemOutput.value) return;
    navigator.clipboard.writeText(pemOutput.value).then(function () {
      var btn = document.getElementById('btnCopy');
      btn.textContent = 'Copied!';
      setTimeout(function () { btn.textContent = 'Copy PEM'; }, 1800);
    });
  });

  document.getElementById('btnDl').addEventListener('click', function () {
    if (!pemOutput.value) return;
    var blob = new Blob([pemOutput.value], { type: 'application/x-x509-ca-cert' });
    var url  = URL.createObjectURL(blob);
    var a    = Object.assign(document.createElement('a'), {
      href: url,
      download: 'meerkat-test-cert-' + Date.now() + '.crt'
    });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  // ── Utilities ────────────────────────────────────────────────────────────────
  function setLoading(on) {
    btnIssue.disabled = on;
    btnIssue.textContent = on ? 'Issuing…' : 'Issue Certificate';
    spinner.hidden = !on;
  }

  function showError(msg) {
    errorMsg.textContent = msg;
    errorBox.hidden = false;
  }

  function hideError() {
    errorBox.hidden = true;
  }

  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

}());
</script>
</body>
</html>
