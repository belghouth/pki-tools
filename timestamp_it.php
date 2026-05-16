<?php
// ── Meerkat TimeStampIt ────────────────────────────────────────────────────────
// Upload or paste content → hash → sign with Meerkat TSA → download .tsr
//
// Reuses ARTIFACT_PARSER infrastructure (x509parse + mod_tsr) for inline rendering.

define('ARTIFACT_PARSER', true);

require_once __DIR__ . '/config.php';
$x509parse_invoked = true;
require_once __DIR__ . '/x509parse.php';
require_once __DIR__ . '/modules/_base.php';
require_once __DIR__ . '/modules/mod_tsr.php';
require_once __DIR__ . '/recaptcha.php';

define('TIT_SIGN_DIR',  MPCA_CA_DIR . '/tsa_sign');
define('TIT_TSA_CNF',   TIT_SIGN_DIR . '/tsa.cnf');
define('TIT_TSA_CERT',  TIT_SIGN_DIR . '/tsa_signing.crt');
define('TIT_MAX_PASTE', 65536);         // 64 KB — pasted text
define('TIT_MAX_FILE',  10 * 1048576);  // 10 MB — file upload

$algo_opts = ['sha256' => 'SHA-256', 'sha384' => 'SHA-384', 'sha512' => 'SHA-512'];
$hash_alg  = 'sha256';

$error    = null;
$tsr_b64  = null;
$dl_name  = 'timestamp.tsr';
$rendered = null;
$ts_label = null;
$src_name = null;

// ── Process submission ────────────────────────────────────────────────────────

function tit_run(array $cmd): array {
    $spec = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $p    = proc_open($cmd, $spec, $pipes);
    if (!$p) return ['ok' => false, 'out' => '', 'err' => 'proc_open failed'];
    $out  = stream_get_contents($pipes[1]);
    $err  = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($p);
    return ['ok' => $code === 0, 'out' => (string) $out, 'err' => (string) $err];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'timestamp_it')) {
            $error = 'reCAPTCHA verification failed. Please try again.';
        }
    }

    $alg      = $_POST['hash_alg'] ?? 'sha256';
    $hash_alg = array_key_exists($alg, $algo_opts) ? $alg : 'sha256';

    $content = null;

    if ($error === null) {
        $up = $_FILES['tit_file'] ?? null;
        if ($up && ($up['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
            if ($up['error'] !== UPLOAD_ERR_OK) {
                $error = match ((int) $up['error']) {
                    UPLOAD_ERR_INI_SIZE,
                    UPLOAD_ERR_FORM_SIZE => 'File exceeds the server upload limit.',
                    UPLOAD_ERR_PARTIAL   => 'File was only partially uploaded.',
                    default              => 'Upload error (code ' . $up['error'] . ').',
                };
                @unlink($up['tmp_name'] ?? '');
            } elseif ($up['size'] > TIT_MAX_FILE) {
                $mb    = round($up['size'] / 1048576, 1);
                $error = "File is too large ({$mb} MB). Maximum is 10 MB.";
                @unlink($up['tmp_name']);
            } else {
                $content  = @file_get_contents($up['tmp_name']);
                $src_name = basename($up['name']);
                @unlink($up['tmp_name']);
                if ($content === false || $content === '') {
                    $error = 'Uploaded file is empty or could not be read.';
                }
            }
        } elseif (isset($_POST['tit_text']) && $_POST['tit_text'] !== '') {
            $text = $_POST['tit_text'];
            if (strlen($text) > TIT_MAX_PASTE) {
                $kb    = round(strlen($text) / 1024, 1);
                $error = "Pasted text is too large ({$kb} KB). Maximum is 64 KB.";
            } else {
                $content  = $text;
                $src_name = 'text';
            }
        } else {
            $error = 'No input provided — paste text or upload a file.';
        }
    }

    if ($error === null && (!file_exists(TIT_TSA_CNF) || !file_exists(TIT_TSA_CERT))) {
        $error = 'TSA not initialized on this server. Run <code>scripts/mpca_init.sh</code> first.';
    }

    if ($error === null && $content !== null) {
        $tmpData = tempnam(sys_get_temp_dir(), 'tit_d_');
        $tmpTsq  = tempnam(sys_get_temp_dir(), 'tit_q_');
        $tmpTsr  = tempnam(sys_get_temp_dir(), 'tit_r_');
        try {
            file_put_contents($tmpData, $content);

            $r = tit_run([OPENSSL_BIN, 'ts', '-query',
                '-data', $tmpData,
                '-' . $hash_alg,
                '-cert',
                '-out', $tmpTsq,
            ]);

            if (!$r['ok']) {
                $error = 'Timestamp request generation failed: ' . trim($r['err']);
            } else {
                $r2 = tit_run([OPENSSL_BIN, 'ts', '-reply',
                    '-config',    TIT_TSA_CNF,
                    '-queryfile', $tmpTsq,
                    '-out',       $tmpTsr,
                ]);

                if (!$r2['ok']) {
                    $error = 'TSA signing failed: ' . trim($r2['err']);
                } else {
                    $tsrBytes = (string) file_get_contents($tmpTsr);
                    if ($tsrBytes === '') {
                        $error = 'TSA produced an empty response.';
                    } else {
                        $tsr_b64  = base64_encode($tsrBytes);
                        $stem     = $src_name ? pathinfo($src_name, PATHINFO_FILENAME) : 'content';
                        $dl_name  = $stem . '_' . date('Ymd_His') . '.tsr';
                        $mod      = new TsrModule();
                        $parsed   = $mod->parse($tsrBytes);
                        $rendered = $mod->render($parsed);
                        $ts_label = $parsed['timestamp'] ?? null;
                    }
                }
            }
        } finally {
            @unlink($tmpData);
            @unlink($tmpTsq);
            @unlink($tmpTsr);
        }
    }
}

$navLabel = 'Meerkat — TimeStampIt';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'Meerkat TimeStampIt — RFC 3161 Timestamp Tool | ' . SITE_DOMAIN,
    'description' => 'Cryptographically timestamp any file or text using the Meerkat RFC 3161 TSA. Upload or paste content, download the signed .tsr token, and inspect the timestamp response inline.',
    'url'         => SITE_BASE_URL . '/timestamp_it.php',
    'jsonld'      => json_encode([
      '@context'            => 'https://schema.org',
      '@type'               => 'WebApplication',
      'name'                => 'Meerkat TimeStampIt',
      'url'                 => SITE_BASE_URL . '/timestamp_it.php',
      'description'         => 'RFC 3161 timestamp tool. Upload or paste content, get a signed TimeStampResp from the Meerkat TSA, download the .tsr token.',
      'applicationCategory' => 'SecurityApplication',
      'operatingSystem'     => 'Any',
      'isAccessibleForFree' => true,
      'author'              => ['@id' => SITE_BASE_URL . '/#person', 'name' => 'Thameur Belghith'],
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
  ]);
  ?>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
  <?php require __DIR__ . '/includes/adsense_head.php'; ?>
  <?php if (recaptcha_configured()): ?>
  <?= recaptcha_head() ?>
  <?php endif; ?>
  <style>
    :root {
      --bg: #0e1014; --surface: #13171e; --border: #2a3040;
      --accent: #00d4aa; --text: #d4dae6; --muted: #6b7a90;
      --danger: #e05c5c; --warn: #f5a623; --amber: #f59e0b;
      --sans: 'IBM Plex Sans', sans-serif; --mono: 'IBM Plex Mono', monospace;
      --radius: 8px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }
    code { font-family: var(--mono); font-size: .82em; background: rgba(255,255,255,.05); padding: .1em .4em; border-radius: 3px; }

    .tit-page { max-width: 860px; margin: 0 auto; padding: 3rem 2rem 6rem; }

    /* ── Header ── */
    .tit-header { margin-bottom: 2rem; }
    .tit-header h1 { font-size: 1.9rem; font-weight: 600; color: #fff; display: flex; align-items: center; gap: .6rem; }
    .tit-header p  { font-size: .88rem; color: var(--muted); margin-top: .3rem; max-width: 640px; }

    /* ── Security notice ── */
    .tit-sec-note {
      display: flex; gap: .75rem; align-items: flex-start;
      background: rgba(0,212,170,.05); border: 1px solid rgba(0,212,170,.15);
      border-radius: var(--radius); padding: .75rem 1rem; margin-bottom: 1.5rem;
      font-size: .8rem; color: var(--muted);
    }
    .tit-sec-note .icon { flex-shrink: 0; color: var(--accent); }

    /* ── Form card ── */
    .tit-form { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; margin-bottom: 1.5rem; }

    /* Algorithm row */
    .tit-algo-row {
      display: flex; align-items: center; gap: 1rem;
      padding: .8rem 1.4rem; border-bottom: 1px solid var(--border);
      background: rgba(0,0,0,.1);
    }
    .tit-algo-row label { font-family: var(--mono); font-size: .7rem; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); white-space: nowrap; }
    .tit-algo-select {
      font-family: var(--mono); font-size: .76rem; color: var(--text);
      background: rgba(0,0,0,.3); border: 1px solid var(--border); border-radius: 4px;
      padding: .3em .7em; outline: none; cursor: pointer;
    }
    .tit-algo-select:focus { border-color: var(--amber); }

    /* Tabs */
    .tit-tabs { display: flex; border-bottom: 1px solid var(--border); }
    .tit-tab {
      flex: 1; padding: .7rem 1rem; font-family: var(--mono); font-size: .72rem; text-transform: uppercase;
      letter-spacing: .07em; color: var(--muted); background: none; border: none; cursor: pointer;
      border-bottom: 2px solid transparent; transition: all .15s;
    }
    .tit-tab:hover { color: var(--text); }
    .tit-tab.active { color: var(--amber); border-bottom-color: var(--amber); background: rgba(245,158,11,.04); }

    .tit-panel { padding: 1.2rem 1.4rem; }
    .tit-panel[hidden] { display: none; }

    /* Textarea */
    .tit-textarea {
      width: 100%; min-height: 160px; resize: vertical;
      background: rgba(0,0,0,.25); border: 1px solid var(--border); border-radius: var(--radius);
      color: #a8c0e8; font-family: var(--mono); font-size: .72rem; line-height: 1.6;
      padding: .75rem; outline: none; transition: border-color .15s;
    }
    .tit-textarea:focus { border-color: var(--amber); }
    .tit-textarea::placeholder { color: #3a4a5e; }
    .tit-limit-note { font-size: .7rem; color: var(--muted); margin-top: .4rem; }

    /* Drop zone */
    .tit-drop {
      border: 2px dashed var(--border); border-radius: var(--radius);
      padding: 2.5rem 1.5rem; text-align: center; cursor: pointer;
      transition: border-color .15s, background .15s; position: relative;
    }
    .tit-drop.dragover { border-color: var(--amber); background: rgba(245,158,11,.04); }
    .tit-drop input[type="file"] { position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%; }
    .tit-drop .dz-icon { font-size: 2rem; margin-bottom: .5rem; }
    .tit-drop p { font-size: .82rem; color: var(--muted); margin: 0; }
    .tit-drop .dz-hint { font-family: var(--mono); font-size: .65rem; color: #3d4f68; margin-top: .4rem; }
    .tit-drop .dz-sel  { font-family: var(--mono); font-size: .78rem; color: var(--amber); margin-top: .5rem; }

    /* Submit bar */
    .tit-submit {
      display: flex; justify-content: flex-end; align-items: center; gap: .75rem;
      padding: .9rem 1.4rem; border-top: 1px solid var(--border); background: rgba(0,0,0,.1);
    }
    .tit-btn {
      font-family: var(--mono); font-size: .75rem; text-transform: uppercase; letter-spacing: .08em;
      background: var(--amber); color: #0e1014; border: none; border-radius: var(--radius);
      padding: .55em 1.7em; cursor: pointer; font-weight: 600; transition: opacity .15s;
    }
    .tit-btn:hover { opacity: .85; }
    .tit-btn-clear {
      background: none; color: var(--muted); border: 1px solid var(--border);
      font-family: var(--mono); font-size: .72rem; letter-spacing: .06em; text-transform: uppercase;
      border-radius: var(--radius); padding: .5em 1em; cursor: pointer; transition: color .15s;
    }
    .tit-btn-clear:hover { color: var(--text); }

    /* ── Error ── */
    .tit-error {
      border: 1px solid rgba(224,92,92,.3); border-left: 3px solid var(--danger);
      background: rgba(224,92,92,.07); border-radius: var(--radius);
      padding: .9rem 1.1rem; margin-bottom: 1.5rem;
    }
    .tit-error .err-label { font-family: var(--mono); font-size: .63rem; text-transform: uppercase; letter-spacing: .1em; color: var(--danger); margin-bottom: .3rem; }
    .tit-error p { font-size: .85rem; color: #e8a0a0; margin: 0; }

    /* ── Success banner ── */
    .tit-success {
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      background: rgba(245,158,11,.07); border: 1px solid rgba(245,158,11,.25);
      border-left: 3px solid var(--amber);
      border-radius: var(--radius); padding: 1rem 1.3rem; margin-bottom: 1.5rem;
      animation: fadein .3s ease;
    }
    @keyframes fadein { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
    .tit-success-left { display: flex; align-items: center; gap: .75rem; }
    .tit-success-eyebrow { font-family: var(--mono); font-size: .6rem; text-transform: uppercase; letter-spacing: .12em; color: var(--amber); margin-bottom: .1rem; }
    .tit-success-title  { font-size: 1rem; font-weight: 600; color: #fff; }
    .tit-success-sub    { font-family: var(--mono); font-size: .7rem; color: var(--muted); margin-top: .1rem; }
    .tit-btn-dl {
      display: inline-flex; align-items: center; gap: .4rem;
      font-family: var(--mono); font-size: .72rem; font-weight: 600; text-transform: uppercase; letter-spacing: .07em;
      background: var(--amber); color: #0e1014; border-radius: var(--radius);
      padding: .5em 1.2em; text-decoration: none; transition: opacity .15s; white-space: nowrap;
    }
    .tit-btn-dl:hover { opacity: .85; color: #0e1014; }

    /* ── xp-* styles (shared renderer output) ── */
    .xp-wrap { font-family: 'IBM Plex Mono',monospace; font-size: .72rem; display: flex; flex-direction: column; gap: 1rem; animation: fadein .35s ease; }
    .xp-section { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
    .xp-section-header { padding: .6rem 1rem; border-bottom: 1px solid var(--border); border-left: 3px solid; background: rgba(255,255,255,.02); display: flex; align-items: center; gap: .75rem; }
    .xp-section-label { font-size: .65rem; font-weight: 600; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); }
    .xp-section-body { padding: .75rem 1rem; display: flex; flex-direction: column; gap: .3rem; }
    .xp-code { font-family: 'IBM Plex Mono',monospace; font-size: .68rem; color: #a8c0e8; word-break: break-all; }
    .xp-muted { color: var(--muted); font-style: italic; }
    .xp-badge { display: inline-flex; align-items: center; font-size: .58rem; font-weight: 700; letter-spacing: .09em; padding: .12em .5em; border-radius: 2px; white-space: nowrap; }
    .xp-badge-neutral { background: rgba(107,122,144,.15); color: #8899aa; border: 1px solid rgba(107,122,144,.25); }
    .xp-badge-info    { background: rgba(0,153,255,.12);   color: #4db8ff; border: 1px solid rgba(0,153,255,.25); }
    .xp-badge-good    { background: rgba(0,212,100,.1);    color: #3ddc7a; border: 1px solid rgba(0,212,100,.25); }
    .xp-badge-warn    { background: rgba(245,166,35,.1);   color: #f5a623; border: 1px solid rgba(245,166,35,.25); }
    .xp-badge-danger  { background: rgba(224,92,92,.12);   color: #e05c5c; border: 1px solid rgba(224,92,92,.25); }
    .xp-fp { font-family: 'IBM Plex Mono',monospace; font-size: .65rem; color: #8899aa; word-break: break-all; letter-spacing: .03em; }
    .xp-row { display: flex; align-items: baseline; gap: .75rem; padding: .2rem 0; border-bottom: 1px solid rgba(42,48,64,.5); flex-wrap: wrap; }
    .xp-row:last-child { border-bottom: none; }
    .xp-label { flex-shrink: 0; width: 8rem; color: var(--muted); font-size: .68rem; }
    .xp-value { color: var(--text); flex: 1; min-width: 0; word-break: break-word; overflow-wrap: anywhere; line-height: 1.6; }

    /* ── Footer ── */
    .site-footer { border-top: 1px solid var(--border); padding: 1.4rem 2rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; font-family: var(--mono); font-size: .72rem; color: var(--muted); }
    .site-footer a { color: var(--muted); }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }

    /* ── Base64 block ── */
    .tit-b64-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; margin-bottom: 1.5rem; }
    .tit-b64-header { display: flex; align-items: center; justify-content: space-between; padding: .55rem 1rem; border-bottom: 1px solid var(--border); background: rgba(0,0,0,.1); }
    .tit-b64-label { font-family: var(--mono); font-size: .63rem; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); }
    .tit-b64-label a { color: var(--amber); text-decoration: none; }
    .tit-b64-label a:hover { color: #fff; }
    .tit-b64-copy { font-family: var(--mono); font-size: .68rem; color: var(--amber); background: none; border: 1px solid rgba(245,158,11,.3); border-radius: 3px; padding: .2em .75em; cursor: pointer; transition: background .15s, color .15s, border-color .15s; }
    .tit-b64-copy:hover { background: rgba(245,158,11,.08); }
    .tit-b64-copy.copied { color: #3ddc7a; border-color: rgba(0,212,100,.3); }
    .tit-b64-textarea { display: block; width: 100%; background: rgba(0,0,0,.2); border: none; color: #8899aa; font-family: var(--mono); font-size: .63rem; line-height: 1.7; padding: .75rem 1rem; resize: none; outline: none; }

    @media (max-width: 600px) {
      .tit-page { padding: 2rem 1rem 4rem; }
      .tit-algo-row { flex-wrap: wrap; }
      .tit-success { flex-direction: column; align-items: flex-start; }
      .xp-label { width: 100%; }
      .xp-value { width: 100%; flex: none; }
      .xp-row { flex-direction: column; gap: .15rem; }
    }
  </style>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<main class="tit-page">

  <div class="tit-header">
    <h1>🕰️ Meerkat TimeStampIt</h1>
    <p>Upload any file or paste text to receive a cryptographically signed RFC 3161 timestamp token. Download the <code>.tsr</code> and inspect the response inline.</p>
  </div>

  <div class="tit-sec-note">
    <span class="icon">🔒</span>
    <span>
      Your content is hashed server-side using the selected algorithm.
      Only the hash — never the raw content — reaches the TSA signing key.
      Temporary files are deleted immediately after timestamping and are never stored or logged.
      The issued token is signed by the <a href="/tsa_doc.php">Meerkat Testing TSA</a> (not a qualified or accredited TSA — for testing only).
    </span>
  </div>

  <?php if ($error): ?>
  <div class="tit-error">
    <div class="err-label">Error</div>
    <p><?= $error ?></p>
  </div>
  <?php endif; ?>

  <form method="post" enctype="multipart/form-data" id="titForm">

    <div class="tit-form">

      <!-- Algorithm selector -->
      <div class="tit-algo-row">
        <label for="titAlgo">Hash Algorithm</label>
        <select name="hash_alg" id="titAlgo" class="tit-algo-select">
          <?php foreach ($algo_opts as $val => $label): ?>
          <option value="<?= $val ?>"<?= $hash_alg === $val ? ' selected' : '' ?>><?= $label ?></option>
          <?php endforeach; ?>
        </select>
        <span style="font-size:.72rem;color:var(--muted)">SHA-256 recommended for most use cases</span>
      </div>

      <!-- Tabs -->
      <div class="tit-tabs" role="tablist">
        <button type="button" class="tit-tab active" id="tab-paste"  role="tab" aria-controls="panel-paste"  aria-selected="true">Paste Text</button>
        <button type="button" class="tit-tab"        id="tab-upload" role="tab" aria-controls="panel-upload" aria-selected="false">Upload File</button>
      </div>

      <!-- Paste panel -->
      <div class="tit-panel" id="panel-paste" role="tabpanel">
        <textarea class="tit-textarea" name="tit_text" id="titText"
                  placeholder="Paste any text content to timestamp…"
                  spellcheck="false" autocomplete="off"></textarea>
        <p class="tit-limit-note">Maximum 64 KB · any plain text, source code, JSON, XML…</p>
      </div>

      <!-- Upload panel -->
      <div class="tit-panel" id="panel-upload" role="tabpanel" hidden>
        <div class="tit-drop" id="titDrop">
          <input type="file" name="tit_file" id="titFile">
          <div class="dz-icon">📂</div>
          <p>Drop any file here, or click to browse</p>
          <p class="dz-hint">PDF, DOCX, source files, binaries… · Max 10 MB</p>
          <p class="dz-sel" id="titSel" hidden></p>
        </div>
      </div>

      <input type="hidden" name="g_recaptcha_token" id="tit_recaptcha_token">
      <div class="tit-submit">
        <button type="reset" class="tit-btn-clear" id="titClear">Clear</button>
        <button type="button" class="tit-btn" onclick="doTimestamp()">Timestamp →</button>
      </div>

    </div><!-- .tit-form -->

  </form>

  <?php if ($tsr_b64): ?>

  <!-- Success banner -->
  <div class="tit-success">
    <div class="tit-success-left">
      <div>
        <div class="tit-success-eyebrow">Timestamp Issued</div>
        <div class="tit-success-title"><?= $ts_label ? htmlspecialchars($ts_label) : 'Token signed successfully' ?></div>
        <div class="tit-success-sub">
          <?= htmlspecialchars(strtoupper($hash_alg)) ?> &nbsp;·&nbsp;
          Meerkat TSA &nbsp;·&nbsp;
          <?= htmlspecialchars($dl_name) ?>
        </div>
      </div>
    </div>
    <a id="titDownloadLink"
       href="data:application/timestamp-reply;base64,<?= htmlspecialchars($tsr_b64, ENT_QUOTES) ?>"
       download="<?= htmlspecialchars($dl_name, ENT_QUOTES) ?>"
       class="tit-btn-dl">⬇ Download .tsr</a>
  </div>

  <!-- Base64 token -->
  <div class="tit-b64-card">
    <div class="tit-b64-header">
      <span class="tit-b64-label">Base64 Token &mdash; paste into <a href="/artifact_parser.php">Artifact Parser</a></span>
      <button type="button" class="tit-b64-copy" id="titCopyB64">Copy</button>
    </div>
    <textarea class="tit-b64-textarea" id="titB64" rows="6" readonly spellcheck="false"><?= htmlspecialchars(chunk_split($tsr_b64, 64, "\n"), ENT_NOQUOTES) ?></textarea>
  </div>

  <!-- Parsed TSR (mod_tsr.php renderer) -->
  <?= $rendered ?>

  <?php require __DIR__ . '/includes/adsense_unit.php'; ?>

  <?php endif; ?>

</main>

<footer class="site-footer">
  <span>&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="/">Home</a>
    <a href="/tsa_doc.php">TSA Reference</a>
    <a href="/artifact_parser.php">Artifact Parser</a>
    <a href="<?= 'mailto:' . CONTACT_EMAIL ?>"><?= CONTACT_EMAIL ?></a>
  </div>
</footer>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>

<script>
var RECAPTCHA_SITE_KEY = <?= json_encode(recaptcha_configured() ? RECAPTCHA_SITE_KEY : '') ?>;

function getRecaptchaToken(action) {
  return new Promise(function (resolve) {
    if (!RECAPTCHA_SITE_KEY) { resolve(''); return; }
    grecaptcha.ready(function () {
      grecaptcha.execute(RECAPTCHA_SITE_KEY, { action: action }).then(resolve);
    });
  });
}

async function doTimestamp() {
  var text   = document.getElementById('titText').value.trim();
  var file   = document.getElementById('titFile');
  if (!text && file && file.files.length) {
    document.getElementById('tab-upload').click();
  }
  var token = await getRecaptchaToken('timestamp_it');
  document.getElementById('tit_recaptcha_token').value = token;
  document.getElementById('titForm').submit();
}

(function () {
  // ── Tab switching ────────────────────────────────────────────────────────────
  var tabs = document.querySelectorAll('.tit-tab');
  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      tabs.forEach(function (t) {
        t.classList.remove('active');
        t.setAttribute('aria-selected', 'false');
        document.getElementById(t.getAttribute('aria-controls')).hidden = true;
      });
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      document.getElementById(tab.getAttribute('aria-controls')).hidden = false;
    });
  });

  // ── Drag and drop ────────────────────────────────────────────────────────────
  var dz   = document.getElementById('titDrop');
  var inp  = document.getElementById('titFile');
  var sel  = document.getElementById('titSel');
  var MAX  = <?= TIT_MAX_FILE ?>;

  function showFile(name) {
    sel.textContent = '📄 ' + name;
    sel.hidden = false;
  }

  function checkSize(f) {
    if (f.size > MAX) {
      alert('File is too large (' + (f.size / 1048576).toFixed(1) + ' MB). Maximum is 10 MB.');
      inp.value = '';
      return false;
    }
    return true;
  }

  inp.addEventListener('change', function () {
    if (inp.files.length && checkSize(inp.files[0])) showFile(inp.files[0].name);
  });
  dz.addEventListener('dragover',  function (e) { e.preventDefault(); dz.classList.add('dragover'); });
  dz.addEventListener('dragleave', function ()  { dz.classList.remove('dragover'); });
  dz.addEventListener('drop', function (e) {
    e.preventDefault();
    dz.classList.remove('dragover');
    var files = e.dataTransfer.files;
    if (files.length && checkSize(files[0])) {
      inp.files = files;
      showFile(files[0].name);
      document.getElementById('tab-upload').click();
    }
  });

  // ── Clear ────────────────────────────────────────────────────────────────────
  document.getElementById('titClear').addEventListener('click', function () {
    document.getElementById('titText').value = '';
    sel.hidden = true;
    inp.value  = '';
  });

  // ── Base64 copy ──────────────────────────────────────────────────────────────
  var copyBtn = document.getElementById('titCopyB64');
  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      var raw = document.getElementById('titB64').value.replace(/\n/g, '');
      navigator.clipboard.writeText(raw).then(function () {
        copyBtn.textContent = 'Copied!';
        copyBtn.classList.add('copied');
        setTimeout(function () {
          copyBtn.textContent = 'Copy';
          copyBtn.classList.remove('copied');
        }, 2000);
      });
    });
  }
}());
</script>
</body>
</html>
