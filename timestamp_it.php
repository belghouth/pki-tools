<?php
// ── Meerkat TimeStampIt ────────────────────────────────────────────────────────
// Paste a hash digest → sign with Meerkat TSA → download .tsr
//
// Reuses ARTIFACT_PARSER infrastructure (x509parse + mod_tsr) for inline rendering.

define('ARTIFACT_PARSER', true);

require_once __DIR__ . '/config.php';
$x509parse_invoked = true;
require_once __DIR__ . '/x509parse.php';
require_once __DIR__ . '/modules/_base.php';
require_once __DIR__ . '/modules/mod_tsr.php';
require_once __DIR__ . '/recaptcha.php';

define('TIT_SIGN_DIR', MPCA_CA_DIR . '/tsa_sign');
define('TIT_TSA_CNF',  TIT_SIGN_DIR . '/tsa.cnf');
define('TIT_TSA_CERT', TIT_SIGN_DIR . '/tsa_signing.crt');

$error         = null;
$tsr_b64       = null;
$dl_name       = 'timestamp.tsr';
$rendered      = null;
$ts_label      = null;
$hash_detected = null;
$hash_input    = '';

// ── Helpers ───────────────────────────────────────────────────────────────────

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

/**
 * Normalize a user-supplied hash string to canonical lowercase hex.
 *
 * Accepts:
 *   • hex — upper or lowercase, optionally separated by spaces / colons / dashes
 *   • base64 — standard (+/) or URL-safe (-_), with or without padding
 *
 * Hash sizes accepted: 32 bytes (SHA-256), 48 bytes (SHA-384), 64 bytes (SHA-512).
 *
 * Returns ['hex' => string, 'alg' => string, 'bits' => int]
 *      or ['error' => string]
 */
function tit_normalize_hash(string $input): array {
    $clean = preg_replace('/[\s:\-]+/', '', $input);
    if ($clean === '') {
        return ['error' => 'No hash provided.'];
    }

    // ── Try hex first (only 0-9 a-f A-F) ────────────────────────────────────────
    if (preg_match('/^[0-9a-fA-F]+$/', $clean)) {
        $hex = strtolower($clean);
        return match (strlen($hex)) {
            64  => ['hex' => $hex, 'alg' => 'sha256', 'bits' => 256],
            96  => ['hex' => $hex, 'alg' => 'sha384', 'bits' => 384],
            128 => ['hex' => $hex, 'alg' => 'sha512', 'bits' => 512],
            default => ['error' => sprintf(
                'Hex string is %d bytes — expected 32 (SHA-256), 48 (SHA-384), or 64 (SHA-512).',
                intdiv(strlen($hex), 2)
            )],
        };
    }

    // ── Try base64 (URL-safe → standard, pad to multiple of 4) ─────────────────
    $b64     = str_replace(['-', '_'], ['+', '/'], $clean);
    $b64     = $b64 . str_repeat('=', (4 - strlen($b64) % 4) % 4);
    $decoded = base64_decode($b64, true);

    if ($decoded !== false && $decoded !== '') {
        $bytes = strlen($decoded);
        return match ($bytes) {
            32 => ['hex' => bin2hex($decoded), 'alg' => 'sha256', 'bits' => 256],
            48 => ['hex' => bin2hex($decoded), 'alg' => 'sha384', 'bits' => 384],
            64 => ['hex' => bin2hex($decoded), 'alg' => 'sha512', 'bits' => 512],
            default => ['error' => sprintf(
                'Base64 decodes to %d bytes — expected 32 (SHA-256), 48 (SHA-384), or 64 (SHA-512).',
                $bytes
            )],
        };
    }

    return ['error' => 'Could not parse the hash — expected hex or base64 (SHA-256, SHA-384, or SHA-512).'];
}

// ── Process submission ────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'timestamp_it')) {
            $error = 'reCAPTCHA verification failed. Please try again.';
        }
    }

    $hash_input = trim($_POST['tit_hash'] ?? '');

    if ($error === null) {
        if ($hash_input === '') {
            $error = 'No hash provided — paste a SHA-256, SHA-384, or SHA-512 digest.';
        } else {
            $hash_info = tit_normalize_hash($hash_input);
            if (isset($hash_info['error'])) {
                $error = $hash_info['error'];
            }
        }
    }

    if ($error === null && (!file_exists(TIT_TSA_CNF) || !file_exists(TIT_TSA_CERT))) {
        $error = 'TSA not initialized on this server. Run <code>scripts/mpca_init.sh</code> first.';
    }

    if ($error === null && isset($hash_info) && !isset($hash_info['error'])) {
        $hash_detected = 'SHA-' . $hash_info['bits'];
        $tmpTsq = tempnam(sys_get_temp_dir(), 'tit_q_');
        $tmpTsr = tempnam(sys_get_temp_dir(), 'tit_r_');
        try {
            $r = tit_run([OPENSSL_BIN, 'ts', '-query',
                '-digest', $hash_info['hex'],
                '-' . $hash_info['alg'],
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
                        $dl_name  = 'timestamp_' . substr($hash_info['hex'], 0, 12) . '_' . date('Ymd_His') . '.tsr';
                        $mod      = new TsrModule();
                        $parsed   = $mod->parse($tsrBytes);
                        $rendered = $mod->render($parsed);
                        $ts_label = $parsed['timestamp'] ?? null;
                    }
                }
            }
        } finally {
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
    'description' => 'Paste a SHA-256, SHA-384, or SHA-512 hash digest to receive a cryptographically signed RFC 3161 timestamp token from the Meerkat TSA. Download the .tsr and inspect the response inline.',
    'url'         => SITE_BASE_URL . '/timestamp_it.php',
    'jsonld'      => json_encode([
      '@context'            => 'https://schema.org',
      '@type'               => 'WebApplication',
      'name'                => 'Meerkat TimeStampIt',
      'url'                 => SITE_BASE_URL . '/timestamp_it.php',
      'description'         => 'RFC 3161 timestamp tool. Paste a hash digest, get a signed TimeStampResp from the Meerkat TSA, download the .tsr token.',
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
      --danger: #e05c5c; --amber: #f59e0b;
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

    /* ── Hash input area ── */
    .tit-hash-wrap { padding: 1.2rem 1.4rem; }
    .tit-hash-input {
      width: 100%; resize: vertical; min-height: 80px;
      background: rgba(0,0,0,.25); border: 1px solid var(--border); border-radius: var(--radius);
      color: #a8c0e8; font-family: var(--mono); font-size: .78rem; line-height: 1.7;
      padding: .75rem 1rem; outline: none; transition: border-color .15s;
      word-break: break-all;
    }
    .tit-hash-input:focus { border-color: var(--amber); }
    .tit-hash-input::placeholder { color: #3a4a5e; }
    .tit-detect-row { display: flex; align-items: center; justify-content: space-between; margin-top: .5rem; min-height: 1.4rem; }
    .tit-detect { font-family: var(--mono); font-size: .68rem; }
    .tit-detect.detected { color: var(--amber); }
    .tit-detect.invalid  { color: var(--danger); }
    .tit-detect.empty    { color: #3a4a5e; }
    .tit-hint { font-size: .72rem; color: var(--muted); }

    /* ── Submit bar ── */
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

    @media (max-width: 600px) {
      .tit-page { padding: 2rem 1rem 4rem; }
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
    <p>Paste a SHA-256, SHA-384, or SHA-512 hash digest to receive a cryptographically signed RFC 3161 timestamp token. Download the <code>.tsr</code> and inspect the response inline.</p>
  </div>

  <div class="tit-sec-note">
    <span class="icon">🔒</span>
    <span>
      The hash you provide becomes the <code>messageImprint</code> in the TSQ — your original content never leaves your machine.
      The issued token is signed by the <a href="/tsa_doc.php">Meerkat Testing TSA</a> (not a qualified or accredited TSA — for testing only).
    </span>
  </div>

  <?php if ($error): ?>
  <div class="tit-error">
    <div class="err-label">Error</div>
    <p><?= $error ?></p>
  </div>
  <?php endif; ?>

  <form method="post" id="titForm">

    <div class="tit-form">

      <div class="tit-hash-wrap">
        <textarea class="tit-hash-input" name="tit_hash" id="titHash" rows="3"
                  placeholder="SHA-256 / SHA-384 / SHA-512 — hex or base64, spaces and colons OK"
                  spellcheck="false" autocomplete="off"><?= htmlspecialchars($hash_input, ENT_NOQUOTES) ?></textarea>
        <div class="tit-detect-row">
          <span class="tit-detect empty" id="titDetect">—</span>
          <span class="tit-hint">hex · BASE64 · with spaces · uppercase — all accepted</span>
        </div>
      </div>

      <input type="hidden" name="g_recaptcha_token" id="tit_recaptcha_token">
      <div class="tit-submit">
        <button type="button" class="tit-btn-clear" id="titClear">Clear</button>
        <button type="button" class="tit-btn" id="titSubmitBtn" onclick="doTimestamp()">Timestamp →</button>
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
          <?= htmlspecialchars($hash_detected) ?> &nbsp;·&nbsp;
          Meerkat TSA &nbsp;·&nbsp;
          <?= htmlspecialchars($dl_name) ?>
        </div>
      </div>
    </div>
    <a href="data:application/timestamp-reply;base64,<?= htmlspecialchars($tsr_b64, ENT_QUOTES) ?>"
       download="<?= htmlspecialchars($dl_name, ENT_QUOTES) ?>"
       class="tit-btn-dl">⬇ Download .tsr</a>
  </div>

  <!-- Base64 token -->
  <div class="tit-b64-card">
    <div class="tit-b64-header">
      <span class="tit-b64-label">Base64 Token</span>
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
  var token = await getRecaptchaToken('timestamp_it');
  document.getElementById('tit_recaptcha_token').value = token;
  document.getElementById('titForm').submit();
}

(function () {

  // ── Real-time algorithm detection ─────────────────────────────────────────────
  var hashEl   = document.getElementById('titHash');
  var detectEl = document.getElementById('titDetect');

  function detectAlgo(raw) {
    var s = raw.replace(/[\s:\-]/g, '');
    if (!s) return null;

    // Hex: only 0-9 a-f A-F
    if (/^[0-9a-fA-F]+$/.test(s)) {
      if (s.length === 64)  return { label: 'SHA-256 (hex)', ok: true };
      if (s.length === 96)  return { label: 'SHA-384 (hex)', ok: true };
      if (s.length === 128) return { label: 'SHA-512 (hex)', ok: true };
      return { label: 'hex — wrong length (' + Math.floor(s.length / 2) + ' bytes)', ok: false };
    }

    // Base64: noPad length determines algorithm
    // SHA-256: 32 bytes → 43 noPad chars (1 padding)
    // SHA-384: 48 bytes → 64 noPad chars (no padding)
    // SHA-512: 64 bytes → 86 noPad chars (2 padding)
    if (/^[A-Za-z0-9+/\-_=]+$/.test(s)) {
      var noPad = s.replace(/=/g, '');
      if (noPad.length === 43 || noPad.length === 44) return { label: 'SHA-256 (base64)', ok: true };
      if (noPad.length === 64)                        return { label: 'SHA-384 (base64)', ok: true };
      if (noPad.length === 86 || noPad.length === 88) return { label: 'SHA-512 (base64)', ok: true };
      return { label: 'base64 — wrong length', ok: false };
    }

    return { label: 'unrecognised format', ok: false };
  }

  function updateDetect() {
    var val = hashEl.value.trim();
    if (!val) {
      detectEl.textContent = '—';
      detectEl.className   = 'tit-detect empty';
      return;
    }
    var r = detectAlgo(val);
    if (!r) {
      detectEl.textContent = '—';
      detectEl.className   = 'tit-detect empty';
    } else if (r.ok) {
      detectEl.textContent = '✓ ' + r.label;
      detectEl.className   = 'tit-detect detected';
    } else {
      detectEl.textContent = '✗ ' + r.label;
      detectEl.className   = 'tit-detect invalid';
    }
  }

  hashEl.addEventListener('input',  updateDetect);
  hashEl.addEventListener('paste',  function () { setTimeout(updateDetect, 0); });
  updateDetect();

  // ── Clear ─────────────────────────────────────────────────────────────────────
  document.getElementById('titClear').addEventListener('click', function () {
    hashEl.value = '';
    updateDetect();
    hashEl.focus();
  });

  // ── Base64 copy ───────────────────────────────────────────────────────────────
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
