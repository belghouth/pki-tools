<?php
// ── Bootstrap ─────────────────────────────────────────────────────────────────
define('ARTIFACT_PARSER', true);
$x509parse_invoked = true;

require_once __DIR__ . '/x509parse.php';
require_once __DIR__ . '/modules/_base.php';
foreach (glob(__DIR__ . '/modules/mod_*.php') as $_mod) require_once $_mod;
require_once __DIR__ . '/recaptcha.php';

$navLabel = 'Meerkat — Artifact Parser';

// ── Security constants ────────────────────────────────────────────────────────

const PRIVATE_KEY_MARKERS = [
    '-----BEGIN RSA PRIVATE KEY-----',
    '-----BEGIN PRIVATE KEY-----',
    '-----BEGIN ENCRYPTED PRIVATE KEY-----',
    '-----BEGIN EC PRIVATE KEY-----',
    '-----BEGIN DSA PRIVATE KEY-----',
    '-----BEGIN OPENSSH PRIVATE KEY-----',
    '-----BEGIN PGP PRIVATE KEY BLOCK-----',
];

const ALLOWED_EXTS = ['pem','crt','cer','csr','der','p7b','p7c','p7s','p7m','p10','req','tsr','tst','tsq','ocsp','crl'];
const BLOCKED_EXTS = ['key','p12','pfx','jks','keystore','pvk','ppk'];
const MAX_BYTES    = 51200; // 50 KB

// ── Process submission ────────────────────────────────────────────────────────

$result       = null;
$error        = null;
$privkey_warn = false;
$posted_pem   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'parse_artifact')) {
            $error = 'reCAPTCHA verification failed. Please try again.';
        }
    }

    $raw  = null;
    $fname = null;
    $ext  = 'pem';

    if ($error === null && !empty($_FILES['ap_file']['tmp_name']) && $_FILES['ap_file']['error'] !== UPLOAD_ERR_NO_FILE) {
        $up = $_FILES['ap_file'];
        if ($up['error'] !== UPLOAD_ERR_OK) {
            $error = 'Upload error (code ' . $up['error'] . ').';
        } elseif ($up['size'] > MAX_BYTES) {
            $error = 'File exceeds 50 KB limit.';
            @unlink($up['tmp_name']);
        } else {
            $fname = basename($up['name']);
            $ext   = strtolower(pathinfo($fname, PATHINFO_EXTENSION));

            if (in_array($ext, BLOCKED_EXTS, true)) {
                $privkey_warn = true;
                $error = 'Blocked: .' . htmlspecialchars($ext) . ' files may contain private key material and are never accepted. The upload was discarded immediately.';
                @unlink($up['tmp_name']);
            } elseif (!in_array($ext, ALLOWED_EXTS, true) && $ext !== '') {
                $error = 'Unsupported extension.' ;
                @unlink($up['tmp_name']);
            } else {
                $raw = @file_get_contents($up['tmp_name']);
                @unlink($up['tmp_name']);
            }
        }
    } elseif ($error === null && !empty($_POST['ap_pem'])) {
        $raw        = trim($_POST['ap_pem']);
        $posted_pem = $raw;
        $ext        = 'pem';
    }

    // ── Private key marker scan (PEM text) ────────────────────────────────────
    if ($raw !== null && $error === null) {
        foreach (PRIVATE_KEY_MARKERS as $marker) {
            if (str_contains((string)$raw, $marker)) {
                $privkey_warn = true;
                $raw   = null; // destroy immediately
                $error = 'SECURITY: Private key material detected in the submitted data. It has been discarded immediately and was never stored or logged. Do not submit private keys to any online tool.';
                break;
            }
        }
    }

    if ($raw !== null && $error === null) {
        if (strlen((string)$raw) > MAX_BYTES) {
            $error = 'Input exceeds 50 KB limit.';
        } elseif (strlen(trim((string)$raw)) === 0) {
            $error = 'No input provided.';
        } else {
            $t0 = microtime(true);

            // Normalize bare base64 (no PEM headers, not already DER) → DER bytes
            // so that module recognize() methods can match via artifact_is_der().
            // base64_decode strict mode rejects invalid chars; no regex needed.
            $bytes = (string) $raw;
            if (!str_contains($bytes, '-----BEGIN') && !artifact_is_der($bytes)) {
                $stripped = preg_replace('/\s+/', '', $bytes);
                if (strlen($stripped) > 16) {
                    $decoded = base64_decode($stripped, true);
                    if ($decoded !== false && strlen($decoded) > 2 && ord($decoded[0]) === 0x30) {
                        $bytes = $decoded;
                    }
                }
            }

            $module = ArtifactRegistry::match($bytes, $ext);

            if ($module === null) {
                $error = 'Artifact type not recognised. Supported types: X.509 certificate, CSR/PKCS#10, CRL, public key, CMS/PKCS#7, OCSP response, RFC 3161 timestamp request (TSQ), RFC 3161 timestamp response (TSR).';
            } else {
                try {
                    $parsed  = $module->parse($bytes);
                    $ms      = round((microtime(true) - $t0) * 1000);
                    $result  = [
                        'label'    => $module->label(),
                        'subtype'  => $module->subtype($parsed),
                        'rendered' => $module->render($parsed),
                        'ms'       => $ms,
                        'fname'    => $fname,
                        'n_mods'   => count(ArtifactRegistry::all()),
                        'pem'      => $parsed['pem'] ?? null,
                        'is_csr'   => str_contains($module->label(), 'CSR'),
                        'csr_san_types' => [],
                        'csr_has_org'   => false,
                    ];
                    // Detect SAN types and Subject O= for factory routing (temp file avoids heredoc injection)
                    if ($result['is_csr'] && $result['pem']) {
                        $csrTmp = tempnam(sys_get_temp_dir(), 'csr_');
                        if ($csrTmp !== false) {
                            file_put_contents($csrTmp, $result['pem']);
                            $csrText = (string) shell_exec(
                                OPENSSL_BIN . ' req -noout -text -in ' . escapeshellarg($csrTmp) . ' 2>/dev/null'
                            );
                            unlink($csrTmp);
                            if (preg_match('/Subject:([^\n]+)/i', $csrText, $sm)) {
                                $result['csr_has_org'] = (bool) preg_match('/\bO\s*=/', $sm[1]);
                            }
                            if (preg_match('/Subject Alternative Name:\s*\n\s*([^\n]+)/i', $csrText, $sn)) {
                                if (preg_match('/DNS:/i', $sn[1]))   $result['csr_san_types'][] = 'dns';
                                if (preg_match('/email:/i', $sn[1])) $result['csr_san_types'][] = 'email';
                            }
                        }
                    }
                } catch (Throwable $e) {
                    $error = 'Parse error: ' . htmlspecialchars($e->getMessage());
                }
            }
        }
    }
}
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'Meerkat Artifact Parser — Universal PKI Artifact Identifier | ' . SITE_DOMAIN,
    'description' => 'Identify and parse any PKI artifact instantly: X.509 certificates, CSRs, CRLs, public keys, CMS/PKCS#7, OCSP responses, and RFC 3161 timestamp tokens. Supports PEM and DER. Private keys rejected server-side.',
    'url'         => SITE_BASE_URL . '/artifact_parser.php',
    'jsonld'      => json_encode([
      '@context'            => 'https://schema.org',
      '@type'               => 'WebApplication',
      'name'                => 'Meerkat Artifact Parser',
      'url'                 => SITE_BASE_URL . '/artifact_parser.php',
      'description'         => 'Universal PKI artifact identifier and parser. Recognises X.509 certificates, CSRs, CRLs, public keys, CMS/PKCS#7, OCSP responses, and RFC 3161 timestamp tokens.',
      'applicationCategory' => 'SecurityApplication',
      'operatingSystem'     => 'Any',
      'isAccessibleForFree' => true,
      'author'              => ['@id' => SITE_BASE_URL . '/#person', 'name' => 'Thameur Belghith'],
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
  ]);
  ?>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">
  <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
  <?php require __DIR__ . '/includes/adsense_head.php'; ?>
  <?= recaptcha_head() ?>
  <style>
    :root {
      --bg: #0e1014; --surface: #13171e; --border: #2a3040;
      --accent: #00d4aa; --text: #d4dae6; --muted: #6b7a90;
      --danger: #e05c5c; --warn: #f5a623;
      --sans: 'IBM Plex Sans', sans-serif; --mono: 'IBM Plex Mono', monospace;
      --radius: 8px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }
    code { font-family: var(--mono); font-size: 0.82em; background: rgba(255,255,255,0.05); padding: .1em .4em; border-radius: 3px; }

    /* ── Layout ── */
    .ap-page { max-width: 900px; margin: 0 auto; padding: 3rem 2rem 6rem; }

    .ap-header { margin-bottom: 2rem; }
    .ap-header h1 { font-size: 2rem; font-weight: 600; color: #fff; display: flex; align-items: center; gap: .6rem; }
    .ap-header h1 img { width: 36px; height: 36px; object-fit: contain; filter: drop-shadow(0 0 6px rgba(0,212,170,.4)); }
    .ap-header p { font-size: .88rem; color: var(--muted); margin-top: .3rem; }

    /* ── Supported types pill row ── */
    .ap-types { display: flex; flex-wrap: wrap; gap: .4rem; margin-bottom: 1.8rem; }
    .ap-type-pill {
      font-family: var(--mono); font-size: .65rem; text-transform: uppercase; letter-spacing: .07em;
      padding: .2em .65em; border-radius: 3px;
      background: rgba(0,212,170,.07); color: var(--accent); border: 1px solid rgba(0,212,170,.18);
    }

    /* ── Private key warning ── */
    .ap-privkey-warning {
      display: flex; align-items: flex-start; gap: .75rem;
      background: rgba(224,92,92,.07); border: 1px solid rgba(224,92,92,.25);
      border-left: 3px solid var(--danger);
      border-radius: var(--radius); padding: .9rem 1.1rem; margin-bottom: 1.6rem;
    }
    .ap-privkey-warning .icon { font-size: 1.1rem; flex-shrink: 0; margin-top: .1rem; }
    .ap-privkey-warning p { font-size: .82rem; color: #e8a0a0; line-height: 1.55; margin: 0; }
    .ap-privkey-warning strong { color: var(--danger); font-weight: 600; }

    /* ── Input form ── */
    .ap-form { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; margin-bottom: 1.5rem; }

    .ap-tabs { display: flex; border-bottom: 1px solid var(--border); }
    .ap-tab {
      flex: 1; padding: .7rem 1rem; font-family: var(--mono); font-size: .72rem; text-transform: uppercase;
      letter-spacing: .07em; color: var(--muted); background: none; border: none; cursor: pointer;
      border-bottom: 2px solid transparent; transition: all .15s;
    }
    .ap-tab:hover { color: var(--text); }
    .ap-tab.active { color: var(--accent); border-bottom-color: var(--accent); background: rgba(0,212,170,.04); }

    .ap-panel { padding: 1.2rem 1.4rem; }
    .ap-panel[hidden] { display: none; }

    /* Drop zone */
    .ap-drop-zone {
      border: 2px dashed var(--border); border-radius: var(--radius);
      padding: 2.5rem 1.5rem; text-align: center; cursor: pointer;
      transition: border-color .15s, background .15s; position: relative;
    }
    .ap-drop-zone.dragover { border-color: var(--accent); background: rgba(0,212,170,.04); }
    .ap-drop-zone input[type="file"] { position: absolute; inset: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; }
    .ap-drop-zone .dz-icon { font-size: 2rem; margin-bottom: .5rem; }
    .ap-drop-zone p { font-size: .82rem; color: var(--muted); margin: 0; }
    .ap-drop-zone .dz-hint { font-family: var(--mono); font-size: .65rem; color: #3d4f68; margin-top: .4rem; }
    .ap-drop-zone .dz-selected { font-size: .78rem; color: var(--accent); margin-top: .5rem; font-family: var(--mono); }

    /* PEM textarea */
    .ap-pem-area {
      width: 100%; min-height: 180px; resize: vertical;
      background: rgba(0,0,0,.25); border: 1px solid var(--border); border-radius: var(--radius);
      color: #a8c0e8; font-family: var(--mono); font-size: .72rem; line-height: 1.55;
      padding: .75rem; outline: none; transition: border-color .15s;
    }
    .ap-pem-area:focus { border-color: var(--accent); }
    .ap-pem-area::placeholder { color: #3a4a5e; }

    /* Submit */
    .ap-submit {
      display: flex; justify-content: flex-end; padding: .9rem 1.4rem;
      border-top: 1px solid var(--border); background: rgba(0,0,0,.1);
      gap: .75rem; align-items: center;
    }
    .ap-btn {
      font-family: var(--mono); font-size: .75rem; text-transform: uppercase; letter-spacing: .08em;
      background: var(--accent); color: #0e1014; border: none; border-radius: var(--radius);
      padding: .55em 1.5em; cursor: pointer; font-weight: 600; transition: opacity .15s;
    }
    .ap-btn:hover { opacity: .85; }
    .ap-btn-clear {
      background: none; color: var(--muted); border: 1px solid var(--border);
      font-family: var(--mono); font-size: .72rem; letter-spacing: .06em; text-transform: uppercase;
      border-radius: var(--radius); padding: .5em 1em; cursor: pointer; transition: color .15s;
    }
    .ap-btn-clear:hover { color: var(--text); }

    /* ── Error box ── */
    .ap-error {
      border: 1px solid rgba(224,92,92,.3); border-left: 3px solid var(--danger);
      background: rgba(224,92,92,.07); border-radius: var(--radius);
      padding: .9rem 1.1rem; margin-bottom: 1.5rem;
    }
    .ap-error .err-title { font-family: var(--mono); font-size: .65rem; text-transform: uppercase; letter-spacing: .1em; color: var(--danger); margin-bottom: .3rem; }
    .ap-error p { font-size: .85rem; color: #e8a0a0; margin: 0; }

    /* ── Identified banner ── */
    .ap-identified {
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      background: rgba(0,212,170,.06); border: 1px solid rgba(0,212,170,.2);
      border-left: 3px solid var(--accent);
      border-radius: var(--radius); padding: 1rem 1.3rem; margin-bottom: 1.5rem;
      animation: fadein .3s ease;
    }
    @keyframes fadein { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
    .ap-id-left { display: flex; align-items: center; gap: .75rem; }
    .ap-id-eyebrow { font-family: var(--mono); font-size: .6rem; text-transform: uppercase; letter-spacing: .12em; color: var(--accent); margin-bottom: .1rem; }
    .ap-id-type { font-size: 1rem; font-weight: 600; color: #fff; }
    .ap-id-sub { font-family: var(--mono); font-size: .72rem; color: var(--accent); margin-top: .1rem; }
    .ap-id-meta { font-family: var(--mono); font-size: .65rem; color: var(--muted); text-align: right; }
    .ap-id-meta div + div { margin-top: .1rem; }

    /* ── Loaded modules footer ── */
    .ap-modules-list { margin-top: 2.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border); }

    /* ── Issue-cert CTA (shown for CSR results) ── */
    .ap-csr-action {
      margin-bottom: 1.5rem; display: flex; justify-content: flex-end; gap: .6rem; flex-wrap: wrap;
    }
    .ap-btn-issue-cert {
      font-family: var(--mono); font-size: .75rem; text-transform: uppercase; letter-spacing: .07em;
      background: none; color: var(--accent);
      border: 1px solid rgba(0,212,170,.4); border-radius: var(--radius);
      padding: .5em 1.1em; cursor: pointer; font-weight: 600;
      transition: background .15s, border-color .15s;
    }
    .ap-btn-issue-cert:hover { background: rgba(0,212,170,.08); border-color: var(--accent); }
    .ap-btn-issue-cert--mpca { color: #a78bfa; border-color: rgba(167,139,250,.4); }
    .ap-btn-issue-cert--mpca:hover { background: rgba(167,139,250,.08); border-color: #a78bfa; }
    .ap-modules-list h3 { font-family: var(--mono); font-size: .65rem; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); margin-bottom: .6rem; }
    .ap-mod-chips { display: flex; flex-wrap: wrap; gap: .4rem; }
    .ap-mod-chip { font-family: var(--mono); font-size: .65rem; color: var(--muted); background: var(--surface); border: 1px solid var(--border); border-radius: 3px; padding: .15em .55em; }

    /* ── xp-* styles (shared with x509parse.php renderer) ── */
    .xp-wrap { font-family: 'IBM Plex Mono',monospace; font-size: .72rem; display: flex; flex-direction: column; gap: 1rem; animation: fadein .35s ease; }
    .xp-section { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
    .xp-section-header { padding: .6rem 1rem; border-bottom: 1px solid var(--border); border-left: 3px solid; background: rgba(255,255,255,.02); display: flex; align-items: center; gap: .75rem; }
    .xp-section-label { font-size: .65rem; font-weight: 600; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); }
    .xp-section-body { padding: .75rem 1rem; display: flex; flex-direction: column; gap: .3rem; }
    .xp-code { font-family: 'IBM Plex Mono',monospace; font-size: .68rem; color: #a8c0e8; word-break: break-all; }
    .xp-oid { color: var(--muted); font-size: .62rem; }
    .xp-oid-name { color: var(--text); }
    .xp-muted { color: var(--muted); font-style: italic; }
    .xp-link { color: var(--accent); text-decoration: none; word-break: break-all; }
    .xp-link:hover { text-decoration: underline; }
    .xp-badge { display: inline-flex; align-items: center; font-size: .58rem; font-weight: 700; letter-spacing: .09em; padding: .12em .5em; border-radius: 2px; white-space: nowrap; }
    .xp-badge-neutral { background: rgba(107,122,144,.15); color: #8899aa; border: 1px solid rgba(107,122,144,.25); }
    .xp-badge-info    { background: rgba(0,153,255,.12);   color: #4db8ff; border: 1px solid rgba(0,153,255,.25); }
    .xp-badge-good    { background: rgba(0,212,100,.1);    color: #3ddc7a; border: 1px solid rgba(0,212,100,.25); }
    .xp-badge-warn    { background: rgba(245,166,35,.1);   color: #f5a623; border: 1px solid rgba(245,166,35,.25); }
    .xp-badge-danger  { background: rgba(224,92,92,.12);   color: #e05c5c; border: 1px solid rgba(224,92,92,.25); }
    .xp-critical-badge { font-size: .56rem; }
    .xp-tag { display: inline-block; font-size: .62rem; padding: .1em .5em; border-radius: 3px; background: rgba(0,153,255,.08); color: #88aacc; border: 1px solid rgba(0,153,255,.15); margin: .1em .2em .1em 0; white-space: nowrap; }
    .dn-table { border-collapse: collapse; width: 100%; }
    .dn-table tr { border-bottom: 1px solid rgba(42,48,64,.5); }
    .dn-table tr:last-child { border-bottom: none; }
    .dn-table td { padding: .2rem 0; vertical-align: top; }
    .dn-key { color: var(--muted); width: 6rem; font-size: .68rem; padding-right: .75rem; white-space: nowrap; }
    .dn-val { color: var(--text); word-break: break-word; overflow-wrap: anywhere; }
    .xp-row { display: flex; align-items: baseline; gap: .75rem; padding: .2rem 0; border-bottom: 1px solid rgba(42,48,64,.5); flex-wrap: wrap; }
    .xp-row:last-child { border-bottom: none; }
    .xp-label { flex-shrink: 0; width: 8rem; color: var(--muted); font-size: .68rem; }
    .xp-value { color: var(--text); flex: 1; min-width: 0; word-break: break-word; overflow-wrap: anywhere; line-height: 1.6; }
    .xp-san-list { display: flex; flex-direction: column; gap: .2rem; }
    .xp-san-entry { display: flex; align-items: baseline; gap: .5rem; }
    .xp-san-type { flex-shrink: 0; width: 3.5rem; text-align: center; font-size: .58rem; font-weight: 700; letter-spacing: .1em; padding: .1em .4em; border-radius: 2px; }
    .xp-san-type.dns   { background: rgba(0,212,170,.1);  color: #00d4aa; border: 1px solid rgba(0,212,170,.2); }
    .xp-san-type.ip    { background: rgba(0,153,255,.1);  color: #4db8ff; border: 1px solid rgba(0,153,255,.2); }
    .xp-san-type.email { background: rgba(245,166,35,.1); color: #f5a623; border: 1px solid rgba(245,166,35,.2); }
    .xp-san-type.uri   { background: rgba(136,102,204,.1);color: #aa88dd; border: 1px solid rgba(136,102,204,.2); }
    .xp-san-type.dir   { background: rgba(107,122,144,.1);color: #8899aa; border: 1px solid rgba(107,122,144,.2); }
    .xp-san-type.other { background: rgba(107,122,144,.1);color: #8899aa; border: 1px solid rgba(107,122,144,.2); }
    .xp-san-val { color: var(--text); word-break: break-all; }
    .xp-policy-block { margin-bottom: .5rem; padding-left: .5rem; border-left: 2px solid rgba(170,100,68,.3); }
    .xp-policy-oid   { margin-bottom: .2rem; }
    .xp-policy-qual  { font-size: .68rem; color: var(--muted); padding-left: .5rem; margin-top: .1rem; }
    .xp-uri-entry { padding: .15rem 0; display: flex; align-items: baseline; gap: .5rem; flex-wrap: wrap; }
    .xp-nc-header { font-size: .62rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; padding: .2rem 0; }
    .xp-nc-header.xp-good   { color: #3ddc7a; }
    .xp-nc-header.xp-danger { color: #e05c5c; }
    .xp-nc-entry { padding: .1rem .5rem; color: var(--text); }
    .xp-ext-block { border: 1px solid var(--border); border-left: 3px solid; border-radius: var(--radius); margin-bottom: .5rem; overflow: hidden; }
    .xp-ext-block:last-child { margin-bottom: 0; }
    .xp-ext-header { padding: .4rem .75rem; background: rgba(255,255,255,.02); border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
    .xp-ext-name { font-weight: 600; color: var(--text); font-size: .7rem; }
    .xp-ext-body { padding: .5rem .75rem; display: flex; flex-direction: column; gap: .25rem; }
    .xp-raw-value { padding: .25rem 0; }
    .xp-fp { font-family: 'IBM Plex Mono',monospace; font-size: .65rem; color: #8899aa; word-break: break-all; letter-spacing: .03em; }
    .xp-serial { font-family: 'IBM Plex Mono',monospace; color: #a8c0e8; word-break: break-all; letter-spacing: .03em; }
    .xp-ski { color: #55aacc; }
    .xp-aki { color: #8899bb; }
    .xp-error { color: var(--danger); padding: 1rem; }
    .xp-sct-list { display: flex; flex-direction: column; gap: .6rem; width: 100%; }
    .xp-sct-block { border: 1px solid var(--border); border-left: 3px solid #44aa88; border-radius: var(--radius); overflow: hidden; }
    .xp-sct-num { font-size: .65rem; font-weight: 600; letter-spacing: .08em; padding: .35rem .75rem; background: rgba(68,170,136,.06); border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
    .xp-sct-log-name { color: #00d4aa; font-weight: 600; }
    .xp-sct-table { border-collapse: collapse; width: 100%; font-size: .68rem; }
    .xp-sct-table tr { border-bottom: 1px solid rgba(42,48,64,.4); }
    .xp-sct-table tr:last-child { border-bottom: none; }
    .xp-sct-table td { padding: .2rem .75rem; vertical-align: top; }
    .xp-sct-table td:first-child { color: var(--muted); white-space: nowrap; width: 6rem; }
    .xp-sct-logid { font-size: .6rem; color: #6699bb; word-break: break-all; }

    /* ── Footer ── */
    .site-footer { border-top: 1px solid var(--border); padding: 1.4rem 2rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; font-family: var(--mono); font-size: .72rem; color: var(--muted); }
    .site-footer a { color: var(--muted); text-decoration: none; }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }

    @media (max-width: 600px) {
      .xp-label { width: 100%; }
      .xp-value { width: 100%; flex: none; }
      .xp-row { flex-direction: column; gap: .15rem; }
      .dn-key { width: 100%; display: block; }
      .dn-table, .dn-table tbody, .dn-table tr, .dn-table td { display: block; width: 100%; }
    }
  </style>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<main class="ap-page">

  <div class="ap-header">
    <h1>
      <img src="/img/meerkat_120.png" alt="">
      Meerkat Artifact Parser
    </h1>
    <p>Identify and parse any PKI artifact — paste Base64/PEM or upload a file. No data is stored or logged.</p>
  </div>

  <!-- Supported types -->
  <div class="ap-types">
    <?php foreach (ArtifactRegistry::all() as $m): ?>
    <span class="ap-type-pill"><?= htmlspecialchars($m->label()) ?></span>
    <?php endforeach; ?>
  </div>

  <!-- Private key warning -->
  <div class="ap-privkey-warning">
    <span class="icon">⛔</span>
    <p>
      <strong>Never submit private keys.</strong>
      Files with extensions <code>.key</code> <code>.p12</code> <code>.pfx</code> <code>.jks</code>
      are blocked. Any PEM containing a <code>PRIVATE KEY</code> marker is detected server-side,
      discarded immediately, and never stored or parsed.
    </p>
  </div>

  <?php if ($error): ?>
  <div class="ap-error<?= $privkey_warn ? ' ap-error--privkey' : '' ?>">
    <div class="err-title"><?= $privkey_warn ? '⛔ Security Warning' : 'Error' ?></div>
    <p><?= $error /* already escaped above */ ?></p>
  </div>
  <?php endif; ?>

  <!-- Input form -->
  <form method="post" enctype="multipart/form-data" class="ap-form" id="apForm">

    <div class="ap-tabs" role="tablist">
      <button type="button" class="ap-tab active" id="tab-paste"   role="tab" aria-selected="true"  aria-controls="panel-paste">Paste Base64 / PEM</button>
      <button type="button" class="ap-tab"         id="tab-upload" role="tab" aria-selected="false" aria-controls="panel-upload">Upload File</button>
    </div>

    <!-- Paste panel -->
    <div class="ap-panel" id="panel-paste" role="tabpanel" aria-labelledby="tab-paste">
      <textarea class="ap-pem-area" name="ap_pem" id="apPem"
                placeholder="Paste Base64, PEM (-----BEGIN ...-----), or any PKI artifact…"
                spellcheck="false" autocomplete="off"><?= htmlspecialchars($posted_pem, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?></textarea>
    </div>

    <!-- Upload panel -->
    <div class="ap-panel" id="panel-upload" role="tabpanel" aria-labelledby="tab-upload" hidden>
      <div class="ap-drop-zone" id="dropZone">
        <input type="file" name="ap_file" id="apFile"
               accept=".pem,.crt,.cer,.csr,.der,.p7b,.p7c,.p7s,.p7m,.p10,.req,.tsr,.tst,.tsq,.ocsp,.crl">
        <div class="dz-icon">📂</div>
        <p>Drop a file here, or click to browse</p>
        <p class="dz-hint">.pem .crt .cer .csr .der .p7b .p7c .p10 .tsr .tsq .ocsp .crl &nbsp;·&nbsp; max 50 KB</p>
        <p class="dz-selected" id="dzSelected" hidden></p>
      </div>
    </div>

    <input type="hidden" name="g_recaptcha_token" id="ap_recaptcha_token">
    <div class="ap-submit">
      <button type="reset" class="ap-btn-clear" id="apClear">Clear</button>
      <button type="button" class="ap-btn" onclick="doAnalyse()">Analyse</button>
    </div>

  </form>

  <?php if ($result): ?>
  <!-- Identified banner -->
  <div class="ap-identified">
    <div class="ap-id-left">
      <div>
        <div class="ap-id-eyebrow">Identified</div>
        <div class="ap-id-type"><?= htmlspecialchars($result['label']) ?></div>
        <?php if ($result['subtype']): ?>
        <div class="ap-id-sub"><?= htmlspecialchars($result['subtype']) ?></div>
        <?php endif; ?>
      </div>
    </div>
    <div class="ap-id-meta">
      <div><?= $result['ms'] ?> ms &nbsp;·&nbsp; <?= $result['n_mods'] ?> modules</div>
      <?php if ($result['fname']): ?>
      <div><?= htmlspecialchars($result['fname']) ?></div>
      <?php endif; ?>
    </div>
  </div>

  <?php if ($result['is_csr'] && $result['pem']): ?>
  <!-- Issue certificate CTA for CSR results -->
  <div class="ap-csr-action"
       id="csrActionBar"
       data-pem="<?= htmlspecialchars(trim($result['pem']), ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?>"
       data-san-types="<?= htmlspecialchars(implode(',', $result['csr_san_types']), ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?>"
       data-has-org="<?= $result['csr_has_org'] ? '1' : '0' ?>">
  </div>
  <?php endif; ?>

  <!-- Parsed output -->
  <?= $result['rendered'] ?>

  <?php require __DIR__ . '/includes/adsense_unit.php'; ?>

  <?php endif; ?>

  <!-- Loaded modules list -->
  <div class="ap-modules-list">
    <h3>Loaded modules (<?= count(ArtifactRegistry::all()) ?>)</h3>
    <div class="ap-mod-chips">
      <?php foreach (ArtifactRegistry::all() as $m): ?>
      <span class="ap-mod-chip"><?= htmlspecialchars($m->label()) ?></span>
      <?php endforeach; ?>
    </div>
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

<script>
var RECAPTCHA_SITE_KEY = <?= json_encode(RECAPTCHA_SITE_KEY) ?>;

function getRecaptchaToken(action) {
  return new Promise(function(resolve) {
    if (!RECAPTCHA_SITE_KEY) { resolve(''); return; }
    grecaptcha.ready(function() {
      grecaptcha.execute(RECAPTCHA_SITE_KEY, {action: action}).then(resolve);
    });
  });
}

async function doAnalyse() {
  var pem = document.getElementById('apPem').value.trim();
  var inp = document.getElementById('apFile');
  // ensure upload tab is active when submitting a file so the input is included
  if (!pem && inp && inp.files.length) {
    document.getElementById('tab-upload').click();
  }
  var token = await getRecaptchaToken('parse_artifact');
  document.getElementById('ap_recaptcha_token').value = token;
  document.getElementById('apForm').submit();
}

(function () {
  // ── Pre-fill from sessionStorage ─────────────────────────────────────────────
  // pki_prefill_cert (cert_factory Parse) takes priority over meerkat_pem (csr_generator Parse)
  var cert = sessionStorage.getItem('pki_prefill_cert');
  var csr  = sessionStorage.getItem('meerkat_pem');
  sessionStorage.removeItem('pki_prefill_cert');
  sessionStorage.removeItem('meerkat_pem');
  var prefill = cert || csr;
  if (prefill) {
    var ta = document.getElementById('apPem');
    if (ta && !ta.value.trim()) {
      ta.value = prefill;
      if (cert) doAnalyse();
    }
  }

  // ── Tab switching ────────────────────────────────────────────────────────────
  var tabs = document.querySelectorAll('.ap-tab');
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

  // ── Drag-and-drop ────────────────────────────────────────────────────────────
  var dz  = document.getElementById('dropZone');
  var inp = document.getElementById('apFile');
  var sel = document.getElementById('dzSelected');

  function showFile(name) {
    sel.textContent = '📄 ' + name;
    sel.hidden = false;
    dz.querySelector('p').hidden = true;
  }

  var MAX_UPLOAD = <?= MAX_BYTES ?>;

  function checkSize(file) {
    if (file.size > MAX_UPLOAD) {
      var kb = Math.round(file.size / 1024);
      alert('File is too large (' + kb + ' KB). PKI artifacts must be under 50 KB.');
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
      inp.files = files; // DataTransfer → input (modern browsers)
      showFile(files[0].name);
    }
  });

  // ── Clear ────────────────────────────────────────────────────────────────────
  document.getElementById('apClear').addEventListener('click', function () {
    document.getElementById('apPem').value = '';
    sel.hidden = true;
    dz.querySelector('p').hidden = false;
  });

  // ── Issue Certificate from CSR ────────────────────────────────────────────────
  var actionBar = document.getElementById('csrActionBar');
  if (actionBar) {
    var pem      = actionBar.dataset.pem;
    var sanTypes = actionBar.dataset.sanTypes ? actionBar.dataset.sanTypes.split(',').filter(Boolean) : [];
    var hasOrg   = actionBar.dataset.hasOrg === '1';
    var hasDns   = sanTypes.indexOf('dns')   !== -1;
    var hasEmail = sanTypes.indexOf('email') !== -1;

    // Routing: dns SAN → TLS; email SAN or (no SAN + org) → MPCA; ambiguous → both
    var showTls  = hasDns  || (!hasEmail);
    var showMpca = hasEmail || (!hasDns);

    function makeIssueBtn(label, cls, factory, storageKey) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'ap-btn-issue-cert' + (cls ? ' ' + cls : '');
      btn.textContent = label;
      btn.addEventListener('click', function () {
        sessionStorage.setItem(storageKey, pem);
        window.open(factory, '_blank');
      });
      return btn;
    }

    if (showTls) {
      actionBar.appendChild(makeIssueBtn(
        'Issue TLS Certificate →', '', '/cert_factory.php', 'pki_prefill_csr'
      ));
    }
    if (showMpca) {
      actionBar.appendChild(makeIssueBtn(
        'Issue MPCA Certificate →', 'ap-btn-issue-cert--mpca', '/mpca_factory.php', 'pki_prefill_csr'
      ));
    }
  }
}());
</script>
</body>
</html>
