<?php
// ── Meerkat e-Seal Signer ─────────────────────────────────────────────────────
// Paste a hash digest → sign with Meerkat e-Seal (CAdES-T) → download .cms
//
// Signs the hash bytes using the e-Seal signing key (ECDSA P-256).
// Embeds an RFC 3161 signature timestamp from the Meerkat TSA (CAdES-T).

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/recaptcha.php';
require_once __DIR__ . '/includes/xades_sign.php';

define('EIT_SIGN_DIR',  MPCA_CA_DIR   . '/eseal_sign');
define('EIT_KEY',       EIT_SIGN_DIR  . '/eseal_signing.key');
define('EIT_CERT',      EIT_SIGN_DIR  . '/eseal_signing.crt');
define('EIT_CA_CHAIN',  EIT_SIGN_DIR  . '/ca_chain.pem');  // CA + Root only (no signer cert)
define('EIT_TSA_DIR',   MPCA_CA_DIR   . '/tsa_sign');
define('EIT_TSA_CNF',   EIT_TSA_DIR   . '/tsa.cnf');

$error         = null;
$cms_b64       = null;
$dl_name       = 'eseal.cms';
$raw_text      = null;
$timestamped   = false;
$hash_detected = null;
$hash_input    = '';
$format        = 'cms';
$with_ts       = true;
$xades_xml     = null;
$xades_dl_name = 'eseal.xades';

// ── Helpers ───────────────────────────────────────────────────────────────────

function eit_run(array $cmd): array {
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

function eit_normalize_hash(string $input): array {
    $clean = preg_replace('/[\s:\-]+/', '', $input);
    if ($clean === '') return ['error' => 'No hash provided.'];
    if (preg_match('/^[0-9a-fA-F]+$/', $clean)) {
        $hex = strtolower($clean);
        return match (strlen($hex)) {
            64  => ['hex' => $hex, 'alg' => 'sha256', 'bits' => 256],
            96  => ['hex' => $hex, 'alg' => 'sha384', 'bits' => 384],
            128 => ['hex' => $hex, 'alg' => 'sha512', 'bits' => 512],
            default => ['error' => sprintf('Hex string is %d bytes — expected 32/48/64.', intdiv(strlen($hex), 2))],
        };
    }
    $b64     = str_replace(['-', '_'], ['+', '/'], $clean);
    $b64    .= str_repeat('=', (4 - strlen($b64) % 4) % 4);
    $decoded = base64_decode($b64, true);
    if ($decoded !== false && $decoded !== '') {
        $bytes = strlen($decoded);
        return match ($bytes) {
            32 => ['hex' => bin2hex($decoded), 'alg' => 'sha256', 'bits' => 256],
            48 => ['hex' => bin2hex($decoded), 'alg' => 'sha384', 'bits' => 384],
            64 => ['hex' => bin2hex($decoded), 'alg' => 'sha512', 'bits' => 512],
            default => ['error' => sprintf('Base64 decodes to %d bytes — expected 32/48/64.', $bytes)],
        };
    }
    return ['error' => 'Could not parse the hash — expected hex or base64 (SHA-256, SHA-384, or SHA-512).'];
}

// ── Minimal DER helpers (for CAdES-T injection) ───────────────────────────────

function eit_der_tlv(string $data, int $offset): array {
    $tag = ord($data[$offset]);
    $off = $offset + 1;
    $lb  = ord($data[$off++]);
    if ($lb < 128) { $len = $lb; }
    else { $n = $lb & 0x7F; $len = 0; for ($i = 0; $i < $n; $i++) $len = ($len << 8) | ord($data[$off++]); }
    return ['tag' => $tag, 'val_off' => $off, 'val_len' => $len, 'end' => $off + $len,
            'tag_off' => $offset];
}

function eit_enc_len(int $len): string {
    if ($len < 128) return chr($len);
    $b = '';
    while ($len > 0) { $b = chr($len & 0xFF) . $b; $len >>= 8; }
    return chr(0x80 | strlen($b)) . $b;
}

function eit_nav_cms(string $der): ?array {
    $ci = eit_der_tlv($der, 0); if ($ci['tag'] !== 0x30) return null;
    $oid_ci = eit_der_tlv($der, $ci['val_off']);
    $exp    = eit_der_tlv($der, $oid_ci['end']); if ($exp['tag'] !== 0xA0) return null;
    $sd     = eit_der_tlv($der, $exp['val_off']); if ($sd['tag'] !== 0x30) return null;

    $cursor = $sd['val_off']; $signerinfos = null; $prefix_len = 0;
    while ($cursor < $sd['end']) {
        $node = eit_der_tlv($der, $cursor);
        if ($node['tag'] === 0x31 && $node['val_len'] > 0) {
            $first = eit_der_tlv($der, $node['val_off']);
            if ($first['tag'] === 0x30 && $first['val_len'] > 0) {
                $fc = eit_der_tlv($der, $first['val_off']);
                if ($fc['tag'] === 0x02) { $signerinfos = $node; $prefix_len = $cursor - $sd['val_off']; break; }
            }
        }
        $cursor = $node['end'];
    }
    if ($signerinfos === null) return null;
    $si = eit_der_tlv($der, $signerinfos['val_off']); if ($si['tag'] !== 0x30) return null;
    return compact('ci', 'exp', 'sd', 'prefix_len', 'signerinfos', 'si');
}

function eit_extract_sig_bytes(string $cms_der): ?string {
    $nav = eit_nav_cms($cms_der); if (!$nav) return null;
    $si  = $nav['si']; $cursor = $si['val_off']; $sig = null;
    while ($cursor < $si['end']) {
        $node = eit_der_tlv($cms_der, $cursor);
        if ($node['tag'] === 0x04) $sig = substr($cms_der, $node['val_off'], $node['val_len']);
        $cursor = $node['end'];
    }
    return $sig;
}

function eit_extract_tst(string $tsr_der): ?string {
    $tsr = eit_der_tlv($tsr_der, 0); if ($tsr['tag'] !== 0x30) return null;
    $sta = eit_der_tlv($tsr_der, $tsr['val_off']); if ($sta['tag'] !== 0x30) return null;
    if ($sta['end'] >= $tsr['end']) return null;
    return substr($tsr_der, $sta['end'], $tsr['end'] - $sta['end']);
}

function eit_inject_tst(string $cms_der, string $tst_der): ?string {
    $oid_tst  = "\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0e";
    $attr_set = "\x31" . eit_enc_len(strlen($tst_der)) . $tst_der;
    $attr_seq = "\x30" . eit_enc_len(strlen($oid_tst) + strlen($attr_set)) . $oid_tst . $attr_set;
    $u_attrs  = "\xa1" . eit_enc_len(strlen($attr_seq)) . $attr_seq;

    $nav = eit_nav_cms($cms_der); if (!$nav) return null;
    ['ci' => $ci, 'exp' => $exp, 'sd' => $sd, 'prefix_len' => $pl, 'signerinfos' => $sis, 'si' => $si] = $nav;

    $new_si_val  = substr($cms_der, $si['val_off'], $si['val_len']) . $u_attrs;
    $new_si      = "\x30" . eit_enc_len(strlen($new_si_val)) . $new_si_val;
    $new_sis     = "\x31" . eit_enc_len(strlen($new_si)) . $new_si;
    $sd_prefix   = substr($cms_der, $sd['val_off'], $pl);
    $new_sd_val  = $sd_prefix . $new_sis;
    $new_sd      = "\x30" . eit_enc_len(strlen($new_sd_val)) . $new_sd_val;
    $new_exp     = "\xa0" . eit_enc_len(strlen($new_sd)) . $new_sd;
    $ci_oid_part = substr($cms_der, $ci['val_off'], $exp['tag_off'] - $ci['val_off']);
    $new_ci_val  = $ci_oid_part . $new_exp;
    return "\x30" . eit_enc_len(strlen($new_ci_val)) . $new_ci_val;
}

// ── Process submission ────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'eseal_signer')) {
            $error = 'reCAPTCHA verification failed. Please try again.';
        }
    }

    $format  = in_array($_POST['format'] ?? '', ['cms', 'xades'], true) ? $_POST['format'] : 'cms';
    $with_ts = isset($_POST['with_ts']);
    $hash_input = trim($_POST['eit_hash'] ?? '');

    if ($error === null) {
        if ($hash_input === '') {
            $error = 'No hash provided — paste a SHA-256, SHA-384, or SHA-512 digest.';
        } else {
            $hash_info = eit_normalize_hash($hash_input);
            if (isset($hash_info['error'])) {
                $error = $hash_info['error'];
            }
        }
    }

    if ($error === null && (!file_exists(EIT_KEY) || !file_exists(EIT_CERT))) {
        $error = 'e-Seal not initialized on this server. Run <code>scripts/mpca_init.sh</code> first.';
    }

    if ($error === null && isset($hash_info) && !isset($hash_info['error'])) {
        $hash_detected = 'SHA-' . $hash_info['bits'];
        $stem = 'eseal_' . substr($hash_info['hex'], 0, 12) . '_' . date('Ymd_His');

        if ($format === 'xades') {
            // ── XAdES path ────────────────────────────────────────────────────
            $cert_pem = (string) file_get_contents(EIT_CERT);
            $key_pem  = (string) file_get_contents(EIT_KEY);
            $xml = xa_sign($hash_info, $cert_pem, $key_pem, $with_ts, EIT_TSA_CNF);
            if ($xml === '') {
                $error = 'XAdES signing failed.';
            } else {
                $xades_xml     = $xml;
                $xades_dl_name = $stem . '.xades';
                $timestamped   = $with_ts && str_contains($xml, 'xades:SignatureTimeStamp');
            }
        } else {
            // ── CAdES / CMS path ──────────────────────────────────────────────
            $tmpIn  = tempnam(sys_get_temp_dir(), 'eit_in_');
            $tmpCms = tempnam(sys_get_temp_dir(), 'eit_cms_');
            $tmpTsq = tempnam(sys_get_temp_dir(), 'eit_tsq_');
            $tmpTsr = tempnam(sys_get_temp_dir(), 'eit_tsr_');
            try {
                file_put_contents($tmpIn, hex2bin($hash_info['hex']));
                $cmd = [OPENSSL_BIN, 'cms', '-sign',
                    '-binary', '-nodetach', '-signer', EIT_CERT, '-inkey', EIT_KEY,
                    '-md', $hash_info['alg'],
                    '-outform', 'DER', '-out', $tmpCms, '-in', $tmpIn,
                ];
                if (file_exists(EIT_CA_CHAIN)) {
                    array_splice($cmd, 3, 0, ['-certfile', EIT_CA_CHAIN]);
                }
                $r = eit_run($cmd);

                if (!$r['ok']) {
                    $error = 'CMS signing failed: ' . trim($r['err']);
                } else {
                    $cmsBytes = (string) file_get_contents($tmpCms);
                    if ($cmsBytes === '') {
                        $error = 'e-Seal produced an empty CMS.';
                    } else {
                        if ($with_ts && file_exists(EIT_TSA_CNF)) {
                            $sig_bytes = eit_extract_sig_bytes($cmsBytes);
                            if ($sig_bytes !== null) {
                                $sig_hex = bin2hex(hash('sha256', $sig_bytes, true));
                                $r2 = eit_run([OPENSSL_BIN, 'ts', '-query',
                                    '-digest', $sig_hex, '-sha256', '-cert', '-out', $tmpTsq]);
                                if ($r2['ok']) {
                                    $r3 = eit_run([OPENSSL_BIN, 'ts', '-reply',
                                        '-config', EIT_TSA_CNF, '-queryfile', $tmpTsq, '-out', $tmpTsr]);
                                    if ($r3['ok']) {
                                        $tsr = (string) file_get_contents($tmpTsr);
                                        $tst = eit_extract_tst($tsr);
                                        if ($tst !== null) {
                                            $cms_t = eit_inject_tst($cmsBytes, $tst);
                                            if ($cms_t !== null) { $cmsBytes = $cms_t; $timestamped = true; }
                                        }
                                    }
                                }
                            }
                        }

                        $cms_b64 = base64_encode($cmsBytes);
                        $dl_name = $stem . '.cms';
                        $p7_name = $stem . '.p7b';

                        $tmpView = tempnam(sys_get_temp_dir(), 'eit_view_');
                        file_put_contents($tmpView, $cmsBytes);
                        $rv = eit_run([OPENSSL_BIN, 'asn1parse', '-inform', 'DER', '-in', $tmpView]);
                        @unlink($tmpView);
                        $raw_text = $rv['out'] ?: $rv['err'];
                    }
                }
            } finally {
                foreach ([$tmpIn, $tmpCms, $tmpTsq, $tmpTsr] as $f) @unlink($f);
            }
        }
    }
}

$navLabel = 'Meerkat — e-Seal Signer';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'Meerkat e-Seal Signer — CAdES-T CMS Signing Tool | ' . SITE_DOMAIN,
    'description' => 'Paste a SHA-256, SHA-384, or SHA-512 hash digest to receive a CAdES-T CMS signature from the Meerkat e-Seal authority. Includes an embedded RFC 3161 timestamp. Download the .cms token and inspect it inline.',
    'url'         => SITE_BASE_URL . '/eseal_signer.php',
    'jsonld'      => json_encode([
      '@context'            => 'https://schema.org',
      '@type'               => 'WebApplication',
      'name'                => 'Meerkat e-Seal Signer',
      'url'                 => SITE_BASE_URL . '/eseal_signer.php',
      'description'         => 'CAdES-T CMS signing tool. Paste a hash digest, get a signed CMS token with embedded RFC 3161 signature timestamp.',
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
  <?php require_once __DIR__ . '/includes/adsense_head.php'; ?>
  <?php if (recaptcha_configured()): ?>
  <?= recaptcha_head() ?>
  <?php endif; ?>
  <style>
    :root {
      --bg: #0e1014; --surface: #13171e; --border: #2a3040;
      --accent: #00d4aa; --text: #d4dae6; --muted: #6b7a90;
      --danger: #e05c5c; --purple: #a78bfa;
      --sans: 'IBM Plex Sans', sans-serif; --mono: 'IBM Plex Mono', monospace;
      --radius: 8px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }
    code { font-family: var(--mono); font-size: .82em; background: rgba(255,255,255,.05); padding: .1em .4em; border-radius: 3px; }

    .eit-page { max-width: 860px; margin: 0 auto; padding: 3rem 2rem 6rem; }

    .eit-header { margin-bottom: 2rem; }
    .eit-header h1 { font-size: 1.9rem; font-weight: 600; color: #fff; display: flex; align-items: center; gap: .6rem; }
    .eit-header p  { font-size: .88rem; color: var(--muted); margin-top: .3rem; max-width: 640px; }

    .eit-sec-note {
      display: flex; gap: .75rem; align-items: flex-start;
      background: rgba(167,139,250,.05); border: 1px solid rgba(167,139,250,.15);
      border-radius: var(--radius); padding: .75rem 1rem; margin-bottom: 1.5rem;
      font-size: .8rem; color: var(--muted);
    }
    .eit-sec-note .icon { flex-shrink: 0; color: var(--purple); }

    .eit-form { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; margin-bottom: 1.5rem; }
    .eit-hash-wrap { padding: 1.2rem 1.4rem; }
    .eit-hash-input {
      width: 100%; resize: vertical; min-height: 80px;
      background: rgba(0,0,0,.25); border: 1px solid var(--border); border-radius: var(--radius);
      color: #b8a8f8; font-family: var(--mono); font-size: .78rem; line-height: 1.7;
      padding: .75rem 1rem; outline: none; transition: border-color .15s; word-break: break-all;
    }
    .eit-hash-input:focus { border-color: var(--purple); }
    .eit-hash-input::placeholder { color: #3a4a5e; }
    .eit-detect-row { display: flex; align-items: center; justify-content: space-between; margin-top: .5rem; min-height: 1.4rem; }
    .eit-detect { font-family: var(--mono); font-size: .68rem; }
    .eit-detect.detected { color: var(--purple); }
    .eit-detect.invalid  { color: var(--danger); }
    .eit-detect.empty    { color: #3a4a5e; }
    .eit-hint { font-size: .72rem; color: var(--muted); }

    .eit-submit {
      display: flex; justify-content: flex-end; align-items: center; gap: .75rem;
      padding: .9rem 1.4rem; border-top: 1px solid var(--border); background: rgba(0,0,0,.1);
    }
    .eit-btn {
      font-family: var(--mono); font-size: .75rem; text-transform: uppercase; letter-spacing: .08em;
      background: var(--purple); color: #0e1014; border: none; border-radius: var(--radius);
      padding: .55em 1.7em; cursor: pointer; font-weight: 600; transition: opacity .15s;
    }
    .eit-btn:hover { opacity: .85; }
    .eit-btn-clear {
      background: none; color: var(--muted); border: 1px solid var(--border);
      font-family: var(--mono); font-size: .72rem; letter-spacing: .06em; text-transform: uppercase;
      border-radius: var(--radius); padding: .5em 1em; cursor: pointer; transition: color .15s;
    }
    .eit-btn-clear:hover { color: var(--text); }

    .eit-error {
      border: 1px solid rgba(224,92,92,.3); border-left: 3px solid var(--danger);
      background: rgba(224,92,92,.07); border-radius: var(--radius);
      padding: .9rem 1.1rem; margin-bottom: 1.5rem;
    }
    .eit-error .err-label { font-family: var(--mono); font-size: .63rem; text-transform: uppercase; letter-spacing: .1em; color: var(--danger); margin-bottom: .3rem; }
    .eit-error p { font-size: .85rem; color: #e8a0a0; margin: 0; }

    .eit-success {
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      background: rgba(167,139,250,.07); border: 1px solid rgba(167,139,250,.25);
      border-left: 3px solid var(--purple);
      border-radius: var(--radius); padding: 1rem 1.3rem; margin-bottom: 1.5rem;
      animation: fadein .3s ease;
    }
    @keyframes fadein { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
    .eit-success-eyebrow { font-family: var(--mono); font-size: .6rem; text-transform: uppercase; letter-spacing: .12em; color: var(--purple); margin-bottom: .1rem; }
    .eit-success-title   { font-size: 1rem; font-weight: 600; color: #fff; }
    .eit-success-sub     { font-family: var(--mono); font-size: .7rem; color: var(--muted); margin-top: .1rem; }
    .eit-ts-badge {
      display: inline-block; font-family: var(--mono); font-size: .62rem;
      background: rgba(34,197,94,.1); border: 1px solid rgba(34,197,94,.3);
      color: #4ade80; border-radius: 3px; padding: .1em .5em; margin-left: .4rem;
    }
    .eit-ts-no-badge {
      display: inline-block; font-family: var(--mono); font-size: .62rem;
      background: rgba(107,122,144,.1); border: 1px solid rgba(107,122,144,.25);
      color: var(--muted); border-radius: 3px; padding: .1em .5em; margin-left: .4rem;
    }
    .eit-dl-row { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; }
    .eit-btn-dl {
      display: inline-flex; align-items: center; gap: .4rem;
      font-family: var(--mono); font-size: .72rem; font-weight: 600; text-transform: uppercase; letter-spacing: .07em;
      background: var(--purple); color: #0e1014; border-radius: var(--radius);
      padding: .5em 1.2em; text-decoration: none; transition: opacity .15s; white-space: nowrap;
    }
    .eit-btn-dl:hover { opacity: .85; color: #0e1014; }
    .eit-btn-dl--outline {
      background: transparent; color: var(--purple);
      border: 1px solid rgba(167,139,250,.4);
    }
    .eit-btn-dl--outline:hover { background: rgba(167,139,250,.08); color: var(--purple); opacity: 1; }
    .eit-btn-parser {
      display: inline-flex; align-items: center; gap: .4rem;
      font-family: var(--mono); font-size: .72rem; font-weight: 600; text-transform: uppercase; letter-spacing: .07em;
      background: transparent; color: var(--accent);
      border: 1px solid rgba(0,212,170,.35); border-radius: var(--radius);
      padding: .5em 1.2em; cursor: pointer; transition: background .15s; white-space: nowrap;
    }
    .eit-btn-parser:hover { background: rgba(0,212,170,.08); }

    .eit-b64-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; margin-bottom: 1.5rem; }
    .eit-b64-header { display: flex; align-items: center; justify-content: space-between; padding: .55rem 1rem; border-bottom: 1px solid var(--border); background: rgba(0,0,0,.1); }
    .eit-b64-label { font-family: var(--mono); font-size: .63rem; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); }
    .eit-b64-copy { font-family: var(--mono); font-size: .68rem; color: var(--purple); background: none; border: 1px solid rgba(167,139,250,.3); border-radius: 3px; padding: .2em .75em; cursor: pointer; transition: background .15s; }
    .eit-b64-copy:hover { background: rgba(167,139,250,.08); }
    .eit-b64-copy.copied { color: #4ade80; border-color: rgba(34,197,94,.3); }
    .eit-b64-textarea { display: block; width: 100%; background: rgba(0,0,0,.2); border: none; color: #8899aa; font-family: var(--mono); font-size: .63rem; line-height: 1.7; padding: .75rem 1rem; resize: none; outline: none; }

    .eit-asn1-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; margin-bottom: 1.5rem; }
    .eit-asn1-header { padding: .55rem 1rem; border-bottom: 1px solid var(--border); background: rgba(0,0,0,.1); }
    .eit-asn1-label { font-family: var(--mono); font-size: .63rem; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); }
    .eit-asn1-pre { margin: 0; padding: .75rem 1rem; font-family: var(--mono); font-size: .62rem; color: #8899aa; overflow-x: auto; white-space: pre; line-height: 1.55; max-height: 420px; overflow-y: auto; }

    .eit-opts {
      display: flex; align-items: center; gap: .9rem; flex-wrap: wrap;
      padding: .7rem 1.4rem; border-top: 1px solid var(--border);
      background: rgba(0,0,0,.08); font-size: .78rem; color: var(--muted);
    }
    .eit-opts-label { font-family: var(--mono); font-size: .65rem; text-transform: uppercase;
                      letter-spacing: .08em; color: var(--muted); margin-right: .1rem; }
    .eit-radio-lbl, .eit-check-lbl {
      display: inline-flex; align-items: center; gap: .35rem; cursor: pointer;
      font-family: var(--mono); font-size: .72rem; color: var(--text);
      user-select: none;
    }
    .eit-radio-lbl input, .eit-check-lbl input { accent-color: var(--purple); cursor: pointer; }
    .eit-opts-sep { color: var(--border); }

    .site-footer { border-top: 1px solid var(--border); padding: 1.4rem 2rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; font-family: var(--mono); font-size: .72rem; color: var(--muted); }
    .site-footer a { color: var(--muted); }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }

    @media (max-width: 600px) {
      .eit-page { padding: 2rem 1rem 4rem; }
      .eit-success { flex-direction: column; align-items: flex-start; }
    }
  </style>
</head>
<body>

<?php require_once __DIR__ . '/includes/site_nav.php'; ?>

<main class="eit-page">

  <div class="eit-header">
    <h1>🔏 Meerkat e-Seal Signer</h1>
    <p>Paste a SHA-256, SHA-384, or SHA-512 hash digest to receive a CAdES or XAdES signature from the Meerkat e-Seal authority. Choose format and whether to include an RFC 3161 signature timestamp (T level).</p>
  </div>

  <div class="eit-sec-note">
    <span class="icon">🔒</span>
    <span>
      The hash you provide is sealed using ECDSA P-256 — your original content never leaves your machine.
      A CAdES-T signature timestamp is embedded via the <a href="/tsa_doc.php">Meerkat TSA</a>.
      Issued tokens are signed by the <a href="/eseal_doc.php">Meerkat e-Seal authority</a> (not a qualified TSP — for testing only).
    </span>
  </div>

  <?php if ($error): ?>
  <div class="eit-error">
    <div class="err-label">Error</div>
    <p><?= $error ?></p>
  </div>
  <?php endif; ?>

  <form method="post" id="eitForm">

    <div class="eit-form">
      <div class="eit-hash-wrap">
        <textarea class="eit-hash-input" name="eit_hash" id="eitHash" rows="3"
                  placeholder="SHA-256 / SHA-384 / SHA-512 — hex or base64, spaces and colons OK"
                  spellcheck="false" autocomplete="off"><?= htmlspecialchars($hash_input, ENT_NOQUOTES) ?></textarea>
        <div class="eit-detect-row">
          <span class="eit-detect empty" id="eitDetect">—</span>
          <span class="eit-hint">hex · base64 · with spaces · uppercase — all accepted</span>
        </div>
      </div>

      <input type="hidden" name="g_recaptcha_token" id="eit_recaptcha_token">

      <div class="eit-opts">
        <span class="eit-opts-label">Format</span>
        <label class="eit-radio-lbl">
          <input type="radio" name="format" value="cms" <?= $format === 'cms' ? 'checked' : '' ?>>
          CAdES-B (CMS)
        </label>
        <label class="eit-radio-lbl">
          <input type="radio" name="format" value="xades" <?= $format === 'xades' ? 'checked' : '' ?>>
          XAdES-B (XML)
        </label>
        <span class="eit-opts-sep">·</span>
        <label class="eit-check-lbl">
          <input type="checkbox" name="with_ts" value="1" <?= $with_ts ? 'checked' : '' ?>>
          Include timestamp (T level)
        </label>
      </div>

      <div class="eit-submit">
        <button type="button" class="eit-btn-clear" id="eitClear">Clear</button>
        <button type="button" class="eit-btn" id="eitSubmitBtn" onclick="doSeal()">e-Seal →</button>
      </div>
    </div>

  </form>

  <?php if ($cms_b64): ?>

  <!-- CAdES success banner -->
  <div class="eit-success">
    <div>
      <div class="eit-success-eyebrow">e-Seal Issued</div>
      <div class="eit-success-title">
        CMS SignedData<?php if ($timestamped): ?>
          <span class="eit-ts-badge">CAdES-T ✓ timestamped</span>
        <?php else: ?>
          <span class="eit-ts-no-badge">CAdES-B</span>
        <?php endif; ?>
      </div>
      <div class="eit-success-sub">
        <?= htmlspecialchars($hash_detected) ?> &nbsp;·&nbsp;
        Meerkat e-Seal &nbsp;·&nbsp;
        <?= htmlspecialchars($dl_name) ?>
      </div>
    </div>
    <div class="eit-dl-row">
      <a href="data:application/pkcs7-mime;base64,<?= htmlspecialchars(base64_encode("-----BEGIN PKCS7-----\n" . chunk_split($cms_b64, 64, "\n") . "-----END PKCS7-----\n"), ENT_QUOTES) ?>"
         download="<?= htmlspecialchars($p7_name, ENT_QUOTES) ?>"
         class="eit-btn-dl">⬇ PKCS#7 PEM</a>
      <a href="data:application/cms;base64,<?= htmlspecialchars($cms_b64, ENT_QUOTES) ?>"
         download="<?= htmlspecialchars($dl_name, ENT_QUOTES) ?>"
         class="eit-btn-dl eit-btn-dl--outline">⬇ Binary DER</a>
      <button type="button" class="eit-btn-parser" onclick="sendToParser()">🔍 Inspect in Artifact Parser</button>
    </div>
  </div>

  <!-- Base64 token -->
  <div class="eit-b64-card">
    <div class="eit-b64-header">
      <span class="eit-b64-label">Base64 Token</span>
      <button type="button" class="eit-b64-copy" id="eitCopyB64">Copy</button>
    </div>
    <textarea class="eit-b64-textarea" id="eitB64" rows="6" readonly spellcheck="false"><?= htmlspecialchars(chunk_split($cms_b64, 64, "\n"), ENT_NOQUOTES) ?></textarea>
  </div>

  <!-- ASN.1 structure -->
  <?php if ($raw_text): ?>
  <div class="eit-asn1-card">
    <div class="eit-asn1-header">
      <span class="eit-asn1-label">CMS Structure (openssl asn1parse)</span>
    </div>
    <pre class="eit-asn1-pre"><?= htmlspecialchars($raw_text) ?></pre>
  </div>
  <?php endif; ?>

  <?php require_once __DIR__ . '/includes/adsense_unit.php'; ?>

  <?php elseif ($xades_xml): ?>

  <!-- XAdES success banner -->
  <div class="eit-success">
    <div>
      <div class="eit-success-eyebrow">e-Seal Issued</div>
      <div class="eit-success-title">
        XAdES detached<?php if ($timestamped): ?>
          <span class="eit-ts-badge">XAdES-B-T ✓ timestamped</span>
        <?php else: ?>
          <span class="eit-ts-no-badge">XAdES-B-B</span>
        <?php endif; ?>
      </div>
      <div class="eit-success-sub">
        <?= htmlspecialchars($hash_detected) ?> &nbsp;·&nbsp;
        Meerkat e-Seal &nbsp;·&nbsp;
        <?= htmlspecialchars($xades_dl_name) ?>
      </div>
    </div>
    <div class="eit-dl-row">
      <a href="data:application/xml;base64,<?= htmlspecialchars(base64_encode($xades_xml), ENT_QUOTES) ?>"
         download="<?= htmlspecialchars($xades_dl_name, ENT_QUOTES) ?>"
         class="eit-btn-dl">⬇ XAdES XML</a>
      <button type="button" class="eit-btn-parser" onclick="sendXadesToParser()">🔍 Inspect in Artifact Parser</button>
    </div>
  </div>

  <!-- XML display -->
  <div class="eit-b64-card">
    <div class="eit-b64-header">
      <span class="eit-b64-label">XAdES XML</span>
      <button type="button" class="eit-b64-copy" id="eitCopyXml">Copy</button>
    </div>
    <textarea class="eit-b64-textarea" id="eitXml" rows="14" readonly spellcheck="false"><?= htmlspecialchars($xades_xml, ENT_NOQUOTES) ?></textarea>
  </div>

  <?php require_once __DIR__ . '/includes/adsense_unit.php'; ?>

  <?php endif; ?>

</main>

<footer class="site-footer">
  <span>&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="/">Home</a>
    <a href="/eseal_doc.php">e-Seal Reference</a>
    <a href="/artifact_parser.php">Artifact Parser</a>
    <a href="<?= 'mailto:' . CONTACT_EMAIL ?>"><?= CONTACT_EMAIL ?></a>
  </div>
</footer>

<?php require_once __DIR__ . '/includes/cookie_banner.php'; ?>

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

async function doSeal() {
  var token = await getRecaptchaToken('eseal_signer');
  document.getElementById('eit_recaptcha_token').value = token;
  document.getElementById('eitForm').submit();
}

(function () {
  var hashEl   = document.getElementById('eitHash');
  var detectEl = document.getElementById('eitDetect');

  function detectAlgo(raw) {
    var s = raw.replace(/[\s:\-]/g, '');
    if (!s) return null;
    if (/^[0-9a-fA-F]+$/.test(s)) {
      if (s.length === 64)  return { label: 'SHA-256 (hex)', ok: true };
      if (s.length === 96)  return { label: 'SHA-384 (hex)', ok: true };
      if (s.length === 128) return { label: 'SHA-512 (hex)', ok: true };
      return { label: 'hex — wrong length (' + Math.floor(s.length / 2) + ' bytes)', ok: false };
    }
    if (/^[A-Za-z0-9+/\-_=]+$/.test(s)) {
      var np = s.replace(/=/g, '');
      if (np.length === 43 || np.length === 44) return { label: 'SHA-256 (base64)', ok: true };
      if (np.length === 64)                     return { label: 'SHA-384 (base64)', ok: true };
      if (np.length === 86 || np.length === 88) return { label: 'SHA-512 (base64)', ok: true };
      return { label: 'base64 — wrong length', ok: false };
    }
    return { label: 'unrecognised format', ok: false };
  }

  function updateDetect() {
    var val = hashEl.value.trim();
    if (!val) { detectEl.textContent = '—'; detectEl.className = 'eit-detect empty'; return; }
    var r = detectAlgo(val);
    if (!r) { detectEl.textContent = '—'; detectEl.className = 'eit-detect empty'; }
    else if (r.ok) { detectEl.textContent = '✓ ' + r.label; detectEl.className = 'eit-detect detected'; }
    else { detectEl.textContent = '✗ ' + r.label; detectEl.className = 'eit-detect invalid'; }
  }

  hashEl.addEventListener('input',  updateDetect);
  hashEl.addEventListener('paste',  function () { setTimeout(updateDetect, 0); });
  updateDetect();

  document.getElementById('eitClear').addEventListener('click', function () {
    hashEl.value = '';
    updateDetect();
    hashEl.focus();
  });

  var copyBtn = document.getElementById('eitCopyB64');
  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      var raw = document.getElementById('eitB64').value.replace(/\n/g, '');
      navigator.clipboard.writeText(raw).then(function () {
        copyBtn.textContent = 'Copied!';
        copyBtn.classList.add('copied');
        setTimeout(function () { copyBtn.textContent = 'Copy'; copyBtn.classList.remove('copied'); }, 2000);
      });
    });
  }

  var copyXmlBtn = document.getElementById('eitCopyXml');
  if (copyXmlBtn) {
    copyXmlBtn.addEventListener('click', function () {
      var xml = document.getElementById('eitXml').value;
      navigator.clipboard.writeText(xml).then(function () {
        copyXmlBtn.textContent = 'Copied!';
        copyXmlBtn.classList.add('copied');
        setTimeout(function () { copyXmlBtn.textContent = 'Copy'; copyXmlBtn.classList.remove('copied'); }, 2000);
      });
    });
  }
}());

function sendToParser() {
  var b64 = document.getElementById('eitB64').value.replace(/\s+/g, '');
  if (!b64) return;
  var pem = '-----BEGIN PKCS7-----\n' + b64.match(/.{1,64}/g).join('\n') + '\n-----END PKCS7-----\n';
  sessionStorage.removeItem('pki_prefill_cert');
  sessionStorage.removeItem('mkt_eseal_xades');
  sessionStorage.removeItem('meerkat_pem');
  sessionStorage.setItem('mkt_eseal_cms', pem);
  window.open('/artifact_parser.php', '_blank');
}

function sendXadesToParser() {
  var xml = document.getElementById('eitXml').value;
  if (!xml) return;
  sessionStorage.removeItem('pki_prefill_cert');
  sessionStorage.removeItem('mkt_eseal_cms');
  sessionStorage.removeItem('meerkat_pem');
  sessionStorage.setItem('mkt_eseal_xades', xml);
  window.open('/artifact_parser.php', '_blank');
}
</script>
</body>
</html>
