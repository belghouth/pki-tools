<?php
require_once __DIR__ . '/recaptcha.php';
require_once __DIR__ . '/config.php';

// ── Profile loader ─────────────────────────────────────────────────────────────

/**
 * Scan MPCA_PROFILES_DIR for *.cnf files and parse their [meta] section.
 * Returns keyed array: [ 'profile_id' => [ 'label', 'description', 'sub_ca',
 *                        'san_type', 'validity_days', 'key_types', 'file' ], … ]
 * Sorted by the optional 'order' meta key (ascending), then by label.
 */
function load_profiles(): array
{
    $dir = MPCA_PROFILES_DIR;
    if (!is_dir($dir)) return [];

    $profiles = [];
    foreach (glob($dir . '/*.cnf') ?: [] as $file) {
        $content = (string) file_get_contents($file);
        // Extract text between [meta] and the next section header (or EOF)
        if (!preg_match('/^\[meta\][^\[]*(?=\[|\z)/ms', $content, $m)) continue;
        $block = $m[0];
        $meta  = [];
        foreach (explode("\n", $block) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === ';' || $line[0] === '#' || $line[0] === '[') continue;
            if (preg_match('/^(\w+)\s*=\s*(.+)$/', $line, $lm)) {
                $meta[trim($lm[1])] = trim($lm[2]);
            }
        }
        if (!isset($meta['label'])) continue;
        $id = basename($file, '.cnf');
        $profiles[$id] = [
            'label'        => $meta['label']        ?? $id,
            'description'  => $meta['description']  ?? '',
            'sub_ca'       => $meta['sub_ca']        ?? '',
            'san_type'     => $meta['san_type']      ?? 'none',
            'validity_days'=> (int) ($meta['validity_days'] ?? 365),
            'key_types'    => $meta['key_types']     ?? 'rsa,ec',
            'order'        => (int) ($meta['order']  ?? 99),
            'file'         => $file,
        ];
    }

    uasort($profiles, fn($a, $b) => $a['order'] <=> $b['order'] ?: strcmp($a['label'], $b['label']));
    return $profiles;
}

// ── CA routing ─────────────────────────────────────────────────────────────────

function mpca_ca_map(): array
{
    $ca  = MPCA_CA_DIR;
    $web = MPCA_WEB_DIR;
    return [
        'smime'    => [
            'cnf'  => "$ca/smime/openssl.cnf",
            'crt'  => "$web/smime_ca.crt",
            'lock' => "$ca/smime/factory.lock",
            'srl'  => "$ca/smime/serial",
            'crl'  => "$web/smime_ca.crl",
        ],
        'personal' => [
            'cnf'  => "$ca/personal/openssl.cnf",
            'crt'  => "$web/personal_ca.crt",
            'lock' => "$ca/personal/factory.lock",
            'srl'  => "$ca/personal/serial",
            'crl'  => "$web/personal_ca.crl",
        ],
        'codesign' => [
            'cnf'  => "$ca/codesign/openssl.cnf",
            'crt'  => "$web/codesign_ca.crt",
            'lock' => "$ca/codesign/factory.lock",
            'srl'  => "$ca/codesign/serial",
            'crl'  => "$web/codesign_ca.crl",
        ],
    ];
}

// ── API ────────────────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    session_start();
    header('Content-Type: application/json; charset=utf-8');
    $action = $_POST['action'] ?? 'issue';
    $result = match ($action) {
        'revoke' => handle_mpca_revoke(),
        default  => handle_mpca_issue(),
    };
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function handle_mpca_issue(): array
{
    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'mpca_issue')) {
            return ['error' => 'reCAPTCHA verification failed. Please try again.'];
        }
    }

    $profileId = trim($_POST['profile'] ?? '');
    $profiles  = load_profiles();
    if ($profileId === '' || !isset($profiles[$profileId])) {
        return ['error' => 'No valid profile selected'];
    }
    $profile = $profiles[$profileId];

    // Collect CSR
    $csrPem = '';
    if (!empty($_POST['csr'])) {
        $csrPem = trim($_POST['csr']);
    } elseif (isset($_FILES['csr_file']) && $_FILES['csr_file']['error'] === UPLOAD_ERR_OK) {
        if ($_FILES['csr_file']['size'] > MAX_CSR_BYTES) {
            return ['error' => 'File exceeds 64 KB limit'];
        }
        $csrPem = trim((string) file_get_contents($_FILES['csr_file']['tmp_name']));
    }
    if (!$csrPem) return ['error' => 'No CSR provided'];
    if (strlen($csrPem) > MAX_CSR_BYTES) return ['error' => 'CSR exceeds 64 KB limit'];
    if (!preg_match('/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/i', $csrPem)) {
        return ['error' => 'Invalid format — expected a PEM CERTIFICATE REQUEST block'];
    }

    // Validate email for profiles that require it
    $email = '';
    if ($profile['san_type'] === 'email') {
        $email = trim($_POST['email'] ?? '');
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['error' => 'A valid email address is required for this profile'];
        }
    }

    $tmpCsr = sys_get_temp_dir() . '/cf_csr_' . bin2hex(random_bytes(8)) . '.pem';
    file_put_contents($tmpCsr, $csrPem . "\n");

    try {
        return process_mpca_csr($tmpCsr, $profile, $email);
    } finally {
        @unlink($tmpCsr);
    }
}

function handle_mpca_revoke(): array
{
    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'mpca_revoke')) {
            return ['error' => 'reCAPTCHA verification failed. Please try again.'];
        }
    }

    $certPem = trim($_POST['cert'] ?? '');
    if (!$certPem || !str_contains($certPem, '-----BEGIN CERTIFICATE-----')) {
        return ['error' => 'No valid certificate PEM provided'];
    }

    $allowed = ['unspecified', 'keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation'];
    $reason  = $_POST['reason'] ?? 'unspecified';
    if (!in_array($reason, $allowed, true)) {
        return ['error' => 'Invalid revocation reason'];
    }

    $tmpCert = sys_get_temp_dir() . '/cf_cert_' . bin2hex(random_bytes(8)) . '.pem';
    file_put_contents($tmpCert, $certPem . "\n");

    // Detect issuing CA from AIA caIssuers URL
    $r    = run_cmd([OPENSSL_BIN, 'x509', '-in', $tmpCert, '-noout', '-text']);
    $text = $r['ok'] ? $r['out'] : '';

    $caMap  = mpca_ca_map();
    $subCa  = null;
    foreach ($caMap as $id => $ca) {
        if (str_contains($text, basename($ca['crt']))) {
            $subCa = $id;
            break;
        }
    }
    if ($subCa === null) {
        @unlink($tmpCert);
        return ['error' => 'Certificate was not issued by any MPCA sub CA'];
    }

    $ca   = $caMap[$subCa];
    $lock = fopen($ca['lock'], 'c');
    if (!$lock) {
        @unlink($tmpCert);
        return ['error' => "Cannot open lock file for sub CA '{$subCa}' — check that the CA directory is writable by the web server (path: {$ca['lock']})"];
    }
    if (!flock($lock, LOCK_EX | LOCK_NB)) {
        fclose($lock);
        @unlink($tmpCert);
        return ['error' => 'CA is busy — please retry in a moment'];
    }

    try {
        $cmd = [OPENSSL_BIN, 'ca', '-config', $ca['cnf'], '-revoke', $tmpCert, '-batch'];
        if ($reason !== 'unspecified') {
            array_push($cmd, '-crl_reason', $reason);
        }
        $r = run_cmd($cmd);

        $alreadyRevoked = str_contains($r['err'] ?? '', 'already revoked');
        if (!$r['ok'] && !$alreadyRevoked) {
            return ['error' => 'Revocation failed: ' . trim($r['err'] ?: $r['out'])];
        }

        prune_expired_revoked(dirname($ca['cnf']) . '/index.txt');

        // Regenerate CRL → DER → publish
        $crlTmp       = sys_get_temp_dir() . '/cf_crl_' . bin2hex(random_bytes(8)) . '.pem';
        $crlDer       = sys_get_temp_dir() . '/cf_crl_' . bin2hex(random_bytes(8)) . '.der';
        $crlPublished = false;
        try {
            $r2 = run_cmd([OPENSSL_BIN, 'ca', '-config', $ca['cnf'], '-gencrl', '-out', $crlTmp, '-batch']);
            if ($r2['ok'] && file_exists($crlTmp)) {
                $r3 = run_cmd([OPENSSL_BIN, 'crl', '-in', $crlTmp, '-outform', 'DER', '-out', $crlDer]);
                if ($r3['ok'] && file_exists($crlDer)) {
                    $crlPublished = copy($crlDer, $ca['crl']);
                }
            }
        } finally {
            @unlink($crlTmp);
            @unlink($crlDer);
        }

        $base = $alreadyRevoked ? 'Certificate was already revoked.' : 'Certificate revoked successfully.';
        $crlNote = $crlPublished
            ? ' CRL has been refreshed.'
            : ' CRL update failed — check that the web directory is writable by the web server.';

        return ['ok' => true, 'message' => $base . $crlNote];

    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
        @unlink($tmpCert);
    }
}

// ── Core issuance ──────────────────────────────────────────────────────────────

function process_mpca_csr(string $csrFile, array $profile, string $email): array
{
    // Parse CSR
    $r = run_cmd([OPENSSL_BIN, 'req', '-in', $csrFile, '-noout', '-text']);
    if (!$r['ok']) return ['error' => 'Failed to parse CSR — check the PEM encoding'];
    $text = $r['out'];

    // Self-signature check
    $r = run_cmd([OPENSSL_BIN, 'req', '-verify', '-in', $csrFile, '-noout']);
    if (!$r['ok'] && !str_contains($r['err'], 'verify OK')) {
        return ['error' => 'CSR self-signature verification failed'];
    }

    // Key type
    $isEc  = (bool) preg_match('/Public Key Algorithm:\s*id-ecPublicKey/i',  $text);
    $isRsa = (bool) preg_match('/Public Key Algorithm:\s*rsaEncryption/i',   $text);
    if (!$isRsa && !$isEc) {
        return ['error' => 'Only RSA and ECDSA keys are accepted'];
    }

    $allowedTypes = array_map('trim', explode(',', $profile['key_types']));
    if ($isRsa && !in_array('rsa', $allowedTypes)) {
        return ['error' => 'RSA keys are not accepted for the "' . $profile['label'] . '" profile'];
    }
    if ($isEc && !in_array('ec', $allowedTypes)) {
        return ['error' => 'ECDSA keys are not accepted for the "' . $profile['label'] . '" profile'];
    }

    // Key size
    if (!preg_match('/Public[-\s]Key:\s*\((\d+)\s*bit\)/i', $text, $m)) {
        return ['error' => 'Could not determine key size'];
    }
    $keyBits = (int) $m[1];
    if ($isRsa && $keyBits < 2048) {
        return ['error' => "RSA key is {$keyBits} bits — minimum accepted is 2048 bits"];
    }
    if ($isEc && !in_array($keyBits, [256, 384, 521], true)) {
        return ['error' => "EC key {$keyBits} bits is not on an accepted curve — use P-256, P-384, or P-521"];
    }

    // CN validation for Mailbox-Validated S/MIME
    if ($profile['sub_ca'] === 'smime' && $email !== '') {
        $csrCn = extract_cn($text);
        if ($csrCn !== '' && strtolower($csrCn) !== strtolower($email)) {
            return ['error' => "For Mailbox-Validated S/MIME the CN in your CSR must equal the email address or be absent.\n"
                . "CSR CN: \"{$csrCn}\" — expected: \"{$email}\"\n"
                . 'Please regenerate your CSR with CN=' . $email . ' or omit CN entirely.'];
        }
    }

    // CA routing
    $caMap = mpca_ca_map();
    $subCa = $profile['sub_ca'];
    if (!isset($caMap[$subCa])) {
        return ['error' => 'Profile references unknown sub CA: ' . $subCa];
    }
    $ca = $caMap[$subCa];
    if (!file_exists($ca['cnf'])) {
        return ['error' => "Sub CA '{$subCa}' is not initialized. Run mpca_init.sh first."];
    }

    // Build extension file: extract from [leaf_ext] onwards, discarding [meta] and any preamble
    $profileContent = (string) file_get_contents($profile['file']);
    if (!preg_match('/^(\[leaf_ext\].*)/ms', $profileContent, $m)) {
        return ['error' => "Profile '{$profile['label']}' has no [leaf_ext] section"];
    }
    $profileContent = $m[1];

    if ($profile['san_type'] === 'email' && $email !== '') {
        $sanValue = 'email:' . $email;
        $profileContent = str_replace('{{SAN}}', $sanValue, $profileContent);
    } else {
        // Remove any leftover {{SAN}} placeholder line entirely
        $profileContent = preg_replace('/^subjectAltName\s*=\s*\{\{SAN\}\}\s*$/m', '', $profileContent);
    }

    $lock = fopen($ca['lock'], 'c');
    if (!$lock) {
        return ['error' => "Cannot open lock file for sub CA '{$subCa}' — check that the CA directory is writable by the web server (path: {$ca['lock']})"];
    }
    if (!flock($lock, LOCK_EX | LOCK_NB)) {
        fclose($lock);
        return ['error' => 'Another issuance is in progress — please retry in a moment'];
    }

    $extFile  = sys_get_temp_dir() . '/cf_ext_'  . bin2hex(random_bytes(8)) . '.cnf';
    $certFile = sys_get_temp_dir() . '/cf_cert_' . bin2hex(random_bytes(8)) . '.pem';

    try {
        file_put_contents($extFile, $profileContent);
        // Random 128-bit serial per BR §7.1.2.4
        file_put_contents($ca['srl'], strtoupper(bin2hex(random_bytes(16))) . "\n");

        $r = run_cmd([
            OPENSSL_BIN, 'ca',
            '-config',     $ca['cnf'],
            '-in',         $csrFile,
            '-out',        $certFile,
            '-extfile',    $extFile,
            '-extensions', 'leaf_ext',
            '-days',       (string) $profile['validity_days'],
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

        $issuerPem    = (string) file_get_contents($ca['crt']);
        $lintFindings = run_pkimetal_collect($certPem, $issuerPem) ?? [];

        $info = parse_cert($certFile);

        return [
            'ok'           => true,
            'profile'      => $profile['label'],
            'certificate'  => trim($certPem),
            'issuer_pem'   => trim($issuerPem),
            'subject'      => $info['subject']    ?? '',
            'issuer'       => $info['issuer']     ?? '',
            'not_before'   => $info['not_before'] ?? '',
            'not_after'    => $info['not_after']  ?? '',
            'serial'       => $info['serial']     ?? '',
            'key_bits'     => $keyBits,
            'email'        => $email,
            'lint_findings' => $lintFindings,
        ];

    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
        @unlink($extFile);
        @unlink($certFile);
    }
}

// ── Shared helpers (mirrors cert_factory.php) ──────────────────────────────────

function run_pkimetal_collect(string $certPem, string $issuerPem): ?array
{
    if (!function_exists('curl_init')) return null;
    $env  = getenv('PKIMETAL_URL');
    $base = rtrim(($env !== false && $env !== '') ? $env : PKIMETAL_URL, '/');
    if ($base === '') return null;
    $cert = openssl_x509_read($certPem);
    if ($cert === false) return null;
    openssl_x509_export($cert, $certClean);
    $issuerClean = '';
    $issuer = openssl_x509_read($issuerPem);
    if ($issuer !== false) openssl_x509_export($issuer, $issuerClean);
    $ch = curl_init($base . '/lintcert');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query(['b64cert' => $certClean, 'b64issuer' => $issuerClean, 'format' => 'json']),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_CONNECTTIMEOUT => 5,
    ]);
    $response = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($response === false || $httpCode !== 200) return null;
    $findings = json_decode((string) $response, true);
    if (!is_array($findings)) return null;
    $out = [];
    foreach ($findings as $f) {
        $sev    = strtolower(trim($f['Severity'] ?? $f['severity'] ?? ''));
        $find   = trim($f['Finding'] ?? $f['finding'] ?? '');
        $code   = trim($f['Code']    ?? $f['code']    ?? '');
        $linter = trim($f['Linter']  ?? $f['linter']  ?? '');
        if ($find === '[EndOfResults]' || $sev === 'meta') continue;
        $out[] = ['severity' => $sev, 'linter' => $linter, 'code' => $code, 'finding' => $find];
    }
    return $out;
}

function extract_cn(string $text): string
{
    if (preg_match('/Subject:.*?\bCN\s*=\s*([^\s,\/\n]+)/i', $text, $m)) return trim($m[1]);
    return '';
}

function parse_cert(string $certFile): array
{
    $r = run_cmd([OPENSSL_BIN, 'x509', '-in', $certFile, '-noout', '-text']);
    if (!$r['ok']) return [];
    $t = $r['out'];
    $out = [];
    if (preg_match('/Subject:\s*(.+)/i',              $t, $m)) $out['subject']    = trim($m[1]);
    if (preg_match('/Issuer:\s*(.+)/i',               $t, $m)) $out['issuer']     = trim($m[1]);
    if (preg_match('/Not Before:\s*(.+)/i',           $t, $m)) $out['not_before'] = trim($m[1]);
    if (preg_match('/Not After\s*:\s*(.+)/i',         $t, $m)) $out['not_after']  = trim($m[1]);
    if (preg_match('/Serial Number:\s*\n?\s*([0-9a-f:]+)/i', $t, $m)) $out['serial'] = trim($m[1]);
    return $out;
}

function prune_expired_revoked(string $indexFile): void
{
    if (!is_file($indexFile)) return;
    $now = gmdate('ymdHis') . 'Z';
    $out = [];
    foreach (file($indexFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $fields = explode("\t", $line);
        if (($fields[0] ?? '') === 'R' && isset($fields[1]) && $fields[1] <= $now) continue;
        $out[] = $line;
    }
    file_put_contents($indexFile, $out ? implode("\n", $out) . "\n" : '');
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

// ── Page ───────────────────────────────────────────────────────────────────────

$profiles   = load_profiles();
$navLabel   = 'MPCA Factory';
$noProfiles = empty($profiles);
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'MPCA Certificate Factory — S/MIME, Code Signing, Client Auth | ' . SITE_DOMAIN,
    'description' => 'Issue S/MIME, code signing, client authentication, and document signing certificates from the thameur.org Multi-Purpose CA. Multiple profiles, profile-driven extensions, pkimetal linting.',
    'url'         => SITE_BASE_URL . '/mpca_factory.php',
  ]);
  ?>
  <?= recaptcha_head() ?>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0e1014; --surface: #13171e; --surface2: #181d26; --border: #2a3040;
      --accent: #00d4aa; --text: #d4dae6; --muted: #6b7a90; --danger: #f87171;
      --warn: #f59e0b;
      --sans: 'IBM Plex Sans', sans-serif; --mono: 'IBM Plex Mono', monospace;
      --radius: 8px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    [hidden] { display: none !important; }
    html { font-size: 15px; scroll-behavior: smooth; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans);
           font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }

    .factory-wrap { max-width: 820px; margin: 0 auto; padding: 3.5rem 2rem 6rem; }

    .page-header { margin-bottom: 2rem; }
    .page-header h1 { font-size: 1.9rem; font-weight: 600; color: #fff; margin-bottom: 0.3rem; }
    .page-header p  { font-size: 0.88rem; color: var(--muted); max-width: 600px; }

    .warn-banner {
      display: flex; align-items: center; gap: 0.6rem;
      border: 1px solid #7c2d12; background: rgba(124,45,18,0.1);
      border-radius: 6px; padding: 0.7rem 1rem; margin-bottom: 1.8rem;
      font-size: 0.82rem; color: #fca5a5;
    }

    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 1.6rem; margin-bottom: 1.5rem;
    }
    .card-section-label {
      font-family: var(--mono); font-size: 0.68rem; text-transform: uppercase;
      letter-spacing: 0.09em; color: var(--muted); margin-bottom: 0.75rem;
    }

    /* Profile selector */
    .profile-select {
      width: 100%; background: var(--bg); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text); font-family: var(--mono);
      font-size: 0.82rem; padding: 0.55em 0.9em; cursor: pointer;
      transition: border-color 0.15s; margin-bottom: 0.7rem;
      appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%236b7a90' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");
      background-repeat: no-repeat; background-position: right 0.8em center;
      padding-right: 2.2em;
    }
    .profile-select:focus { outline: none; border-color: var(--accent); }
    .profile-desc {
      font-size: 0.8rem; color: var(--muted); line-height: 1.55;
      min-height: 1.4em; margin-bottom: 1rem;
    }
    .profile-meta {
      display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.2rem;
    }
    .profile-badge {
      font-family: var(--mono); font-size: 0.65rem; text-transform: uppercase;
      letter-spacing: 0.07em; padding: 0.2em 0.6em; border-radius: 3px;
      background: rgba(0,212,170,0.08); color: var(--accent);
      border: 1px solid rgba(0,212,170,0.2);
    }

    /* Input tabs */
    .input-tabs { display: flex; border-bottom: 1px solid var(--border); margin-bottom: 1.2rem; }
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

    .csr-area {
      width: 100%; background: var(--bg); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text); font-family: var(--mono);
      font-size: 0.72rem; line-height: 1.6; padding: 0.9rem 1rem;
      resize: vertical; min-height: 180px; transition: border-color 0.15s;
    }
    .csr-area:focus { outline: none; border-color: var(--accent); }
    .csr-area::placeholder { color: var(--muted); }

    .file-drop {
      border: 1px dashed var(--border); border-radius: 6px;
      padding: 2.5rem 1rem; text-align: center; cursor: pointer;
      transition: border-color 0.15s, background 0.15s; position: relative;
    }
    .file-drop:hover, .file-drop.drag-over { border-color: var(--accent); background: rgba(0,212,170,0.04); }
    .file-drop input[type=file] { position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; }
    .file-drop p { font-size: 0.85rem; color: var(--muted); pointer-events: none; }
    .file-drop .drop-icon { font-size: 1.6rem; margin-bottom: 0.4rem; }
    .file-selected { font-family: var(--mono); font-size: 0.72rem; color: var(--accent);
                     margin-top: 0.7rem; padding: 0.4rem 0.7rem;
                     background: rgba(0,212,170,0.06); border-radius: 4px; }

    /* Extra inputs */
    .field-row { margin-top: 1.1rem; }
    .field-label { font-family: var(--mono); font-size: 0.68rem; text-transform: uppercase;
                   letter-spacing: 0.08em; color: var(--muted); margin-bottom: 0.35rem; display: block; }
    .field-input {
      width: 100%; background: var(--bg); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text); font-family: var(--mono);
      font-size: 0.82rem; padding: 0.5em 0.9em; transition: border-color 0.15s;
    }
    .field-input:focus { outline: none; border-color: var(--accent); }
    .field-input::placeholder { color: var(--muted); }
    .field-hint { font-size: 0.73rem; color: var(--muted); margin-top: 0.3rem; }

    /* Submit */
    .submit-row { display: flex; align-items: center; gap: 1rem; margin-top: 1.4rem; }
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
    .btn-ghost:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
    .btn-ghost:disabled { opacity: 0.4; cursor: not-allowed; }
    .spinner { width: 18px; height: 18px; border: 2px solid var(--border);
               border-top-color: var(--accent); border-radius: 50%;
               animation: spin 0.7s linear infinite; flex-shrink: 0; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* Error */
    .error-box {
      display: flex; align-items: flex-start; gap: 0.6rem;
      background: rgba(248,113,113,0.08); border: 1px solid rgba(248,113,113,0.3);
      border-radius: 6px; padding: 0.8rem 1rem; margin-top: 1rem;
      font-size: 0.83rem; color: var(--danger);
    }
    #errorMsg { white-space: pre-wrap; font-family: var(--mono); font-size: 0.78rem; }

    /* Result */
    .result-header {
      display: flex; align-items: center; justify-content: space-between;
      flex-wrap: wrap; gap: 0.8rem; margin-bottom: 1.2rem;
    }
    .result-header h2 { font-size: 1rem; font-weight: 600; color: var(--accent); }
    .result-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }

    .cert-info {
      display: grid; grid-template-columns: max-content 1fr;
      gap: 0.3rem 1rem; font-family: var(--mono); font-size: 0.72rem; margin-bottom: 1.2rem;
    }
    .ci-key { color: var(--muted); white-space: nowrap; }
    .ci-val { color: var(--text); word-break: break-all; }

    .pem-wrap { position: relative; margin-bottom: 1rem; }
    .pem-output {
      width: 100%; background: var(--bg); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text); font-family: var(--mono);
      font-size: 0.7rem; line-height: 1.6; padding: 0.9rem 1rem;
      resize: vertical; min-height: 180px; cursor: default;
    }
    .pem-output:focus { outline: none; }

    .chain-note { font-size: 0.78rem; color: var(--muted); margin-top: 0.6rem;
                  padding-top: 1rem; border-top: 1px solid var(--border); }

    /* Revoke */
    .revoke-row {
      display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap;
      margin-top: 1.2rem; padding-top: 1rem; border-top: 1px solid var(--border);
    }
    .revoke-label { font-size: 0.8rem; color: var(--muted); white-space: nowrap; }
    .revoke-reason {
      font-family: var(--mono); font-size: 0.75rem;
      background: var(--bg); border: 1px solid var(--border);
      border-radius: 5px; color: var(--text); padding: 0.45em 0.7em;
      flex: 1; max-width: 240px; cursor: pointer;
    }
    .revoke-reason:focus { outline: none; border-color: var(--danger); }
    .btn-danger {
      font-family: var(--mono); font-size: 0.78rem; letter-spacing: 0.05em;
      text-transform: uppercase; background: #991b1b; color: #fef2f2;
      border: none; border-radius: 5px; padding: 0.55em 1.4em;
      cursor: pointer; font-weight: 600; transition: opacity 0.15s; white-space: nowrap;
    }
    .btn-danger:hover:not(:disabled) { background: #b91c1c; }
    .btn-danger:disabled { opacity: 0.4; cursor: not-allowed; }
    .revoke-result { font-size: 0.83rem; padding: 0.65rem 1rem; border-radius: 6px; margin-top: 0.8rem; }
    .revoke-result.ok  { background: rgba(0,212,170,0.07); border: 1px solid rgba(0,212,170,0.3); color: var(--accent); }
    .revoke-result.err { background: rgba(248,113,113,0.08); border: 1px solid rgba(248,113,113,0.3); color: var(--danger); }

    /* Lint findings */
    .lint-results { margin-top: 1.2rem; padding-top: 1rem; border-top: 1px solid var(--border); }
    .lint-title { font-size: 0.78rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.6rem; }
    .lint-finding { display: flex; align-items: baseline; gap: 0.6rem; font-family: var(--mono); font-size: 0.72rem; padding: 0.3rem 0; border-bottom: 1px solid rgba(255,255,255,0.04); word-break: break-all; }
    .lint-finding:last-child { border-bottom: none; }
    .lint-sev { font-size: 0.62rem; font-weight: 700; letter-spacing: 0.05em; border-radius: 3px; padding: 0.1em 0.45em; white-space: nowrap; flex-shrink: 0; }
    .lint-error .lint-sev, .lint-fatal .lint-sev { background: rgba(248,113,113,0.15); color: #f87171; }
    .lint-error, .lint-fatal { color: #f87171; }
    .lint-warning .lint-sev { background: rgba(251,191,36,0.12); color: #fbbf24; }
    .lint-warning { color: #fbbf24; }
    .lint-notice .lint-sev { background: rgba(96,165,250,0.12); color: #60a5fa; }
    .lint-notice { color: #60a5fa; }
    .lint-info .lint-sev, .lint-pass .lint-sev { background: rgba(160,160,160,0.08); color: var(--muted); }
    .lint-info, .lint-pass { color: var(--muted); }

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
    <h1>MPCA Certificate Factory</h1>
    <p>Issue S/MIME, client authentication, document signing, and code signing certificates
       from the thameur.org Multi-Purpose CA. Profiles drive all extensions automatically.</p>
  </div>

  <div class="warn-banner">
    <span>⚠</span>
    <span><strong>Test infrastructure.</strong> Certificates from this CA are not trusted by any browser or OS
    and must never be used to secure real services.
    <a href="<?= htmlspecialchars(MPCA_BASE_URL . '/mpca.html', ENT_QUOTES) ?>">CA repository →</a></span>
  </div>

<?php if ($noProfiles): ?>
  <div class="card">
    <p style="color:var(--muted);font-size:0.9rem;">
      No certificate profiles found in <code><?= htmlspecialchars(MPCA_PROFILES_DIR, ENT_QUOTES) ?></code>.<br>
      Run <code>mpca_init.sh</code> to initialize the CA hierarchy, then ensure profile
      <code>.cnf</code> files are present in the profiles directory.
    </p>
  </div>
<?php else: ?>

  <!-- Issue card -->
  <div class="card">

    <!-- Profile selector -->
    <div class="card-section-label">Certificate Profile</div>
    <select class="profile-select" id="profileSelect" name="profile">
      <option value="">— Select a profile —</option>
      <?php foreach ($profiles as $id => $p): ?>
      <option value="<?= htmlspecialchars($id, ENT_QUOTES) ?>">
        <?= htmlspecialchars($p['label'], ENT_QUOTES) ?>
      </option>
      <?php endforeach; ?>
    </select>
    <div class="profile-desc" id="profileDesc">Select a profile to see its description.</div>
    <div class="profile-meta" id="profileMeta" hidden></div>

    <form id="issueForm" enctype="multipart/form-data" novalidate>
      <input type="hidden" name="profile" id="profileInput">

      <!-- CSR input -->
      <div class="card-section-label" style="margin-top:1.2rem">Certificate Signing Request</div>
      <div class="input-tabs" role="tablist">
        <button class="input-tab active" role="tab" data-tab="paste">Paste CSR</button>
        <button class="input-tab"        role="tab" data-tab="upload">Upload File</button>
      </div>

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

      <!-- Email field (shown for email san_type profiles) -->
      <div class="field-row" id="emailRow" hidden>
        <label class="field-label" for="emailInput">Email Address (rfc822Name SAN)</label>
        <input class="field-input" type="email" id="emailInput" name="email"
               placeholder="user@example.com" autocomplete="email" spellcheck="false">
        <p class="field-hint">Will appear as <code>rfc822Name</code> in the Subject Alternative Name extension.</p>
      </div>

      <div class="submit-row">
        <button class="btn-primary" type="submit" id="btnIssue" disabled>Issue Certificate</button>
        <div class="spinner" id="spinner" hidden></div>
      </div>

    </form>

    <div class="error-box" id="errorBox" hidden>
      <span>✕</span>
      <span id="errorMsg"></span>
    </div>
  </div>

  <!-- Result card -->
  <div class="card" id="resultCard" hidden>
    <div class="result-header">
      <h2 id="resultTitle">✔ Certificate Issued</h2>
      <div class="result-actions">
        <button class="btn-ghost" id="btnCopy">Copy PEM</button>
        <button class="btn-ghost" id="btnDl">Download .crt</button>
        <button class="btn-ghost" id="btnLint">Lint</button>
        <button class="btn-ghost" id="btnParse">Parse</button>
      </div>
    </div>

    <div class="cert-info" id="certInfo"></div>

    <textarea class="pem-output" id="pemOutput" readonly spellcheck="false"></textarea>

    <p class="chain-note" id="chainNote"></p>

    <div class="lint-results" id="lintResults" hidden>
      <p class="lint-title">Lint Results</p>
      <div id="lintFindings"></div>
    </div>

    <div class="revoke-row">
      <span class="revoke-label">Revocation reason:</span>
      <select class="revoke-reason" id="revokeReason">
        <option value="unspecified">Unspecified</option>
        <option value="keyCompromise">Key Compromise</option>
        <option value="affiliationChanged">Affiliation Changed</option>
        <option value="superseded">Superseded</option>
        <option value="cessationOfOperation">Cessation of Operation</option>
      </select>
      <button class="btn-danger" id="btnRevoke">Revoke this Certificate</button>
    </div>
    <div class="revoke-result" id="revokeResult" hidden></div>
  </div>

<?php endif; ?>

</main>

<footer class="site-footer">
  <span>&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="/">Home</a>
    <a href="<?= htmlspecialchars(MPCA_BASE_URL . '/mpca.html', ENT_QUOTES) ?>">CA Repository</a>
    <a href="/references.php">PKI References</a>
    <a href="/privacy.php">Privacy Policy</a>
  </div>
</footer>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>

<script>
(function () {
  'use strict';

  var RECAPTCHA_SITE_KEY = <?= json_encode(RECAPTCHA_SITE_KEY) ?>;
  var MPCA_BASE_URL      = <?= json_encode(MPCA_BASE_URL) ?>;

  var PROFILES = <?= json_encode(array_map(fn($p) => [
    'label'     => $p['label'],
    'desc'      => $p['description'],
    'san_type'  => $p['san_type'],
    'sub_ca'    => $p['sub_ca'],
    'validity'  => $p['validity_days'],
    'key_types' => $p['key_types'],
  ], $profiles), JSON_UNESCAPED_UNICODE) ?>;

  var CA_LABELS = { smime: 'S/MIME CA', personal: 'Personal CA', codesign: 'Code Signing CA' };

  function getRecaptchaToken(action) {
    return new Promise(function (resolve) {
      if (typeof grecaptcha === 'undefined' || !RECAPTCHA_SITE_KEY) { resolve(''); return; }
      grecaptcha.ready(function () {
        grecaptcha.execute(RECAPTCHA_SITE_KEY, { action: action }).then(resolve);
      });
    });
  }

  // ── Pre-fill CSR from csr_generator / artifact_parser via sessionStorage ─────
  (function () {
    var stored = sessionStorage.getItem('pki_prefill_csr') || sessionStorage.getItem('meerkat_csr');
    if (stored) {
      var ta = document.getElementById('csrText');
      if (ta && !ta.value.trim()) ta.value = stored;
      sessionStorage.removeItem('pki_prefill_csr');
      sessionStorage.removeItem('meerkat_csr');
    }
  })();

  // ── Profile selector ─────────────────────────────────────────────────────────
  var profileSelect = document.getElementById('profileSelect');
  var profileInput  = document.getElementById('profileInput');
  var profileDesc   = document.getElementById('profileDesc');
  var profileMeta   = document.getElementById('profileMeta');
  var emailRow      = document.getElementById('emailRow');
  var btnIssue      = document.getElementById('btnIssue');

  profileSelect.addEventListener('change', function () {
    var id = profileSelect.value;
    profileInput.value = id;
    var p = id ? PROFILES[id] : null;

    if (!p) {
      profileDesc.textContent  = 'Select a profile to see its description.';
      profileMeta.hidden = true;
      emailRow.hidden    = true;
      btnIssue.disabled  = true;
      return;
    }

    profileDesc.textContent = p.desc;
    profileMeta.hidden = false;
    profileMeta.innerHTML =
      '<span class="profile-badge">' + (CA_LABELS[p.sub_ca] || p.sub_ca) + '</span>' +
      '<span class="profile-badge">Max ' + p.validity + ' days</span>' +
      '<span class="profile-badge">SAN: ' + (p.san_type === 'none' ? 'none' : p.san_type) + '</span>' +
      '<span class="profile-badge">Keys: ' + p.key_types.toUpperCase() + '</span>';

    emailRow.hidden   = (p.san_type !== 'email');
    btnIssue.disabled = false;
  });

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
    fileDrop.addEventListener(ev, function (e) { e.preventDefault(); fileDrop.classList.add('drag-over'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    fileDrop.addEventListener(ev, function (e) { e.preventDefault(); fileDrop.classList.remove('drag-over'); });
  });
  fileDrop.addEventListener('drop', function (e) {
    var f = e.dataTransfer && e.dataTransfer.files[0];
    if (f) { fileSelected.hidden = false; fileSelected.textContent = '📄 ' + f.name + ' (' + Math.ceil(f.size / 1024) + ' KB)'; }
  });
  fileInput.addEventListener('change', function () {
    if (fileInput.files[0]) {
      fileSelected.hidden = false;
      fileSelected.textContent = '📄 ' + fileInput.files[0].name + ' (' + Math.ceil(fileInput.files[0].size / 1024) + ' KB)';
    }
  });

  // ── Form submission ──────────────────────────────────────────────────────────
  var form       = document.getElementById('issueForm');
  var spinner    = document.getElementById('spinner');
  var errorBox   = document.getElementById('errorBox');
  var errorMsg   = document.getElementById('errorMsg');
  var resultCard = document.getElementById('resultCard');
  var certInfo   = document.getElementById('certInfo');
  var pemOutput  = document.getElementById('pemOutput');
  var chainNote  = document.getElementById('chainNote');
  var issuedIssuerPem = '';

  form.addEventListener('submit', function (e) { e.preventDefault(); doIssue(); });

  async function doIssue() {
    var profileId = profileSelect.value;
    if (!profileId) { showError('Please select a certificate profile.'); return; }

    var activeTab = document.querySelector('.input-tab.active');
    if (activeTab && activeTab.dataset.tab === 'paste') {
      if (!document.getElementById('csrText').value.trim()) {
        showError('Please paste a PEM CSR.'); return;
      }
    }

    var p = PROFILES[profileId];
    if (p && p.san_type === 'email') {
      var em = document.getElementById('emailInput').value.trim();
      if (!em) { showError('An email address is required for this profile.'); return; }
    }

    setLoading(true);
    hideError();
    resultCard.hidden = true;

    var fd = new FormData(form);
    fd.set('action', 'issue');
    fd.set('g_recaptcha_token', await getRecaptchaToken('mpca_issue'));

    try {
      var resp = await fetch('', { method: 'POST', body: fd });
      var data = await resp.json();
    } catch (err) {
      showError('Request failed: ' + err.message);
      setLoading(false);
      return;
    }

    setLoading(false);
    if (data.error) { showError(data.error); return; }
    showResult(data);
  }

  function showResult(data) {
    document.getElementById('resultTitle').textContent = '✔ ' + data.profile + ' Certificate Issued';

    var rows = [
      ['Profile',    data.profile],
      ['Subject',    data.subject],
      ['Issuer',     data.issuer],
      ['Not Before', data.not_before],
      ['Not After',  data.not_after],
      ['Serial',     data.serial],
      ['Key',        data.key_bits + '-bit'],
    ];
    if (data.email) rows.splice(2, 0, ['Email (SAN)', data.email]);

    certInfo.innerHTML = rows.map(function (r) {
      return '<div class="ci-key">' + r[0] + '</div><div class="ci-val">' + esc(r[1]) + '</div>';
    }).join('');

    pemOutput.value = data.certificate;
    issuedIssuerPem = data.issuer_pem || '';
    chainNote.innerHTML = 'Chain: <a href="' + esc(MPCA_BASE_URL) + '/' +
      ({ smime: 'smime_chain.pem', personal: 'personal_chain.pem', codesign: 'codesign_chain.pem' }[
        (PROFILES[profileSelect.value] || {}).sub_ca
      ] || 'mpca.html') + '" target="_blank" rel="noopener">Download issuing chain PEM</a>';

    var lintSection  = document.getElementById('lintResults');
    var lintFindings = document.getElementById('lintFindings');
    var findings = data.lint_findings || [];
    if (findings.length > 0) {
      lintFindings.innerHTML = findings.map(function (f) {
        var label = '[' + f.linter + '] ' + (f.code ? f.code + ': ' : '') + f.finding;
        return '<div class="lint-finding lint-' + f.severity + '">'
             + '<span class="lint-sev">' + f.severity.toUpperCase() + '</span>'
             + '<span>' + esc(label) + '</span>'
             + '</div>';
      }).join('');
      lintSection.hidden = false;
    } else {
      lintSection.hidden = true;
    }

    resultCard.hidden = false;
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ── Result buttons ────────────────────────────────────────────────────────────
  document.getElementById('btnCopy').addEventListener('click', function () {
    navigator.clipboard.writeText(pemOutput.value);
  });
  document.getElementById('btnDl').addEventListener('click', function () {
    dlText(pemOutput.value, 'mpca-cert.crt', 'application/x-x509-user-cert');
  });
  document.getElementById('btnLint').addEventListener('click', function () {
    if (!pemOutput.value) return;
    sessionStorage.setItem('pki_prefill_cert',   pemOutput.value);
    sessionStorage.setItem('pki_prefill_issuer', issuedIssuerPem);
    window.open('/linters.php', '_blank');
  });
  document.getElementById('btnParse').addEventListener('click', function () {
    if (!pemOutput.value) return;
    sessionStorage.setItem('pki_prefill_cert', pemOutput.value);
    window.open('/artifact_parser.php', '_blank');
  });

  // ── Revoke ────────────────────────────────────────────────────────────────────
  var btnRevoke    = document.getElementById('btnRevoke');
  var revokeResult = document.getElementById('revokeResult');
  btnRevoke.addEventListener('click', async function () {
    if (!confirm('Revoke this certificate? This cannot be undone.')) return;
    btnRevoke.disabled = true;
    revokeResult.hidden = true;

    var fd = new FormData();
    fd.append('action', 'revoke');
    fd.append('cert',   pemOutput.value);
    fd.append('reason', document.getElementById('revokeReason').value);
    fd.append('g_recaptcha_token', await getRecaptchaToken('mpca_revoke'));

    try {
      var resp = await fetch('', { method: 'POST', body: fd });
      var data = await resp.json();
    } catch (err) {
      revokeResult.className = 'revoke-result err';
      revokeResult.textContent = 'Request failed: ' + err.message;
      revokeResult.hidden = false;
      btnRevoke.disabled = false;
      return;
    }

    revokeResult.hidden = false;
    if (data.ok) {
      revokeResult.className   = 'revoke-result ok';
      revokeResult.textContent = data.message;
    } else {
      revokeResult.className   = 'revoke-result err';
      revokeResult.textContent = data.error || 'Revocation failed';
      btnRevoke.disabled = false;
    }
  });

  // ── Utilities ────────────────────────────────────────────────────────────────
  function setLoading(on) {
    btnIssue.disabled = on;
    spinner.hidden    = !on;
  }
  function showError(msg) {
    errorMsg.textContent = msg;
    errorBox.hidden = false;
  }
  function hideError() { errorBox.hidden = true; }

  function esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
  function dlText(content, filename, type) {
    var blob = new Blob([content], { type: type });
    var url  = URL.createObjectURL(blob);
    var a    = Object.assign(document.createElement('a'), { href: url, download: filename });
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }

})();
</script>

<?= recaptcha_bind_js([
    ['button_name' => 'action', 'button_value' => 'issue',  'action' => 'mpca_issue'],
    ['button_name' => 'action', 'button_value' => 'revoke', 'action' => 'mpca_revoke'],
]) ?>

</body>
</html>
