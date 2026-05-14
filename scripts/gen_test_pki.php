<?php
/**
 * gen_test_pki.php — Meerkat Test PKI generator
 *
 * Generates (or rotates) the Meerkat Root CA and Meerkat Test Issuing CA 1.
 * Run on the server whenever you need a fresh set of test certificates.
 *
 * Usage:
 *   php scripts/gen_test_pki.php
 *
 * Output:
 *   /var/www/thameur.org/pki-ca/private/root.key       — Root CA key (mode 600)
 *   /var/www/thameur.org/pki-ca/private/issuing.key    — Issuing CA key (mode 600)
 *   /var/www/thameur.org/pki-ca/root-db/openssl.cnf    — persistent Root CA config (for cron)
 *   /var/www/thameur.org/pki-ca/issuing-db/openssl.cnf — persistent Issuing CA config (for cron)
 *   /var/www/pki.thameur.org/meerkat-root.crt
 *   /var/www/pki.thameur.org/meerkat-root.crl          — Root ARL (lists revoked CAs, 365-day validity)
 *   /var/www/pki.thameur.org/meerkat-issuing.crt
 *   /var/www/pki.thameur.org/meerkat-issuing.crl       — Issuing CRL (lists revoked end-entities, 7-day validity)
 */

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit;
}

// ── Terminal colours ──────────────────────────────────────────────────────────

function step(string $msg): void  { echo "\033[1;36m▶ $msg\033[0m\n"; }
function ok(string $msg): void    { echo "\033[1;32m✔ $msg\033[0m\n"; }
function fail(string $msg): void  { echo "\033[1;31m✘ $msg\033[0m\n"; }
function info(string $msg): void  { echo "\033[0;37m  $msg\033[0m\n"; }
function warn(string $msg): void  { echo "\033[1;33m⚠ $msg\033[0m\n"; }

// ── Paths ─────────────────────────────────────────────────────────────────────

$ROOT    = dirname(__DIR__);
$PKI_CA  = $ROOT . '/pki-ca';
$PRIV    = $PKI_CA . '/private';
$PKI_WEB = '/var/www/pki.thameur.org';

$ROOT_KEY  = $PRIV    . '/root.key';
$ISSU_KEY  = $PRIV    . '/issuing.key';
$ROOT_CRT  = $PKI_WEB . '/meerkat-root.crt';
$ROOT_CRL  = $PKI_WEB . '/meerkat-root.crl';
$ISSU_CRT  = $PKI_WEB . '/meerkat-issuing.crt';
$ISSU_CRL  = $PKI_WEB . '/meerkat-issuing.crl';

// Persistent CA databases (survive between CRL refreshes, used by cron scripts)
$ROOT_DB   = $PKI_CA . '/root-db';
$ISSU_DB   = $PKI_CA . '/issuing-db';

// ── CA identity ───────────────────────────────────────────────────────────────

$ROOT_SUBJ  = '/C=TN/O=Thameur Belghith/CN=Meerkat Root CA';
$ISSU_SUBJ  = '/C=TN/O=Thameur Belghith/CN=Meerkat Test Issuing CA 1';
$ROOT_DAYS  = 3650;   // ~10 years
$ISSU_DAYS  = 1825;   // ~5 years
$ARL_DAYS   = 365;    // Root ARL — 1 year (revoked CAs change rarely)
$CRL_DAYS   = 7;      // Issuing CRL — 7 days (CABF BR §4.9.7 max 10 days)

// AIA / CDP URLs served from pki.thameur.org
$ROOT_AIA_URL = 'http://pki.thameur.org/meerkat-root.crt';
$ROOT_ARL_URL = 'http://pki.thameur.org/meerkat-root.crl';   // ARL signed by Root (CDP in Issuing CA cert)
$ISSU_AIA_URL = 'http://pki.thameur.org/meerkat-issuing.crt';
$ISSU_CRL_URL = 'http://pki.thameur.org/meerkat-issuing.crl'; // CRL signed by Issuing (CDP in end-entity certs)

// ── Pre-flight ────────────────────────────────────────────────────────────────

step('Pre-flight checks');

$openssl = '/usr/bin/openssl';
if (!is_executable($openssl)) {
    fail("openssl not found at $openssl");
    exit(1);
}
info("openssl: $openssl");

$ver = trim((string) shell_exec("$openssl version 2>&1"));
info("version: $ver");
ok('openssl found');

// ── Directory setup ───────────────────────────────────────────────────────────

step('Creating directories');

foreach ([$PKI_CA, $PRIV, $PKI_WEB, $ROOT_DB, $ISSU_DB] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
        info("created $dir");
    }
}
chmod($PRIV, 0700);

// .gitignore: keep directory, ignore all private key material
$gi = $PKI_CA . '/.gitignore';
if (!file_exists($gi)) {
    file_put_contents($gi, "private/\n");
    info("wrote $gi");
}
ok('Directories ready');

// ── Temp dir for OpenSSL config files ─────────────────────────────────────────

$tmp = sys_get_temp_dir() . '/meerkat_pki_' . getmypid();
mkdir($tmp, 0700, true);

// Cleanup on exit
register_shutdown_function(function () use ($tmp) {
    if (is_dir($tmp)) {
        foreach (glob("$tmp/*") as $f) { @unlink($f); }
        @rmdir($tmp);
    }
});

// ── Helper: run a command with proc_open (no shell injection) ─────────────────

function run(array $cmd, ?string $stdinData = null): array
{
    $desc = [
        0 => $stdinData !== null ? ['pipe', 'r'] : ['file', '/dev/null', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = proc_open($cmd, $desc, $pipes);
    if (!$proc) {
        return ['ok' => false, 'out' => '', 'err' => 'proc_open failed', 'code' => -1];
    }
    if ($stdinData !== null) {
        fwrite($pipes[0], $stdinData);
        fclose($pipes[0]);
    }
    $out  = stream_get_contents($pipes[1]);
    $err  = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return ['ok' => $code === 0, 'out' => $out, 'err' => $err, 'code' => $code];
}

// ── Helper: write a temp openssl.cnf snippet ──────────────────────────────────

function writeCnf(string $path, string $content): void
{
    file_put_contents($path, $content);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Root CA private key (RSA-4096)
// ─────────────────────────────────────────────────────────────────────────────

step('Generating Root CA private key (RSA-4096)');

$r = run([$openssl, 'genrsa', '-out', $ROOT_KEY, '4096']);
if (!$r['ok']) {
    fail("genrsa root key: " . trim($r['err']));
    exit(1);
}
chmod($ROOT_KEY, 0600);
ok('Root CA key: ' . $ROOT_KEY);

// ─────────────────────────────────────────────────────────────────────────────
// 2. Root CA certificate (self-signed)
//    Extensions: basicConstraints critical, keyUsage critical, SKI
//    No policies, no AIA, no CDP, no EKU — per BR §7.1.2.1
// ─────────────────────────────────────────────────────────────────────────────

step('Generating Root CA certificate');

$rootCnfPath = "$tmp/root.cnf";
writeCnf($rootCnfPath, <<<CNF
[ req ]
distinguished_name = dn
x509_extensions    = v3_root_ca
prompt             = no

[ dn ]
C  = TN
O  = Thameur Belghith
CN = Meerkat Root CA

[ v3_root_ca ]
basicConstraints = critical, CA:TRUE
keyUsage         = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
CNF);

$r = run([
    $openssl, 'req', '-new', '-x509',
    '-key', $ROOT_KEY,
    '-out', $ROOT_CRT,
    '-days', (string) $ROOT_DAYS,
    '-sha256',
    '-config', $rootCnfPath,
    '-subj', $ROOT_SUBJ,
]);
if (!$r['ok']) {
    fail("root CA cert: " . trim($r['err']));
    exit(1);
}
ok('Root CA cert: ' . $ROOT_CRT);

// ─────────────────────────────────────────────────────────────────────────────
// 3. Issuing CA private key (RSA-2048)
// ─────────────────────────────────────────────────────────────────────────────

step('Generating Issuing CA private key (RSA-2048)');

$r = run([$openssl, 'genrsa', '-out', $ISSU_KEY, '2048']);
if (!$r['ok']) {
    fail("genrsa issuing key: " . trim($r['err']));
    exit(1);
}
// Root key stays root-only; issuing key readable by www-data for cert_factory.php
chgrp($PRIV,     'www-data'); chmod($PRIV,     0710);
chgrp($ISSU_KEY, 'www-data'); chmod($ISSU_KEY, 0640);
ok('Issuing CA key: ' . $ISSU_KEY);

// ─────────────────────────────────────────────────────────────────────────────
// 4. Issuing CA CSR
// ─────────────────────────────────────────────────────────────────────────────

step('Generating Issuing CA CSR');

$issuCsr = "$tmp/issuing.csr";
$issuCnfPath = "$tmp/issuing_req.cnf";
writeCnf($issuCnfPath, <<<CNF
[ req ]
distinguished_name = dn
prompt             = no

[ dn ]
C  = TN
O  = Thameur Belghith
CN = Meerkat Test Issuing CA 1
CNF);

$r = run([
    $openssl, 'req', '-new',
    '-key', $ISSU_KEY,
    '-out', $issuCsr,
    '-config', $issuCnfPath,
]);
if (!$r['ok']) {
    fail("issuing CSR: " . trim($r['err']));
    exit(1);
}
ok('Issuing CA CSR generated');

// ─────────────────────────────────────────────────────────────────────────────
// 5. Issuing CA certificate — signed by Root CA
//    Extensions per BR §7.1.2.2:
//      basicConstraints critical CA:TRUE pathLen:0
//      keyUsage critical keyCertSign cRLSign
//      extendedKeyUsage serverAuth (required per cabf.serverauth.ca)
//      SKI hash, AKI from Root SKI
//      certificatePolicies 2.23.140.1.2.1 (DV)
//      AIA (caIssuers) → Root CRT URL
//      CDP → Root ARL URL (ARL is issued by the CA that signed this cert — the Root)
// ─────────────────────────────────────────────────────────────────────────────

step('Signing Issuing CA certificate');

$issuExtPath = "$tmp/issuing_ext.cnf";
writeCnf($issuExtPath, <<<CNF
[ v3_issuing_ca ]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
certificatePolicies    = 2.23.140.1.2.1
authorityInfoAccess    = caIssuers;URI:$ROOT_AIA_URL
crlDistributionPoints  = URI:$ROOT_ARL_URL
CNF);

// Use a minimal serial database under tmp so openssl x509 does not need a full CA dir
$r = run([
    $openssl, 'x509', '-req',
    '-in', $issuCsr,
    '-CA', $ROOT_CRT,
    '-CAkey', $ROOT_KEY,
    '-CAcreateserial',
    '-CAserial', "$tmp/root.srl",
    '-out', $ISSU_CRT,
    '-days', (string) $ISSU_DAYS,
    '-sha256',
    '-extfile', $issuExtPath,
    '-extensions', 'v3_issuing_ca',
]);
if (!$r['ok']) {
    fail("issuing CA cert: " . trim($r['err']));
    exit(1);
}
ok('Issuing CA cert: ' . $ISSU_CRT);

// ─────────────────────────────────────────────────────────────────────────────
// 6. Persistent CA databases + Root ARL + Issuing CRL
//
//    Each CA needs its own openssl.cnf with an index.txt and crlnumber.
//    These persist on disk so the cron refresh scripts can re-sign CRLs
//    without re-running the full PKI rotation.
//    On each rotation the databases are reset (fresh CA = no prior revocations).
// ─────────────────────────────────────────────────────────────────────────────

step('Initialising persistent CA databases');

// Reset both databases on rotation (new CA, fresh slate)
// root-db: root-only (only cron runs refresh_root_crl.sh as root)
file_put_contents("$ROOT_DB/index.txt", '');
file_put_contents("$ROOT_DB/crlnumber", "01\n");
chmod($ROOT_DB, 0700);

// issuing-db: www-data needs rwx so cert_factory.php can sign via openssl ca
file_put_contents("$ISSU_DB/index.txt", '');
file_put_contents("$ISSU_DB/crlnumber", "01\n");
chgrp($ISSU_DB, 'www-data'); chmod($ISSU_DB, 0770);
chgrp("$ISSU_DB/index.txt",  'www-data'); chmod("$ISSU_DB/index.txt",  0660);
chgrp("$ISSU_DB/crlnumber",  'www-data'); chmod("$ISSU_DB/crlnumber",  0660);

// Write persistent openssl.cnf for Root CA (used by cron/refresh_root_crl.sh)
writeCnf("$ROOT_DB/openssl.cnf", <<<CNF
[ ca ]
default_ca = CA_default

[ CA_default ]
database         = $ROOT_DB/index.txt
crlnumber        = $ROOT_DB/crlnumber
certificate      = $ROOT_CRT
private_key      = $ROOT_KEY
default_md       = sha256
default_crl_days = $ARL_DAYS
crl_extensions   = crl_ext

[ crl_ext ]
authorityKeyIdentifier = keyid:always
CNF);

// Write persistent openssl.cnf for Issuing CA
// Used by: cron/refresh_issuing_crl.sh AND cert_factory.php (openssl ca signing)
$ISSU_NEWCERTS = $ISSU_DB . '/newcerts';
if (!is_dir($ISSU_NEWCERTS)) {
    mkdir($ISSU_NEWCERTS, 0700, true);
    info("created $ISSU_NEWCERTS");
}
chgrp($ISSU_NEWCERTS, 'www-data'); chmod($ISSU_NEWCERTS, 0770);

// Reset cert serial on rotation (fresh CA)
file_put_contents("$ISSU_DB/cert.srl", "01\n");
chgrp("$ISSU_DB/cert.srl", 'www-data'); chmod("$ISSU_DB/cert.srl", 0660);

writeCnf("$ISSU_DB/openssl.cnf", <<<CNF
[ ca ]
default_ca = CA_default

[ CA_default ]
database         = $ISSU_DB/index.txt
serial           = $ISSU_DB/cert.srl
new_certs_dir    = $ISSU_DB/newcerts
crlnumber        = $ISSU_DB/crlnumber
certificate      = $ISSU_CRT
private_key      = $ISSU_KEY
default_md       = sha256
default_days     = 90
default_crl_days = $CRL_DAYS
unique_subject   = no
copy_extensions  = none
policy           = policy_anything

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

[ crl_ext ]
authorityKeyIdentifier = keyid:always
CNF);

chgrp("$ISSU_DB/openssl.cnf", 'www-data'); chmod("$ISSU_DB/openssl.cnf", 0640);
ok('CA databases initialised');

// ── Root ARL (Authority Revocation List — lists revoked CA certs, 365-day validity)

step('Generating Root CA ARL');

$r = run([
    $openssl, 'ca',
    '-gencrl',
    '-config',  "$ROOT_DB/openssl.cnf",
    '-out',     $ROOT_CRL,
    '-outform', 'DER',
    '-batch',
]);
if (!$r['ok']) {
    fail("Root ARL generation: " . trim($r['err']));
    exit(1);
}
ok('Root ARL: ' . $ROOT_CRL);

// ── Issuing CRL (lists revoked end-entity certs, 7-day validity)

step('Generating Issuing CA CRL');

$r = run([
    $openssl, 'ca',
    '-gencrl',
    '-config',  "$ISSU_DB/openssl.cnf",
    '-out',     $ISSU_CRL,
    '-outform', 'DER',
    '-batch',
]);
if (!$r['ok']) {
    fail("Issuing CRL generation: " . trim($r['err']));
    exit(1);
}
ok('Issuing CRL: ' . $ISSU_CRL);

// Allow www-data (PHP-FPM) to overwrite the issuing CRL after revocations
chgrp($ISSU_CRL, 'www-data'); chmod($ISSU_CRL, 0664);

// ─────────────────────────────────────────────────────────────────────────────
// 7. Chain verification
// ─────────────────────────────────────────────────────────────────────────────

step('Verifying certificate chain');

$r = run([
    $openssl, 'verify',
    '-CAfile', $ROOT_CRT,
    $ISSU_CRT,
]);
if (!$r['ok']) {
    fail("Chain verification failed: " . trim($r['err']) . trim($r['out']));
    exit(1);
}
ok(trim($r['out']));

// ─────────────────────────────────────────────────────────────────────────────
// 8. Fingerprint summary
// ─────────────────────────────────────────────────────────────────────────────

step('Certificate fingerprints');

foreach ([
    'Root CA'     => $ROOT_CRT,
    'Issuing CA'  => $ISSU_CRT,
] as $label => $cert) {
    $r = run([$openssl, 'x509', '-in', $cert, '-noout', '-fingerprint', '-sha256']);
    info(sprintf('%-12s %s', $label, trim($r['out'])));
    $r2 = run([$openssl, 'x509', '-in', $cert, '-noout', '-dates']);
    foreach (explode("\n", trim($r2['out'])) as $line) {
        if ($line) info(str_repeat(' ', 12) . $line);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Optional zlint run
// ─────────────────────────────────────────────────────────────────────────────

$zlint = '/usr/local/bin/zlint';
if (is_executable($zlint)) {
    step('Running zlint');
    foreach ([
        'Root CA'    => $ROOT_CRT,
        'Issuing CA' => $ISSU_CRT,
    ] as $label => $cert) {
        // Convert PEM → DER for zlint
        $der = "$tmp/" . strtolower(str_replace(' ', '_', $label)) . '.der';
        run([$openssl, 'x509', '-in', $cert, '-out', $der, '-outform', 'DER']);

        $r = run([$zlint, '-certFile', $der]);
        $lines = array_filter(explode("\n", trim($r['out'])));

        $errors = array_filter($lines, fn($l) => str_starts_with($l, 'e_'));
        $warns  = array_filter($lines, fn($l) => str_starts_with($l, 'w_'));

        info("$label — " . count($errors) . " errors, " . count($warns) . " warnings");
        foreach ($errors as $e) {
            warn("  $e");
        }
    }
    ok('zlint done');
} else {
    info('zlint not in PATH — skipping lint (install from https://github.com/zmap/zlint)');
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Write index.html for pki.thameur.org
// ─────────────────────────────────────────────────────────────────────────────

step('Writing index.html');

function cert_meta(string $openssl, string $cert): array
{
    $fp   = run([$openssl, 'x509', '-in', $cert, '-noout', '-fingerprint', '-sha256']);
    $fp   = trim(str_replace('sha256 Fingerprint=', '', $fp['out']));
    $dates = run([$openssl, 'x509', '-in', $cert, '-noout', '-dates']);
    $not_before = $not_after = '';
    foreach (explode("\n", $dates['out']) as $line) {
        if (str_starts_with($line, 'notBefore=')) $not_before = trim(substr($line, 10));
        if (str_starts_with($line, 'notAfter='))  $not_after  = trim(substr($line, 9));
    }
    return ['fp' => $fp, 'not_before' => $not_before, 'not_after' => $not_after];
}

$root_meta = cert_meta($openssl, $ROOT_CRT);
$issu_meta = cert_meta($openssl, $ISSU_CRT);
$generated = gmdate('j F Y \a\t H:i \U\T\C');

$html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Meerkat Test PKI — pki.thameur.org</title>
  <style>
    :root {
      --bg: #0e1014; --surface: #13171e; --border: #2a3040;
      --accent: #00d4aa; --text: #d4dae6; --muted: #6b7a90;
      --mono: 'IBM Plex Mono', 'Fira Mono', monospace;
      --sans: 'IBM Plex Sans', system-ui, sans-serif;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans);
           font-weight: 300; line-height: 1.75; padding: 3rem 1.5rem 5rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }
    .wrap { max-width: 760px; margin: 0 auto; }

    h1 { font-size: 1.6rem; font-weight: 600; color: #fff; margin-bottom: 0.25rem; }
    .sub { font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
           letter-spacing: 0.05em; margin-bottom: 2.5rem; }

    .warning {
      border: 1px solid #7c2d12; background: rgba(124,45,18,0.12);
      border-radius: 6px; padding: 0.9rem 1.1rem; margin-bottom: 2.5rem;
      font-size: 0.83rem; color: #fca5a5;
    }
    .warning strong { color: #f87171; }

    h2 { font-size: 0.72rem; font-family: var(--mono); text-transform: uppercase;
         letter-spacing: 0.1em; color: var(--muted); margin-bottom: 1rem; }

    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 1.2rem 1.4rem; margin-bottom: 1rem;
    }
    .card-title { font-weight: 600; color: #fff; margin-bottom: 0.6rem; }
    .card-meta { font-family: var(--mono); font-size: 0.7rem; color: var(--muted);
                 line-height: 1.9; word-break: break-all; }
    .card-meta span { color: var(--text); }
    .dl-btn {
      display: inline-block; margin-top: 0.9rem;
      font-family: var(--mono); font-size: 0.7rem; letter-spacing: 0.06em;
      text-transform: uppercase; border: 1px solid var(--accent);
      color: var(--accent); border-radius: 4px; padding: 0.3em 0.85em;
      transition: background 0.15s;
    }
    .dl-btn:hover { background: rgba(0,212,170,0.1); color: #fff; border-color: #fff; }

    .footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border);
              font-family: var(--mono); font-size: 0.68rem; color: var(--muted); }
    .footer a { color: var(--muted); }
    .footer a:hover { color: var(--accent); }
  </style>
</head>
<body>
<div class="wrap">

  <h1>Meerkat Test PKI</h1>
  <p class="sub">pki.thameur.org &nbsp;·&nbsp; Generated {$generated}</p>

  <div class="warning">
    <strong>Test use only.</strong> These certificates are not trusted by any
    browser or operating system and must never be used to secure real services.
    They exist solely to validate linter behaviour on <a href="https://thameur.org">thameur.org</a>.
  </div>

  <h2>Certificates &amp; CRL</h2>

  <div class="card">
    <div class="card-title">Meerkat Root CA</div>
    <div class="card-meta">
      RSA 4096 &nbsp;·&nbsp; SHA-256 &nbsp;·&nbsp; Self-signed<br>
      Not before &nbsp;<span>{$root_meta['not_before']}</span><br>
      Not after &nbsp;&nbsp;<span>{$root_meta['not_after']}</span><br>
      SHA-256 &nbsp;&nbsp;&nbsp;&nbsp;<span>{$root_meta['fp']}</span>
    </div>
    <a class="dl-btn" href="/meerkat-root.crt">Download .crt</a>
  </div>

  <div class="card">
    <div class="card-title">Meerkat Test Issuing CA 1</div>
    <div class="card-meta">
      RSA 2048 &nbsp;·&nbsp; SHA-256 &nbsp;·&nbsp; Signed by Root CA<br>
      Not before &nbsp;<span>{$issu_meta['not_before']}</span><br>
      Not after &nbsp;&nbsp;<span>{$issu_meta['not_after']}</span><br>
      SHA-256 &nbsp;&nbsp;&nbsp;&nbsp;<span>{$issu_meta['fp']}</span><br>
      AIA &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span>http://pki.thameur.org/meerkat-root.crt</span><br>
      CDP &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span>http://pki.thameur.org/meerkat-root.crl</span>
    </div>
    <a class="dl-btn" href="/meerkat-issuing.crt">Download .crt</a>
    &nbsp;
    <a class="dl-btn" href="/meerkat-issuing.crl">Download issuing CRL</a>
  </div>

  <div class="card">
    <div class="card-title">Root ARL &amp; Issuing CRL</div>
    <div class="card-meta">
      Root ARL &nbsp;&nbsp;&nbsp;<span>http://pki.thameur.org/meerkat-root.crl</span> &nbsp;·&nbsp; 365-day validity<br>
      Issuing CRL &nbsp;<span>http://pki.thameur.org/meerkat-issuing.crl</span> &nbsp;·&nbsp; 7-day validity
    </div>
    <a class="dl-btn" href="/meerkat-root.crl">Download Root ARL</a>
    &nbsp;
    <a class="dl-btn" href="/meerkat-issuing.crl">Download Issuing CRL</a>
  </div>

  <div class="footer">
    <a href="https://thameur.org">thameur.org</a> &nbsp;·&nbsp;
    <a href="https://thameur.org/linters.php">Linters</a> &nbsp;·&nbsp;
    Rotated on demand — fingerprints above are always current
  </div>

</div>
</body>
</html>
HTML;

file_put_contents($PKI_WEB . '/index.html', $html);
ok('index.html written');

// ─────────────────────────────────────────────────────────────────────────────
// Done
// ─────────────────────────────────────────────────────────────────────────────

echo "\n";
ok('PKI rotation complete');
info("Root CA  : $ROOT_CRT");
info("Root ARL : $ROOT_CRL  (365d — refresh monthly via cron/refresh_root_crl.sh)");
info("Issuing  : $ISSU_CRT");
info("Issuing CRL: $ISSU_CRL  (7d — refresh every 6 days via cron/refresh_issuing_crl.sh)");
info("Index    : {$PKI_WEB}/index.html");
echo "\n";
exit(0);
