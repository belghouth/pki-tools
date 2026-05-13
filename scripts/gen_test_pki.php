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
 *   /var/www/thameur.org/pki-tools/pki-ca/private/root.key    — Root CA key (mode 600)
 *   /var/www/thameur.org/pki-tools/pki-ca/private/issuing.key — Issuing CA key (mode 600)
 *   /var/www/pki.thameur.org/meerkat-root.crt
 *   /var/www/pki.thameur.org/meerkat-issuing.crt
 *   /var/www/pki.thameur.org/meerkat-issuing.crl
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
$ISSU_CRT  = $PKI_WEB . '/meerkat-issuing.crt';
$ISSU_CRL  = $PKI_WEB . '/meerkat-issuing.crl';

// ── CA identity ───────────────────────────────────────────────────────────────

$ROOT_SUBJ  = '/C=TN/O=Thameur Belghith/CN=Meerkat Root CA';
$ISSU_SUBJ  = '/C=TN/O=Thameur Belghith/CN=Meerkat Test Issuing CA 1';
$ROOT_DAYS  = 3650;   // ~10 years
$ISSU_DAYS  = 1825;   // ~5 years
$CRL_DAYS   = 30;

// AIA / CDP served from pki.thameur.org
$ROOT_AIA_URL = 'http://pki.thameur.org/meerkat-root.crt';
$ISSU_CRL_URL = 'http://pki.thameur.org/meerkat-issuing.crl';
$ISSU_AIA_URL = 'http://pki.thameur.org/meerkat-issuing.crt';

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

foreach ([$PKI_CA, $PRIV, $PKI_WEB] as $dir) {
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
chmod($ISSU_KEY, 0600);
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
//      SKI hash, AKI from Root SKI
//      certificatePolicies 2.23.140.1.2.1 (DV)
//      AIA (caIssuers) → Root CRT URL
//      CDP → Issuing CRL URL
// ─────────────────────────────────────────────────────────────────────────────

step('Signing Issuing CA certificate');

$issuExtPath = "$tmp/issuing_ext.cnf";
writeCnf($issuExtPath, <<<CNF
[ v3_issuing_ca ]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
certificatePolicies    = 2.23.140.1.2.1
authorityInfoAccess    = caIssuers;URI:$ROOT_AIA_URL
crlDistributionPoints  = URI:$ISSU_CRL_URL
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
// 6. Initial empty CRL from Issuing CA
// ─────────────────────────────────────────────────────────────────────────────

step('Generating initial (empty) CRL');

// openssl ca needs a minimal directory structure
$caDb    = "$tmp/ca_db";
mkdir($caDb, 0700, true);
file_put_contents("$caDb/index.txt", '');
file_put_contents("$caDb/crlnumber", "01\n");

$crlCnfPath = "$tmp/ca.cnf";
writeCnf($crlCnfPath, <<<CNF
[ ca ]
default_ca = CA_default

[ CA_default ]
database        = $caDb/index.txt
crlnumber       = $caDb/crlnumber
certificate     = $ISSU_CRT
private_key     = $ISSU_KEY
default_md      = sha256
default_crl_days = $CRL_DAYS
crl_extensions  = crl_ext

[ crl_ext ]
authorityKeyIdentifier = keyid:always
CNF);

$r = run([
    $openssl, 'ca',
    '-gencrl',
    '-config', $crlCnfPath,
    '-out', $ISSU_CRL,
    '-batch',
]);
if (!$r['ok']) {
    fail("CRL generation: " . trim($r['err']));
    exit(1);
}
ok('Issuing CA CRL: ' . $ISSU_CRL);

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
// Done
// ─────────────────────────────────────────────────────────────────────────────

echo "\n";
ok('PKI rotation complete');
info("Root CA  : $ROOT_CRT");
info("Issuing  : $ISSU_CRT");
info("CRL      : $ISSU_CRL");
info("Deploy pki/ to https://pki.thameur.org/ for AIA + CRL to resolve.");
echo "\n";
exit(0);
