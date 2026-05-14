<?php
require_once __DIR__ . '/recaptcha.php';
require_once __DIR__ . '/config.php';

// ── API ───────────────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    session_start();
    header('Content-Type: application/json; charset=utf-8');
    $action = $_POST['action'] ?? 'issue';
    $result = match ($action) {
        'revoke'             => handle_revoke(),
        'generate_csr'       => handle_generate_csr(),
        'generate_challenge' => handle_generate_challenge(),
        'verify_dcv'         => handle_verify_dcv(),
        'issue_precert'      => handle_issue(true),
        default              => handle_issue(false),
    };
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function handle_issue(bool $precert = false): array
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

    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'issue_cert')) {
            return ['error' => 'reCAPTCHA verification failed. Please try again.'];
        }
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
        $omit_cn = !empty($_POST['omit_cn']);
        return process_csr($tmpCsr, $precert, $omit_cn);
    } finally {
        @unlink($tmpCsr);
    }
}

function handle_revoke(): array
{
    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'revoke_cert')) {
            return ['error' => 'reCAPTCHA verification failed. Please try again.'];
        }
    }

    $certPem = trim($_POST['cert'] ?? '');
    if (!$certPem || !str_contains($certPem, '-----BEGIN CERTIFICATE-----')) {
        return ['error' => 'No valid certificate PEM provided'];
    }

    $allowed = ['unspecified', 'keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'privilegeWithdrawn'];
    $reason  = $_POST['reason'] ?? 'unspecified';
    if (!in_array($reason, $allowed, true)) {
        return ['error' => 'Invalid revocation reason'];
    }

    if (!file_exists(ISSUING_DB_CNF)) {
        return ['error' => 'The issuing CA is not yet initialised — please check back shortly.'];
    }

    $tmpCert = sys_get_temp_dir() . '/cf_rev_' . bin2hex(random_bytes(8)) . '.pem';
    file_put_contents($tmpCert, $certPem . "\n");

    $lock = fopen(ISSUING_LOCK, 'w');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
        if ($lock) fclose($lock);
        @unlink($tmpCert);
        return ['error' => 'CA is busy — please retry in a moment'];
    }

    try {
        $r = run_cmd([OPENSSL_BIN, 'ca',
            '-config',     ISSUING_DB_CNF,
            '-revoke',     $tmpCert,
            '-crl_reason', $reason,
            '-batch',
        ]);

        $alreadyRevoked = str_contains($r['err'] ?? '', 'already revoked');
        if (!$r['ok'] && !$alreadyRevoked) {
            return ['error' => 'Revocation failed'];
        }

        // Immediately regenerate the CRL so the revoked cert is visible.
        // openssl ca -gencrl outputs PEM only; convert to DER separately.
        $crlPem = sys_get_temp_dir() . '/cf_crl_' . bin2hex(random_bytes(8)) . '.pem';
        $crlDer = sys_get_temp_dir() . '/cf_crl_' . bin2hex(random_bytes(8)) . '.der';
        $r2 = run_cmd([OPENSSL_BIN, 'ca',
            '-config',  ISSUING_DB_CNF,
            '-gencrl',
            '-crlexts', 'crl_ext',
            '-out',     $crlPem,
            '-batch',
        ]);
        if ($r2['ok'] && file_exists($crlPem)) {
            $r3 = run_cmd([OPENSSL_BIN, 'crl', '-in', $crlPem, '-outform', 'DER', '-out', $crlDer]);
            if ($r3['ok'] && file_exists($crlDer)) {
                @copy($crlDer, ISSUING_CRL_OUT);
            }
            @unlink($crlPem);
            @unlink($crlDer);
        }

        return ['ok' => true, 'message' => $alreadyRevoked
            ? 'Certificate was already revoked. CRL refreshed.'
            : 'Certificate revoked successfully. CRL has been refreshed.'];

    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
        @unlink($tmpCert);
    }
}

function handle_generate_csr(): array
{
    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'generate_csr')) {
            return ['error' => 'reCAPTCHA verification failed. Please try again.'];
        }
    }

    $raw = trim($_POST['domains'] ?? '');
    if (!$raw) {
        return ['error' => 'No domains provided'];
    }

    $domains = [];
    foreach (explode(',', $raw) as $part) {
        $d = strtolower(trim($part));
        if ($d === '') continue;
        if (!is_valid_dns($d)) {
            return ['error' => "\"$d\" is not a valid domain name"];
        }
        if (is_reserved_name($d)) {
            return ['error' => "\"$d\" is a reserved or internal name and cannot be issued to"];
        }
        if (in_array($d, $domains, true)) continue;
        if (count($domains) >= MAX_SANS) {
            return ['error' => 'Too many domains (max ' . MAX_SANS . ')'];
        }
        $domains[] = $d;
    }

    if (empty($domains)) {
        return ['error' => 'No valid domains provided'];
    }

    $tmpKey = sys_get_temp_dir() . '/cf_gk_' . bin2hex(random_bytes(8)) . '.key';
    $tmpCsr = sys_get_temp_dir() . '/cf_gc_' . bin2hex(random_bytes(8)) . '.csr';
    $tmpCnf = sys_get_temp_dir() . '/cf_gn_' . bin2hex(random_bytes(8)) . '.cnf';

    try {
        $r = run_cmd([OPENSSL_BIN, 'genrsa', '-out', $tmpKey, '2048']);
        if (!$r['ok']) {
            return ['error' => 'Temporary key generation failed'];
        }

        // For each wildcard auto-add its base domain if not already present
        $extras = [];
        foreach ($domains as $d) {
            if (str_starts_with($d, '*.')) {
                $base = substr($d, 2);
                if (!in_array($base, $domains, true) && !in_array($base, $extras, true)) {
                    $extras[] = $base;
                }
            }
        }
        $domains = array_merge($domains, $extras);

        // CN must never be a wildcard — use first non-wildcard domain
        $cn = '';
        foreach ($domains as $d) {
            if (!str_starts_with($d, '*.')) { $cn = $d; break; }
        }
        if ($cn === '') $cn = substr($domains[0], 2);

        $sanStr = implode(',', array_map(fn($d) => 'DNS:' . $d, $domains));
        file_put_contents($tmpCnf, implode("\n", [
            '[req]',
            'distinguished_name = dn',
            'req_extensions     = san',
            'prompt             = no',
            '[dn]',
            'CN=' . $cn,
            '[san]',
            'subjectAltName = ' . $sanStr,
        ]));

        $r = run_cmd([OPENSSL_BIN, 'req', '-new',
            '-key',    $tmpKey,
            '-out',    $tmpCsr,
            '-config', $tmpCnf,
        ]);
        if (!$r['ok']) {
            return ['error' => 'CSR generation failed'];
        }

        $csrPem = (string) file_get_contents($tmpCsr);
        if (!str_contains($csrPem, '-----BEGIN CERTIFICATE REQUEST-----')) {
            return ['error' => 'CSR generation produced no output'];
        }

        return ['ok' => true, 'csr' => trim($csrPem), 'domains' => array_values($domains)];

    } finally {
        @unlink($tmpKey);
        @unlink($tmpCsr);
        @unlink($tmpCnf);
    }
}

function handle_generate_challenge(): array
{
    if (recaptcha_configured()) {
        $token = trim($_POST['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'issue_cert')) {
            return ['error' => 'reCAPTCHA verification failed. Please try again.'];
        }
    }

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
    if (!preg_match('/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/i', $csrPem)) {
        return ['error' => 'Invalid format — expected a PEM CERTIFICATE REQUEST block'];
    }

    $method = $_POST['dcv_method'] ?? 'http';
    if (!in_array($method, ['http', 'dns', 'dns-cname', 'tls-alpn'], true)) {
        return ['error' => 'Invalid DCV method'];
    }
    $precert = !empty($_POST['precert']);

    $tmpCsr = sys_get_temp_dir() . '/cf_csr_' . bin2hex(random_bytes(8)) . '.pem';
    file_put_contents($tmpCsr, $csrPem . "\n");
    try {
        $r = run_cmd([OPENSSL_BIN, 'req', '-in', $tmpCsr, '-noout', '-text']);
        if (!$r['ok']) {
            return ['error' => 'Failed to parse CSR — check the PEM encoding'];
        }
        $text = $r['out'];
    } finally {
        @unlink($tmpCsr);
    }

    $sans = extract_dns_sans($text);
    if (empty($sans)) {
        $cn = extract_cn($text);
        if ($cn !== '' && is_valid_dns($cn)) $sans[] = $cn;
    }
    if (empty($sans)) {
        return ['error' => 'No valid DNS SANs found in CSR'];
    }

    foreach ($sans as $san) {
        if (!is_valid_dns($san)) {
            return ['error' => "Invalid DNS name: \"$san\""];
        }
        if (in_array($method, ['http', 'tls-alpn'], true) && str_starts_with($san, '*.')) {
            return ['error' => ucfirst($method === 'http' ? 'HTTP' : 'TLS-ALPN') . ' DCV cannot be used for wildcard SANs — switch to DNS TXT or DNS CNAME.'];
        }
    }

    $caaErr = check_caa($sans);
    if ($caaErr !== null) {
        return ['error' => $caaErr];
    }

    // One token per unique base domain (wildcards validate their base domain)
    $tokens = [];
    foreach ($sans as $san) {
        $domain = str_starts_with($san, '*.') ? substr($san, 2) : $san;
        if (!isset($tokens[$domain])) {
            $tokens[$domain] = rtrim(strtr(base64_encode(random_bytes(20)), '+/', '-_'), '=');
        }
    }

    $_SESSION['dcv'] = [
        'method'   => $method,
        'tokens'   => $tokens,
        'csr_pem'  => $csrPem,
        'precert'  => $precert,
        'omit_cn'  => !empty($_POST['omit_cn']),
        'expires'  => time() + 3600,
    ];

    return ['ok' => true, 'method' => $method, 'tokens' => $tokens, 'sans' => $sans];
}

function handle_verify_dcv(): array
{
    if (empty($_SESSION['dcv'])) {
        return ['error' => 'No active DCV challenge — please generate a challenge first.'];
    }
    $sess = $_SESSION['dcv'];
    if (time() > $sess['expires']) {
        unset($_SESSION['dcv']);
        return ['error' => 'DCV challenge expired (>1 hour) — please generate a new challenge.'];
    }

    $method  = $sess['method'];
    $tokens  = $sess['tokens'];
    $results = [];
    $allOk   = true;

    foreach ($tokens as $domain => $token) {
        $r = match ($method) {
            'http'      => dcv_verify_http($domain, $token),
            'dns'       => dcv_verify_dns($domain, $token),
            'dns-cname' => dcv_verify_dns_cname($domain, $token),
            'tls-alpn'  => dcv_verify_tls_alpn($domain, $token),
            default     => ['ok' => false, 'error' => 'Unknown DCV method'],
        };
        $results[$domain] = $r;
        if (!$r['ok']) $allOk = false;
    }

    if (!$allOk) {
        return ['ok' => false, 'results' => $results];
    }

    $csrPem  = $sess['csr_pem'];
    $precert = $sess['precert'];
    $omit_cn = $sess['omit_cn'] ?? false;
    unset($_SESSION['dcv']);

    $tmpCsr = sys_get_temp_dir() . '/cf_csr_' . bin2hex(random_bytes(8)) . '.pem';
    file_put_contents($tmpCsr, $csrPem . "\n");
    try {
        $result = process_csr($tmpCsr, $precert, $omit_cn);
        if (isset($result['ok']) && $result['ok']) {
            $result['dcv_passed'] = true;
        }
        return $result;
    } finally {
        @unlink($tmpCsr);
    }
}

function dcv_verify_http(string $domain, string $token): array
{
    $url = 'http://' . $domain . '/.well-known/pki-validation/' . $token;
    $ch  = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_USERAGENT      => 'PKITools-DCV/1.0',
    ]);
    $body = (string) curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $cerr = curl_error($ch);
    curl_close($ch);

    if ($cerr !== '') {
        return ['ok' => false, 'error' => 'Connection failed: ' . $cerr];
    }
    if ($code !== 200) {
        return ['ok' => false, 'error' => "HTTP $code — file not found or not accessible"];
    }
    if (trim($body) !== $token) {
        return ['ok' => false, 'error' => 'File content does not match the expected token'];
    }
    return ['ok' => true];
}

function dcv_verify_dns(string $domain, string $token): array
{
    $recs = @dns_get_record('_pki-validation.' . $domain, DNS_TXT);
    if ($recs === false || !is_array($recs)) {
        return ['ok' => false, 'error' => 'DNS lookup failed'];
    }
    foreach ($recs as $rec) {
        $val = trim($rec['txt'] ?? ($rec['entries'][0] ?? ''));
        if ($val === $token) {
            return ['ok' => true];
        }
    }
    return ['ok' => false, 'error' => 'TXT record _pki-validation.' . $domain . ' not found or value mismatch'];
}

function dcv_verify_dns_cname(string $domain, string $token): array
{
    // Expected: _pki-validation.DOMAIN CNAME TOKEN.dcv.PKI_DOMAIN
    $cname_label = '_pki-validation.' . $domain;
    $expected_target = strtolower($token . '.dcv.' . PKI_DOMAIN . '.');
    $recs = @dns_get_record($cname_label, DNS_CNAME);
    if ($recs === false || !is_array($recs) || empty($recs)) {
        return ['ok' => false, 'error' => 'No CNAME record found for ' . $cname_label];
    }
    foreach ($recs as $rec) {
        $target = strtolower(rtrim($rec['target'] ?? '', '.') . '.');
        if ($target === $expected_target) {
            return ['ok' => true];
        }
    }
    $found = implode(', ', array_map(fn($r) => $r['target'] ?? '?', $recs));
    return ['ok' => false, 'error' => "CNAME target mismatch — expected {$expected_target}, found: {$found}"];
}

function dcv_verify_tls_alpn(string $domain, string $token): array
{
    // Connect to domain:443 with ALPN "acme-tls/1", retrieve the presented certificate,
    // then check its acmeValidation SAN extension contains SHA-256(token).
    // We use openssl s_client because PHP stream contexts do not expose ALPN negotiation.
    $expected_hash = hash('sha256', $token);
    $cmd = [
        OPENSSL_BIN, 's_client',
        '-connect', $domain . ':443',
        '-alpn', 'acme-tls/1',
        '-servername', $domain,
        '-showcerts',
    ];
    $r = run_cmd_input($cmd, '', 5);
    if (!$r['ok'] && trim($r['out']) === '') {
        return ['ok' => false, 'error' => 'TLS connection failed: ' . $r['err']];
    }
    $out = $r['out'];
    // Extract the first PEM certificate from the output
    if (!preg_match('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $out, $m)) {
        return ['ok' => false, 'error' => 'Could not extract certificate from TLS handshake'];
    }
    $certPem = "-----BEGIN CERTIFICATE-----\n" . trim($m[1]) . "\n-----END CERTIFICATE-----\n";
    $tmp = sys_get_temp_dir() . '/cf_alpn_' . bin2hex(random_bytes(6)) . '.pem';
    file_put_contents($tmp, $certPem);
    try {
        // Check ALPN was actually negotiated
        if (!str_contains($out, 'acme-tls/1')) {
            return ['ok' => false, 'error' => 'Server did not negotiate ALPN "acme-tls/1"'];
        }
        // Dump the certificate text and look for the acmeValidation OID (1.3.6.1.5.5.7.1.31) or its hex value
        $r2 = run_cmd([OPENSSL_BIN, 'x509', '-in', $tmp, '-noout', '-text']);
        if (!$r2['ok']) {
            return ['ok' => false, 'error' => 'Certificate parse failed'];
        }
        $certText = $r2['out'];
        // The acmeValidation extension value is the SHA-256 hash as a 32-byte DER OCTET STRING
        // openssl prints it as hex pairs; we look for the expected hash in the extension dump
        $hashLower = strtolower($expected_hash);
        $hashColon = implode(':', str_split($hashLower, 2)); // "ab:cd:ef:..."
        if (str_contains(strtolower($certText), $hashLower) || str_contains(strtolower($certText), $hashColon)) {
            return ['ok' => true];
        }
        return ['ok' => false, 'error' => 'acmeValidation extension not found or hash mismatch (expected SHA-256: ' . $expected_hash . ')'];
    } finally {
        @unlink($tmp);
    }
}

function is_reserved_name(string $name): bool
{
    $name = strtolower($name);
    if (str_starts_with($name, '*.')) $name = substr($name, 2);

    // IPv4 / IPv6 addresses
    if (filter_var($name, FILTER_VALIDATE_IP) !== false) return true;

    // Reverse DNS
    if (str_ends_with($name, '.arpa')) return true;

    // Tor hidden services
    if (str_ends_with($name, '.onion')) return true;

    // IANA / RFC 2606 / RFC 6761 special-use / internal names
    foreach (['.local', '.localhost', '.internal', '.localdomain',
              '.example', '.invalid', '.test', '.home', '.corp', '.lan'] as $sfx) {
        if (str_ends_with($name, $sfx)) return true;
    }

    // Single-label (already caught by is_valid_dns requiring ≥2 labels, belt-and-suspenders)
    if (!str_contains($name, '.')) return true;

    return false;
}

function process_csr(string $csrFile, bool $precert = false, bool $omit_cn = false): array
{
    // 1. Parse (also validates PEM structure)
    $r = run_cmd([OPENSSL_BIN, 'req', '-in', $csrFile, '-noout', '-text']);
    if (!$r['ok']) {
        return ['error' => 'Failed to parse CSR — check the PEM encoding'];
    }
    $text = $r['out'];

    // 2. Signature self-check
    $r = run_cmd([OPENSSL_BIN, 'req', '-verify', '-in', $csrFile, '-noout']);
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

    // 8. CAA check
    $caaErr = check_caa($sans);
    if ($caaErr !== null) {
        return ['error' => $caaErr];
    }

    // 9. Sign — serialised through a lock file (openssl ca is not re-entrant)
    $lock = fopen(ISSUING_LOCK, 'w');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
        if ($lock) fclose($lock);
        return ['error' => 'Another issuance is in progress — please retry in a moment'];
    }

    $extFile     = sys_get_temp_dir() . '/cf_ext_'  . bin2hex(random_bytes(8)) . '.cnf';
    $certFile    = sys_get_temp_dir() . '/cf_cert_' . bin2hex(random_bytes(8)) . '.pem';
    $preExtFile  = null;
    $preCertFile = null;
    $scts        = [];

    try {
        // CN must never be a wildcard — use first non-wildcard SAN
        $certCn = '';
        foreach ($sans as $s) {
            if (!str_starts_with($s, '*.')) { $certCn = $s; break; }
        }
        if ($certCn === '') $certCn = substr($sans[0], 2);

        // BR §7.1.4.2: commonName is NOT RECOMMENDED — omit when requested
        $subj   = $omit_cn ? '/' : '/CN=' . $certCn;
        $sanStr = implode(', ', array_map(fn($s) => 'DNS:' . $s, $sans));

        $extLines = [
            '[ v3_ee ]',
            // critical — required by BR §7.1.2.7.6 and zlint e_sub_cert_basic_constraints_not_critical
            'basicConstraints       = critical, CA:FALSE',
            // keyEncipherment removed — discouraged per BR §7.1.2.7.11 for modern TLS
            'keyUsage               = critical, digitalSignature',
            'extendedKeyUsage       = serverAuth, clientAuth',
            // Explicitly suppress SKI — NOT RECOMMENDED for subscriber certs per BR §7.1.2.7.
            // Setting it here prevents copy_extensions from pulling it out of the CSR.
            'subjectKeyIdentifier   = none',
            'authorityKeyIdentifier = keyid:always',
            'certificatePolicies    = 2.23.140.1.2.1',
            'authorityInfoAccess    = caIssuers;URI:' . AIA_URL,
            'crlDistributionPoints  = URI:' . CDP_URL,
            'subjectAltName         = ' . $sanStr,
        ];

        if ($precert) {
            // ── Precertificate (user-requested) ──────────────────────────────────
            // RFC 6962 §3.1 CT poison extension — critical, ASN.1 NULL (DER 05 00)
            $extLines[] = '1.3.6.1.4.1.11129.2.4.3 = critical, DER:05:00';
            file_put_contents($extFile, implode("\n", $extLines));
            // BR §7.1.2.4 random 128-bit serial
            file_put_contents(ISSUING_DB_SRL, strtoupper(bin2hex(random_bytes(16))) . "\n");

            $r = run_cmd([
                OPENSSL_BIN, 'ca',
                '-config',     ISSUING_DB_CNF,
                '-in',         $csrFile,
                '-out',        $certFile,
                '-subj',       $subj,
                '-extfile',    $extFile,
                '-extensions', 'v3_ee',
                '-days',       (string) CERT_DAYS,
                '-notext',
                '-batch',
            ]);
            if (!$r['ok']) {
                return ['error' => 'Signing failed: ' . trim($r['err'] ?: $r['out'])];
            }

        } else {
            // ── Regular certificate — issue precert → get SCTs → issue final cert ─

            // Step 1: issue precert internally (not returned to user)
            $preExtFile  = sys_get_temp_dir() . '/cf_ext_pre_'  . bin2hex(random_bytes(8)) . '.cnf';
            $preCertFile = sys_get_temp_dir() . '/cf_cert_pre_' . bin2hex(random_bytes(8)) . '.pem';

            file_put_contents($preExtFile, implode("\n", array_merge($extLines, [
                '1.3.6.1.4.1.11129.2.4.3 = critical, DER:05:00',
            ])));
            file_put_contents(ISSUING_DB_SRL, strtoupper(bin2hex(random_bytes(16))) . "\n");

            $rPre = run_cmd([
                OPENSSL_BIN, 'ca',
                '-config',     ISSUING_DB_CNF,
                '-in',         $csrFile,
                '-out',        $preCertFile,
                '-subj',       $subj,
                '-extfile',    $preExtFile,
                '-extensions', 'v3_ee',
                '-days',       (string) CERT_DAYS,
                '-notext',
                '-batch',
            ]);
            if (!$rPre['ok']) {
                return ['error' => 'Precert issuance failed: ' . trim($rPre['err'] ?: $rPre['out'])];
            }

            // Step 2: submit precert chain to CT log(s) and collect SCTs
            $precertPem = (string) file_get_contents($preCertFile);
            $issuerPem  = (string) file_get_contents(ISSUING_CRT);
            $needed     = ct_required_count(CERT_DAYS);

            for ($i = 0; $i < $needed; $i++) {
                $sct = ct_submit($precertPem, $issuerPem);
                if (isset($sct['error'])) {
                    return ['error' => 'CT log submission failed: ' . $sct['error']];
                }
                $scts[] = $sct;
            }

            // Step 3: issue final cert with embedded SCT list (OID 1.3.6.1.4.1.11129.2.4.2)
            $extLines[] = '1.3.6.1.4.1.11129.2.4.2 = ' . ct_build_sct_ext($scts);
            file_put_contents($extFile, implode("\n", $extLines));
            file_put_contents(ISSUING_DB_SRL, strtoupper(bin2hex(random_bytes(16))) . "\n");

            $r = run_cmd([
                OPENSSL_BIN, 'ca',
                '-config',     ISSUING_DB_CNF,
                '-in',         $csrFile,
                '-out',        $certFile,
                '-subj',       $subj,
                '-extfile',    $extFile,
                '-extensions', 'v3_ee',
                '-days',       (string) CERT_DAYS,
                '-notext',
                '-batch',
            ]);
            if (!$r['ok']) {
                return ['error' => 'Signing failed: ' . trim($r['err'] ?: $r['out'])];
            }
        }

        $certPem = (string) file_get_contents($certFile);
        if (!str_contains($certPem, '-----BEGIN CERTIFICATE-----')) {
            return ['error' => 'Signing produced no output'];
        }

        $info = parse_cert($certFile);

        return [
            'ok'          => true,
            'precert'     => $precert,
            'scts'        => array_map(fn($s) => [
                'log'      => $s['log_description'] ?? 'Meerkat Testing CT Log',
                'operator' => $s['log_operator']    ?? '',
            ], $scts),
            'certificate' => trim($certPem),
            'subject'     => $omit_cn ? '(empty — CN omitted per BR §7.1.4.2)' : 'CN=' . $certCn,
            'sans'        => $sans,
            'key_bits'    => $keyBits,
            'issuer'      => $info['issuer']     ?? 'CN=Meerkat Test Issuing CA 1',
            'not_before'  => $info['not_before'] ?? '',
            'not_after'   => $info['not_after']  ?? '',
            'serial'      => $info['serial']     ?? '',
        ];

    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
        @unlink($extFile);
        @unlink($certFile);
        if ($preExtFile)  @unlink($preExtFile);
        if ($preCertFile) @unlink($preCertFile);
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

// ── CT log integration ────────────────────────────────────────────────────────

function ct_required_count(int $days): int
{
    // Chrome CT policy / BR SCT count requirements by validity period
    if ($days <= 180) return 2;
    if ($days <= 397) return 3;
    return 4;
}

function ct_submit(string $precert_pem, string $issuer_pem): array
{
    // Extract the base64 body of the FIRST PEM block only (handles files with a chain)
    $pem_b64 = static function(string $p): string {
        if (preg_match('/-----BEGIN [^-]+-----\s*(.*?)\s*-----END [^-]+-----/s', $p, $m)) {
            return preg_replace('/\s+/', '', $m[1]);
        }
        return '';
    };

    $chain0 = $pem_b64($precert_pem);
    $chain1 = $pem_b64($issuer_pem);
    if ($chain0 === '' || $chain1 === '') {
        return ['error' => 'Failed to extract DER from certificate PEM'];
    }

    // JSON_UNESCAPED_SLASHES is required: base64 contains '/' which PHP escapes to '\/'
    // by default, corrupting the value for any CT log that doesn't unescape it first.
    $payload = json_encode(['chain' => [$chain0, $chain1]], JSON_UNESCAPED_SLASHES);
    if ($payload === false) {
        return ['error' => 'Failed to encode CT submission payload'];
    }

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => CT_LOG_URL,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        // Bypass DNS — connect to loopback directly to avoid an external round-trip
        CURLOPT_RESOLVE        => [CT_LOG_RESOLVE],
    ]);
    $body = (string) curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $cerr = curl_error($ch);
    curl_close($ch);

    if ($cerr !== '')  return ['error' => "cURL: $cerr"];
    if ($code !== 200) return ['error' => "CT log HTTP $code: " . substr($body, 0, 300)];
    $json = json_decode($body, true);
    if (!is_array($json) || !isset($json['id'])) return ['error' => 'Invalid CT log response'];
    return $json;
}

function ct_sct_binary(array $sct): string
{
    // Binary SCT (RFC 6962 §3.2): version(1) + log_id(32) + timestamp(8 BE uint64)
    // + extensions_len(2=0) + DigitallySigned
    return "\x00"
         . base64_decode($sct['id'])
         . pack('J', (int) $sct['timestamp'])
         . "\x00\x00"
         . base64_decode($sct['signature']);
}

function ct_build_sct_ext(array $scts): string
{
    // TLS-serialized SignedCertificateTimestampList (RFC 6962 §3.3)
    $entries = '';
    foreach ($scts as $sct) {
        $bin      = ct_sct_binary($sct);
        $entries .= pack('n', strlen($bin)) . $bin;
    }
    $list = pack('n', strlen($entries)) . $entries;

    // Extension value is OCTET STRING { list_bytes } (OID 1.3.6.1.4.1.11129.2.4.2)
    $len = strlen($list);
    $der = $len < 0x80
        ? "\x04" . chr($len) . $list
        : ($len < 0x100
            ? "\x04\x81" . chr($len) . $list
            : "\x04\x82" . pack('n', $len) . $list);

    // Return as OpenSSL DER: literal for the extension file
    return 'DER:' . implode(':', str_split(bin2hex($der), 2));
}

// ─────────────────────────────────────────────────────────────────────────────

if (!defined('DNS_CAA')) define('DNS_CAA', 256);

function check_caa(array $sans): ?string
{
    $issuer  = CAA_ISSUER;
    $checked = [];

    foreach ($sans as $san) {
        $isWild = str_starts_with($san, '*.');
        $domain = $isWild ? substr($san, 2) : $san;
        $key    = $domain . ($isWild ? ':w' : ':r');
        if (in_array($key, $checked, true)) continue;
        $checked[] = $key;

        $err = caa_check_domain($domain, $isWild, $issuer);
        if ($err !== null) return $err;
    }
    return null;
}

function caa_check_domain(string $domain, bool $isWild, string $issuer): ?string
{
    $parts = explode('.', $domain);
    $n     = count($parts);

    for ($i = 0; $i <= $n - 2; $i++) {
        $candidate = implode('.', array_slice($parts, $i));
        $recs = @dns_get_record($candidate, DNS_CAA);

        if ($recs === false || !is_array($recs)) return null; // DNS failure — don't block
        if (empty($recs)) continue;                           // no CAA here, walk up

        $issue     = [];
        $issuewild = [];
        foreach ($recs as $r) {
            $tag = strtolower($r['tag'] ?? '');
            $val = trim($r['value'] ?? '');
            if ($tag === 'issue')     $issue[]     = $val;
            if ($tag === 'issuewild') $issuewild[] = $val;
        }

        // Wildcards: issuewild takes precedence when present
        if ($isWild && !empty($issuewild)) {
            if (!in_array($issuer, $issuewild, true)) {
                return "CAA policy on {$candidate} blocks wildcard issuance.\n"
                     . "Add this DNS record to authorise this CA:\n"
                     . "  {$candidate} IN CAA 0 issuewild \"{$issuer}\"";
            }
            return null;
        }
        // issue applies to both regular and wildcard fallback
        if (!empty($issue)) {
            if (!in_array($issuer, $issue, true)) {
                $tag = $isWild ? 'issuewild' : 'issue';
                return "CAA policy on {$candidate} blocks certificate issuance.\n"
                     . "Add this DNS record to authorise this CA:\n"
                     . "  {$candidate} IN CAA 0 {$tag} \"{$issuer}\"";
            }
            return null;
        }
        return null; // CAA records present but no issue/issuewild — no restriction
    }
    return null; // no CAA records found anywhere — issuance permitted
}

function is_valid_dns(string $name): bool
{
    // Allow exactly "*.fqdn" — the wildcard must be the entire first label
    if (str_starts_with($name, '*.')) {
        return is_valid_dns(substr($name, 2));
    }
    if ($name === '*' || str_contains($name, '*')) return false;
    if (strlen($name) === 0 || strlen($name) > 253) return false;
    $labels = explode('.', $name);
    if (count($labels) < 2) return false;
    foreach ($labels as $label) {
        if ($label === '' || strlen($label) > 63) return false;
        if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$/', $label)) return false;
    }
    return true;
}

function parse_cert(string $certFile): array
{
    $r = run_cmd([OPENSSL_BIN, 'x509', '-in', $certFile, '-noout', '-text']);
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

// Like run_cmd but closes stdin immediately so commands that read from it (like openssl s_client) terminate.
function run_cmd_input(array $cmd, string $stdin_data, int $timeout_sec = 10): array
{
    $proc = proc_open($cmd, [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes);
    if (!$proc) return ['ok' => false, 'out' => '', 'err' => 'proc_open failed', 'code' => -1];
    if ($stdin_data !== '') fwrite($pipes[0], $stdin_data);
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $out = $err = '';
    $deadline = microtime(true) + $timeout_sec;
    while (microtime(true) < $deadline) {
        $r = [$pipes[1], $pipes[2]];
        $w = $e = [];
        if (@stream_select($r, $w, $e, 0, 100000) > 0) {
            $out .= (string) stream_get_contents($pipes[1]);
            $err .= (string) stream_get_contents($pipes[2]);
        }
        $status = proc_get_status($proc);
        if (!$status['running']) break;
    }
    // Collect any remaining output
    stream_set_blocking($pipes[1], true);
    stream_set_blocking($pipes[2], true);
    $out .= (string) stream_get_contents($pipes[1]);
    $err .= (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return ['ok' => $code === 0, 'out' => $out, 'err' => $err, 'code' => $code];
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
    'title'       => 'Meerkat TLS Test Certificate Factory — BR-Compliant DV TLS | ' . SITE_DOMAIN,
    'description' => 'Issue BR-compliant DV TLS certificates from the Meerkat Test CA. DNS SANs only — no IPs, no email. RSA ≥ 2048. CN derived from SANs. For linter testing and chain validation.',
    'url'         => SITE_BASE_URL . '/cert_factory.php',
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
    .btn-ghost:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
    .btn-ghost:disabled { opacity: 0.4; cursor: not-allowed; }

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
    #errorMsg { white-space: pre-wrap; font-family: var(--mono); font-size: 0.78rem; }

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

    /* ── CSR builder ── */
    .csr-builder {
      margin-top: 1.2rem; padding-top: 1rem;
      border-top: 1px solid var(--border);
    }
    .csr-builder-toggle {
      background: none; border: none; color: var(--muted); cursor: pointer;
      font-family: var(--sans); font-size: 0.82rem; padding: 0;
      display: flex; align-items: center; gap: 0.4rem; transition: color 0.15s;
    }
    .csr-builder-toggle:hover { color: var(--accent); }
    .toggle-chevron { font-size: 0.65rem; transition: transform 0.2s; display: inline-block; }
    .toggle-chevron.open { transform: rotate(90deg); }
    .csr-builder-body { margin-top: 0.9rem; }
    .csr-warn-note {
      border: 1px solid #854d0e; background: rgba(133,77,14,0.12);
      border-radius: 6px; padding: 0.65rem 0.9rem; margin-bottom: 0.9rem;
      font-size: 0.8rem; color: #fde68a; line-height: 1.6;
    }
    .precert-note {
      border: 1px solid #92400e; background: rgba(146,64,14,0.12);
      border-radius: 6px; padding: 0.65rem 0.9rem; margin-bottom: 1rem;
      font-size: 0.82rem; color: #fcd34d; line-height: 1.6;
    }
    .csr-domain-row {
      display: flex; gap: 0.6rem; align-items: stretch; flex-wrap: wrap;
    }
    .domain-input {
      flex: 1; min-width: 200px;
      background: var(--bg); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text); font-family: var(--mono);
      font-size: 0.78rem; padding: 0.5em 0.9em; transition: border-color 0.15s;
    }
    .domain-input:focus { outline: none; border-color: var(--accent); }
    .domain-input::placeholder { color: var(--muted); }
    .csr-domain-hint { font-size: 0.75rem; color: var(--muted); margin-top: 0.4rem; }
    .csr-builder-error {
      margin-top: 0.6rem; font-size: 0.8rem; color: var(--danger);
      padding: 0.5rem 0.8rem; background: rgba(248,113,113,0.08);
      border: 1px solid rgba(248,113,113,0.25); border-radius: 5px;
    }
    .csr-ok-badge {
      margin-top: 0.6rem; font-size: 0.8rem; color: var(--accent);
      padding: 0.5rem 0.8rem; background: rgba(0,212,170,0.07);
      border: 1px solid rgba(0,212,170,0.25); border-radius: 5px;
    }

    /* ── Revocation row ── */
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
      cursor: pointer; font-weight: 600; transition: opacity 0.15s;
      white-space: nowrap;
    }
    .btn-danger:hover:not(:disabled) { background: #b91c1c; }
    .btn-danger:disabled { opacity: 0.4; cursor: not-allowed; }
    .revoke-result {
      font-size: 0.83rem; padding: 0.65rem 1rem;
      border-radius: 6px; margin-top: 0.8rem;
    }
    .revoke-result.ok  { background: rgba(0,212,170,0.07); border: 1px solid rgba(0,212,170,0.3); color: var(--accent); }
    .revoke-result.err { background: rgba(248,113,113,0.08); border: 1px solid rgba(248,113,113,0.3); color: var(--danger); }

    /* ── DCV section ── */
    .dcv-section {
      margin-top: 1.2rem; padding-top: 1rem;
      border-top: 1px solid var(--border);
    }
    .dcv-check-label {
      display: flex; align-items: center; gap: 0.5rem;
      font-size: 0.84rem; cursor: pointer; user-select: none;
    }
    .dcv-check-label input[type=checkbox] { accent-color: var(--accent); width: 15px; height: 15px; }
    .dcv-method-panel { margin-top: 0.9rem; }
    .dcv-method-opts { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
    .dcv-method-opt { display: flex; align-items: center; gap: 0.4rem; font-size: 0.83rem; cursor: pointer; }
    .dcv-method-opt input[type=radio] { accent-color: var(--accent); }
    .dcv-opt-note { font-size: 0.77rem; color: var(--muted); line-height: 1.5; max-width: 500px; }

    /* ── DCV challenge card ── */
    .dcv-challenge-header { display: flex; align-items: center; gap: 0.8rem; margin-bottom: 1.1rem; }
    .dcv-challenge-header h2 { font-size: 1rem; font-weight: 600; color: #fff; }
    .dcv-badge {
      font-family: var(--mono); font-size: 0.65rem; text-transform: uppercase;
      letter-spacing: 0.07em; padding: 0.2em 0.6em; border-radius: 3px;
      background: rgba(0,212,170,0.12); color: var(--accent);
      border: 1px solid rgba(0,212,170,0.3);
    }
    .dcv-badge.dns       { background: rgba(139,92,246,0.1); color: #a78bfa; border-color: rgba(139,92,246,0.3); }
    .dcv-badge.dns-cname { background: rgba(139,92,246,0.1); color: #a78bfa; border-color: rgba(139,92,246,0.3); }
    .dcv-badge.tls-alpn  { background: rgba(251,191,36,0.1);  color: var(--warn); border-color: rgba(251,191,36,0.3); }
    .dcv-challenge-item { padding: 0.9rem 0; border-bottom: 1px solid var(--border); }
    .dcv-challenge-item:last-child { border-bottom: none; }
    .dcv-challenge-domain {
      font-family: var(--mono); font-size: 0.78rem; font-weight: 600;
      color: #fff; margin-bottom: 0.6rem;
    }
    .dcv-token-block { margin-bottom: 0.5rem; }
    .dcv-token-label {
      font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.06em;
      color: var(--muted); margin-bottom: 0.25rem;
    }
    .dcv-token-row { display: flex; align-items: center; gap: 0.5rem; }
    .dcv-token-value {
      font-family: var(--mono); font-size: 0.72rem; color: var(--accent);
      background: var(--bg); border: 1px solid var(--border);
      border-radius: 4px; padding: 0.3em 0.6em;
      word-break: break-all; flex: 1;
    }
    .dcv-copy-btn {
      font-family: var(--mono); font-size: 0.65rem; text-transform: uppercase;
      background: none; border: 1px solid var(--border); border-radius: 4px;
      color: var(--muted); padding: 0.25em 0.55em; cursor: pointer; white-space: nowrap;
      transition: border-color 0.15s, color 0.15s; flex-shrink: 0;
    }
    .dcv-copy-btn:hover { border-color: var(--accent); color: var(--accent); }
    .dcv-verify-row { margin-top: 1.2rem; display: flex; align-items: center; gap: 1rem; }
    .dcv-result-item { display: flex; align-items: flex-start; gap: 0.4rem; font-size: 0.8rem; margin-top: 0.5rem; }
    .dcv-result-ok  { color: var(--accent); }
    .dcv-result-err { color: var(--danger); font-family: var(--mono); font-size: 0.77rem; }

    .omit-cn-ref {
      font-family: var(--mono); font-size: 0.65rem; letter-spacing: 0.04em;
      padding: 0.1em 0.5em; border-radius: 3px; margin-left: 0.4rem;
      background: rgba(251,191,36,0.08); color: var(--warn);
      border: 1px solid rgba(251,191,36,0.25); vertical-align: middle;
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
    <h1>Meerkat TLS Test Certificate Factory</h1>
    <p>Issue a BR-compliant DV TLS certificate from the Meerkat Test CA. Only DNS SANs are accepted —
       IPs, email addresses, and other SAN types are rejected. CN is always derived from the first DNS SAN;
       all other CSR fields are stripped. RSA ≥ 2048 only.</p>
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

      <!-- CSR builder -->
      <div class="csr-builder">
        <button type="button" class="csr-builder-toggle" id="csrBuilderToggle">
          <span class="toggle-chevron" id="toggleChevron">▶</span>
          Create CSR for me
        </button>
        <div class="csr-builder-body" id="csrBuilderBody" hidden>
          <div class="csr-warn-note">
            ⚠ <strong>No private key will be delivered.</strong> A throw-away 2048-bit RSA key is
            generated server-side and discarded immediately after signing. Use this option only to
            test how a certificate looks — never to secure a real service.
          </div>
          <div class="csr-domain-row">
            <input type="text" class="domain-input" id="domainInput"
                   placeholder="example.com, www.example.com, api.example.com"
                   spellcheck="false" autocomplete="off">
            <button type="button" class="btn-primary" id="btnGenCsr">Generate CSR</button>
          </div>
          <p class="csr-domain-hint">Separate multiple domains with commas. No IPs, or internal names.</p>
          <div class="csr-builder-error" id="csrBuilderError" hidden></div>
          <div class="csr-ok-badge" id="csrBuilderOk" hidden></div>
        </div>
      </div>

      <!-- DCV options -->
      <div class="dcv-section">
        <label class="dcv-check-label">
          <input type="checkbox" id="dcvEnabled">
          Enforce Domain Control Validation (DCV)
        </label>
        <div class="dcv-method-panel" id="dcvMethodPanel" hidden>
          <div class="dcv-method-opts">
            <label class="dcv-method-opt">
              <input type="radio" name="dcv_method" value="http" id="dcvHttp" checked>
              HTTP <code style="font-size:0.72rem;color:var(--muted)">/.well-known/pki-validation/</code>
            </label>
            <label class="dcv-method-opt">
              <input type="radio" name="dcv_method" value="dns" id="dcvDns">
              DNS TXT <code style="font-size:0.72rem;color:var(--muted)">_pki-validation</code>
            </label>
            <label class="dcv-method-opt">
              <input type="radio" name="dcv_method" value="dns-cname" id="dcvDnsCname">
              DNS CNAME <code style="font-size:0.72rem;color:var(--muted)">_pki-validation → TOKEN.dcv</code>
            </label>
            <label class="dcv-method-opt">
              <input type="radio" name="dcv_method" value="tls-alpn" id="dcvTlsAlpn">
              TLS-ALPN <code style="font-size:0.72rem;color:var(--muted)">port 443, acme-tls/1</code>
            </label>
          </div>
          <p class="dcv-opt-note" id="dcvOptNote">Place a file at each domain's
            <code>/.well-known/pki-validation/TOKEN</code> URL containing exactly the token value.</p>
        </div>
      </div>

      <!-- Subject options -->
      <div class="dcv-section" style="margin-top:0.6rem">
        <label class="dcv-check-label">
          <input type="checkbox" id="omitCn" name="omit_cn" value="1">
          Omit commonName from subject
          <span class="omit-cn-ref">BR §7.1.4.2 — commonName NOT RECOMMENDED</span>
        </label>
        <p class="dcv-opt-note" style="margin-top:0.4rem">
          When checked the subject will be an empty sequence and the SAN extension is the
          sole source of domain names, as recommended by the Baseline Requirements.
        </p>
      </div>

      <div class="submit-row">
        <button class="btn-primary" type="submit" id="btnIssue">Issue Certificate</button>
        <button class="btn-ghost" type="button" id="btnPrecert">Issue Precertificate</button>
        <div class="spinner" id="spinner" hidden></div>
      </div>

    </form>

    <div class="error-box" id="errorBox" hidden>
      <span class="err-icon">✕</span>
      <span id="errorMsg"></span>
    </div>
  </div>

  <!-- DCV challenge card -->
  <div class="card" id="dcvCard" hidden>
    <div class="dcv-challenge-header">
      <h2>DCV Challenge</h2>
      <span class="dcv-badge" id="dcvBadge">HTTP</span>
    </div>
    <div id="dcvItems"></div>
    <div class="dcv-verify-row">
      <button class="btn-primary" type="button" id="btnVerifyDcv">Verify &amp; Issue</button>
      <div class="spinner" id="dcvSpinner" hidden></div>
    </div>
    <div class="error-box" id="dcvErrorBox" hidden>
      <span class="err-icon">✕</span>
      <span id="dcvErrMsg"></span>
    </div>
  </div>

  <!-- Result card (hidden until a cert is issued) -->
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

    <div class="precert-note" id="precertNote" hidden>
      ⚠ <strong>This is a precertificate</strong> (RFC 6962). It contains the CT poison extension
      (OID 1.3.6.1.4.1.11129.2.4.3, critical) and <strong>cannot be used for TLS</strong>. It is
      intended for submission to Certificate Transparency logs and linter testing only.
    </div>

    <div class="cert-info" id="certInfo"></div>

    <div class="pem-wrap">
      <textarea class="pem-output" id="pemOutput" readonly spellcheck="false"></textarea>
    </div>

    <p class="chain-note">
      Chain: <a href="<?= PKI_BASE_URL ?>/meerkat-root.crt">Meerkat Root CA</a>
      → <a href="<?= PKI_BASE_URL ?>/meerkat-issuing.crt">Meerkat Test Issuing CA 1</a>
      → this certificate<br>
      Install the Root CA to trust this cert locally for linter testing.
      PKI repository: <a href="<?= PKI_BASE_URL ?>" target="_blank" rel="noopener"><?= PKI_DOMAIN ?></a>
    </p>

    <div class="revoke-row" id="revokeRow">
      <span class="revoke-label">Revocation reason:</span>
      <select class="revoke-reason" id="revokeReason">
        <option value="unspecified">Unspecified</option>
        <option value="keyCompromise">Key Compromise</option>
        <option value="affiliationChanged">Affiliation Changed</option>
        <option value="superseded">Superseded</option>
        <option value="cessationOfOperation">Cessation of Operation</option>
        <option value="privilegeWithdrawn">Privilege Withdrawn</option>
      </select>
      <button class="btn-danger" id="btnRevoke">Revoke this Certificate</button>
    </div>
    <div class="revoke-result" id="revokeResult" hidden></div>
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
(function () {
  'use strict';

  var RECAPTCHA_SITE_KEY = <?= json_encode(RECAPTCHA_SITE_KEY) ?>;
  var ISSUING_CA_PEM     = <?= json_encode(file_exists(ISSUING_CRT) ? trim((string) file_get_contents(ISSUING_CRT)) : '') ?>;

  function getRecaptchaToken(action) {
    return new Promise(function (resolve) {
      if (typeof grecaptcha === 'undefined' || RECAPTCHA_SITE_KEY === 'YOUR_RECAPTCHA_SITE_KEY_HERE') {
        resolve('');
        return;
      }
      grecaptcha.ready(function () {
        grecaptcha.execute(RECAPTCHA_SITE_KEY, { action: action }).then(resolve);
      });
    });
  }

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
  var btnPrecert = document.getElementById('btnPrecert');
  var spinner    = document.getElementById('spinner');
  var errorBox   = document.getElementById('errorBox');
  var errorMsg   = document.getElementById('errorMsg');
  var resultCard = document.getElementById('resultCard');
  var certInfo   = document.getElementById('certInfo');
  var pemOutput  = document.getElementById('pemOutput');

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (dcvEnabled.checked) doGenerateChallenge('issue');
    else doIssue('issue');
  });

  btnPrecert.addEventListener('click', function () {
    if (dcvEnabled.checked) doGenerateChallenge('issue_precert');
    else doIssue('issue_precert');
  });

  async function doIssue(action) {
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

    fd.set('action', action);
    var token = await getRecaptchaToken('issue_cert');
    fd.append('g_recaptcha_token', token);

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
    var isPrecert = !!data.precert;

    // PEM
    pemOutput.value = data.certificate;

    // Header title + precert note
    var resultTitle = document.getElementById('resultTitle');
    var precertNote = document.getElementById('precertNote');
    var revokeRow   = document.getElementById('revokeRow');
    if (isPrecert) {
      resultTitle.textContent = '⚠ Precertificate Issued';
      resultTitle.style.color = '#fcd34d';
      precertNote.hidden = false;
      revokeRow.hidden = true;
    } else {
      resultTitle.textContent = '✔ Certificate Issued';
      resultTitle.style.color = '';
      precertNote.hidden = true;
      revokeRow.hidden = false;
    }

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

    if (!isPrecert) {
      // Reset revocation state for the new cert
      document.getElementById('btnRevoke').disabled = false;
      document.getElementById('btnRevoke').textContent = 'Revoke this Certificate';
      var rr = document.getElementById('revokeResult');
      rr.hidden = true;
      rr.className = 'revoke-result';
      rr.textContent = '';
    }
  }

  function row(key, val) {
    return '<span class="ci-key">' + key + '</span><span class="ci-val">' + val + '</span>';
  }

  // ── CSR prefill from artifact parser ────────────────────────────────────────
  (function () {
    var csr = sessionStorage.getItem('pki_prefill_csr');
    if (!csr) return;
    sessionStorage.removeItem('pki_prefill_csr');
    var ta = document.getElementById('csrText');
    if (ta && !ta.value.trim()) {
      ta.value = csr;
      // Ensure paste tab is active
      tabs.forEach(function (t) { t.classList.remove('active'); });
      panes.forEach(function (p) { p.classList.remove('active'); });
      var pasteTab  = document.querySelector('[data-tab="paste"]');
      var pastePane = document.getElementById('pane-paste');
      if (pasteTab)  pasteTab.classList.add('active');
      if (pastePane) pastePane.classList.add('active');
    }
  }());

  // ── Lint / Parse ─────────────────────────────────────────────────────────────
  document.getElementById('btnLint').addEventListener('click', function () {
    if (!pemOutput.value) return;
    sessionStorage.setItem('pki_prefill_cert',   pemOutput.value);
    sessionStorage.setItem('pki_prefill_issuer', ISSUING_CA_PEM);
    window.open('/linters.php', '_blank');
  });

  document.getElementById('btnParse').addEventListener('click', function () {
    if (!pemOutput.value) return;
    sessionStorage.setItem('pki_prefill_cert', pemOutput.value);
    window.open('/artifact_parser.php', '_blank');
  });

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
    btnIssue.disabled   = on;
    btnPrecert.disabled = on;
    btnIssue.textContent   = on ? 'Issuing…' : 'Issue Certificate';
    btnPrecert.textContent = on ? 'Issuing…' : 'Issue Precertificate';
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

  // ── CSR builder ─────────────────────────────────────────────────────────────
  var csrBuilderToggle = document.getElementById('csrBuilderToggle');
  var csrBuilderBody   = document.getElementById('csrBuilderBody');
  var toggleChevron    = document.getElementById('toggleChevron');
  var domainInput      = document.getElementById('domainInput');
  var btnGenCsr        = document.getElementById('btnGenCsr');
  var csrBuilderError  = document.getElementById('csrBuilderError');
  var csrBuilderOk     = document.getElementById('csrBuilderOk');

  csrBuilderToggle.addEventListener('click', function () {
    var open = !csrBuilderBody.hidden;
    csrBuilderBody.hidden = open;
    toggleChevron.classList.toggle('open', !open);
  });

  btnGenCsr.addEventListener('click', function () { doGenCsr(); });
  domainInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); doGenCsr(); }
  });

  async function doGenCsr() {
    var raw = domainInput.value.trim();
    if (!raw) {
      showCsrError('Enter at least one domain.');
      return;
    }

    csrBuilderError.hidden = true;
    csrBuilderOk.hidden    = true;
    btnGenCsr.disabled     = true;
    btnGenCsr.textContent  = 'Generating…';

    var token = await getRecaptchaToken('generate_csr');
    var fd = new FormData();
    fd.append('action',            'generate_csr');
    fd.append('domains',           raw);
    fd.append('g_recaptcha_token', token);

    try {
      var resp = await fetch(window.location.href, { method: 'POST', body: fd });
      if (!resp.ok) throw new Error('Server returned ' + resp.status);
      var data = await resp.json();
      if (data.error) {
        showCsrError(data.error);
        return;
      }
      // Populate the paste tab and switch to it
      document.getElementById('csrText').value = data.csr;
      tabs.forEach(function (t) { t.classList.remove('active'); });
      panes.forEach(function (p) { p.classList.remove('active'); });
      var pasteTab  = document.querySelector('[data-tab="paste"]');
      var pastePane = document.getElementById('pane-paste');
      if (pasteTab)  pasteTab.classList.add('active');
      if (pastePane) pastePane.classList.add('active');

      csrBuilderOk.hidden      = false;
      csrBuilderOk.textContent = '✔ CSR ready — ' + (data.domains || []).join(', ') + '. Click Issue Certificate to continue.';
    } catch (err) {
      showCsrError('Request failed: ' + err.message);
    } finally {
      btnGenCsr.disabled    = false;
      btnGenCsr.textContent = 'Generate CSR';
    }
  }

  function showCsrError(msg) {
    csrBuilderError.hidden      = false;
    csrBuilderError.textContent = '✕ ' + msg;
    csrBuilderOk.hidden         = true;
  }

  // ── DCV ──────────────────────────────────────────────────────────────────────
  var dcvEnabled     = document.getElementById('dcvEnabled');
  var dcvMethodPanel = document.getElementById('dcvMethodPanel');
  var dcvOptNote     = document.getElementById('dcvOptNote');
  var dcvCard        = document.getElementById('dcvCard');
  var dcvBadge       = document.getElementById('dcvBadge');
  var dcvItems       = document.getElementById('dcvItems');
  var btnVerifyDcv   = document.getElementById('btnVerifyDcv');
  var dcvSpinner     = document.getElementById('dcvSpinner');
  var dcvErrorBox    = document.getElementById('dcvErrorBox');
  var dcvErrMsg      = document.getElementById('dcvErrMsg');

  var dcvChallengeActive = false;

  dcvEnabled.addEventListener('change', function () {
    dcvMethodPanel.hidden = !dcvEnabled.checked;
    if (!dcvEnabled.checked) {
      dcvCard.hidden = true;
      dcvChallengeActive = false;
    }
  });

  var dcvMethodNotes = {
    'http':      'Place a file at each domain\'s /.well-known/pki-validation/TOKEN URL containing exactly the token value.',
    'dns':       'Add a DNS TXT record named _pki-validation.DOMAIN with the token value.',
    'dns-cname': 'Add a DNS CNAME record: _pki-validation.DOMAIN → TOKEN.dcv.' + window.location.hostname + '. The CA verifies the CNAME target.',
    'tls-alpn':  'Host a TLS listener on port 443 for each domain. It must negotiate ALPN "acme-tls/1" and present a self-signed certificate containing the acmeValidation extension. Wildcards are not supported.'
  };

  document.querySelectorAll('input[name="dcv_method"]').forEach(function (radio) {
    radio.addEventListener('change', function () {
      var m = document.querySelector('input[name="dcv_method"]:checked').value;
      dcvOptNote.textContent = dcvMethodNotes[m] || '';
      if (dcvChallengeActive) {
        dcvCard.hidden = true;
        dcvChallengeActive = false;
        showError('DCV method changed — click Issue Certificate to generate a new challenge.');
      }
    });
  });

  btnVerifyDcv.addEventListener('click', function () { doVerifyDcv(); });

  async function doGenerateChallenge(action) {
    var activeTab = document.querySelector('.input-tab.active');
    var tabMethod = activeTab ? activeTab.dataset.tab : 'paste';

    if (tabMethod === 'paste') {
      var txt = document.getElementById('csrText').value.trim();
      if (!txt) { showError('Please paste a PEM CSR.'); return; }
      if (!txt.includes('CERTIFICATE REQUEST')) {
        showError('Not a valid PEM CERTIFICATE REQUEST block.');
        return;
      }
    } else {
      if (!fileInput.files[0]) { showError('Please select a file.'); return; }
    }

    setLoading(true);
    hideError();
    dcvCard.hidden = true;
    resultCard.hidden = true;

    var fd = new FormData(form);
    if (tabMethod === 'paste') fd.delete('csr_file');
    else                       fd.delete('csr');
    fd.set('action', 'generate_challenge');
    fd.set('precert', action === 'issue_precert' ? '1' : '');
    var methodRadio = document.querySelector('input[name="dcv_method"]:checked');
    fd.set('dcv_method', methodRadio ? methodRadio.value : 'http');
    var rcToken = await getRecaptchaToken('issue_cert');
    fd.append('g_recaptcha_token', rcToken);

    try {
      var resp = await fetch(window.location.href, { method: 'POST', body: fd });
      if (!resp.ok) throw new Error('Server returned ' + resp.status);
      var data = await resp.json();
      if (data.error) { showError(data.error); return; }
      dcvChallengeActive = true;
      renderDcvInstructions(data);
    } catch (err) {
      showError('Request failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  }

  function renderDcvInstructions(data) {
    var m = data.method;
    var badgeLabels = { 'http': 'HTTP', 'dns': 'DNS TXT', 'dns-cname': 'DNS CNAME', 'tls-alpn': 'TLS-ALPN' };
    dcvBadge.textContent = badgeLabels[m] || m.toUpperCase();
    dcvBadge.className   = 'dcv-badge ' + (m === 'http' ? '' : m);

    var html = '';
    Object.keys(data.tokens).forEach(function (domain) {
      var token = data.tokens[domain];
      html += '<div class="dcv-challenge-item">';
      html += '<div class="dcv-challenge-domain">' + esc(domain) + '</div>';

      if (m === 'http') {
        var urlRaw = 'http://' + domain + '/.well-known/pki-validation/' + token;
        html += tokenBlock('URL', esc(urlRaw), urlRaw);
        html += tokenBlock('File content (exact)', esc(token), token);

      } else if (m === 'dns') {
        var nameRaw = '_pki-validation.' + domain;
        html += tokenBlock('DNS record name', esc(nameRaw), nameRaw);
        html += '<div class="dcv-token-block"><div class="dcv-token-label">Type</div>'
              + '<div class="dcv-token-row"><span class="dcv-token-value">TXT</span></div></div>';
        html += tokenBlock('Value', esc(token), token);

      } else if (m === 'dns-cname') {
        var cnameFrom = '_pki-validation.' + domain;
        var cnameTo   = token + '.dcv.' + window.location.hostname + '.';
        html += tokenBlock('CNAME record name', esc(cnameFrom), cnameFrom);
        html += '<div class="dcv-token-block"><div class="dcv-token-label">Type</div>'
              + '<div class="dcv-token-row"><span class="dcv-token-value">CNAME</span></div></div>';
        html += tokenBlock('CNAME target (include trailing dot)', esc(cnameTo), cnameTo);

      } else if (m === 'tls-alpn') {
        // Compute SHA-256 of token in browser to display the expected extension value
        html += tokenBlock('Token (used to derive the cert extension value)', esc(token), token);
        html += '<div class="dcv-token-block"><div class="dcv-token-label">Setup</div>'
              + '<div class="dcv-token-row"><span class="dcv-token-value" style="color:var(--muted);font-size:0.7rem">'
              + 'Run a TLS listener on ' + esc(domain) + ':443 that negotiates ALPN "acme-tls/1" '
              + 'and presents a self-signed cert with a subjectAltName of ' + esc(domain)
              + ' and an acmeValidation extension (OID 1.3.6.1.5.5.7.1.31) containing SHA-256 of the token above.'
              + '</span></div></div>';
      }

      html += '</div>';
    });
    dcvItems.innerHTML = html;
    dcvErrorBox.hidden = true;
    dcvCard.hidden = false;
    dcvCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function tokenBlock(label, display, copyVal) {
    var jsonVal = JSON.stringify(copyVal).replace(/"/g, '&quot;');
    return '<div class="dcv-token-block">'
      + '<div class="dcv-token-label">' + label + '</div>'
      + '<div class="dcv-token-row">'
      + '<span class="dcv-token-value">' + display + '</span>'
      + '<button class="dcv-copy-btn" onclick="dcvCopy(this,' + jsonVal + ')">Copy</button>'
      + '</div></div>';
  }

  async function doVerifyDcv() {
    btnVerifyDcv.disabled    = true;
    btnVerifyDcv.textContent = 'Verifying…';
    dcvSpinner.hidden        = false;
    dcvErrorBox.hidden       = true;
    resultCard.hidden        = true;

    var fd = new FormData();
    fd.append('action', 'verify_dcv');

    try {
      var resp = await fetch(window.location.href, { method: 'POST', body: fd });
      if (!resp.ok) throw new Error('Server returned ' + resp.status);
      var data = await resp.json();
      if (data.ok) {
        dcvCard.hidden = true;
        dcvChallengeActive = false;
        renderResult(data);
      } else if (data.error) {
        dcvErrMsg.textContent = data.error;
        dcvErrorBox.hidden = false;
      } else {
        renderDcvResults(data.results || {});
      }
    } catch (err) {
      dcvErrMsg.textContent = 'Request failed: ' + err.message;
      dcvErrorBox.hidden = false;
    } finally {
      btnVerifyDcv.disabled    = false;
      btnVerifyDcv.textContent = 'Verify & Issue';
      dcvSpinner.hidden        = true;
    }
  }

  function renderDcvResults(results) {
    var items   = dcvItems.querySelectorAll('.dcv-challenge-item');
    var domains = Object.keys(results);
    domains.forEach(function (domain, i) {
      var r    = results[domain];
      var item = items[i];
      if (!item) return;
      var existing = item.querySelector('.dcv-result-item');
      if (existing) existing.remove();
      var el = document.createElement('div');
      el.className = 'dcv-result-item ' + (r.ok ? 'dcv-result-ok' : 'dcv-result-err');
      el.innerHTML = r.ok
        ? '<span>&#10004;</span><span>Verified</span>'
        : '<span>&#10005;</span><span>' + esc(r.error || 'Verification failed') + '</span>';
      item.appendChild(el);
    });
  }

  window.dcvCopy = function (btn, text) {
    navigator.clipboard.writeText(text).then(function () {
      var orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(function () { btn.textContent = orig; }, 1800);
    });
  };

  // ── Revocation ───────────────────────────────────────────────────────────────
  document.getElementById('btnRevoke').addEventListener('click', function () {
    doRevoke();
  });

  async function doRevoke() {
    var btn    = document.getElementById('btnRevoke');
    var result = document.getElementById('revokeResult');
    var reason = document.getElementById('revokeReason').value;
    var cert   = pemOutput.value;

    if (!cert) return;

    btn.disabled    = true;
    btn.textContent = 'Revoking…';
    result.hidden   = true;
    result.className = 'revoke-result';

    var token = await getRecaptchaToken('revoke_cert');

    var fd = new FormData();
    fd.append('action',             'revoke');
    fd.append('cert',               cert);
    fd.append('reason',             reason);
    fd.append('g_recaptcha_token',  token);

    try {
      var resp = await fetch(window.location.href, { method: 'POST', body: fd });
      if (!resp.ok) throw new Error('Server returned ' + resp.status);
      var data = await resp.json();
      result.hidden = false;
      if (data.ok) {
        result.classList.add('ok');
        result.textContent = '✔ ' + data.message;
      } else {
        result.classList.add('err');
        result.textContent = '✕ ' + (data.error || 'Unknown error');
        btn.disabled    = false;
        btn.textContent = 'Revoke this Certificate';
      }
    } catch (err) {
      result.hidden = false;
      result.classList.add('err');
      result.textContent = '✕ Request failed: ' + err.message;
      btn.disabled    = false;
      btn.textContent = 'Revoke this Certificate';
    }
  }

}());
</script>
</body>
</html>
