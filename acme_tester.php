<?php
require_once __DIR__ . '/config.php';

// ── POST / API ────────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    session_start();
    header('Content-Type: application/json; charset=utf-8');
    set_time_limit(120);
    $action = $_POST['action'] ?? '';
    $result = match ($action) {
        'init'     => acme_action_init(),
        'order'    => acme_action_order(),
        'verify'   => acme_action_verify(),
        'finalize' => acme_action_finalize(),
        'revoke'   => acme_action_revoke(),
        'ari'      => acme_action_ari(),
        'report'   => acme_action_report(),
        'reset'    => (function () {
            unset($_SESSION['acme'], $_SESSION['acme_log']);
            return ['ok' => true];
        })(),
        default => ['error' => 'Unknown action'],
    };
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// ── JOSE / ACME helpers ───────────────────────────────────────────────────────

function ab64(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function ab64d(string $data): string
{
    return (string) base64_decode(strtr($data, '-_', '+/'));
}

function acme_keypair(): array
{
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($key, $pem);
    return ['pem' => $pem, 'details' => openssl_pkey_get_details($key)];
}

function acme_jwk(array $det): array
{
    $r = $det['rsa'];
    return ['e' => ab64($r['e']), 'kty' => 'RSA', 'n' => ab64($r['n'])];
}

function acme_thumb(array $jwk): string
{
    $ord = ['e' => $jwk['e'], 'kty' => $jwk['kty'], 'n' => $jwk['n']];
    return ab64(hash('sha256', json_encode($ord, JSON_UNESCAPED_SLASHES), true));
}

function acme_sign(array $protected, $payload, string $pem): string
{
    $p  = ab64(json_encode($protected, JSON_UNESCAPED_SLASHES));
    $pl = ($payload === '') ? '' : ab64(json_encode($payload, JSON_UNESCAPED_SLASHES));
    openssl_sign($p . '.' . $pl, $sig, openssl_pkey_get_private($pem), OPENSSL_ALGO_SHA256);
    return json_encode(['protected' => $p, 'payload' => $pl, 'signature' => ab64($sig)], JSON_UNESCAPED_SLASHES);
}

function acme_eab_sign(string $kid, string $mac_b64url, array $jwk, string $url): array
{
    $prot = ab64(json_encode(['alg' => 'HS256', 'kid' => $kid, 'url' => $url], JSON_UNESCAPED_SLASHES));
    $payl = ab64(json_encode($jwk, JSON_UNESCAPED_SLASHES));
    $sig  = ab64(hash_hmac('sha256', $prot . '.' . $payl, ab64d($mac_b64url), true));
    return ['protected' => $prot, 'payload' => $payl, 'signature' => $sig];
}

function acme_http(string $method, string $url, ?string $body, bool $skip_tls): array
{
    $ch   = curl_init();
    $hdrs = ['User-Agent: PKITools-ACMETester/1.0'];
    if ($body !== null) {
        $hdrs[] = 'Content-Type: application/jose+json';
    }
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_HEADER         => true,
        CURLOPT_HTTPHEADER     => $hdrs,
        CURLOPT_SSL_VERIFYPEER => !$skip_tls,
        CURLOPT_SSL_VERIFYHOST => $skip_tls ? 0 : 2,
        CURLOPT_FOLLOWLOCATION => false,
    ]);
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body ?? '');
    } elseif ($method === 'HEAD') {
        curl_setopt($ch, CURLOPT_NOBODY, true);
    }
    $raw  = (string) curl_exec($ch);
    $code = (int)    curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hsz  = (int)    curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $cerr = curl_error($ch);
    curl_close($ch);

    $raw_hdrs = substr($raw, 0, $hsz);
    $raw_body = substr($raw, $hsz);

    $hmap = [];
    foreach (explode("\r\n", $raw_hdrs) as $line) {
        if (strpos($line, ':') !== false) {
            [$k, $v] = explode(':', $line, 2);
            $hmap[strtolower(trim($k))] = trim($v);
        }
    }
    return [
        'ok'       => ($code >= 200 && $code < 300),
        'code'     => $code,
        'headers'  => $hmap,
        'body'     => $raw_body,
        'json'     => json_decode($raw_body, true),
        'cerr'     => $cerr,
        'raw_hdrs' => $raw_hdrs,
        'raw_body' => $raw_body,
    ];
}

function &acme_sess(): array
{
    if (!isset($_SESSION['acme'])) {
        $_SESSION['acme'] = [];
    }
    return $_SESSION['acme'];
}

function acme_log_entry(string $step, string $method, string $url, string $req, array $resp): void
{
    if (!isset($_SESSION['acme_log'])) {
        $_SESSION['acme_log'] = [];
    }
    $_SESSION['acme_log'][] = [
        'step'      => $step,
        'method'    => $method,
        'url'       => $url,
        'req_body'  => $req,
        'resp_code' => $resp['code'],
        'resp_hdrs' => $resp['raw_hdrs'],
        'resp_body' => $resp['raw_body'],
        'ok'        => $resp['ok'],
        'ts'        => date('c'),
    ];
}

function acme_post_req(string $url, $payload): array
{
    $s    = &acme_sess();
    $skip = $s['skip_tls'] ?? false;

    if (empty($s['nonce'])) {
        $rn = acme_http('HEAD', $s['directory']['newNonce'], null, $skip);
        $s['nonce'] = $rn['headers']['replay-nonce'] ?? '';
    }

    $protected = ['alg' => 'RS256', 'nonce' => $s['nonce'], 'url' => $url];
    if (!empty($s['account_url'])) {
        $protected['kid'] = $s['account_url'];
    } else {
        $protected['jwk'] = $s['jwk'];
    }

    $jws = acme_sign($protected, $payload, $s['key_pem']);
    $r   = acme_http('POST', $url, $jws, $skip);
    $s['nonce'] = $r['headers']['replay-nonce'] ?? null;
    return $r;
}

function acme_run_cmd(array $cmd): array
{
    $proc = proc_open($cmd,
        [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes);
    if (!$proc) {
        return ['ok' => false, 'out' => '', 'err' => 'proc_open failed'];
    }
    $out  = stream_get_contents($pipes[1]);
    $err  = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return ['ok' => $code === 0, 'out' => (string) $out, 'err' => (string) $err];
}

function acme_gen_csr(array $domains): array
{
    $tmpKey = sys_get_temp_dir() . '/at_k_' . bin2hex(random_bytes(6)) . '.key';
    $tmpCsr = sys_get_temp_dir() . '/at_c_' . bin2hex(random_bytes(6)) . '.csr';
    $tmpCnf = sys_get_temp_dir() . '/at_n_' . bin2hex(random_bytes(6)) . '.cnf';
    try {
        $r = acme_run_cmd([OPENSSL_BIN, 'genrsa', '-out', $tmpKey, '2048']);
        if (!$r['ok']) {
            return ['error' => 'Key generation failed: ' . $r['err']];
        }
        $cn = '';
        foreach ($domains as $d) {
            if (!str_starts_with($d, '*.')) { $cn = $d; break; }
        }
        if ($cn === '') $cn = substr($domains[0], 2);
        $sans = implode(',', array_map(fn($d) => 'DNS:' . $d, $domains));
        file_put_contents($tmpCnf, implode("\n", [
            '[req]', 'distinguished_name = dn', 'req_extensions = san', 'prompt = no',
            '[dn]',  'CN=' . $cn,
            '[san]', 'subjectAltName = ' . $sans,
        ]));
        $r = acme_run_cmd([OPENSSL_BIN, 'req', '-new', '-key', $tmpKey, '-out', $tmpCsr, '-config', $tmpCnf]);
        if (!$r['ok']) {
            return ['error' => 'CSR generation failed'];
        }
        return ['ok' => true, 'csr_pem' => trim((string) file_get_contents($tmpCsr))];
    } finally {
        @unlink($tmpKey); @unlink($tmpCsr); @unlink($tmpCnf);
    }
}

function acme_csr_der(string $csr_pem): string
{
    $tmpIn  = sys_get_temp_dir() . '/at_ci_' . bin2hex(random_bytes(6)) . '.pem';
    $tmpOut = sys_get_temp_dir() . '/at_co_' . bin2hex(random_bytes(6)) . '.der';
    file_put_contents($tmpIn, $csr_pem);
    try {
        $r = acme_run_cmd([OPENSSL_BIN, 'req', '-in', $tmpIn, '-outform', 'DER', '-out', $tmpOut]);
        return ($r['ok'] && file_exists($tmpOut)) ? (string) file_get_contents($tmpOut) : '';
    } finally {
        @unlink($tmpIn); @unlink($tmpOut);
    }
}

function acme_parse_cert_pem(string $pem): array
{
    $tmp = sys_get_temp_dir() . '/at_cp_' . bin2hex(random_bytes(6)) . '.pem';
    file_put_contents($tmp, $pem);
    $r = acme_run_cmd([OPENSSL_BIN, 'x509', '-in', $tmp, '-noout', '-text']);
    @unlink($tmp);
    if (!$r['ok']) return [];
    $t   = $r['out'];
    $out = [];
    if (preg_match('/Subject:\s*(.+)/i',                          $t, $m)) $out['subject']    = trim($m[1]);
    if (preg_match('/Issuer:\s*(.+)/i',                           $t, $m)) $out['issuer']     = trim($m[1]);
    if (preg_match('/Not Before:\s*(.+)/i',                       $t, $m)) $out['not_before'] = trim($m[1]);
    if (preg_match('/Not After\s*:\s*(.+)/i',                     $t, $m)) $out['not_after']  = trim($m[1]);
    if (preg_match('/Serial Number:\s*\n?\s*([0-9a-f:]+)/i',      $t, $m)) $out['serial']     = trim($m[1]);
    if (preg_match('/X509v3 Authority Key Identifier:\s*\n\s*(?:keyid:)?([0-9A-F:]+)/i', $t, $m)) {
        $out['aki_hex'] = strtolower(str_replace(':', '', $m[1]));
    }
    $out['serial_hex'] = strtolower(str_replace(':', '', $out['serial'] ?? ''));
    $sans = [];
    if (preg_match('/Subject Alternative Name:\s*\n((?:[ \t]+[^\n]+\n?)+)/m', $t, $m)) {
        preg_match_all('/DNS:([^\s,]+)/i', $m[1], $dm);
        $sans = $dm[1];
    }
    $out['sans'] = $sans;
    return $out;
}

// ── Action handlers ───────────────────────────────────────────────────────────

function acme_action_init(): array
{
    $endpoint = trim($_POST['endpoint'] ?? '');
    $email    = trim($_POST['email']    ?? '');
    $skip_tls = !empty($_POST['skip_tls']);
    $eab_kid  = trim($_POST['eab_kid']  ?? '');
    $eab_mac  = trim($_POST['eab_mac']  ?? '');

    if (!$endpoint) return ['error' => 'ACME endpoint URL is required'];
    if (!filter_var($endpoint, FILTER_VALIDATE_URL)) return ['error' => 'Invalid endpoint URL'];
    if (!$email)    return ['error' => 'Email is required for account creation'];

    $_SESSION['acme']     = ['skip_tls' => $skip_tls];
    $_SESSION['acme_log'] = [];
    $s = &acme_sess();

    $steps = [];

    // 1. Fetch directory
    $r = acme_http('GET', $endpoint, null, $skip_tls);
    acme_log_entry('Fetch directory', 'GET', $endpoint, '', $r);

    if ($r['cerr']) {
        return ['error' => 'Connection failed: ' . $r['cerr'],
                'steps' => [['name' => 'Fetch directory', 'ok' => false, 'detail' => $r['cerr']]]];
    }
    if (!$r['ok']) {
        return ['error' => "Directory returned HTTP {$r['code']}",
                'steps' => [['name' => 'Fetch directory', 'ok' => false, 'detail' => "HTTP {$r['code']}: " . substr($r['raw_body'], 0, 200)]]];
    }
    $dir = $r['json'];
    if (!is_array($dir)) {
        return ['error' => 'Directory response is not valid JSON',
                'steps' => [['name' => 'Fetch directory', 'ok' => false, 'detail' => 'Not valid JSON: ' . substr($r['raw_body'], 0, 200)]]];
    }

    $required = ['newNonce', 'newAccount', 'newOrder', 'revokeCert', 'keyChange'];
    $optional = ['renewalInfo'];
    $dir_checks = [];
    foreach ($required as $k) {
        $dir_checks[] = ['field' => $k, 'required' => true,  'present' => isset($dir[$k])];
    }
    foreach ($optional as $k) {
        $dir_checks[] = ['field' => $k, 'required' => false, 'present' => isset($dir[$k])];
    }
    $missing = array_filter($dir_checks, fn($c) => $c['required'] && !$c['present']);
    $dir_ok  = empty($missing);

    $ct = $r['headers']['content-type'] ?? '';
    $warnings = [];
    if (!str_contains($ct, 'application/json')) {
        $warnings[] = "Content-Type \"{$ct}\" — expected application/json";
    }

    $steps[] = [
        'name'     => 'Fetch directory',
        'ok'       => $dir_ok,
        'detail'   => $dir_ok
            ? 'All required fields present' . (isset($dir['renewalInfo']) ? ' · ARI supported' : '')
            : 'Missing: ' . implode(', ', array_column(array_values($missing), 'field')),
        'checks'   => $dir_checks,
        'warnings' => $warnings,
    ];

    if (!$dir_ok) {
        return ['error' => 'Directory is missing required fields', 'steps' => $steps];
    }
    $s['directory'] = $dir;

    // 2. Generate key pair
    $kp = acme_keypair();
    $s['key_pem']    = $kp['pem'];
    $s['jwk']        = acme_jwk($kp['details']);
    $s['thumbprint'] = acme_thumb($s['jwk']);
    $steps[] = ['name' => 'Generate ACME key pair', 'ok' => true, 'detail' => 'RSA-2048 ephemeral key generated'];

    // 3. Fetch nonce
    $rn = acme_http('HEAD', $dir['newNonce'], null, $skip_tls);
    acme_log_entry('Get nonce', 'HEAD', $dir['newNonce'], '', $rn);
    $nonce    = $rn['headers']['replay-nonce'] ?? '';
    $nonce_ok = $nonce !== '';
    $steps[] = [
        'name'   => 'Get nonce (HEAD newNonce)',
        'ok'     => $nonce_ok,
        'detail' => $nonce_ok ? 'Nonce received (' . strlen($nonce) . ' chars)' : 'No Replay-Nonce header returned',
    ];
    if (!$nonce_ok) {
        return ['error' => 'Server did not return Replay-Nonce', 'steps' => $steps];
    }
    $s['nonce'] = $nonce;

    // 4. Create account
    $payload = ['termsOfServiceAgreed' => true, 'contact' => ['mailto:' . $email]];
    if ($eab_kid && $eab_mac) {
        $payload['externalAccountBinding'] = acme_eab_sign($eab_kid, $eab_mac, $s['jwk'], $dir['newAccount']);
    }

    $ra = acme_post_req($dir['newAccount'], $payload);
    acme_log_entry('Create account', 'POST', $dir['newAccount'], '(JWS — key material omitted)', $ra);

    $acct_ok   = ($ra['code'] === 200 || $ra['code'] === 201);
    $acct_url  = $ra['headers']['location'] ?? '';
    $acct_warns = [];
    $acct_detail = '';

    if ($ra['cerr']) {
        $acct_detail = 'Connection error: ' . $ra['cerr'];
        $acct_ok = false;
    } elseif (!$ra['ok']) {
        // Non-2xx — show code + full problem detail
        $prob  = $ra['json'];
        $acct_detail = "HTTP {$ra['code']}";
        if (!empty($prob['type']))   $acct_detail .= ' · ' . $prob['type'];
        if (!empty($prob['detail'])) $acct_detail .= ': ' . $prob['detail'];
        elseif ($ra['raw_body'] !== '') $acct_detail .= ' · ' . substr($ra['raw_body'], 0, 300);
    } else {
        $acct_status = $ra['json']['status'] ?? null;
        $acct_detail = "HTTP {$ra['code']} — account " . ($acct_status ?? '(no status in body)');
        // RFC 8555 §7.3: 201 for new account, 200 for existing — Location MUST be present
        if ($ra['code'] === 200) {
            $acct_warns[] = 'Server returned 200 instead of 201 — may be an existing account';
        }
        if (!$acct_url) {
            $acct_warns[] = 'No Location header — RFC 8555 §7.3 requires it; account URL unknown';
        }
        $nonce_hdr = $ra['headers']['replay-nonce'] ?? '';
        if (!$nonce_hdr) {
            $acct_warns[] = 'No Replay-Nonce in response — RFC 8555 §6.5 requires it on every POST response';
        }
        $ct = $ra['headers']['content-type'] ?? '';
        if ($ct && !str_contains($ct, 'json')) {
            $acct_warns[] = "Unexpected Content-Type: {$ct}";
        }
        if ($acct_status === null) {
            $acct_warns[] = 'Response body missing "status" field';
        }
    }

    $steps[] = [
        'name'     => 'Create account (POST newAccount)',
        'ok'       => $acct_ok,
        'warn'     => $acct_ok && !empty($acct_warns),
        'detail'   => $acct_detail,
        'warnings' => $acct_warns,
    ];
    if (!$acct_ok) {
        return ['error' => 'Account creation failed — HTTP ' . $ra['code']
                         . ($ra['json']['detail'] ? ': ' . $ra['json']['detail'] : ''), 'steps' => $steps];
    }
    if ($acct_url) $s['account_url'] = $acct_url;

    return [
        'ok'        => true,
        'steps'     => $steps,
        'has_ari'   => isset($dir['renewalInfo']),
        'meta'      => $dir['meta'] ?? [],
        'acct_url'  => $acct_url,
    ];
}

function acme_action_order(): array
{
    $s = &acme_sess();
    if (empty($s['directory'])) return ['error' => 'Session expired — restart the test'];

    $raw    = trim($_POST['domains'] ?? '');
    $method = $_POST['challenge_method'] ?? 'http-01';
    if (!$raw) return ['error' => 'No domains provided'];
    if (!in_array($method, ['http-01', 'dns-01'], true)) return ['error' => 'Invalid challenge method'];

    $domains = [];
    foreach (explode(',', $raw) as $p) {
        $d = strtolower(trim($p));
        if ($d && !in_array($d, $domains, true)) $domains[] = $d;
    }
    if (empty($domains)) return ['error' => 'No valid domains'];
    $s['domains']          = $domains;
    $s['challenge_method'] = $method;

    $steps = [];

    // Place order
    $identifiers = array_map(fn($d) => ['type' => 'dns', 'value' => $d], $domains);
    $ro = acme_post_req($s['directory']['newOrder'], ['identifiers' => $identifiers]);
    acme_log_entry('Place order', 'POST', $s['directory']['newOrder'], '(JWS)', $ro);

    if (!$ro['ok']) {
        $prob = $ro['json'];
        $err_detail = "HTTP {$ro['code']}";
        if (!empty($prob['type']))   $err_detail .= ' · ' . $prob['type'];
        if (!empty($prob['detail'])) $err_detail .= ': ' . $prob['detail'];
        elseif ($ro['raw_body'] !== '') $err_detail .= ' · ' . substr($ro['raw_body'], 0, 300);
        $steps[] = ['name' => 'Place order (POST newOrder)', 'ok' => false, 'detail' => $err_detail];
        return ['error' => 'Order placement failed — ' . $err_detail, 'steps' => $steps];
    }
    $order     = $ro['json'] ?? [];
    $order_url = $ro['headers']['location'] ?? '';
    $order_warns = [];
    // RFC 8555 §7.4: server MUST respond 201 Created for a new order
    if ($ro['code'] !== 201) {
        $order_warns[] = "HTTP {$ro['code']} returned — RFC 8555 §7.4 requires 201 Created for new orders";
    }
    if (!$order_url) {
        $order_warns[] = 'No Location header — RFC 8555 §7.4 requires it; cannot poll order status';
    }
    // Validate required order fields
    foreach (['status', 'identifiers', 'authorizations', 'finalize'] as $f) {
        if (!isset($order[$f])) $order_warns[] = "Response body missing required field: \"{$f}\"";
    }
    if (!$ro['headers']['replay-nonce'] ?? '') {
        $order_warns[] = 'No Replay-Nonce in response';
    }
    $steps[] = [
        'name'     => 'Place order (POST newOrder)',
        'ok'       => true,
        'warn'     => !empty($order_warns),
        'detail'   => "HTTP {$ro['code']} — order " . ($order['status'] ?? '(no status)'),
        'warnings' => $order_warns,
    ];
    $s['order_url']    = $order_url;
    $s['finalize_url'] = $order['finalize'] ?? '';

    // Without a finalize URL we cannot proceed
    if (!$s['finalize_url']) {
        return ['error' => 'Order response missing "finalize" URL — cannot proceed', 'steps' => $steps];
    }

    // Fetch authorizations
    $authz_list = [];
    foreach ($order['authorizations'] ?? [] as $authz_url) {
        $ra = acme_post_req($authz_url, '');
        acme_log_entry('Fetch authz', 'POST', $authz_url, '(POST-as-GET)', $ra);

        if (!$ra['ok']) {
            $prob = $ra['json'];
            $det  = "HTTP {$ra['code']}";
            if (!empty($prob['detail'])) $det .= ': ' . $prob['detail'];
            elseif ($ra['raw_body'] !== '') $det .= ' · ' . substr($ra['raw_body'], 0, 200);
            $steps[] = ['name' => 'Fetch authorization', 'ok' => false, 'detail' => $det];
            continue;
        }
        $authz   = $ra['json'];
        $domain  = $authz['identifier']['value'] ?? '?';
        $challs  = $authz['challenges'] ?? [];

        $selected  = null;
        $all_types = [];
        foreach ($challs as $c) {
            $all_types[] = $c['type'];
            if ($c['type'] === $method) $selected = $c;
        }

        $thumb    = $s['thumbprint'];
        $key_auth = '';
        $dns_val  = '';
        if ($selected) {
            $token    = $selected['token'] ?? '';
            $key_auth = $token . '.' . $thumb;
            if ($method === 'dns-01') {
                $dns_val = ab64(hash('sha256', $key_auth, true));
            }
        }

        $authz_list[] = [
            'domain'    => $domain,
            'authz_url' => $authz_url,
            'status'    => $authz['status'] ?? '?',
            'wildcard'  => $authz['wildcard'] ?? false,
            'challenge' => $selected,
            'key_auth'  => $key_auth,
            'dns_val'   => $dns_val,
            'all_types' => $all_types,
        ];
        $steps[] = [
            'name'   => "Fetch authz: {$domain}",
            'ok'     => (bool) $selected,
            'detail' => $selected
                ? "{$method} available — authz " . ($authz['status'] ?? '?')
                : "{$method} not offered (server has: " . implode(', ', $all_types) . ')',
        ];
    }

    $s['authz'] = $authz_list;
    $no_chall = array_filter($authz_list, fn($a) => !$a['challenge']);
    if (!empty($no_chall)) {
        $doms = implode(', ', array_column(array_values($no_chall), 'domain'));
        return ['error' => "{$method} not available for: {$doms}", 'steps' => $steps];
    }

    return ['ok' => true, 'steps' => $steps, 'authz' => $authz_list, 'method' => $method];
}

function acme_action_verify(): array
{
    $s = &acme_sess();
    if (empty($s['authz'])) return ['error' => 'Session expired — restart the test'];

    $steps = [];

    // Signal each challenge
    foreach ($s['authz'] as $authz) {
        $chall = $authz['challenge'];
        if (!$chall || empty($chall['url'])) continue;
        $domain = $authz['domain'];
        $rv = acme_post_req($chall['url'], new stdClass());
        acme_log_entry("Signal challenge: {$domain}", 'POST', $chall['url'], '(JWS {})', $rv);
        $ok = ($rv['code'] === 200);
        $steps[] = [
            'name'   => "Signal: {$domain}",
            'ok'     => $ok,
            'detail' => $ok ? 'Challenge signaled (HTTP 200)' : "HTTP {$rv['code']}: " . ($rv['json']['detail'] ?? substr($rv['raw_body'], 0, 200)),
        ];
    }

    // Poll authorizations
    $results = [];
    $all_ok  = true;
    foreach ($s['authz'] as $authz) {
        $domain    = $authz['domain'];
        $authz_url = $authz['authz_url'];
        $status    = 'pending';
        $err       = null;

        for ($i = 0; $i < 20; $i++) {
            sleep(3);
            $rp     = acme_post_req($authz_url, '');
            acme_log_entry("Poll authz: {$domain} (#" . ($i + 1) . ')', 'POST', $authz_url, '(POST-as-GET)', $rp);
            $status = $rp['json']['status'] ?? 'unknown';
            if ($status === 'valid') break;
            if ($status === 'invalid') {
                foreach ($rp['json']['challenges'] ?? [] as $c) {
                    if (!empty($c['error'])) { $err = $c['error']['detail'] ?? $c['error']['type'] ?? 'invalid'; break; }
                }
                break;
            }
        }

        $ok = ($status === 'valid');
        if (!$ok) $all_ok = false;
        $results[$domain] = ['ok' => $ok, 'status' => $status, 'error' => $err ?? ($ok ? null : "Timed out — status: {$status}")];
        $steps[] = [
            'name'   => "Verify authz: {$domain}",
            'ok'     => $ok,
            'detail' => $ok ? 'Authorization valid' : ($err ?? "Status: {$status}"),
        ];
    }

    return ['ok' => $all_ok, 'steps' => $steps, 'results' => $results];
}

function acme_action_finalize(): array
{
    $s = &acme_sess();
    if (empty($s['finalize_url'])) return ['error' => 'Session expired — restart the test'];

    $csr_pem = trim($_POST['csr'] ?? '');
    $steps   = [];

    if ($csr_pem) {
        if (!str_contains($csr_pem, 'CERTIFICATE REQUEST')) {
            return ['error' => 'Invalid CSR format'];
        }
        $steps[] = ['name' => 'CSR', 'ok' => true, 'detail' => 'Using provided CSR'];
    } else {
        $r = acme_gen_csr($s['domains'] ?? []);
        if (!empty($r['error'])) return ['error' => $r['error']];
        $csr_pem = $r['csr_pem'];
        $steps[] = ['name' => 'CSR', 'ok' => true, 'detail' => 'Generated throwaway CSR (2048-bit RSA, key discarded)'];
    }

    $csr_der = acme_csr_der($csr_pem);
    if (!$csr_der) return ['error' => 'Failed to convert CSR to DER'];

    // Finalize
    $rf = acme_post_req($s['finalize_url'], ['csr' => ab64($csr_der)]);
    acme_log_entry('Finalize order', 'POST', $s['finalize_url'], '(JWS)', $rf);
    $fin_ok = ($rf['code'] === 200);
    $steps[] = [
        'name'   => 'Finalize order',
        'ok'     => $fin_ok,
        'detail' => $fin_ok ? 'HTTP 200 — order processing' : "HTTP {$rf['code']}: " . ($rf['json']['detail'] ?? substr($rf['raw_body'], 0, 200)),
    ];
    if (!$fin_ok) {
        return ['error' => 'Finalize failed: ' . ($rf['json']['detail'] ?? "HTTP {$rf['code']}"), 'steps' => $steps];
    }

    // Poll order
    $order_url   = $s['order_url'];
    $cert_url    = '';
    $order_status = 'processing';
    for ($i = 0; $i < 20; $i++) {
        sleep(3);
        $rp = acme_post_req($order_url, '');
        acme_log_entry("Poll order (#" . ($i + 1) . ')', 'POST', $order_url, '(POST-as-GET)', $rp);
        $order_status = $rp['json']['status'] ?? 'unknown';
        $cert_url     = $rp['json']['certificate'] ?? '';
        if ($order_status === 'valid') break;
        if ($order_status === 'invalid') {
            $err = $rp['json']['error']['detail'] ?? 'Order invalid';
            $steps[] = ['name' => 'Poll order', 'ok' => false, 'detail' => $err];
            return ['error' => 'Order failed: ' . $err, 'steps' => $steps];
        }
    }
    $steps[] = ['name' => 'Poll order', 'ok' => $order_status === 'valid', 'detail' => "Order status: {$order_status}"];
    if ($order_status !== 'valid') {
        return ['error' => "Order timed out — status: {$order_status}", 'steps' => $steps];
    }
    if (!$cert_url) {
        return ['error' => 'No certificate URL in completed order', 'steps' => $steps];
    }

    // Download certificate
    $rc = acme_post_req($cert_url, '');
    acme_log_entry('Download certificate', 'POST', $cert_url, '(POST-as-GET)', $rc);
    $cert_ok = $rc['ok'] && str_contains($rc['body'], '-----BEGIN CERTIFICATE-----');
    $steps[] = ['name' => 'Download certificate', 'ok' => $cert_ok, 'detail' => $cert_ok ? 'Certificate downloaded' : "HTTP {$rc['code']}"];
    if (!$cert_ok) {
        return ['error' => 'Certificate download failed', 'steps' => $steps];
    }

    $s['cert_pem'] = $rc['body'];
    $s['cert_url'] = $cert_url;
    $info = acme_parse_cert_pem($rc['body']);

    return [
        'ok'         => true,
        'steps'      => $steps,
        'certificate'=> trim($rc['body']),
        'csr_pem'    => $csr_pem,
        'subject'    => $info['subject']    ?? '',
        'issuer'     => $info['issuer']     ?? '',
        'not_before' => $info['not_before'] ?? '',
        'not_after'  => $info['not_after']  ?? '',
        'serial'     => $info['serial']     ?? '',
        'sans'       => $info['sans']       ?? [],
    ];
}

function acme_action_revoke(): array
{
    $s = &acme_sess();
    if (empty($s['cert_pem']) || empty($s['directory']['revokeCert'])) {
        return ['error' => 'No certificate in session or revokeCert URL missing'];
    }
    if (!preg_match('/-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----/s', $s['cert_pem'], $m)) {
        return ['error' => 'Could not extract certificate DER'];
    }
    $cert_b64 = ab64(base64_decode(preg_replace('/\s+/', '', $m[1])));
    $rr = acme_post_req($s['directory']['revokeCert'], ['certificate' => $cert_b64, 'reason' => 0]);
    acme_log_entry('Revoke certificate', 'POST', $s['directory']['revokeCert'], '(JWS)', $rr);
    $ok = ($rr['code'] === 200);
    return [
        'ok'     => $ok,
        'steps'  => [['name' => 'Revoke certificate (POST revokeCert)', 'ok' => $ok,
                       'detail' => $ok ? 'HTTP 200 — revoked (reason=0 unspecified)' : "HTTP {$rr['code']}: " . ($rr['json']['detail'] ?? substr($rr['raw_body'], 0, 200))]],
        'detail' => $ok ? 'Certificate revoked successfully' : ($rr['json']['detail'] ?? "HTTP {$rr['code']}"),
    ];
}

function acme_action_ari(): array
{
    $s       = &acme_sess();
    $ari_url = $s['directory']['renewalInfo'] ?? '';
    if (!$ari_url) return ['ok' => false, 'supported' => false, 'detail' => 'renewalInfo not in directory'];
    if (empty($s['cert_pem'])) return ['error' => 'No certificate in session'];

    $info       = acme_parse_cert_pem($s['cert_pem']);
    $serial_hex = $info['serial_hex'] ?? '';
    $aki_hex    = $info['aki_hex']    ?? '';

    if (!$serial_hex || !$aki_hex) {
        return ['ok' => false, 'supported' => true, 'detail' => 'Could not extract serial/AKI for ARI cert ID'];
    }

    $aki_sha    = ab64(hash('sha256', hex2bin($aki_hex), true));
    $serial_sha = ab64(hash('sha256', hex2bin($serial_hex), true));
    $cert_id    = $aki_sha . '.' . $serial_sha;
    $ari_full   = rtrim($ari_url, '/') . '/' . $cert_id;

    $ra = acme_http('GET', $ari_full, null, $s['skip_tls'] ?? false);
    acme_log_entry('ARI renewalInfo', 'GET', $ari_full, '', $ra);

    return [
        'ok'        => $ra['ok'],
        'supported' => true,
        'cert_id'   => $cert_id,
        'url'       => $ari_full,
        'code'      => $ra['code'],
        'body'      => $ra['json'] ?? null,
        'raw_body'  => $ra['raw_body'],
        'steps'     => [['name' => 'ARI renewalInfo (GET renewalInfo)', 'ok' => $ra['ok'],
                          'detail' => "HTTP {$ra['code']}" . ($ra['ok'] ? ' — ARI response received' : '')]],
    ];
}

function acme_action_report(): array
{
    $log = $_SESSION['acme_log'] ?? [];
    $s   = acme_sess();
    $dir = $s['directory'] ?? [];

    // Build URL summary: collect all unique URLs from the log
    $urls_seen = [];
    foreach ($log as $entry) {
        $u = $entry['url'] ?? '';
        if ($u) $urls_seen[] = $u;
    }

    // Parse each URL into components grouped by origin
    $origins = [];
    foreach ($urls_seen as $u) {
        $p = parse_url($u);
        if (!$p || empty($p['host'])) continue;
        $scheme = strtolower($p['scheme'] ?? 'https');
        $host   = strtolower($p['host']);
        $port   = (int)($p['port'] ?? ($scheme === 'https' ? 443 : 80));
        $path   = $p['path'] ?? '/';
        $key    = $scheme . '://' . $host . ':' . $port;
        if (!isset($origins[$key])) {
            $origins[$key] = ['scheme' => $scheme, 'host' => $host, 'port' => $port, 'paths' => []];
        }
        if (!in_array($path, $origins[$key]['paths'], true)) {
            $origins[$key]['paths'][] = $path;
        }
    }

    // Annotate directory fields with which URL each maps to
    $dir_map = [];
    $dir_fields = ['newNonce', 'newAccount', 'newOrder', 'revokeCert', 'keyChange', 'renewalInfo'];
    foreach ($dir_fields as $f) {
        if (isset($dir[$f])) $dir_map[$f] = $dir[$f];
    }

    // Technology fingerprinting
    $tech_signals = [];
    $all_urls_str = implode(' ', $urls_seen);
    $tech_patterns = [
        'EJBCA'              => ['/ejbca/', ':8442', ':8080/ejbca'],
        'Boulder (Let\'s Encrypt)' => ['acme-v02.api.letsencrypt.org', 'acme-staging-v02.api.letsencrypt.org'],
        'Smallstep/step-ca'  => ['/acme/', '/1.0/'],
        'Sectigo'            => ['sectigo.com', 'comodo.com'],
        'DigiCert'           => ['digicert.com'],
        'GlobalSign'         => ['globalsign.com'],
        'ZeroSSL'            => ['zerossl.com'],
        'Entrust'            => ['entrust.com'],
        'Buypass'            => ['buypass.com'],
        'SwissSign'          => ['swisssign.com'],
        'Google Trust Services' => ['pki.goog'],
        'Microsoft'          => ['microsoft.com'],
        'Venafi'             => ['venafi.com'],
        'AppViewX'           => ['appviewx.com'],
        'Keyfactor'          => ['keyfactor.com'],
        'Dogtag/RHCS'        => ['/ca/acme/', ':8080/ca/', ':8443/ca/'],
    ];
    foreach ($tech_patterns as $tech => $patterns) {
        foreach ($patterns as $pat) {
            if (stripos($all_urls_str, $pat) !== false) {
                if (!in_array($tech, $tech_signals, true)) $tech_signals[] = $tech;
                break;
            }
        }
    }

    return [
        'ok'        => true,
        'log'       => $log,
        'url_summary' => [
            'origins'   => array_values($origins),
            'dir_map'   => $dir_map,
            'tech'      => $tech_signals,
        ],
    ];
}

// ── Page ──────────────────────────────────────────────────────────────────────
$navLabel = 'ACME Tester';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'ACME Endpoint Tester — RFC 8555 Protocol Validator | ' . SITE_DOMAIN,
    'description' => 'Test any ACME (RFC 8555) endpoint: directory validation, account creation, order placement, http-01/dns-01 challenges, certificate issuance, revocation, and ARI.',
    'url'         => SITE_BASE_URL . '/acme_tester.php',
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
      --warn: #fcd34d; --purple: #a78bfa;
      --sans: 'IBM Plex Sans', sans-serif; --mono: 'IBM Plex Mono', monospace;
      --radius: 8px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    [hidden] { display: none !important; }
    html { font-size: 15px; scroll-behavior: smooth; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }

    .wrap { max-width: 860px; margin: 0 auto; padding: 3.5rem 2rem 6rem; }
    .page-header { margin-bottom: 2rem; }
    .page-header h1 { font-size: 1.9rem; font-weight: 600; color: #fff; margin-bottom: 0.3rem; }
    .page-header p  { font-size: 0.88rem; color: var(--muted); max-width: 640px; }

    .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.6rem; margin-bottom: 1.5rem; }
    .card-title { font-size: 1rem; font-weight: 600; color: #fff; margin-bottom: 1.2rem; }

    /* ── Inputs ── */
    .field { margin-bottom: 1rem; }
    .field label { display: block; font-size: 0.8rem; color: var(--muted); margin-bottom: 0.35rem; letter-spacing: 0.04em; }
    .field input[type=text], .field input[type=url], .field input[type=email] {
      width: 100%; background: var(--bg); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text); font-family: var(--mono); font-size: 0.78rem;
      padding: 0.5em 0.9em; transition: border-color 0.15s;
    }
    .field input:focus { outline: none; border-color: var(--accent); }
    .field input::placeholder { color: var(--muted); }
    .field-row { display: flex; gap: 1rem; flex-wrap: wrap; }
    .field-row .field { flex: 1; min-width: 180px; }

    .csr-area {
      width: 100%; background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
      color: var(--text); font-family: var(--mono); font-size: 0.72rem; line-height: 1.6;
      padding: 0.9rem 1rem; resize: vertical; min-height: 130px; transition: border-color 0.15s;
    }
    .csr-area:focus { outline: none; border-color: var(--accent); }
    .csr-area::placeholder { color: var(--muted); }

    .toggle-row { display: flex; align-items: center; gap: 0.4rem; cursor: pointer; font-size: 0.82rem; color: var(--muted); margin-bottom: 0.7rem; user-select: none; }
    .toggle-row:hover { color: var(--accent); }
    .toggle-chevron { font-size: 0.65rem; transition: transform 0.2s; }
    .toggle-chevron.open { transform: rotate(90deg); }

    .method-opts { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
    .method-opt { display: flex; align-items: center; gap: 0.4rem; font-size: 0.84rem; cursor: pointer; }
    .method-opt input[type=radio] { accent-color: var(--accent); }

    .skip-tls-label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; cursor: pointer; color: var(--muted); margin-top: 0.8rem; }
    .skip-tls-label input { accent-color: var(--warn); }

    /* ── Buttons ── */
    .btn-primary {
      font-family: var(--mono); font-size: 0.78rem; letter-spacing: 0.05em; text-transform: uppercase;
      background: var(--accent); color: #0e1014; border: none; border-radius: 5px;
      padding: 0.55em 1.4em; cursor: pointer; font-weight: 600; transition: opacity 0.15s;
    }
    .btn-primary:hover:not(:disabled) { opacity: 0.85; }
    .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }
    .btn-ghost {
      font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.05em; text-transform: uppercase;
      background: none; border: 1px solid var(--border); border-radius: 5px;
      padding: 0.45em 1em; cursor: pointer; color: var(--muted); transition: border-color 0.15s, color 0.15s;
    }
    .btn-ghost:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
    .btn-ghost:disabled { opacity: 0.4; cursor: not-allowed; }
    .btn-report {
      font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.05em; text-transform: uppercase;
      background: none; border: 1px solid rgba(139,92,246,0.5); border-radius: 5px;
      padding: 0.45em 1em; cursor: pointer; color: var(--purple); transition: border-color 0.15s, color 0.15s;
    }
    .btn-report:hover:not(:disabled) { border-color: var(--purple); color: #fff; }
    .submit-row { display: flex; align-items: center; gap: 1rem; margin-top: 1.2rem; flex-wrap: wrap; }
    .spinner { width: 18px; height: 18px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.7s linear infinite; flex-shrink: 0; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ── Error box ── */
    .error-box {
      display: flex; align-items: flex-start; gap: 0.6rem;
      background: rgba(248,113,113,0.08); border: 1px solid rgba(248,113,113,0.3);
      border-radius: 6px; padding: 0.8rem 1rem; margin-top: 1rem; font-size: 0.83rem; color: var(--danger);
    }
    .err-icon { flex-shrink: 0; margin-top: 0.1rem; }
    .err-text { white-space: pre-wrap; font-family: var(--mono); font-size: 0.78rem; }

    /* ── Steps list ── */
    .steps-list { display: flex; flex-direction: column; gap: 0.5rem; }
    .step-item { display: flex; align-items: flex-start; gap: 0.7rem; font-size: 0.83rem; padding: 0.45rem 0; border-bottom: 1px solid var(--border); }
    .step-item:last-child { border-bottom: none; }
    .step-icon { font-size: 0.9rem; flex-shrink: 0; margin-top: 0.05rem; width: 1.1em; text-align: center; }
    .step-ok   .step-icon { color: var(--accent); }
    .step-fail .step-icon { color: var(--danger); }
    .step-warn .step-icon { color: var(--warn); }
    .step-run  .step-icon { color: var(--muted); }
    .step-name { font-family: var(--mono); font-size: 0.76rem; color: #fff; white-space: nowrap; }
    .step-detail { font-size: 0.77rem; color: var(--muted); margin-left: 0.2rem; word-break: break-all; }
    .step-section-title { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin: 0.9rem 0 0.4rem; }
    .dir-checks { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.4rem; }
    .dir-check {
      font-family: var(--mono); font-size: 0.65rem; padding: 0.15em 0.5em; border-radius: 3px;
      border: 1px solid; display: flex; align-items: center; gap: 0.3rem;
    }
    .dir-check.ok   { border-color: rgba(0,212,170,0.35); background: rgba(0,212,170,0.07); color: var(--accent); }
    .dir-check.miss { border-color: rgba(248,113,113,0.35); background: rgba(248,113,113,0.07); color: var(--danger); }
    .dir-check.opt  { border-color: rgba(107,122,144,0.35); background: rgba(107,122,144,0.07); color: var(--muted); }

    /* ── Challenge card (reused from cert_factory DCV) ── */
    .chall-header { display: flex; align-items: center; gap: 0.8rem; margin-bottom: 1.1rem; }
    .chall-header h2 { font-size: 1rem; font-weight: 600; color: #fff; }
    .chall-badge {
      font-family: var(--mono); font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.07em;
      padding: 0.2em 0.6em; border-radius: 3px;
      background: rgba(0,212,170,0.12); color: var(--accent); border: 1px solid rgba(0,212,170,0.3);
    }
    .chall-badge.dns { background: rgba(139,92,246,0.1); color: var(--purple); border-color: rgba(139,92,246,0.3); }
    .chall-item { padding: 0.9rem 0; border-bottom: 1px solid var(--border); }
    .chall-item:last-child { border-bottom: none; }
    .chall-domain { font-family: var(--mono); font-size: 0.78rem; font-weight: 600; color: #fff; margin-bottom: 0.6rem; }
    .token-block  { margin-bottom: 0.5rem; }
    .token-label  { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin-bottom: 0.25rem; }
    .token-row    { display: flex; align-items: center; gap: 0.5rem; }
    .token-value  { font-family: var(--mono); font-size: 0.72rem; color: var(--accent); background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.3em 0.6em; word-break: break-all; flex: 1; }
    .copy-btn     { font-family: var(--mono); font-size: 0.65rem; text-transform: uppercase; background: none; border: 1px solid var(--border); border-radius: 4px; color: var(--muted); padding: 0.25em 0.55em; cursor: pointer; white-space: nowrap; transition: border-color 0.15s, color 0.15s; flex-shrink: 0; }
    .copy-btn:hover { border-color: var(--accent); color: var(--accent); }
    .chall-result { display: flex; align-items: flex-start; gap: 0.4rem; font-size: 0.8rem; margin-top: 0.5rem; }
    .chall-result.ok  { color: var(--accent); }
    .chall-result.err { color: var(--danger); font-family: var(--mono); font-size: 0.77rem; }

    /* ── Cert result card ── */
    .result-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.8rem; margin-bottom: 1.2rem; }
    .result-header h2 { font-size: 1rem; font-weight: 600; color: var(--accent); }
    .result-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .cert-info { display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1rem; font-family: var(--mono); font-size: 0.72rem; margin-bottom: 1.2rem; }
    .ci-key { color: var(--muted); white-space: nowrap; }
    .ci-val { color: var(--text); word-break: break-all; }
    .san-list { display: flex; flex-wrap: wrap; gap: 0.3rem; }
    .san-tag { display: inline-block; font-family: var(--mono); font-size: 0.68rem; padding: 0.15em 0.5em; border-radius: 3px; border: 1px solid rgba(0,212,170,0.3); background: rgba(0,212,170,0.07); color: var(--accent); }
    .pem-wrap { position: relative; margin-bottom: 1rem; }
    .pem-output { width: 100%; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-family: var(--mono); font-size: 0.7rem; line-height: 1.6; padding: 0.9rem 1rem; resize: vertical; min-height: 160px; cursor: default; }
    .pem-output:focus { outline: none; }

    /* ── Post-issuance card ── */
    .test-row { display: flex; align-items: center; gap: 0.6rem; padding: 0.5rem 0; border-bottom: 1px solid var(--border); font-size: 0.84rem; }
    .test-row:last-child { border-bottom: none; }
    .test-label { font-family: var(--mono); font-size: 0.76rem; color: var(--muted); min-width: 140px; }
    .test-result { font-size: 0.8rem; }
    .test-ok   { color: var(--accent); }
    .test-fail { color: var(--danger); }
    .test-skip { color: var(--muted); font-style: italic; }

    /* ── Report ── */
    .report-entry { border: 1px solid var(--border); border-radius: 6px; margin-bottom: 0.8rem; overflow: hidden; }
    .report-entry-hdr { display: flex; align-items: center; gap: 0.6rem; padding: 0.55rem 0.9rem; background: var(--surface2); cursor: pointer; font-size: 0.78rem; }
    .report-entry-hdr:hover { background: var(--border); }
    .report-method { font-family: var(--mono); font-size: 0.68rem; padding: 0.1em 0.45em; border-radius: 3px; background: rgba(0,212,170,0.1); color: var(--accent); border: 1px solid rgba(0,212,170,0.2); white-space: nowrap; }
    .report-method.post { background: rgba(139,92,246,0.1); color: var(--purple); border-color: rgba(139,92,246,0.2); }
    .report-url { font-family: var(--mono); font-size: 0.72rem; color: var(--text); word-break: break-all; flex: 1; }
    .report-code { font-family: var(--mono); font-size: 0.72rem; padding: 0.1em 0.45em; border-radius: 3px; white-space: nowrap; }
    .report-code.ok   { background: rgba(0,212,170,0.1); color: var(--accent); }
    .report-code.fail { background: rgba(248,113,113,0.1); color: var(--danger); }
    .report-body { padding: 0.8rem 0.9rem; display: none; }
    .report-body.open { display: block; }
    .raw-block { font-family: var(--mono); font-size: 0.68rem; color: var(--text); white-space: pre-wrap; word-break: break-all; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.6rem 0.8rem; max-height: 300px; overflow-y: auto; margin-top: 0.4rem; }
    .raw-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.07em; color: var(--muted); margin-bottom: 0.2rem; margin-top: 0.6rem; }
    .raw-label:first-child { margin-top: 0; }
    .report-dl-row { margin-top: 1rem; display: flex; gap: 0.8rem; }

    /* ── Report summary ── */
    .rpt-summary { margin-bottom: 1.4rem; }
    .rpt-tech { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem; padding: 0.5rem 0.8rem; background: rgba(139,92,246,0.07); border: 1px solid rgba(139,92,246,0.18); border-radius: 6px; font-size: 0.78rem; }
    .rpt-tech-label { color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; }
    .rpt-tech-tag { padding: 0.12em 0.55em; background: rgba(139,92,246,0.15); color: var(--purple); border: 1px solid rgba(139,92,246,0.3); border-radius: 4px; font-size: 0.72rem; font-family: var(--mono); }
    .rpt-origin { border: 1px solid var(--border); border-radius: 6px; margin-bottom: 0.9rem; overflow: hidden; }
    .rpt-origin-hdr { display: flex; align-items: center; gap: 0.4rem; padding: 0.5rem 0.9rem; background: var(--surface2); flex-wrap: wrap; }
    .rpt-scheme { font-family: var(--mono); font-size: 0.68rem; padding: 0.1em 0.5em; border-radius: 3px; background: rgba(0,212,170,0.1); color: var(--accent); border: 1px solid rgba(0,212,170,0.2); }
    .rpt-host { font-family: var(--mono); font-size: 0.82rem; color: var(--text); font-weight: 600; }
    .rpt-port { font-family: var(--mono); font-size: 0.78rem; color: var(--muted); }
    .rpt-port-warn { font-size: 0.66rem; color: var(--warn); background: rgba(251,191,36,0.08); border: 1px solid rgba(251,191,36,0.25); border-radius: 3px; padding: 0.08em 0.45em; }
    .rpt-paths { width: 100%; border-collapse: collapse; font-size: 0.76rem; }
    .rpt-paths thead th { text-align: left; font-size: 0.64rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); padding: 0.35rem 0.9rem; border-bottom: 1px solid var(--border); background: var(--surface2); }
    .rpt-paths tbody tr { border-bottom: 1px solid var(--border); }
    .rpt-paths tbody tr:last-child { border-bottom: none; }
    .rpt-path-cell { padding: 0.38rem 0.9rem; font-family: var(--mono); color: var(--text); word-break: break-all; }
    .rpt-path-cell code { background: none; font-size: 0.74rem; }
    .rpt-field-cell { padding: 0.38rem 0.9rem; }
    .rpt-field-tag { display: inline-block; font-family: var(--mono); font-size: 0.65rem; padding: 0.08em 0.4em; border-radius: 3px; background: rgba(0,212,170,0.08); color: var(--accent); border: 1px solid rgba(0,212,170,0.18); margin: 0.1em; }
    .rpt-field-none { color: var(--muted); font-size: 0.72rem; }

    /* ── Footer ── */
    .site-footer { border-top: 1px solid var(--border); padding: 1.4rem 2rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; font-family: var(--mono); font-size: 0.72rem; color: var(--muted); }
    .site-footer a { color: var(--muted); }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }

    @media (max-width: 600px) {
      .wrap { padding: 2rem 1rem 4rem; }
      .cert-info { grid-template-columns: 1fr; }
      .ci-key { color: var(--accent); font-size: 0.65rem; }
    }
  </style>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<main class="wrap">

  <div class="page-header">
    <h1>ACME Endpoint Tester</h1>
    <p>Validates an RFC 8555 ACME endpoint end-to-end: directory, account, order, challenges,
       certificate issuance, revocation, and ARI. All raw protocol exchanges are captured for the report.</p>
  </div>

  <!-- Input card -->
  <div class="card" id="inputCard">
    <div class="card-title">Endpoint Configuration</div>

    <div class="field">
      <label>ACME Directory URL</label>
      <input type="url" id="endpoint" placeholder="https://acme-v02.api.letsencrypt.org/directory" spellcheck="false" autocomplete="off">
    </div>

    <div class="field-row">
      <div class="field">
        <label>Account Email</label>
        <input type="email" id="email" placeholder="admin@example.com" autocomplete="off">
      </div>
      <div class="field">
        <label>Domains (comma-separated)</label>
        <input type="text" id="domains" placeholder="example.com, www.example.com" spellcheck="false" autocomplete="off">
      </div>
    </div>

    <div style="margin-bottom:0.9rem">
      <label style="font-size:0.8rem;color:var(--muted);display:block;margin-bottom:0.5rem">Challenge Method</label>
      <div class="method-opts">
        <label class="method-opt"><input type="radio" name="chall_method" value="http-01" checked> http-01</label>
        <label class="method-opt"><input type="radio" name="chall_method" value="dns-01"> dns-01</label>
      </div>
    </div>

    <!-- EAB toggle -->
    <button type="button" class="toggle-row" id="eabToggle">
      <span class="toggle-chevron" id="eabChevron">▶</span> External Account Binding (EAB)
    </button>
    <div id="eabBody" hidden>
      <div class="field-row">
        <div class="field">
          <label>EAB Key ID</label>
          <input type="text" id="eabKid" placeholder="key-id" spellcheck="false" autocomplete="off">
        </div>
        <div class="field">
          <label>EAB MAC Key (base64url)</label>
          <input type="text" id="eabMac" placeholder="base64url-encoded MAC key" spellcheck="false" autocomplete="off">
        </div>
      </div>
      <button type="button" class="btn-ghost" id="btnGenEab" style="margin-top:0.3rem;font-size:0.7rem">
        Generate random EAB credentials
      </button>
      <p style="font-size:0.74rem;color:var(--muted);margin-top:0.4rem">
        Random credentials will be rejected by real CAs. Use this to test how the server handles
        unrecognised-but-correctly-formatted EAB.
      </p>
    </div>

    <!-- CSR toggle -->
    <button type="button" class="toggle-row" id="csrToggle" style="margin-top:0.4rem">
      <span class="toggle-chevron" id="csrChevron">▶</span> Provide CSR (optional — generated automatically if omitted)
    </button>
    <div id="csrBody" hidden>
      <textarea class="csr-area" id="csrInput"
                placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
                spellcheck="false" autocomplete="off"></textarea>
    </div>

    <label class="skip-tls-label">
      <input type="checkbox" id="skipTls"> Skip TLS verification (for staging/self-signed endpoints)
    </label>

    <div class="submit-row">
      <button class="btn-primary" id="btnStart">Start Test</button>
      <div class="spinner" id="spinner" hidden></div>
      <span id="statusText" style="font-size:0.78rem;color:var(--muted)"></span>
    </div>

    <div class="error-box" id="errorBox" hidden>
      <span class="err-icon">✕</span>
      <span class="err-text" id="errorMsg"></span>
    </div>
  </div>

  <!-- Progress card -->
  <div class="card" id="progressCard" hidden>
    <div class="card-title">Test Progress</div>
    <div class="steps-list" id="stepsList"></div>
    <div class="submit-row" style="margin-top:1.2rem" id="reportBtnRow" hidden>
      <button class="btn-report" id="btnReport">Generate Report</button>
    </div>
  </div>

  <!-- Challenge card -->
  <div class="card" id="challCard" hidden>
    <div class="chall-header">
      <h2>ACME Challenges</h2>
      <span class="chall-badge" id="challBadge">http-01</span>
    </div>
    <div id="challItems"></div>
    <div class="submit-row" style="margin-top:1.2rem">
      <button class="btn-primary" id="btnVerify">Verify &amp; Continue</button>
      <div class="spinner" id="verifySpin" hidden></div>
    </div>
    <div class="error-box" id="challError" hidden>
      <span class="err-icon">✕</span>
      <span class="err-text" id="challErrMsg"></span>
    </div>
  </div>

  <!-- Certificate card -->
  <div class="card" id="certCard" hidden>
    <div class="result-header">
      <h2 id="certTitle">✔ Certificate Issued</h2>
      <div class="result-actions">
        <button class="btn-ghost" id="btnCopy">Copy PEM</button>
        <button class="btn-ghost" id="btnDl">Download .crt</button>
        <button class="btn-ghost" id="btnLint">Lint</button>
        <button class="btn-ghost" id="btnParse">Parse</button>
      </div>
    </div>
    <div class="cert-info" id="certInfoGrid"></div>
    <div class="pem-wrap">
      <textarea class="pem-output" id="pemOutput" readonly spellcheck="false"></textarea>
    </div>
  </div>

  <!-- Post-issuance tests card -->
  <div class="card" id="postCard" hidden>
    <div class="card-title">Post-Issuance Tests</div>
    <div class="steps-list" id="postSteps"></div>
  </div>

  <!-- Report card -->
  <div class="card" id="reportCard" hidden>
    <div class="card-title" style="color:var(--purple)">Protocol Evidence Report</div>
    <div id="reportSummary"></div>
    <div id="reportEntries"></div>
    <div class="report-dl-row">
      <button class="btn-ghost" id="btnDlReport">Download Report (JSON)</button>
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
(function () {
  'use strict';

  var ISSUING_CA_PEM = <?= json_encode(file_exists(ISSUING_CRT) ? trim((string) file_get_contents(ISSUING_CRT)) : '') ?>;

  // ── DOM refs ─────────────────────────────────────────────────────────────────
  var btnStart    = document.getElementById('btnStart');
  var spinner     = document.getElementById('spinner');
  var statusText  = document.getElementById('statusText');
  var errorBox    = document.getElementById('errorBox');
  var errorMsg    = document.getElementById('errorMsg');
  var progressCard= document.getElementById('progressCard');
  var stepsList   = document.getElementById('stepsList');
  var challCard   = document.getElementById('challCard');
  var challBadge  = document.getElementById('challBadge');
  var challItems  = document.getElementById('challItems');
  var btnVerify   = document.getElementById('btnVerify');
  var verifySpin  = document.getElementById('verifySpin');
  var challError  = document.getElementById('challError');
  var challErrMsg = document.getElementById('challErrMsg');
  var certCard    = document.getElementById('certCard');
  var certInfoGrid= document.getElementById('certInfoGrid');
  var pemOutput   = document.getElementById('pemOutput');
  var postCard      = document.getElementById('postCard');
  var postSteps     = document.getElementById('postSteps');
  var reportBtnRow  = document.getElementById('reportBtnRow');
  var reportCard    = document.getElementById('reportCard');
  var reportSummary = document.getElementById('reportSummary');
  var reportEntries = document.getElementById('reportEntries');

  // ── Toggles ──────────────────────────────────────────────────────────────────
  makeToggle('eabToggle', 'eabBody', 'eabChevron');
  makeToggle('csrToggle', 'csrBody', 'csrChevron');

  function makeToggle(btnId, bodyId, chevId) {
    document.getElementById(btnId).addEventListener('click', function () {
      var body = document.getElementById(bodyId);
      var chev = document.getElementById(chevId);
      body.hidden = !body.hidden;
      chev.classList.toggle('open', !body.hidden);
    });
  }

  // ── EAB generator ────────────────────────────────────────────────────────────
  document.getElementById('btnGenEab').addEventListener('click', function () {
    var kidBytes = new Uint8Array(8);
    var macBytes = new Uint8Array(32);
    crypto.getRandomValues(kidBytes);
    crypto.getRandomValues(macBytes);
    var kid = 'test-' + Array.from(kidBytes).map(function(b){ return b.toString(16).padStart(2,'0'); }).join('');
    var mac = btoa(String.fromCharCode.apply(null, macBytes))
                .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    document.getElementById('eabKid').value = kid;
    document.getElementById('eabMac').value = mac;
    var eabBody = document.getElementById('eabBody');
    if (eabBody.hidden) {
      eabBody.hidden = false;
      document.getElementById('eabChevron').classList.add('open');
    }
  });

  // ── Main flow ─────────────────────────────────────────────────────────────────
  btnStart.addEventListener('click', function () { runTest(); });

  async function runTest() {
    var endpoint = document.getElementById('endpoint').value.trim();
    var email    = document.getElementById('email').value.trim();
    var domains  = document.getElementById('domains').value.trim();
    var method   = document.querySelector('input[name="chall_method"]:checked')?.value || 'http-01';
    var skipTls  = document.getElementById('skipTls').checked;
    var eabKid   = document.getElementById('eabKid').value.trim();
    var eabMac   = document.getElementById('eabMac').value.trim();

    if (!endpoint) { showError('ACME endpoint URL is required.'); return; }
    if (!email)    { showError('Email is required.'); return; }
    if (!domains)  { showError('At least one domain is required.'); return; }

    hideError();
    resetCards();
    setLoading(true, 'Fetching directory…');

    // ── Step A: init (directory + account) ──
    var fd = new FormData();
    fd.append('action',   'init');
    fd.append('endpoint', endpoint);
    fd.append('email',    email);
    if (skipTls) fd.append('skip_tls', '1');
    if (eabKid)  fd.append('eab_kid', eabKid);
    if (eabMac)  fd.append('eab_mac', eabMac);

    var data = await post(fd);
    if (!data) return;
    progressCard.hidden = false;
    reportBtnRow.hidden = false;
    appendSteps(data.steps || []);
    if (data.error) { showError(data.error); setLoading(false); return; }

    // ── Step B: order ──
    setLoading(true, 'Placing order…');
    var fd2 = new FormData();
    fd2.append('action',           'order');
    fd2.append('domains',          domains);
    fd2.append('challenge_method', method);

    var data2 = await post(fd2);
    if (!data2) return;
    appendSteps(data2.steps || []);
    if (data2.error) { showError(data2.error); setLoading(false); return; }

    setLoading(false);

    // ── Show challenges ──
    renderChallenges(data2.authz || [], method);
  }

  function renderChallenges(authz, method) {
    var isHttp = method === 'http-01';
    challBadge.textContent = method;
    challBadge.className   = 'chall-badge' + (isHttp ? '' : ' dns');

    var html = '';
    authz.forEach(function (a) {
      var domain = a.domain;
      var chall  = a.challenge || {};
      var token  = chall.token || '';
      html += '<div class="chall-item">';
      html += '<div class="chall-domain">' + esc(domain) + (a.wildcard ? ' <span style="color:var(--purple);font-size:0.68rem">[wildcard]</span>' : '') + '</div>';
      if (isHttp) {
        var url = 'http://' + domain + '/.well-known/acme-challenge/' + token;
        html += tknBlock('URL', esc(url), url);
        html += tknBlock('File content (key authorization)', esc(a.key_auth), a.key_auth);
      } else {
        var name = '_acme-challenge.' + domain;
        html += tknBlock('DNS record name', esc(name), name);
        html += '<div class="token-block"><div class="token-label">Type</div><div class="token-row"><span class="token-value">TXT</span></div></div>';
        html += tknBlock('Value (SHA-256 of key authorization, base64url)', esc(a.dns_val), a.dns_val);
      }
      html += '</div>';
    });
    challItems.innerHTML = html;
    challError.hidden = true;
    challCard.hidden  = false;
    challCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function tknBlock(label, display, copyVal) {
    var jv = JSON.stringify(copyVal).replace(/"/g, '&quot;');
    return '<div class="token-block">'
      + '<div class="token-label">' + label + '</div>'
      + '<div class="token-row"><span class="token-value">' + display + '</span>'
      + '<button class="copy-btn" onclick="acmeCopy(this,' + jv + ')">Copy</button>'
      + '</div></div>';
  }

  // ── Verify ───────────────────────────────────────────────────────────────────
  btnVerify.addEventListener('click', function () { doVerify(); });

  async function doVerify() {
    btnVerify.disabled = true;
    verifySpin.hidden  = false;
    challError.hidden  = true;

    var data = await post(fd1('verify'));
    verifySpin.hidden = true;
    btnVerify.disabled = false;
    if (!data) return;

    appendSteps(data.steps || []);

    // Per-domain results in challenge card
    var results = data.results || {};
    document.querySelectorAll('.chall-item').forEach(function (item, i) {
      var domain = item.querySelector('.chall-domain').textContent.trim().split(' ')[0];
      var r = results[domain];
      if (!r) return;
      var ex = item.querySelector('.chall-result');
      if (ex) ex.remove();
      var el = document.createElement('div');
      el.className = 'chall-result ' + (r.ok ? 'ok' : 'err');
      el.innerHTML = r.ok ? '&#10004; Verified' : '&#10005; ' + esc(r.error || 'Failed');
      item.appendChild(el);
    });

    if (data.error) { challErrMsg.textContent = data.error; challError.hidden = false; return; }
    if (!data.ok)   { challErrMsg.textContent = 'One or more authorizations failed — fix the challenge and retry.'; challError.hidden = false; return; }

    // All valid — finalize
    challCard.hidden = true;
    await doFinalize();
  }

  async function doFinalize() {
    setLoading(true, 'Finalizing order…');

    var fd = new FormData();
    fd.append('action', 'finalize');
    var csr = document.getElementById('csrInput').value.trim();
    if (csr) fd.append('csr', csr);

    var data = await post(fd);
    if (!data) return;
    appendSteps(data.steps || []);
    if (data.error) { showError(data.error); setLoading(false); return; }

    setLoading(false);
    renderCert(data);

    // Post-issuance tests
    await doPostTests(data);
  }

  function renderCert(data) {
    pemOutput.value = data.certificate || '';
    var sans = (data.sans || []).map(function (s) { return '<span class="san-tag">' + esc(s) + '</span>'; }).join('');
    certInfoGrid.innerHTML = [
      ciRow('Subject',    esc(data.subject    || '—')),
      ciRow('SANs',       '<div class="san-list">' + (sans || '—') + '</div>'),
      ciRow('Issuer',     esc(data.issuer     || '—')),
      ciRow('Not Before', esc(data.not_before || '—')),
      ciRow('Not After',  esc(data.not_after  || '—')),
      ciRow('Serial',     esc(data.serial     || '—')),
    ].join('');
    certCard.hidden = false;
    certCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function ciRow(k, v) {
    return '<span class="ci-key">' + k + '</span><span class="ci-val">' + v + '</span>';
  }

  async function doPostTests(certData) {
    postCard.hidden = false;
    postSteps.innerHTML = '';

    // Revoke
    addPostStep('spinner', 'Revoke certificate', '');
    var rv = await post(fd1('revoke'));
    replaceLastPostStep(rv && rv.ok, 'Revoke certificate', rv ? rv.detail : 'Request failed');

    // ARI
    addPostStep('spinner', 'ARI renewalInfo', '');
    var ar = await post(fd1('ari'));
    if (!ar) {
      replaceLastPostStep(false, 'ARI renewalInfo', 'Request failed');
    } else if (!ar.supported) {
      replaceLastPostStep(null, 'ARI renewalInfo', 'Not supported (not in directory)');
    } else {
      var ariDetail = 'HTTP ' + ar.code + ' — cert ID: ' + (ar.cert_id || '?');
      if (ar.body && ar.body.suggestedWindow) {
        ariDetail += ' · window start: ' + (ar.body.suggestedWindow.start || '');
      }
      replaceLastPostStep(ar.ok, 'ARI renewalInfo', ariDetail);
    }

    postCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function addPostStep(icon, name, detail) {
    var el = document.createElement('div');
    el.className = 'step-item step-run';
    el.innerHTML = '<span class="step-icon">↺</span>'
      + '<div><div class="step-name">' + esc(name) + '</div>'
      + '<div class="step-detail">' + esc(detail) + '</div></div>';
    postSteps.appendChild(el);
  }

  function replaceLastPostStep(ok, name, detail) {
    var last = postSteps.lastElementChild;
    if (!last) return;
    var cls    = ok === null ? 'step-warn' : (ok ? 'step-ok' : 'step-fail');
    var icon   = ok === null ? '—'          : (ok ? '✔'       : '✕');
    last.className = 'step-item ' + cls;
    last.innerHTML = '<span class="step-icon">' + icon + '</span>'
      + '<div><div class="step-name">' + esc(name) + '</div>'
      + '<div class="step-detail">' + esc(detail) + '</div></div>';
  }

  // ── Report ───────────────────────────────────────────────────────────────────
  var reportData = null;

  document.getElementById('btnReport').addEventListener('click', async function () {
    var data = await post(fd1('report'));
    if (!data || !data.log) return;
    reportData = data;
    renderReportSummary(data.url_summary || {});
    renderReport(data.log);
    reportCard.hidden = false;
    reportCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  function renderReportSummary(summary) {
    var origins = summary.origins || [];
    var dirMap  = summary.dir_map || {};
    var tech    = summary.tech    || [];

    // Build a reverse lookup: url → field name(s)
    var urlToFields = {};
    Object.keys(dirMap).forEach(function (field) {
      var u = dirMap[field];
      if (!urlToFields[u]) urlToFields[u] = [];
      urlToFields[u].push(field);
    });

    var html = '<div class="rpt-summary">';

    // Technology detection banner
    if (tech.length) {
      html += '<div class="rpt-tech">'
        + '<span class="rpt-tech-label">Detected technology:</span> '
        + tech.map(function (t) { return '<span class="rpt-tech-tag">' + esc(t) + '</span>'; }).join(' ')
        + '</div>';
    }

    // One block per origin (unique scheme+host+port)
    origins.forEach(function (o) {
      var defaultPort = o.scheme === 'https' ? 443 : 80;
      var portNote = (o.port !== defaultPort) ? ' <span class="rpt-port-warn">non-standard port</span>' : '';
      html += '<div class="rpt-origin">';
      html += '<div class="rpt-origin-hdr">'
        + '<span class="rpt-scheme">' + esc(o.scheme.toUpperCase()) + '</span>'
        + '<span class="rpt-host">' + esc(o.host) + '</span>'
        + '<span class="rpt-port">:' + esc(String(o.port)) + '</span>'
        + portNote
        + '</div>';
      html += '<table class="rpt-paths">'
        + '<thead><tr><th>Path</th><th>ACME field</th></tr></thead><tbody>';
      o.paths.forEach(function (path) {
        var fullUrl = o.scheme + '://' + o.host + ':' + o.port + path;
        var fields  = urlToFields[fullUrl] || [];
        html += '<tr>'
          + '<td class="rpt-path-cell"><code>' + esc(path) + '</code></td>'
          + '<td class="rpt-field-cell">'
          + (fields.length ? fields.map(function (f) { return '<span class="rpt-field-tag">' + esc(f) + '</span>'; }).join(' ') : '<span class="rpt-field-none">—</span>')
          + '</td></tr>';
      });
      html += '</tbody></table></div>';
    });

    if (!origins.length) {
      html += '<p style="color:var(--muted);font-size:0.82rem">No URL data recorded yet.</p>';
    }

    html += '</div>';
    reportSummary.innerHTML = html;
  }

  function renderReport(log) {
    reportEntries.innerHTML = '';
    if (!log.length) {
      reportEntries.innerHTML = '<p style="color:var(--muted);font-size:0.82rem;padding:0.5rem 0">No log entries yet.</p>';
      return;
    }
    log.forEach(function (entry) {
      var isOk   = entry.ok;
      var meth   = (entry.method || 'GET').toUpperCase();
      var div    = document.createElement('div');
      div.className = 'report-entry';
      div.innerHTML =
        '<div class="report-entry-hdr" onclick="toggleReport(this)">'
        + '<span class="report-method ' + meth.toLowerCase() + '">' + esc(meth) + '</span>'
        + '<span class="report-url">' + esc(entry.step + ' — ' + entry.url) + '</span>'
        + '<span class="report-code ' + (isOk ? 'ok' : 'fail') + '">' + esc(String(entry.resp_code)) + '</span>'
        + '<span style="font-size:0.7rem;color:var(--muted)">' + esc(entry.ts || '') + '</span>'
        + '</div>'
        + '<div class="report-body">'
        + '<div class="raw-label">Request</div>'
        + '<div class="raw-block">' + esc(entry.req_body || '(no body)') + '</div>'
        + '<div class="raw-label">Response Headers</div>'
        + '<div class="raw-block">' + esc(entry.resp_hdrs || '') + '</div>'
        + '<div class="raw-label">Response Body</div>'
        + '<div class="raw-block">' + esc(entry.resp_body || '') + '</div>'
        + '</div>';
      reportEntries.appendChild(div);
    });
  }

  window.toggleReport = function (hdr) {
    var body = hdr.nextElementSibling;
    body.classList.toggle('open');
  };

  document.getElementById('btnDlReport').addEventListener('click', function () {
    if (!reportData) return;
    var blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    var url  = URL.createObjectURL(blob);
    var a    = Object.assign(document.createElement('a'), { href: url, download: 'acme-report-' + Date.now() + '.json' });
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  });

  // ── Cert actions ─────────────────────────────────────────────────────────────
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
    var a    = Object.assign(document.createElement('a'), { href: url, download: 'acme-cert-' + Date.now() + '.crt' });
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  });

  document.getElementById('btnLint').addEventListener('click', function () {
    if (!pemOutput.value) return;
    sessionStorage.setItem('pki_prefill_cert', pemOutput.value);
    if (ISSUING_CA_PEM) sessionStorage.setItem('pki_prefill_issuer', ISSUING_CA_PEM);
    window.open('/linters.php', '_blank');
  });

  document.getElementById('btnParse').addEventListener('click', function () {
    if (!pemOutput.value) return;
    sessionStorage.setItem('pki_prefill_cert', pemOutput.value);
    window.open('/artifact_parser.php', '_blank');
  });

  // ── Utilities ─────────────────────────────────────────────────────────────────
  function fd1(action) {
    var fd = new FormData();
    fd.append('action', action);
    return fd;
  }

  async function post(fd) {
    try {
      var resp = await fetch(window.location.href, { method: 'POST', body: fd });
      if (!resp.ok) throw new Error('Server returned ' + resp.status);
      return await resp.json();
    } catch (err) {
      showError('Request failed: ' + err.message);
      setLoading(false);
      return null;
    }
  }

  function appendSteps(steps) {
    steps.forEach(function (s) {
      var isWarn = s.ok && s.warn;
      var cls    = !s.ok ? 'step-fail' : (isWarn ? 'step-warn' : 'step-ok');
      var icon   = !s.ok ? '✕'         : (isWarn ? '⚠'         : '✔');
      var el     = document.createElement('div');
      el.className = 'step-item ' + cls;
      el.innerHTML = '<span class="step-icon">' + icon + '</span>'
        + '<div style="flex:1">'
        + '<div class="step-name">' + esc(s.name) + '</div>'
        + (s.detail ? '<div class="step-detail">' + esc(s.detail) + '</div>' : '')
        + (s.warnings && s.warnings.length ? s.warnings.map(function (w) {
            return '<div class="step-detail" style="color:var(--warn)">⚠ ' + esc(w) + '</div>';
          }).join('') : '')
        + (s.checks ? renderDirChecks(s.checks) : '')
        + '</div>';
      stepsList.appendChild(el);
    });
  }

  function renderDirChecks(checks) {
    return '<div class="dir-checks">' + checks.map(function (c) {
      var cls = !c.present ? (c.required ? 'miss' : 'opt') : 'ok';
      return '<span class="dir-check ' + cls + '">'
        + (c.present ? '&#10004;' : (c.required ? '&#10005;' : '—'))
        + ' ' + esc(c.field) + '</span>';
    }).join('') + '</div>';
  }

  function resetCards() {
    stepsList.innerHTML = '';
    challItems.innerHTML = '';
    certInfoGrid.innerHTML = '';
    postSteps.innerHTML = '';
    reportEntries.innerHTML = '';
    reportSummary.innerHTML = '';
    pemOutput.value = '';
    reportBtnRow.hidden = true;
    progressCard.hidden = challCard.hidden = certCard.hidden = postCard.hidden = reportCard.hidden = true;
  }

  function setLoading(on, msg) {
    btnStart.disabled  = on;
    spinner.hidden     = !on;
    statusText.textContent = on ? (msg || '') : '';
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

  window.acmeCopy = function (btn, text) {
    navigator.clipboard.writeText(text).then(function () {
      var orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(function () { btn.textContent = orig; }, 1800);
    });
  };

}());
</script>
</body>
</html>
