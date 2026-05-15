<?php
/**
 * revocation.php — OCSP and CRL revocation checker
 *
 * Must only be invoked by linters.php (or another PHP script that sets
 * $revocation_invoked = true before including this file).
 * Direct HTTP access returns 403.
 *
 * Provides:
 *   revocation_buttons(string $ee_pem, ?string $root_pem): string
 *     — renders the revocation button group (enabled/disabled per cert state)
 *
 *   revocation_handle_post(string $action, string $ee_pem, ?string $root_pem): string
 *     — executes the requested revocation action, returns HTML result
 *
 *   revocation_is_action(string $action): bool
 *     — returns true if $action is a revocation action name
 */

// ── Direct access guard ───────────────────────────────────────────────────────
if (!isset($revocation_invoked) || $revocation_invoked !== true) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('403 Forbidden: this file must not be accessed directly.');
}

require_once __DIR__ . '/config.php';

// ── pkilint binary resolver (reuse pattern from pkilint.php) ─────────────────
// We call pkilint_binary() if pkilint.php is already loaded; otherwise use
// our own resolver for lint_crl and lint_ocsp_response.

function revoc_pkilint_bin(string $cmd): ?string {
    if (function_exists('pkilint_binary')) {
        return pkilint_binary($cmd);
    }
    foreach (['/usr/local/bin', '/usr/bin', '/bin'] as $dir) {
        $p = $dir . '/' . $cmd;
        if (is_executable($p)) return $p;
    }
    return null;
}

// ── Certificate data extraction ───────────────────────────────────────────────

/**
 * Extracts revocation-relevant URLs from a parsed certificate.
 * Returns:
 *   ocsp_urls   => string[]   (from AIA)
 *   crl_urls    => string[]   (from CDP)
 *   delta_urls  => string[]   (from CDP with delta CRL indicator)
 *   has_must_staple => bool
 */
function revoc_extract_urls(string $pem): array {
    $result = [
        'ocsp_urls'       => [],
        'crl_urls'        => [],
        'delta_urls'      => [],
        'has_must_staple' => false,
    ];

    $cert = openssl_x509_read($pem);
    if ($cert === false) return $result;

    $d    = openssl_x509_parse($cert, true);
    $exts = $d['extensions'] ?? [];

    // OCSP — from AIA
    $aia = $exts['authorityInfoAccess'] ?? '';
    preg_match_all('/OCSP\s*-\s*URI:(\S+)/i', $aia, $m);
    $result['ocsp_urls'] = array_values(array_unique($m[1] ?? []));

    // CRL Distribution Points
    $cdp = $exts['crlDistributionPoints'] ?? '';
    preg_match_all('/URI:(\S+)/i', $cdp, $m2);
    $result['crl_urls'] = array_values(array_unique($m2[1] ?? []));

    // Delta CRL — indicated by the deltaIndicator extension OR delta CDP URIs.
    // openssl_x509_parse exposes the freshestCRL extension for delta CDPs.
    $fresh = $exts['freshestCRL'] ?? $exts['2.5.29.46'] ?? '';
    if ($fresh !== '') {
        preg_match_all('/URI:(\S+)/i', $fresh, $m3);
        $result['delta_urls'] = array_values(array_unique($m3[1] ?? []));
    }

    // Must-Staple — TLS Feature extension
    $tlsf = $exts['1.3.6.1.5.5.7.1.24'] ?? $exts['tlsfeature'] ?? '';
    $result['has_must_staple'] = $tlsf !== '' && (str_contains($tlsf, '5') || str_contains(strtolower($tlsf), 'status_request'));

    return $result;
}

// ── HTTP fetch helper ─────────────────────────────────────────────────────────

function revoc_http_fetch(string $url, string $method = 'GET', ?string $body = null, array $headers = []): array {
    if (!function_exists('curl_init')) {
        return ['data' => null, 'http_code' => 0, 'error' => 'cURL extension not available.'];
    }

    $ch = curl_init($url);
    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => 'PKI-Linters/1.0',
    ];

    if ($method === 'POST' && $body !== null) {
        $opts[CURLOPT_POST]       = true;
        $opts[CURLOPT_POSTFIELDS] = $body;
    }

    if (!empty($headers)) {
        $opts[CURLOPT_HTTPHEADER] = $headers;
    }

    curl_setopt_array($ch, $opts);
    $data     = curl_exec($ch);
    $code     = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err      = curl_error($ch);
    curl_close($ch);

    return [
        'data'      => $data === false ? null : $data,
        'http_code' => $code,
        'error'     => $err !== '' ? $err : null,
    ];
}

// ── OCSP checker ─────────────────────────────────────────────────────────────

function revoc_fmt_duration(int $seconds): string {
    if ($seconds < 60)    return $seconds . 's';
    if ($seconds < 3600)  return floor($seconds / 60) . 'm ' . ($seconds % 60) . 's';
    if ($seconds < 86400) return floor($seconds / 3600) . 'h ' . floor(($seconds % 3600) / 60) . 'm';
    return floor($seconds / 86400) . 'd ' . floor(($seconds % 86400) / 3600) . 'h';
}

function revoc_check_ocsp(string $ee_pem, string $issuer_pem): array {
    $result = [
        // Core
        'status'        => 'unknown',
        'reason'        => null,
        'revoked_at'    => null,
        'this_update'   => null,
        'next_update'   => null,
        'responder_url' => null,
        'responder_id'  => null,
        'raw_response'  => null,
        'error'         => null,
        // Response signature
        'sig_algorithm' => null,
        // Freshness / compliance
        'age_seconds'        => null,
        'remaining_seconds'  => null,
        'next_update_absent' => false,
        'cabf_age_ok'        => null,  // CA/B Forum BR: max 10 days
        // Delegated responder
        'delegated'                  => false,
        'responder_cert_expiry'      => null,
        'responder_cert_valid'       => null,
        'responder_cert_has_eku'     => null,  // id-kp-OCSPSigning
        'responder_cert_has_nocheck' => null,  // id-pkix-ocsp-nocheck
        // HTTP transport
        'http_status'         => null,
        'http_content_type'   => null,
        'http_cache_control'  => null,
        'http_max_age'        => null,
        'http_etag'           => null,
        'http_latency_ms'     => null,
        'http_response_bytes' => null,
        'stapling_size_ok'    => null,
        'http_get_supported'  => null,
        // Nonce
        'nonce_echoed' => null,
        // TLS (HTTPS endpoints only)
        'tls_version'    => null,
        'tls_cipher'     => null,
        'tls_cert_valid' => null,
        'tls_cert_error' => null,
    ];

    $urls = revoc_extract_urls($ee_pem);
    if (empty($urls['ocsp_urls'])) {
        $result['error'] = 'No OCSP responder URL found in the certificate AIA extension.';
        return $result;
    }

    $responder_url           = $urls['ocsp_urls'][0];
    $result['responder_url'] = $responder_url;

    $tmp_ee     = tempnam(sys_get_temp_dir(), 'revoc_ee_');
    $tmp_issuer = tempnam(sys_get_temp_dir(), 'revoc_is_');
    $tmp_resp   = tempnam(sys_get_temp_dir(), 'revoc_rsp_');
    $tmp_req    = tempnam(sys_get_temp_dir(), 'revoc_rq_');

    try {
        $ee_cert = openssl_x509_read($ee_pem);
        openssl_x509_export($ee_cert, $ee_clean);
        file_put_contents($tmp_ee, $ee_clean);

        $is_cert = openssl_x509_read($issuer_pem);
        openssl_x509_export($is_cert, $is_clean);
        file_put_contents($tmp_issuer, $is_clean);

        // ── Main OCSP request ─────────────────────────────────────────────────
        // -reqout: save the DER request so we can reuse it for cURL/GET probes.
        // -noverify: skip chain verification (we parse manually below).
        $cmd = 'openssl ocsp'
             . ' -issuer '  . escapeshellarg($tmp_issuer)
             . ' -cert '    . escapeshellarg($tmp_ee)
             . ' -url '     . escapeshellarg($responder_url)
             . ' -reqout '  . escapeshellarg($tmp_req)
             . ' -respout ' . escapeshellarg($tmp_resp)
             . ' -noverify'
             . ' -resp_text'
             . ' 2>&1';

        $lines     = [];
        $exit_code = null;
        exec($cmd, $lines, $exit_code);
        $output = implode("\n", $lines);

        if (file_exists($tmp_resp) && filesize($tmp_resp) > 0) {
            $result['raw_response'] = file_get_contents($tmp_resp);
        }

        if ($output === '' && $exit_code !== 0) {
            $result['error'] = 'openssl ocsp produced no output. Check that openssl is installed and the responder URL is reachable.';
            return $result;
        }

        // ── Parse core fields ─────────────────────────────────────────────────
        if (preg_match('/:\s*(good|revoked|unknown)/i', $output, $m)) {
            $result['status'] = strtolower($m[1]);
        }
        if (preg_match('/Reason:\s*(.+)/i', $output, $m))          $result['reason']       = trim($m[1]);
        if (preg_match('/Revocation Time:\s*(.+)/i', $output, $m)) $result['revoked_at']   = trim($m[1]);
        if (preg_match('/This Update:\s*(.+)/i', $output, $m))     $result['this_update']  = trim($m[1]);
        if (preg_match('/Next Update:\s*(.+)/i', $output, $m))     $result['next_update']  = trim($m[1]);
        if (preg_match('/Responder Id:\s*(.+)/i', $output, $m))    $result['responder_id'] = trim($m[1]);

        // First Signature Algorithm line belongs to the OCSP response itself.
        if (preg_match('/Signature Algorithm:\s*(.+)/i', $output, $m)) {
            $result['sig_algorithm'] = trim($m[1]);
        }

        // ── Freshness ─────────────────────────────────────────────────────────
        if ($result['this_update'] !== null) {
            $ts = strtotime($result['this_update']);
            if ($ts !== false) {
                $result['age_seconds'] = max(0, time() - $ts);
                $result['cabf_age_ok'] = $result['age_seconds'] <= 864000; // 10 days
            }
        }
        if ($result['next_update'] !== null) {
            $ts = strtotime($result['next_update']);
            if ($ts !== false) $result['remaining_seconds'] = max(0, $ts - time());
        } else {
            $result['next_update_absent'] = true;
        }

        // ── Delegated responder detection ────────────────────────────────────
        //
        // Definitive check: compare the Responder ID against the issuer's own
        // identity. Two ID forms exist (RFC 6960 §4.2.2.3):
        //
        //   byName — the responder's subject DN. Delegated if != issuer subject.
        //   byKey  — SHA-1(SubjectPublicKeyInfo). Delegated if != issuer SPKI hash.
        //
        // We compute the issuer's SPKI SHA-1 via openssl and compare against
        // both forms. This is correct regardless of whether the response
        // includes an embedded cert.
        //
        // Separately, if the response DOES include a Certificate: block we
        // parse EKU, nocheck, and expiry from it.

        // Compute issuer SPKI SHA-1 (hex) for byKey comparison.
        $issuer_spki_hash = '';
        $spki_lines = []; $spki_exit = null;
        exec('openssl x509 -pubkey -noout -in ' . escapeshellarg($tmp_issuer)
            . ' | openssl pkey -pubin -outform DER 2>/dev/null'
            . ' | openssl dgst -sha1 -hex 2>/dev/null',
            $spki_lines, $spki_exit);
        if ($spki_exit === 0 && !empty($spki_lines)) {
            // Output: "SHA1(stdin)= <hex>" or just "<hex>"
            $spki_raw = trim(implode('', $spki_lines));
            if (preg_match('/([0-9a-f]{40})/i', $spki_raw, $m)) {
                $issuer_spki_hash = strtoupper($m[1]);
            }
        }

        // Responder ID from openssl output.
        $responder_id_raw = $result['responder_id'] ?? '';
        $is_delegated = false;

        if ($responder_id_raw !== '') {
            if (preg_match('/^[0-9A-F:]{2}([0-9A-F:]{38,})$/i', $responder_id_raw)) {
                // byKey form — hex, possibly colon-separated.
                $rid_hex = strtoupper(str_replace(':', '', $responder_id_raw));
                $is_delegated = ($issuer_spki_hash !== '' && $rid_hex !== $issuer_spki_hash);
            } else {
                // byName form — full DN string.
                $issuer_data    = openssl_x509_parse($is_cert);
                $issuer_subject = $issuer_data['name'] ?? '';
                // Normalise separators and whitespace for comparison.
                $norm = fn(string $s): string => strtolower(trim(preg_replace('/\s*[,\/]\s*/', ',', $s)));
                $is_delegated = ($issuer_subject !== '' &&
                    $norm($responder_id_raw) !== $norm($issuer_subject));
            }
        }

        $result['delegated'] = $is_delegated;

        // Parse embedded cert (if response includes one) regardless of
        // delegation status — it gives us EKU / nocheck / expiry.
        $cert_pos = strpos($output, "\nCertificate:\n");
        if ($cert_pos !== false) {
            $cert_section = substr($output, $cert_pos);
            $result['responder_cert_has_eku']     = (bool) preg_match('/OCSP Signing/i',  $cert_section);
            $result['responder_cert_has_nocheck'] = (bool) preg_match('/OCSP No Check/i', $cert_section);
            if (preg_match('/Not After\s*:\s*(.+)/i', $cert_section, $m)) {
                $expiry_str                      = trim($m[1]);
                $result['responder_cert_expiry'] = $expiry_str;
                $expiry_ts                       = strtotime($expiry_str);
                $result['responder_cert_valid']  = ($expiry_ts !== false && $expiry_ts > time());
            }
        }

        // ── HTTP probe via cURL (headers, latency, size, GET support) ─────────
        $request_der = (file_exists($tmp_req) && filesize($tmp_req) > 0)
            ? file_get_contents($tmp_req) : null;

        if ($request_der !== null && function_exists('curl_init')) {
            // POST with header capture
            $ch = curl_init($responder_url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => true,
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $request_der,
                CURLOPT_HTTPHEADER     => ['Content-Type: application/ocsp-request'],
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_USERAGENT      => 'PKI-Linters/1.0',
            ]);
            $full_resp  = curl_exec($ch);
            $hdr_size   = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $latency_ms = (int) round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
            $http_code  = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($full_resp !== false && $http_code > 0) {
                $headers_raw   = substr($full_resp, 0, $hdr_size);
                $response_body = substr($full_resp, $hdr_size);

                $result['http_status']         = $http_code;
                $result['http_latency_ms']     = $latency_ms;
                $result['http_response_bytes'] = strlen($response_body);
                $result['stapling_size_ok']    = strlen($response_body) < 65535;

                if (preg_match('/^Content-Type:\s*(.+)$/im', $headers_raw, $m)) {
                    $result['http_content_type'] = trim($m[1]);
                }
                if (preg_match('/^Cache-Control:\s*(.+)$/im', $headers_raw, $m)) {
                    $result['http_cache_control'] = trim($m[1]);
                    if (preg_match('/max-age=(\d+)/i', $result['http_cache_control'], $m2)) {
                        $result['http_max_age'] = (int) $m2[1];
                    }
                }
                if (preg_match('/^ETag:\s*(.+)$/im', $headers_raw, $m)) {
                    $result['http_etag'] = trim(trim($m[1]), '"');
                }
            }

            // GET support (RFC 5019): base64url-encode the request DER and append to URL
            $b64req  = rtrim(strtr(base64_encode($request_der), '+/', '-_'), '=');
            $get_url = rtrim($responder_url, '/') . '/' . $b64req;
            $ch2 = curl_init($get_url);
            curl_setopt_array($ch2, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPGET        => true,
                CURLOPT_TIMEOUT        => 8,
                CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_USERAGENT      => 'PKI-Linters/1.0',
            ]);
            $get_resp = curl_exec($ch2);
            $get_code = (int) curl_getinfo($ch2, CURLINFO_HTTP_CODE);
            curl_close($ch2);
            // Accepted if server returns 200 with a non-trivial body
            $result['http_get_supported'] = ($get_code === 200 && $get_resp !== false && strlen((string)$get_resp) > 10);
        }

        // ── Nonce test (separate request with -nonce) ─────────────────────────
        // Tests whether the responder echoes nonces (replay protection).
        // A cached/CDN response typically ignores nonces.
        $nonce_lines = []; $nonce_exit = null;
        exec('openssl ocsp'
            . ' -issuer '  . escapeshellarg($tmp_issuer)
            . ' -cert '    . escapeshellarg($tmp_ee)
            . ' -url '     . escapeshellarg($responder_url)
            . ' -nonce -noverify -resp_text 2>&1',
            $nonce_lines, $nonce_exit);
        $nonce_out = implode("\n", $nonce_lines);
        // "Nonce" appears in response extensions only if the responder echoed it
        $result['nonce_echoed'] = ($nonce_out !== '' && (bool) preg_match('/Response Nonce|Nonce:\s*[0-9a-f]/i', $nonce_out));

        // ── TLS probe (HTTPS endpoints only) ──────────────────────────────────
        if (str_starts_with(strtolower($responder_url), 'https://')) {
            $parsed = parse_url($responder_url);
            $host   = $parsed['host'] ?? '';
            $port   = (int) ($parsed['port'] ?? 443);
            if ($host !== '') {
                $tls_lines = []; $tls_exit = null;
                exec('echo Q | openssl s_client'
                    . ' -connect '    . escapeshellarg("$host:$port")
                    . ' -servername ' . escapeshellarg($host)
                    . ' 2>&1',
                    $tls_lines, $tls_exit);
                $tls_out = implode("\n", $tls_lines);
                if (preg_match('/^\s*Protocol\s*:\s*(.+)$/im', $tls_out, $m))  $result['tls_version'] = trim($m[1]);
                if (preg_match('/^\s*Cipher\s*:\s*(.+)$/im',   $tls_out, $m))  $result['tls_cipher']  = trim($m[1]);
                if (preg_match('/Verify return code:\s*0\b/i',  $tls_out)) {
                    $result['tls_cert_valid'] = true;
                } elseif (preg_match('/Verify return code:\s*\d+\s*\(([^)]+)\)/i', $tls_out, $m)) {
                    $result['tls_cert_valid'] = false;
                    $result['tls_cert_error'] = trim($m[1]);
                }
            }
        }

    } finally {
        @unlink($tmp_ee);
        @unlink($tmp_issuer);
        @unlink($tmp_resp);
        @unlink($tmp_req);
    }

    return $result;
}

// ── CRL checker ──────────────────────────────────────────────────────────────

function revoc_check_crl(string $ee_pem, bool $delta = false): array {
    $result = [
        'status'      => 'unknown',
        'crl_url'     => null,
        'issuer'      => null,
        'this_update' => null,
        'next_update' => null,
        'crl_number'  => null,
        'entries'     => 0,
        'raw_crl'     => null,
        'error'       => null,
    ];

    $urls     = revoc_extract_urls($ee_pem);
    $url_list = $delta ? $urls['delta_urls'] : $urls['crl_urls'];

    if (empty($url_list)) {
        $result['error'] = $delta
            ? 'No Delta CRL URL found in the certificate (freshestCRL extension absent).'
            : 'No CRL distribution point URL found in the certificate CDP extension.';
        return $result;
    }

    $crl_url          = $url_list[0];
    $result['crl_url'] = $crl_url;

    // Fetch CRL — enforce size cap (10 MB) to avoid memory issues with large CRLs.
    $fetch = revoc_http_fetch($crl_url);
    if ($fetch['error'] !== null || $fetch['data'] === null) {
        $result['error'] = 'Failed to fetch CRL from ' . $crl_url . ': ' . ($fetch['error'] ?? 'no data returned');
        return $result;
    }

    $crl_data = $fetch['data'];
    if (strlen($crl_data) > 10 * 1024 * 1024) {
        $result['error'] = 'CRL is larger than 10 MB — skipping to avoid memory exhaustion.';
        return $result;
    }

    $result['raw_crl'] = $crl_data;

    // Write CRL to temp file for openssl crl parsing.
    $tmp_crl = tempnam(sys_get_temp_dir(), 'revoc_crl_');
    try {
        file_put_contents($tmp_crl, $crl_data);

        // Parse CRL metadata with openssl crl.
        // RFC 5280 CDPs should serve DER, but many CAs serve PEM; auto-detect.
        $inform = (str_starts_with(ltrim($crl_data), '-----') ? 'PEM' : 'DER');
        $cmd = 'openssl crl'
             . ' -in '     . escapeshellarg($tmp_crl)
             . ' -inform ' . $inform
             . ' -text'
             . ' -noout'
             . ' 2>&1';

        $lines     = [];
        $exit_code = null;
        exec($cmd, $lines, $exit_code);
        $output = implode("\n", $lines);

        if ($exit_code !== 0 || $output === '') {
            $result['error'] = 'Failed to parse CRL with openssl crl (exit ' . $exit_code . ').';
            return $result;
        }

        // Parse metadata
        if (preg_match('/Issuer:\s*(.+)/i', $output, $m)) {
            $result['issuer'] = trim($m[1]);
        }
        if (preg_match('/Last Update:\s*(.+)/i', $output, $m)) {
            $result['this_update'] = trim($m[1]);
        }
        if (preg_match('/Next Update:\s*(.+)/i', $output, $m)) {
            $result['next_update'] = trim($m[1]);
        }
        if (preg_match('/CRL Number[^:]*:\s*(\d+)/i', $output, $m)) {
            $result['crl_number'] = $m[1];
        }

        // Count revoked entries.
        $result['entries'] = substr_count($output, 'Serial Number:');

        // Check if EE serial appears in the CRL.
        $ee_cert   = openssl_x509_read($ee_pem);
        $ee_data   = openssl_x509_parse($ee_cert);
        $ee_serial = strtoupper($ee_data['serialNumberHex'] ?? '');

        if ($ee_serial !== '') {
            // openssl crl text output lists serials as hex without leading zeros.
            // Normalise and search.
            preg_match_all('/Serial Number:\s*([0-9a-fA-F:]+)/i', $output, $sm);
            $revoked_serials = array_map(
                fn($s) => strtoupper(str_replace(':', '', $s)),
                $sm[1] ?? []
            );
            $ee_serial_norm = ltrim($ee_serial, '0') ?: '0';
            $found = false;
            foreach ($revoked_serials as $rs) {
                if (ltrim($rs, '0') === $ee_serial_norm) {
                    $found = true;
                    break;
                }
            }
            $result['status'] = $found ? 'revoked' : 'good';
        }

    } finally {
        @unlink($tmp_crl);
    }

    return $result;
}

// ── pkilint linting of fetched objects ───────────────────────────────────────

function revoc_lint_crl(string $raw_crl_der): string {
    $bin = revoc_pkilint_bin('lint_crl');
    if ($bin === null) return '__NO_BIN__';

    $tmp = tempnam(sys_get_temp_dir(), 'revoc_lcrl_');
    try {
        file_put_contents($tmp, $raw_crl_der);
        // lint_crl requires -t (type: CRL|ARL) and -p (profile: PKIX|BR).
        // We use CRL + BR for WebPKI (CAB Forum BR profile).
        $cmd   = escapeshellarg($bin) . ' lint -f JSON -s INFO -t CRL -p BR ' . escapeshellarg($tmp) . ' 2>&1';
        $lines = []; $exit = null;
        exec($cmd, $lines, $exit);
        $out = implode("\n", $lines);
        // If BR profile fails (e.g. non-BR CRL), retry with PKIX profile.
        if (str_contains($out, 'level=fatal') || str_contains($out, 'error:')) {
            $cmd2  = escapeshellarg($bin) . ' lint -f JSON -s INFO -t CRL -p PKIX ' . escapeshellarg($tmp) . ' 2>&1';
            $lines2 = []; $exit2 = null;
            exec($cmd2, $lines2, $exit2);
            $out2 = implode("\n", $lines2);
            // Use PKIX output if it looks more valid
            if (str_contains($out2, '"results"') || (!str_contains($out2, 'error:'))) {
                $out = $out2;
            }
        }
        $out = implode("\n", $lines);
        return $out !== '' ? $out : '__EMPTY__';
    } finally {
        @unlink($tmp);
    }
}

function revoc_lint_ocsp(string $raw_ocsp_der): string {
    $bin = revoc_pkilint_bin('lint_ocsp_response');
    if ($bin === null) return '__NO_BIN__';

    $tmp = tempnam(sys_get_temp_dir(), 'revoc_locsp_');
    try {
        file_put_contents($tmp, $raw_ocsp_der);
        // lint_ocsp_response lint -f JSON -s INFO <file>
        $cmd   = escapeshellarg($bin) . ' lint -f JSON -s INFO ' . escapeshellarg($tmp) . ' 2>&1';
        $lines = []; $exit = null;
        exec($cmd, $lines, $exit);
        $out = implode("\n", $lines);
        return $out !== '' ? $out : '__EMPTY__';
    } finally {
        @unlink($tmp);
    }
}

// ── HTML rendering helpers ────────────────────────────────────────────────────

function revoc_e(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8');
}

function revoc_status_html(string $status): string {
    return match($status) {
        'good'    => '<span class="revoc-status revoc-good">● GOOD</span>',
        'revoked' => '<span class="revoc-status revoc-revoked">● REVOKED</span>',
        default   => '<span class="revoc-status revoc-unknown">● UNKNOWN</span>',
    };
}

function revoc_row(string $label, string $value): string {
    return '<div class="revoc-row">'
         . '<span class="revoc-label">' . revoc_e($label) . '</span>'
         . '<span class="revoc-value">' . $value . '</span>'
         . '</div>';
}

function revoc_pkilint_findings_html(string $raw_json, string $source_label): string {
    // Sentinel values from lint functions
    if ($raw_json === '__NO_BIN__') {
        return '<div class="revoc-lint-clean" style="color:var(--muted);">lint_'
             . revoc_e(strtolower(str_replace(' ', '_', $source_label)))
             . ' not installed — pkilint linting skipped.</div>';
    }
    if ($raw_json === '__EMPTY__') {
        return '<div class="revoc-lint-clean" style="color:var(--muted);">pkilint returned no output for '
             . revoc_e($source_label) . '.</div>';
    }
    if ($raw_json === '') return '';

    // Separate plain-text lines from JSON (same pattern as pkilint.php)
    $lines      = explode("\n", trim($raw_json));
    $json_line  = null;
    $plain_msgs = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') continue;
        if ($line[0] === '{' || $line[0] === '[') {
            $json_line = $line;
        } else {
            $plain_msgs[] = $line;
        }
    }

    $notices = '';
    foreach ($plain_msgs as $msg) {
        $notices .= '<div class="revoc-lint-plain-msg">⚠ ' . revoc_e($msg) . '</div>';
    }

    if ($json_line === null) {
        return '<div class="revoc-lint-section">'
             . '<div class="revoc-lint-header">pkilint — ' . revoc_e($source_label) . '</div>'
             . $notices
             . '<div class="revoc-lint-clean" style="color:var(--muted);">No JSON output returned.</div>'
             . '</div>';
    }

    $decoded = json_decode($json_line, true);
    $results = is_array($decoded) ? ($decoded['results'] ?? $decoded) : null;

    if (!is_array($results)) {
        return '<div class="revoc-lint-section">'
             . '<div class="revoc-lint-header">pkilint — ' . revoc_e($source_label) . '</div>'
             . $notices
             . '<div class="revoc-lint-clean" style="color:var(--muted);">Could not parse pkilint JSON output.</div>'
             . '<pre style="font-size:0.62rem;color:var(--muted);white-space:pre-wrap;word-break:break-all;">'
             . revoc_e(substr($raw_json, 0, 500)) . '</pre>'
             . '</div>';
    }

    if (count($results) === 0) {
        return '<div class="revoc-lint-section">'
             . '<div class="revoc-lint-header">pkilint — ' . revoc_e($source_label) . '</div>'
             . $notices
             . '<div class="revoc-lint-clean">✓ No findings.</div>'
             . '</div>';
    }

    $colours = [
        'NOTICE'   => ['#4db8ff', 'rgba(0,153,255,0.07)',  'rgba(0,153,255,0.22)'],
        'WARNING'  => ['#f5a623', 'rgba(245,166,35,0.08)', 'rgba(245,166,35,0.28)'],
        'ERROR'    => ['#e05c5c', 'rgba(224,92,92,0.08)',  'rgba(224,92,92,0.28)'],
        'CRITICAL' => ['#ff4444', 'rgba(224,60,60,0.12)',  'rgba(224,60,60,0.40)'],
        'FATAL'    => ['#ff2222', 'rgba(200,30,30,0.18)',  'rgba(200,30,30,0.55)'],
        'INFO'     => ['#8899aa', 'rgba(107,122,144,0.07)','rgba(107,122,144,0.20)'],
    ];

    $rows = '';
    foreach ($results as $result) {
        $findings  = $result['finding_descriptions'] ?? [];
        $node_path = $result['node_path'] ?? '';
        $validator = $result['validator']  ?? '';
        foreach ($findings as $f) {
            $sev  = strtoupper($f['severity'] ?? 'INFO');
            $code = $f['code']    ?? '';
            $msg  = $f['message'] ?? '';
            $c    = $colours[$sev] ?? $colours['INFO'];
            $rows .= '<div class="revoc-lint-row" style="background:' . $c[1] . ';border-left:3px solid ' . $c[2] . '">'
                   . '<span class="revoc-lint-badge" style="color:' . $c[0] . '">' . revoc_e($sev) . '</span>'
                   . '<span class="revoc-lint-body">'
                   . '<span class="revoc-lint-code">'  . revoc_e($code)      . '</span>'
                   . ($msg       ? '<span class="revoc-lint-msg">'  . revoc_e($msg)       . '</span>' : '')
                   . ($node_path ? '<span class="revoc-lint-path">@ ' . revoc_e($node_path) . '</span>' : '')
                   . ($validator ? '<span class="revoc-lint-vali">'  . revoc_e($validator)  . '</span>' : '')
                   . '</span>'
                   . '</div>';
        }
    }

    return '<div class="revoc-lint-section">'
         . '<div class="revoc-lint-header">pkilint — ' . revoc_e($source_label) . '</div>'
         . $notices
         . '<div class="revoc-lint-rows">' . $rows . '</div>'
         . '</div>';
}

// ── Result renderers ──────────────────────────────────────────────────────────

function revoc_render_ocsp(array $r, string $lint_html): string {
    $out = '';

    // ── Status ────────────────────────────────────────────────────────────────
    $out .= revoc_row('Status', revoc_status_html($r['status']));
    if ($r['reason'])     $out .= revoc_row('Reason',     '<span class="revoc-warn">' . revoc_e($r['reason']) . '</span>');
    if ($r['revoked_at']) $out .= revoc_row('Revoked At', '<code class="revoc-code">' . revoc_e($r['revoked_at']) . '</code>');

    // ── Responder ────────────────────────────────────────────────────────────
    $out .= '<div class="revoc-sub-header">Responder</div>';
    if ($r['responder_url']) {
        $out .= revoc_row('URL', '<a class="revoc-link" href="' . revoc_e($r['responder_url']) . '" target="_blank" rel="noopener">' . revoc_e($r['responder_url']) . '</a>');
    }
    if ($r['responder_id']) {
        $out .= revoc_row('Responder ID', '<code class="revoc-code">' . revoc_e($r['responder_id']) . '</code>');
    }
    if ($r['sig_algorithm']) {
        $sig = $r['sig_algorithm'];
        $sig_warn = preg_match('/sha1|md5/i', $sig) ? ' <span class="revoc-warn">⚠ Weak hash</span>' : '';
        $out .= revoc_row('Signature', '<code class="revoc-code">' . revoc_e($sig) . '</code>' . $sig_warn);
    }

    // Delegated responder cert
    if ($r['delegated']) {
        $out .= revoc_row('Type', '<span class="revoc-muted">Delegated OCSP responder</span>');
        if ($r['responder_cert_has_eku'] !== null) {
            $out .= revoc_row('OCSPSigning EKU', $r['responder_cert_has_eku']
                ? '<span class="revoc-ok">✓ Present</span>'
                : '<span class="revoc-bad">✗ Missing — misconfiguration</span>');
        }
        if ($r['responder_cert_has_nocheck'] !== null) {
            $out .= revoc_row('OCSP No-Check', $r['responder_cert_has_nocheck']
                ? '<span class="revoc-ok">✓ Present</span>'
                : '<span class="revoc-warn">⚠ Absent — clients may chain-check the responder cert</span>');
        }
        if ($r['responder_cert_expiry'] !== null) {
            $exp_html = '<code class="revoc-code">' . revoc_e($r['responder_cert_expiry']) . '</code>';
            if ($r['responder_cert_valid'] === false) {
                $exp_html .= ' <span class="revoc-bad">✗ EXPIRED</span>';
            }
            $out .= revoc_row('Responder Cert Expiry', $exp_html);
        }
    } else {
        $out .= revoc_row('Type', '<span class="revoc-muted">CA signing directly (not delegated)</span>');
    }

    // ── Freshness ─────────────────────────────────────────────────────────────
    $out .= '<div class="revoc-sub-header">Freshness</div>';
    if ($r['this_update']) $out .= revoc_row('This Update', '<code class="revoc-code">' . revoc_e($r['this_update']) . '</code>');

    if ($r['next_update_absent']) {
        $out .= revoc_row('Next Update', '<span class="revoc-warn">⚠ Absent — not recommended for publicly-trusted certificates</span>');
    } elseif ($r['next_update']) {
        $out .= revoc_row('Next Update', '<code class="revoc-code">' . revoc_e($r['next_update']) . '</code>');
    }

    if ($r['age_seconds'] !== null) {
        $age_html = '<code class="revoc-code">' . revoc_e(revoc_fmt_duration($r['age_seconds'])) . '</code>';
        if ($r['cabf_age_ok'] === false) {
            $age_html .= ' <span class="revoc-bad">✗ Exceeds 10-day CA/B Forum BR limit</span>';
        } elseif ($r['age_seconds'] > 604800) {
            $age_html .= ' <span class="revoc-warn">⚠ Over 7 days old</span>';
        }
        $out .= revoc_row('Response Age', $age_html);
    }

    if ($r['remaining_seconds'] !== null) {
        $rem_html = '<code class="revoc-code">' . revoc_e(revoc_fmt_duration($r['remaining_seconds'])) . '</code>';
        // Only warn when the response is actually being cached/reused.
        // A live-signed response (nonce echoed, or age < 60s) has a nextUpdate
        // that is never reached in practice — alerting there is noise.
        $is_live = ($r['nonce_echoed'] === true) || ($r['age_seconds'] !== null && $r['age_seconds'] < 60);
        if (!$is_live) {
            if ($r['remaining_seconds'] < 3600) {
                $rem_html .= ' <span class="revoc-bad">✗ Expiring within the hour</span>';
            } elseif ($r['remaining_seconds'] < 86400) {
                $rem_html .= ' <span class="revoc-warn">⚠ Expiring within 24 hours</span>';
            }
        }
        $out .= revoc_row('Remaining Validity', $rem_html);
    }

    // ── HTTP transport ────────────────────────────────────────────────────────
    $out .= '<div class="revoc-sub-header">HTTP Transport</div>';

    if ($r['http_status'] !== null) {
        $s_html = '<code class="revoc-code">' . revoc_e((string)$r['http_status']) . '</code>';
        if ($r['http_status'] !== 200) $s_html .= ' <span class="revoc-warn">⚠ Expected 200</span>';
        $out .= revoc_row('HTTP Status', $s_html);
    }

    if ($r['http_latency_ms'] !== null) {
        $lat_html = '<code class="revoc-code">' . revoc_e($r['http_latency_ms'] . ' ms') . '</code>';
        if ($r['http_latency_ms'] > 1000)      $lat_html .= ' <span class="revoc-bad">✗ Very high latency</span>';
        elseif ($r['http_latency_ms'] > 500)   $lat_html .= ' <span class="revoc-warn">⚠ High latency</span>';
        $out .= revoc_row('Latency', $lat_html);
    }

    if ($r['http_content_type'] !== null) {
        $ct_ok   = str_contains($r['http_content_type'], 'application/ocsp-response');
        $ct_html = '<code class="revoc-code">' . revoc_e($r['http_content_type']) . '</code>';
        if (!$ct_ok) $ct_html .= ' <span class="revoc-bad">✗ Must be application/ocsp-response</span>';
        $out .= revoc_row('Content-Type', $ct_html);
    }

    if ($r['http_cache_control'] !== null) {
        $out .= revoc_row('Cache-Control', '<code class="revoc-code">' . revoc_e($r['http_cache_control']) . '</code>');
    } else {
        $out .= revoc_row('Cache-Control', '<span class="revoc-warn">⚠ Absent — CDN caching not explicitly controlled</span>');
    }

    if ($r['http_max_age'] !== null) {
        $out .= revoc_row('max-age', '<code class="revoc-code">' . revoc_e(revoc_fmt_duration($r['http_max_age'])) . '</code>');
    }

    if ($r['http_etag'] !== null) {
        $out .= revoc_row('ETag', '<code class="revoc-code">' . revoc_e($r['http_etag']) . '</code>');
    }

    if ($r['http_response_bytes'] !== null) {
        $sz    = $r['http_response_bytes'];
        $sz_html = '<code class="revoc-code">' . revoc_e(number_format($sz) . ' bytes') . '</code>';
        if ($r['stapling_size_ok'] === false) {
            $sz_html .= ' <span class="revoc-bad">✗ Too large for TLS stapling in some implementations (&gt; 65 535 B)</span>';
        } elseif ($sz > 10240) {
            $sz_html .= ' <span class="revoc-warn">⚠ Large — verify stapling buffer on your TLS server</span>';
        } else {
            $sz_html .= ' <span class="revoc-ok">✓ Stapling-friendly</span>';
        }
        $out .= revoc_row('Response Size', $sz_html);
    }

    if ($r['http_get_supported'] !== null) {
        $out .= revoc_row('GET (RFC 5019)', $r['http_get_supported']
            ? '<span class="revoc-ok">✓ Supported — CDN-cacheable</span>'
            : '<span class="revoc-muted">✗ Not supported — POST only (not CDN-cacheable)</span>');
    }

    // ── Nonce ─────────────────────────────────────────────────────────────────
    if ($r['nonce_echoed'] !== null) {
        $out .= revoc_row('Nonce', $r['nonce_echoed']
            ? '<span class="revoc-ok">✓ Echoed — response is request-specific, not served from cache</span>'
            : '<span class="revoc-muted">Not echoed — CDN / pre-signed response (no per-request replay protection)</span>');
    }

    // ── TLS (HTTPS endpoints only) ────────────────────────────────────────────
    if ($r['tls_version'] !== null || $r['tls_cipher'] !== null || $r['tls_cert_valid'] !== null) {
        $out .= '<div class="revoc-sub-header">TLS Endpoint</div>';
        if ($r['tls_version']) $out .= revoc_row('Protocol', '<code class="revoc-code">' . revoc_e($r['tls_version']) . '</code>');
        if ($r['tls_cipher'])  $out .= revoc_row('Cipher',   '<code class="revoc-code">' . revoc_e($r['tls_cipher']) . '</code>');
        if ($r['tls_cert_valid'] === true) {
            $out .= revoc_row('Endpoint Cert', '<span class="revoc-ok">✓ Valid</span>');
        } elseif ($r['tls_cert_valid'] === false) {
            $out .= revoc_row('Endpoint Cert', '<span class="revoc-bad">✗ Invalid'
                . ($r['tls_cert_error'] ? ': ' . revoc_e($r['tls_cert_error']) : '') . '</span>');
        }
    }

    $out .= $lint_html;
    return $out;
}

function revoc_render_crl(array $r, string $lint_html, bool $delta = false): string {
    $label = $delta ? 'Delta CRL' : 'CRL';
    $out   = revoc_row('Status',      revoc_status_html($r['status']));
    if ($r['crl_url'])    $out .= revoc_row($label . ' URL',  '<a class="revoc-link" href="' . revoc_e($r['crl_url']) . '" target="_blank" rel="noopener">' . revoc_e($r['crl_url']) . '</a>');
    if ($r['issuer'])     $out .= revoc_row('CRL Issuer',    '<code class="revoc-code">' . revoc_e($r['issuer']) . '</code>');
    if ($r['this_update']) $out .= revoc_row('This Update',  '<code class="revoc-code">' . revoc_e($r['this_update']) . '</code>');
    if ($r['next_update']) $out .= revoc_row('Next Update',  '<code class="revoc-code">' . revoc_e($r['next_update']) . '</code>');
    if ($r['crl_number'] !== null) $out .= revoc_row('CRL Number', '<code class="revoc-code">' . revoc_e($r['crl_number']) . '</code>');
    $out .= revoc_row('Revoked Entries', '<span class="revoc-code">' . revoc_e((string)$r['entries']) . '</span>');
    $out .= $lint_html;
    return $out;
}

// ── CSS ───────────────────────────────────────────────────────────────────────

function revoc_styles(): string {
    return <<<CSS
<style>
.revoc-wrap { font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; display: flex; flex-direction: column; gap: 0.35rem; }
.revoc-row { display: flex; align-items: baseline; gap: 0.75rem; padding: 0.22rem 0; border-bottom: 1px solid rgba(42,48,64,0.5); flex-wrap: wrap; }
.revoc-row:last-child { border-bottom: none; }
.revoc-label { flex-shrink: 0; width: 10rem; color: var(--muted); font-size: 0.68rem; }
.revoc-value { color: var(--text); flex: 1; word-break: break-all; line-height: 1.6; }
.revoc-code { font-family: 'IBM Plex Mono', monospace; font-size: 0.68rem; color: #a8c0e8; }
.revoc-link { color: var(--accent2); text-decoration: none; word-break: break-all; }
.revoc-link:hover { text-decoration: underline; }
.revoc-warn   { color: var(--warn); }
.revoc-ok     { color: #3ddc7a; }
.revoc-bad    { color: #e05c5c; }
.revoc-muted  { color: var(--muted); }
.revoc-status { font-weight: 700; font-size: 0.78rem; letter-spacing: 0.06em; }
.revoc-good    { color: #3ddc7a; }
.revoc-revoked { color: #e05c5c; }
.revoc-unknown { color: #8899aa; }
.revoc-sub-header {
  font-size: 0.6rem; font-weight: 600; letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--muted); margin-top: 0.75rem; margin-bottom: 0.1rem;
  padding-top: 0.6rem; border-top: 1px solid var(--border);
}
/* pkilint findings */
.revoc-lint-section { margin-top: 1rem; border-top: 1px solid var(--border); padding-top: 0.75rem; }
.revoc-lint-header { font-size: 0.62rem; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted); margin-bottom: 0.5rem; }
.revoc-lint-clean { font-size: 0.7rem; color: #3ddc7a; margin-top: 0.75rem; }
.revoc-lint-rows { display: flex; flex-direction: column; gap: 2px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface2); }
.revoc-lint-row { display: flex; align-items: flex-start; gap: 0.75rem; padding: 0.3rem 0.75rem; line-height: 1.6; }
.revoc-lint-badge { flex-shrink: 0; width: 5.5rem; font-weight: 700; font-size: 0.6rem; letter-spacing: 0.1em; margin-top: 0.15em; }
.revoc-lint-body { display: flex; flex-direction: column; gap: 0.08rem; flex: 1; word-break: break-all; }
.revoc-lint-code { color: #d4dae6; font-weight: 500; }
.revoc-lint-msg  { color: #a8b4c8; font-size: 0.68rem; }
.revoc-lint-path { color: #6b7a90; font-size: 0.66rem; font-style: italic; }
.revoc-lint-vali { color: #4a5568; font-size: 0.64rem; }
/* Buttons */
.revoc-section { display: flex; flex-direction: column; gap: 0.5rem; }
.revoc-group-label { font-family: var(--mono); font-size: 0.65rem; font-weight: 600; letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted); padding-bottom: 0.25rem; border-bottom: 1px solid var(--border); }
.revoc-buttons { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.btn-revoc {
    font-family: var(--mono); font-size: 0.72rem; font-weight: 500; letter-spacing: 0.06em;
    color: var(--text); background: var(--surface2); border: 1px solid var(--border2);
    border-radius: var(--radius); padding: 0.5rem 1.1rem; cursor: pointer;
    display: flex; align-items: center; gap: 0.5rem;
    transition: background var(--transition), border-color var(--transition), color var(--transition), transform var(--transition), box-shadow var(--transition);
}
.btn-revoc:hover:not(:disabled) {
    background: rgba(245,166,35,0.08); border-color: var(--warn); color: var(--warn);
    transform: translateY(-1px); box-shadow: 0 3px 10px rgba(245,166,35,0.12);
}
.btn-revoc:disabled { opacity: 0.32; cursor: not-allowed; border-color: var(--border); color: var(--muted); }
.btn-revoc .arrow { opacity: 0; transform: translateX(-4px); transition: opacity var(--transition), transform var(--transition); font-size: 0.7rem; }
.btn-revoc:hover:not(:disabled) .arrow { opacity: 1; transform: translateX(0); }
.revoc-btn-hint { font-size: 0.65rem; color: var(--muted); font-style: italic; }
.revoc-lint-plain-msg { font-size: 0.68rem; color: var(--warn); padding: 0.25rem 0; }
.revoc-lint-linter-label { font-size: 0.6rem; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: #3a4458; padding: 0.3rem 0.75rem 0.1rem; border-bottom: 1px solid #1d2330; margin-top: 0.2rem; }
</style>
CSS;
}

// ── pkilint version (shared constant set by pkilint.php, or re-detect) ────────

function revoc_pkilint_version(): string {
    // If pkilint.php already ran, reuse its version detection result.
    // Otherwise probe pip directly.
    foreach (['/usr/local/bin/pip', '/usr/bin/pip', '/usr/local/bin/pip3', '/usr/bin/pip3'] as $pip) {
        if (!is_executable($pip)) continue;
        $raw = trim(shell_exec(escapeshellarg($pip) . ' show pkilint 2>/dev/null | grep -i ^Version:') ?? '');
        if (preg_match('/\d+\.\d+\.\d+\S*/', $raw, $m)) return 'v' . $m[0];
    }
    return '';
}

// ── pkimetal availability ─────────────────────────────────────────────────────

function revoc_pkimetal_url(): string {
    $env = getenv('PKIMETAL_URL');
    return ($env !== false && $env !== '') ? rtrim($env, '/') : PKIMETAL_URL;
}

function revoc_pkimetal_available(): bool {
    if (!function_exists('curl_init')) return false;
    $ch = curl_init(revoc_pkimetal_url() . '/');
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2, CURLOPT_CONNECTTIMEOUT => 2]);
    curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return $code > 0;
}

// ── pkimetal CRL/OCSP linting ─────────────────────────────────────────────────

function revoc_pkimetal_lint_crl(string $raw_crl_der): string {
    if (!function_exists('curl_init')) return '__NO_BIN__';
    $b64 = base64_encode($raw_crl_der);
    $ch  = curl_init(revoc_pkimetal_url() . '/lintcrl');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query(['b64crl' => $b64, 'format' => 'json']),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_CONNECTTIMEOUT => 5,
    ]);
    $resp = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($resp === false || $code !== 200) return '__EMPTY__';
    return $resp;
}

function revoc_pkimetal_lint_ocsp(string $raw_ocsp_der): string {
    if (!function_exists('curl_init')) return '__NO_BIN__';
    $b64 = base64_encode($raw_ocsp_der);
    $ch  = curl_init(revoc_pkimetal_url() . '/lintocsp');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query(['b64ocsp' => $b64, 'format' => 'json']),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_CONNECTTIMEOUT => 5,
    ]);
    $resp = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($resp === false || $code !== 200) return '__EMPTY__';
    return $resp;
}

// ── pkimetal findings renderer ────────────────────────────────────────────────
// pkimetal response is a flat JSON array: [{Linter, Finding, Severity, ...}]
// Same PascalCase structure as pkimetal.php

function revoc_pkimetal_findings_html(string $raw, string $source_label): string {
    if ($raw === '__NO_BIN__' || $raw === '__EMPTY__' || $raw === '') return '';

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return '<div class="revoc-lint-section">'
             . '<div class="revoc-lint-header">pkimetal — ' . revoc_e($source_label) . '</div>'
             . '<div class="revoc-lint-plain-msg">⚠ Could not parse pkimetal response.</div>'
             . '</div>';
    }

    $colours = [
        'fatal'   => ['#ff2222', 'rgba(200,30,30,0.18)',   'rgba(200,30,30,0.55)'],
        'error'   => ['#e05c5c', 'rgba(224,92,92,0.08)',   'rgba(224,92,92,0.28)'],
        'warning' => ['#f5a623', 'rgba(245,166,35,0.08)',  'rgba(245,166,35,0.28)'],
        'notice'  => ['#4db8ff', 'rgba(0,153,255,0.07)',   'rgba(0,153,255,0.22)'],
        'info'    => ['#8899aa', 'rgba(107,122,144,0.07)', 'rgba(107,122,144,0.20)'],
        'debug'   => ['#556070', 'rgba(107,122,144,0.05)', 'rgba(107,122,144,0.15)'],
    ];

    // Group by linter, separate meta
    $by_linter = [];
    foreach ($decoded as $f) {
        $linter   = trim($f['Linter']   ?? $f['linter']   ?? 'pkimetal');
        $severity = strtolower(trim($f['Severity'] ?? $f['severity'] ?? 'info'));
        $finding  = trim($f['Finding']  ?? $f['finding']  ?? '');
        if ($finding === '[EndOfResults]') continue;
        if ($severity === 'meta') {
            $by_linter[$linter]['meta'][] = $finding;
        } else {
            $by_linter[$linter]['findings'][] = ['severity' => $severity, 'finding' => $finding];
        }
    }

    $real = array_sum(array_map(fn($l) => count($l['findings'] ?? []), $by_linter));
    if ($real === 0 && empty(array_filter($by_linter, fn($l) => !empty($l['findings'])))) {
        return '<div class="revoc-lint-section">'
             . '<div class="revoc-lint-header">pkimetal — ' . revoc_e($source_label) . '</div>'
             . '<div class="revoc-lint-clean">✓ No findings.</div>'
             . '</div>';
    }

    $rows = '';
    foreach ($by_linter as $linter => $data) {
        $findings = $data['findings'] ?? [];
        $meta     = $data['meta']     ?? [];
        if (empty($findings)) continue;
        $rows .= '<div class="revoc-lint-linter-label">'
               . revoc_e($linter)
               . ($meta ? ' <span style="color:#2a3040;font-style:italic;font-size:0.58rem;">' . revoc_e(implode(' · ', $meta)) . '</span>' : '')
               . '</div>';
        foreach ($findings as $item) {
            $sev = $item['severity'];
            $c   = $colours[$sev] ?? $colours['info'];
            $rows .= '<div class="revoc-lint-row" style="background:' . $c[1] . ';border-left:3px solid ' . $c[2] . '">'
                   . '<span class="revoc-lint-badge" style="color:' . $c[0] . '">' . revoc_e(strtoupper($sev)) . '</span>'
                   . '<span class="revoc-lint-body"><span class="revoc-lint-code">' . revoc_e($item['finding']) . '</span></span>'
                   . '</div>';
        }
    }

    return '<div class="revoc-lint-section">'
         . '<div class="revoc-lint-header">pkimetal — ' . revoc_e($source_label) . '</div>'
         . '<div class="revoc-lint-rows">' . $rows . '</div>'
         . '</div>';
}

// ── Public API ────────────────────────────────────────────────────────────────

function revocation_is_action(string $action): bool {
    return in_array($action, [
        'revoc_ocsp', 'revoc_crl', 'revoc_delta',
        'revoc_ocsp_pkimetal', 'revoc_crl_pkimetal', 'revoc_delta_pkimetal',
    ], true);
}

/**
 * Renders the revocation button group.
 * Buttons are enabled/disabled based on what's in the certificate and
 * whether the issuer PEM is present.
 */
function revocation_buttons(string $ee_pem, ?string $root_pem): string {
    $urls       = revoc_extract_urls($ee_pem);
    $has_issuer = $root_pem !== null && trim($root_pem) !== '';

    $has_ocsp  = !empty($urls['ocsp_urls']);
    $has_crl   = !empty($urls['crl_urls']);
    $has_delta = !empty($urls['delta_urls']);

    $lint_crl_bin  = revoc_pkilint_bin('lint_crl');
    $lint_ocsp_bin = revoc_pkilint_bin('lint_ocsp_response');
    $pkilint_ver   = ($lint_crl_bin || $lint_ocsp_bin) ? revoc_pkilint_version() : '';
    $pkimetal_up   = revoc_pkimetal_available();
    $pkimetal_ver  = ''; // fetched on demand — avoid extra HTTP on page load

    // ── Button definitions ────────────────────────────────────────────────────
    // Each group: [title, buttons[]]
    $groups = [];

    // ── pkilint group ─────────────────────────────────────────────────────────
    $pkilint_btns = [];

    if ($lint_ocsp_bin) {
        $ocsp_ok = $has_ocsp && $has_issuer;
        $label   = 'lint_ocsp_response' . ($pkilint_ver ? ' ' . $pkilint_ver : '');
        $title   = match(true) {
            !$has_ocsp   => 'No OCSP URL in AIA extension',
            !$has_issuer => 'Issuer/root certificate required for OCSP',
            default      => 'OCSP: check status + lint response with pkilint lint_ocsp_response',
        };
        $pkilint_btns[] = ['name' => 'revoc_action', 'value' => 'revoc_ocsp',
                           'label' => $label, 'enabled' => $ocsp_ok, 'title' => $title];
    }

    if ($lint_crl_bin) {
        $label = 'lint_crl' . ($pkilint_ver ? ' ' . $pkilint_ver : '');

        $crl_ok = $has_crl;
        $pkilint_btns[] = ['name' => 'revoc_action', 'value' => 'revoc_crl',
                           'label' => $label . ' (CRL)',
                           'enabled' => $crl_ok,
                           'title' => $crl_ok ? 'Fetch CRL, check revocation status + lint with pkilint lint_crl -t CRL -p BR' : 'No CRL distribution point URL in certificate'];

        $delta_ok = $has_delta;
        $pkilint_btns[] = ['name' => 'revoc_action', 'value' => 'revoc_delta',
                           'label' => $label . ' (Delta CRL)',
                           'enabled' => $delta_ok,
                           'title' => $delta_ok ? 'Fetch Delta CRL, check revocation status + lint with pkilint lint_crl -t CRL -p BR' : 'No Delta CRL URL in certificate (freshestCRL extension absent)'];
    }

    // Fallback buttons when pkilint binaries are absent — status check only
    if (!$lint_ocsp_bin) {
        $ocsp_ok = $has_ocsp && $has_issuer;
        $title   = match(true) {
            !$has_ocsp   => 'No OCSP URL in AIA extension',
            !$has_issuer => 'Issuer/root certificate required for OCSP',
            default      => 'Check OCSP status (lint_ocsp_response not installed)',
        };
        $pkilint_btns[] = ['name' => 'revoc_action', 'value' => 'revoc_ocsp',
                           'label' => 'OCSP status', 'enabled' => $ocsp_ok, 'title' => $title];
    }
    if (!$lint_crl_bin) {
        $pkilint_btns[] = ['name' => 'revoc_action', 'value' => 'revoc_crl',
                           'label' => 'CRL status',
                           'enabled' => $has_crl,
                           'title' => $has_crl ? 'Check CRL status (lint_crl not installed)' : 'No CRL distribution point URL in certificate'];
        $pkilint_btns[] = ['name' => 'revoc_action', 'value' => 'revoc_delta',
                           'label' => 'Delta CRL status',
                           'enabled' => $has_delta,
                           'title' => $has_delta ? 'Check Delta CRL status (lint_crl not installed)' : 'No Delta CRL URL in certificate'];
    }

    if (!empty($pkilint_btns)) {
        $groups[] = ['label' => 'pkilint', 'buttons' => $pkilint_btns];
    }

    // ── pkimetal group ────────────────────────────────────────────────────────
    if ($pkimetal_up) {
        $pkimetal_btns = [];

        $ocsp_ok = $has_ocsp && $has_issuer;
        $pkimetal_btns[] = ['name' => 'revoc_action', 'value' => 'revoc_ocsp_pkimetal',
                            'label' => 'pkimetal lintocsp',
                            'enabled' => $ocsp_ok,
                            'title' => match(true) {
                                !$has_ocsp   => 'No OCSP URL in AIA extension',
                                !$has_issuer => 'Issuer/root certificate required for OCSP',
                                default      => 'Fetch OCSP response + lint with pkimetal /lintocsp',
                            }];

        $pkimetal_btns[] = ['name' => 'revoc_action', 'value' => 'revoc_crl_pkimetal',
                            'label' => 'pkimetal lintcrl',
                            'enabled' => $has_crl,
                            'title' => $has_crl ? 'Fetch CRL + lint with pkimetal /lintcrl' : 'No CRL distribution point URL in certificate'];

        $pkimetal_btns[] = ['name' => 'revoc_action', 'value' => 'revoc_delta_pkimetal',
                            'label' => 'pkimetal lintcrl (delta)',
                            'enabled' => $has_delta,
                            'title' => $has_delta ? 'Fetch Delta CRL + lint with pkimetal /lintcrl' : 'No Delta CRL URL in certificate'];

        $groups[] = ['label' => 'pkimetal', 'buttons' => $pkimetal_btns];
    }

    // ── Render ────────────────────────────────────────────────────────────────
    $html = revoc_styles();
    $html .= '<div class="revoc-section">';

    foreach ($groups as $group) {
        $html .= '<div class="linter-group">';
        $html .= '<div class="linter-group-label">' . revoc_e($group['label']) . '</div>';
        $html .= '<div class="linter-buttons">';
        foreach ($group['buttons'] as $btn) {
            $html .= '<button'
                   . ' type="submit"'
                   . ' name="' . revoc_e($btn['name']) . '"'
                   . ' value="' . revoc_e($btn['value']) . '"'
                   . ' class="btn-linter"'
                   . ' title="' . revoc_e($btn['title']) . '"'
                   . ' formaction="' . revoc_e($_SERVER['PHP_SELF']) . '"'
                   . ($btn['enabled'] ? '' : ' disabled')
                   . '>'
                   . revoc_e($btn['label'])
                   . ($btn['enabled'] ? '<span class="arrow">→</span>' : '')
                   . '</button>';
        }
        $html .= '</div></div>';
    }

    if (!$has_issuer && $has_ocsp) {
        $html .= '<span class="revoc-btn-hint">OCSP requires the issuer certificate in the field above.</span>';
    }

    $html .= '</div>';
    return $html;
}

/**
 * Executes a revocation action and returns HTML result.
 */
function revocation_handle_post(string $action, string $ee_pem, ?string $root_pem): string {
    $html = '<div class="revoc-wrap">';

    switch ($action) {

        // ── pkilint actions ───────────────────────────────────────────────────

        case 'revoc_ocsp':
            if ($root_pem === null || trim($root_pem) === '') {
                return '<div class="revoc-wrap"><div class="revoc-row"><span class="revoc-warn">Issuer/root certificate is required for OCSP checking.</span></div></div>';
            }
            $r = revoc_check_ocsp($ee_pem, $root_pem);
            if ($r['error']) {
                $html .= '<div class="revoc-row"><span class="revoc-label">Error</span><span class="revoc-value revoc-warn">' . revoc_e($r['error']) . '</span></div>';
            } else {
                $lint_json = $r['raw_response'] ? revoc_lint_ocsp($r['raw_response']) : '__NO_BIN__';
                $lint_html = revoc_pkilint_findings_html($lint_json, 'OCSP Response');
                $html .= revoc_render_ocsp($r, $lint_html);
            }
            break;

        case 'revoc_crl':
            $r = revoc_check_crl($ee_pem, false);
            if ($r['error']) {
                $html .= '<div class="revoc-row"><span class="revoc-label">Error</span><span class="revoc-value revoc-warn">' . revoc_e($r['error']) . '</span></div>';
            } else {
                $lint_json = $r['raw_crl'] ? revoc_lint_crl($r['raw_crl']) : '__NO_BIN__';
                $lint_html = revoc_pkilint_findings_html($lint_json, 'CRL');
                $html .= revoc_render_crl($r, $lint_html, false);
            }
            break;

        case 'revoc_delta':
            $r = revoc_check_crl($ee_pem, true);
            if ($r['error']) {
                $html .= '<div class="revoc-row"><span class="revoc-label">Error</span><span class="revoc-value revoc-warn">' . revoc_e($r['error']) . '</span></div>';
            } else {
                $lint_json = $r['raw_crl'] ? revoc_lint_crl($r['raw_crl']) : '__NO_BIN__';
                $lint_html = revoc_pkilint_findings_html($lint_json, 'Delta CRL');
                $html .= revoc_render_crl($r, $lint_html, true);
            }
            break;

        // ── pkimetal actions ──────────────────────────────────────────────────

        case 'revoc_ocsp_pkimetal':
            if ($root_pem === null || trim($root_pem) === '') {
                return '<div class="revoc-wrap"><div class="revoc-row"><span class="revoc-warn">Issuer/root certificate is required for OCSP checking.</span></div></div>';
            }
            $r = revoc_check_ocsp($ee_pem, $root_pem);
            if ($r['error']) {
                $html .= '<div class="revoc-row"><span class="revoc-label">Error</span><span class="revoc-value revoc-warn">' . revoc_e($r['error']) . '</span></div>';
            } else {
                $lint_html = $r['raw_response'] ? revoc_pkimetal_findings_html(revoc_pkimetal_lint_ocsp($r['raw_response']), 'OCSP Response') : '';
                $html .= revoc_render_ocsp($r, $lint_html);
            }
            break;

        case 'revoc_crl_pkimetal':
            $r = revoc_check_crl($ee_pem, false);
            if ($r['error']) {
                $html .= '<div class="revoc-row"><span class="revoc-label">Error</span><span class="revoc-value revoc-warn">' . revoc_e($r['error']) . '</span></div>';
            } else {
                $lint_html = $r['raw_crl'] ? revoc_pkimetal_findings_html(revoc_pkimetal_lint_crl($r['raw_crl']), 'CRL') : '';
                $html .= revoc_render_crl($r, $lint_html, false);
            }
            break;

        case 'revoc_delta_pkimetal':
            $r = revoc_check_crl($ee_pem, true);
            if ($r['error']) {
                $html .= '<div class="revoc-row"><span class="revoc-label">Error</span><span class="revoc-value revoc-warn">' . revoc_e($r['error']) . '</span></div>';
            } else {
                $lint_html = $r['raw_crl'] ? revoc_pkimetal_findings_html(revoc_pkimetal_lint_crl($r['raw_crl']), 'Delta CRL') : '';
                $html .= revoc_render_crl($r, $lint_html, true);
            }
            break;

        default:
            $html .= '<div class="revoc-row"><span class="revoc-warn">Unknown revocation action.</span></div>';
    }

    $html .= '</div>';
    return $html;
}

