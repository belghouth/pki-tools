<?php
/**
 * x509parse.php — X.509 Certificate Parser
 *
 * Renders a full structured breakdown of an X.509 certificate.
 * Must only be invoked by linters.php (or another PHP script that sets
 * $x509parse_invoked = true before including this file).
 * Direct HTTP access returns 403.
 *
 * Usage from linters.php:
 *   $x509parse_invoked = true;
 *   require_once __DIR__ . '/x509parse.php';
 *   echo x509parse_render($ee_pem);
 */

// ── Direct access guard ───────────────────────────────────────────────────────
if (!isset($x509parse_invoked) || $x509parse_invoked !== true) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('403 Forbidden: this file must not be accessed directly.');
}

// ── OID registry ──────────────────────────────────────────────────────────────

function x509_oid_name(string $oid): string {
    static $map = [
        // DN attributes
        '2.5.4.3'                => 'CN (Common Name)',
        '2.5.4.4'                => 'SN (Surname)',
        '2.5.4.5'                => 'serialNumber',
        '2.5.4.6'                => 'C (Country)',
        '2.5.4.7'                => 'L (Locality)',
        '2.5.4.8'                => 'ST (State/Province)',
        '2.5.4.9'                => 'streetAddress',
        '2.5.4.10'               => 'O (Organization)',
        '2.5.4.11'               => 'OU (Organizational Unit)',
        '2.5.4.12'               => 'title',
        '2.5.4.17'               => 'postalCode',
        '2.5.4.42'               => 'givenName',
        '2.5.4.43'               => 'initials',
        '2.5.4.97'               => 'organizationIdentifier',
        '1.2.840.113549.1.9.1'   => 'emailAddress',
        '0.9.2342.19200300.100.1.25' => 'DC (Domain Component)',
        '0.9.2342.19200300.100.1.1'  => 'UID (User ID)',
        '1.3.6.1.4.1.311.60.2.1.1'  => 'jurisdictionL',
        '1.3.6.1.4.1.311.60.2.1.2'  => 'jurisdictionST',
        '1.3.6.1.4.1.311.60.2.1.3'  => 'jurisdictionC',
        // Signature algorithms
        '1.2.840.113549.1.1.1'   => 'rsaEncryption',
        '1.2.840.113549.1.1.5'   => 'sha1WithRSAEncryption',
        '1.2.840.113549.1.1.11'  => 'sha256WithRSAEncryption',
        '1.2.840.113549.1.1.12'  => 'sha384WithRSAEncryption',
        '1.2.840.113549.1.1.13'  => 'sha512WithRSAEncryption',
        '1.2.840.10045.4.3.2'    => 'ecdsa-with-SHA256',
        '1.2.840.10045.4.3.3'    => 'ecdsa-with-SHA384',
        '1.2.840.10045.4.3.4'    => 'ecdsa-with-SHA512',
        '1.3.101.112'            => 'Ed25519',
        '1.3.101.113'            => 'Ed448',
        // Extended Key Usage
        '1.3.6.1.5.5.7.3.1'     => 'serverAuth (TLS Web Server)',
        '1.3.6.1.5.5.7.3.2'     => 'clientAuth (TLS Web Client)',
        '1.3.6.1.5.5.7.3.3'     => 'codeSigning',
        '1.3.6.1.5.5.7.3.4'     => 'emailProtection',
        '1.3.6.1.5.5.7.3.8'     => 'timeStamping',
        '1.3.6.1.5.5.7.3.9'     => 'OCSPSigning',
        '1.3.6.1.4.1.311.10.3.4' => 'Microsoft EFS',
        '1.3.6.1.4.1.311.10.3.12' => 'Microsoft Document Signing',
        // Certificate Policies
        '2.23.140.1.1'           => 'CAB/F EV TLS',
        '2.23.140.1.2.1'         => 'CAB/F DV TLS',
        '2.23.140.1.2.2'         => 'CAB/F OV TLS',
        '2.23.140.1.2.3'         => 'CAB/F IV TLS',
        '2.23.140.1.3'           => 'CAB/F EV Code Signing',
        '2.23.140.1.4.1'         => 'CAB/F Non-EV Code Signing',
        '2.23.140.1.5.1.1'       => 'CAB/F S/MIME Mailbox DV',
        '2.23.140.1.5.1.2'       => 'CAB/F S/MIME Mailbox LV',
        '2.23.140.1.5.2.1'       => 'CAB/F S/MIME Org DV',
        '2.23.140.1.5.2.2'       => 'CAB/F S/MIME Org LV',
        '2.23.140.1.5.3.1'       => 'CAB/F S/MIME Sponsor DV',
        '2.23.140.1.5.4.1'       => 'CAB/F S/MIME Individual DV',
        '2.5.29.32.0'            => 'anyPolicy',
        '1.3.6.1.5.5.7.2.1'     => 'CPS URI qualifier',
        '1.3.6.1.5.5.7.2.2'     => 'User Notice qualifier',
        // Extensions
        '2.5.29.9'               => 'Subject Directory Attributes',
        '2.5.29.14'              => 'Subject Key Identifier',
        '2.5.29.15'              => 'Key Usage',
        '2.5.29.16'              => 'Private Key Usage Period',
        '2.5.29.17'              => 'Subject Alternative Name',
        '2.5.29.18'              => 'Issuer Alternative Name',
        '2.5.29.19'              => 'Basic Constraints',
        '2.5.29.30'              => 'Name Constraints',
        '2.5.29.31'              => 'CRL Distribution Points',
        '2.5.29.32'              => 'Certificate Policies',
        '2.5.29.33'              => 'Policy Mappings',
        '2.5.29.35'              => 'Authority Key Identifier',
        '2.5.29.36'              => 'Policy Constraints',
        '2.5.29.37'              => 'Extended Key Usage',
        '2.5.29.46'              => 'Delta CRL Indicator',
        '2.5.29.54'              => 'Inhibit anyPolicy',
        '1.3.6.1.5.5.7.1.1'     => 'Authority Information Access',
        '1.3.6.1.5.5.7.1.11'    => 'Subject Information Access',
        '1.3.6.1.4.1.11129.2.4.2' => 'CT Signed Certificate Timestamps',
        '1.3.6.1.4.1.11129.2.4.3' => 'CT Precertificate Poison',
        '1.3.6.1.5.5.7.1.24'    => 'TLS Feature (OCSP Must-Staple)',
        '2.16.840.1.113730.1.1'  => 'Netscape Certificate Type',
        '1.2.840.113549.1.9.15'  => 'SMIMECapabilities',
        // Public key algorithms
        '1.2.840.10045.2.1'      => 'EC Public Key',
        '1.2.840.113549.1.1.1'   => 'RSA Public Key',
        // EC curves
        '1.2.840.10045.3.1.7'    => 'P-256 (prime256v1)',
        '1.3.132.0.34'           => 'P-384 (secp384r1)',
        '1.3.132.0.35'           => 'P-521 (secp521r1)',
        '1.3.132.0.10'           => 'secp256k1',
    ];
    return $map[$oid] ?? $oid;
}

// ── Helper: HTML escaping shorthand ──────────────────────────────────────────

function xpe(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8');
}

// ── Helper: format DN array ───────────────────────────────────────────────────

function x509_format_dn(array $dn): string {
    $order = ['CN','O','OU','L','ST','C','emailAddress','serialNumber',
              'street','postalCode','DC','UID','title','givenName','SN'];
    $rows  = '';
    $shown = [];
    foreach ($order as $k) {
        if (!isset($dn[$k])) continue;
        $vals = is_array($dn[$k]) ? $dn[$k] : [$dn[$k]];
        foreach ($vals as $v) {
            $rows .= '<tr><td class="dn-key">' . xpe($k) . '</td>'
                   . '<td class="dn-val">' . xpe((string)$v) . '</td></tr>';
        }
        $shown[] = $k;
    }
    // Any remaining keys not in order list
    foreach ($dn as $k => $v) {
        if (in_array($k, $shown, true)) continue;
        $vals = is_array($v) ? $v : [$v];
        foreach ($vals as $val) {
            $rows .= '<tr><td class="dn-key">' . xpe((string)$k) . '</td>'
                   . '<td class="dn-val">' . xpe((string)$val) . '</td></tr>';
        }
    }
    return $rows ? '<table class="dn-table">' . $rows . '</table>' : '<span class="xp-muted">—</span>';
}

// ── Helper: Key Usage bits ────────────────────────────────────────────────────

function x509_key_usage_bits(string $raw): array {
    $names = [
        'Digital Signature', 'Non-Repudiation / Content Commitment',
        'Key Encipherment', 'Data Encipherment', 'Key Agreement',
        'Key Cert Sign', 'CRL Sign', 'Encipher Only', 'Decipher Only',
    ];
    $set = [];
    foreach ($names as $i => $name) {
        if (str_contains($raw, $name) || preg_match('/\b' . preg_quote($name, '/') . '\b/', $raw)) {
            $set[] = $name;
        }
    }
    // openssl_x509_parse returns a comma-separated string for keyUsage
    if (empty($set) && $raw !== '') {
        $set = array_map('trim', explode(',', $raw));
    }
    return $set;
}

// ── Helper: section wrapper ───────────────────────────────────────────────────

function xp_section(string $id, string $label, string $color, string $content): string {
    return '<div class="xp-section" id="xps-' . xpe($id) . '">'
         . '<div class="xp-section-header" style="border-left-color:' . $color . '">'
         . '<span class="xp-section-label">' . xpe($label) . '</span>'
         . '</div>'
         . '<div class="xp-section-body">' . $content . '</div>'
         . '</div>';
}

// ── Helper: field row ─────────────────────────────────────────────────────────

function xp_row(string $label, string $value, string $extra_class = ''): string {
    return '<div class="xp-row' . ($extra_class ? ' ' . $extra_class : '') . '">'
         . '<span class="xp-label">' . xpe($label) . '</span>'
         . '<span class="xp-value">' . $value . '</span>'
         . '</div>';
}

function xp_badge(string $text, string $type = 'neutral'): string {
    return '<span class="xp-badge xp-badge-' . xpe($type) . '">' . xpe($text) . '</span>';
}

function xp_tag(string $text): string {
    return '<span class="xp-tag">' . xpe($text) . '</span>';
}

// ── Main renderer ─────────────────────────────────────────────────────────────

function x509parse_render(string $pem): string {
    $cert = openssl_x509_read($pem);
    if ($cert === false) {
        return '<div class="xp-error">Failed to parse certificate.</div>';
    }

    $d = openssl_x509_parse($cert, true);
    if (!$d) {
        return '<div class="xp-error">openssl_x509_parse returned no data.</div>';
    }

    $pub = openssl_pkey_get_public($cert);
    $pub_details = $pub ? openssl_pkey_get_details($pub) : null;

    // ── Fingerprints ──────────────────────────────────────────────────────────
    $fp_sha256 = strtoupper(openssl_x509_fingerprint($cert, 'sha256') ?: '');
    $fp_sha1   = strtoupper(openssl_x509_fingerprint($cert, 'sha1')   ?: '');
    // Format as colon-separated hex pairs
    $fmt_fp = fn(string $fp): string => implode(':', str_split($fp, 2));

    // ── Serial ────────────────────────────────────────────────────────────────
    $serial_hex = strtoupper($d['serialNumberHex'] ?? dechex((int)($d['serialNumber'] ?? 0)));
    $serial_dec = $d['serialNumber'] ?? '';
    // Format hex with colons every 2 chars
    $serial_fmt = implode(':', str_split($serial_hex, 2));

    // ── Validity ──────────────────────────────────────────────────────────────
    $not_before_ts = $d['validFrom_time_t'] ?? 0;
    $not_after_ts  = $d['validTo_time_t']   ?? 0;
    $now           = time();
    $seconds_left  = $not_after_ts - $now;
    $days_left     = (int)($seconds_left / 86400);
    $validity_days = (int)(($not_after_ts - $not_before_ts) / 86400);
    $is_expired    = $seconds_left < 0;
    $not_before    = gmdate('Y-m-d H:i:s', $not_before_ts) . ' UTC';
    $not_after     = gmdate('Y-m-d H:i:s', $not_after_ts)  . ' UTC';

    // ── Version ───────────────────────────────────────────────────────────────
    $version = 'v' . (((int)($d['version'] ?? 2)) + 1);

    // ── Signature algorithm ───────────────────────────────────────────────────
    $sig_alg_oid  = $d['signatureTypeSN'] ?? $d['signatureTypeLN'] ?? '';
    $sig_alg_name = $d['signatureTypeLN'] ?? $sig_alg_oid;

    // ── Public key ────────────────────────────────────────────────────────────
    $key_html = '';
    if ($pub_details) {
        $key_type = match($pub_details['type'] ?? -1) {
            OPENSSL_KEYTYPE_RSA => 'RSA',
            OPENSSL_KEYTYPE_EC  => 'EC',
            OPENSSL_KEYTYPE_DSA => 'DSA',
            default             => 'Unknown',
        };
        $key_bits = $pub_details['bits'] ?? 0;
        $key_html .= xp_row('Algorithm', xp_badge($key_type, 'info'));
        $key_html .= xp_row('Key Size', xp_badge($key_bits . ' bits',
            $key_bits >= 3072 ? 'good' : ($key_bits >= 2048 ? 'warn' : 'danger')));

        if ($key_type === 'EC' && isset($pub_details['ec']['curve_name'])) {
            $curve = $pub_details['ec']['curve_name'];
            $key_html .= xp_row('Curve', '<code class="xp-code">' . xpe($curve) . '</code>');
        }
        if ($key_type === 'RSA' && isset($pub_details['rsa']['e'])) {
            // Public exponent
            $e_bin = $pub_details['rsa']['e'];
            $e_int = 0;
            for ($i = 0; $i < strlen($e_bin); $i++) {
                $e_int = ($e_int << 8) | ord($e_bin[$i]);
            }
            $key_html .= xp_row('Public Exponent', '<code class="xp-code">' . xpe((string)$e_int) . '</code>');
        }
    } else {
        $key_html = '<div class="xp-muted">Key details unavailable.</div>';
    }

    // ── Extensions ───────────────────────────────────────────────────────────
    $exts      = $d['extensions'] ?? [];
    $ext_html  = '';

    // Known extension handlers
    $ext_handlers = [

        'subjectKeyIdentifier' => function(string $v): string {
            return xp_row('Key ID', '<code class="xp-code xp-ski">' . xpe(strtoupper(str_replace(':', ':', $v))) . '</code>');
        },

        'authorityKeyIdentifier' => function(string $v): string {
            $out = '';
            foreach (explode("\n", $v) as $line) {
                $line = trim($line);
                if ($line === '') continue;
                if (str_starts_with($line, 'keyid:')) {
                    $out .= xp_row('Key ID', '<code class="xp-code xp-aki">' . xpe(strtoupper(trim(substr($line, 6)))) . '</code>');
                } elseif (str_starts_with($line, 'DirName:')) {
                    $out .= xp_row('Dir Name', '<code class="xp-code">' . xpe(trim(substr($line, 8))) . '</code>');
                } elseif (str_starts_with($line, 'serial:')) {
                    $out .= xp_row('Serial', '<code class="xp-code">' . xpe(strtoupper(trim(substr($line, 7)))) . '</code>');
                } else {
                    $out .= xp_row('', xpe($line));
                }
            }
            return $out;
        },

        'basicConstraints' => function(string $v): string {
            $is_ca     = str_contains(strtolower($v), 'ca:true');
            $path_match = [];
            preg_match('/pathlen:\s*(\d+)/i', $v, $path_match);
            $out  = xp_row('CA', xp_badge($is_ca ? 'TRUE' : 'FALSE', $is_ca ? 'warn' : 'neutral'));
            if (!empty($path_match[1])) {
                $out .= xp_row('Path Length', xp_badge($path_match[1], 'info'));
            }
            return $out;
        },

        'keyUsage' => function(string $v): string {
            $bits = array_filter(array_map('trim', explode(',', $v)));
            $out  = '';
            foreach ($bits as $b) {
                if ($b !== '') $out .= xp_tag($b) . ' ';
            }
            return xp_row('Usages', $out ?: '<span class="xp-muted">none</span>');
        },

        'extendedKeyUsage' => function(string $v): string {
            $oids = array_filter(array_map('trim', explode(',', $v)));
            $out  = '';
            foreach ($oids as $oid) {
                $name = x509_oid_name($oid);
                $out .= xp_tag($name) . ' ';
            }
            return xp_row('Purposes', $out ?: '<span class="xp-muted">none</span>');
        },

        'subjectAltName' => function(string $v): string {
            $entries = array_filter(array_map('trim', explode(',', $v)));
            $out = '';
            foreach ($entries as $entry) {
                if (str_starts_with($entry, 'DNS:')) {
                    $out .= '<div class="xp-san-entry"><span class="xp-san-type dns">DNS</span><span class="xp-san-val">' . xpe(substr($entry, 4)) . '</span></div>';
                } elseif (str_starts_with($entry, 'IP Address:') || str_starts_with($entry, 'IP:')) {
                    $ip = str_starts_with($entry, 'IP Address:') ? substr($entry, 11) : substr($entry, 3);
                    $out .= '<div class="xp-san-entry"><span class="xp-san-type ip">IP</span><span class="xp-san-val">' . xpe(trim($ip)) . '</span></div>';
                } elseif (str_starts_with($entry, 'email:') || str_starts_with($entry, 'RFC822:')) {
                    $email = str_starts_with($entry, 'email:') ? substr($entry, 6) : substr($entry, 7);
                    $out .= '<div class="xp-san-entry"><span class="xp-san-type email">EMAIL</span><span class="xp-san-val">' . xpe(trim($email)) . '</span></div>';
                } elseif (str_starts_with($entry, 'URI:')) {
                    $out .= '<div class="xp-san-entry"><span class="xp-san-type uri">URI</span><span class="xp-san-val">' . xpe(substr($entry, 4)) . '</span></div>';
                } elseif (str_starts_with($entry, 'DirName:')) {
                    $out .= '<div class="xp-san-entry"><span class="xp-san-type dir">DIR</span><span class="xp-san-val">' . xpe(substr($entry, 8)) . '</span></div>';
                } elseif (str_starts_with($entry, 'othername:') || str_starts_with($entry, 'otherName:')) {
                    $out .= '<div class="xp-san-entry"><span class="xp-san-type other">OTHER</span><span class="xp-san-val">' . xpe(substr($entry, 10)) . '</span></div>';
                } else {
                    $out .= '<div class="xp-san-entry"><span class="xp-san-type other">?</span><span class="xp-san-val">' . xpe($entry) . '</span></div>';
                }
            }
            return '<div class="xp-san-list">' . $out . '</div>';
        },

        'certificatePolicies' => function(string $v): string {
            $out   = '';
            $lines = array_filter(array_map('trim', explode("\n", $v)));
            $current_policy = null;
            foreach ($lines as $line) {
                if (str_starts_with($line, 'Policy:')) {
                    if ($current_policy !== null) {
                        $out .= '</div>';
                    }
                    $oid  = trim(substr($line, 7));
                    $name = x509_oid_name($oid);
                    $label = $name !== $oid ? "<span class='xp-oid-name'>" . xpe($name) . "</span> <code class='xp-code xp-oid'>" . xpe($oid) . "</code>"
                                            : "<code class='xp-code xp-oid'>" . xpe($oid) . "</code>";
                    $out .= '<div class="xp-policy-block"><div class="xp-policy-oid">' . $label . '</div>';
                    $current_policy = $oid;
                } elseif (str_starts_with($line, 'CPS:')) {
                    $url = trim(substr($line, 4));
                    $out .= '<div class="xp-policy-qual"><span class="xp-muted">CPS</span> <a class="xp-link" href="' . xpe($url) . '" target="_blank" rel="noopener">' . xpe($url) . '</a></div>';
                } elseif ($line !== '' && $current_policy !== null) {
                    $out .= '<div class="xp-policy-qual"><span class="xp-muted">' . xpe($line) . '</span></div>';
                }
            }
            if ($current_policy !== null) $out .= '</div>';
            return $out;
        },

        'crlDistributionPoints' => function(string $v): string {
            $out = '';
            foreach (array_filter(array_map('trim', explode("\n", $v))) as $line) {
                if (str_contains($line, 'URI:')) {
                    preg_match_all('/URI:(\S+)/', $line, $m);
                    foreach ($m[1] as $url) {
                        $out .= '<div class="xp-uri-entry"><span class="xp-muted">CDP</span> <a class="xp-link" href="' . xpe($url) . '" target="_blank" rel="noopener">' . xpe($url) . '</a></div>';
                    }
                } elseif (trim($line) !== '' && !str_starts_with($line, 'Full Name:') && !str_starts_with($line, 'CRL Distribution Points')) {
                    $out .= '<div class="xp-uri-entry xp-muted">' . xpe($line) . '</div>';
                }
            }
            return $out ?: xp_row('', xpe($v));
        },

        'authorityInfoAccess' => function(string $v): string {
            $out = '';
            foreach (array_filter(array_map('trim', explode("\n", $v))) as $line) {
                if (preg_match('/^(OCSP|CA Issuers)\s*-\s*URI:(.+)$/', $line, $m)) {
                    $type = trim($m[1]);
                    $url  = trim($m[2]);
                    $badge_type = $type === 'OCSP' ? 'info' : 'neutral';
                    $out .= '<div class="xp-uri-entry">'
                          . xp_badge($type, $badge_type)
                          . ' <a class="xp-link" href="' . xpe($url) . '" target="_blank" rel="noopener">' . xpe($url) . '</a>'
                          . '</div>';
                } elseif (trim($line) !== '') {
                    $out .= '<div class="xp-uri-entry xp-muted">' . xpe($line) . '</div>';
                }
            }
            return $out ?: xp_row('', xpe($v));
        },

        'ct_precert_scts' => function(string $v) use ($cert): string {
            // The extension value from openssl_x509_parse is a string — we need
            // to decode from the raw DER. Export to PEM, strip headers, base64-decode.
            openssl_x509_export($cert, $pem_out);
            $b64 = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $pem_out);
            $der = base64_decode($b64, true);
            if (!$der) return xp_row('SCTs', '<span class="xp-muted">Could not decode certificate DER.</span>');

            $known_logs = [
                '7d59a0a38f61ae0abf04440e5b5754ceae5f05c59d8f9d15e9aad8b72c2c4b4' => 'DigiCert Nessie2024',
                '8a328f1638be40c2c15a2c5f26e44a56e84e6f75e75f6ed8d64fede36484f7a' => 'DigiCert Nessie2025',
                '4e75a3275c9a10c3385b6cd4df3f52eb1df0e08e1b8d69c0b1fa64b1629a39e' => 'DigiCert Yeti2025',
                '6ff141b5647e4222f7ef052cefae7c21fd608e27d2af5a6e9f4b8a37d6633ee' => 'DigiCert Yeti2024',
                '7d3ef2f88fff88556824c2c0ca9e5289792bc50e78097f2e6a9768997e22f0d7' => 'Google Argon2025h1',
                'eec095ee8d72640f92e3c3b91bc712a3696a097b4b6a1a1438e647b2cbedc5f' => 'Google Argon2025h2',
                'd76d7d10d1a7f577c2c7e95fd700bff982c9335a65e1d0b30173170c8c56977'  => 'Google Argon2026h1',
                '76ff88ba577778238e6dfcc9c7000a82e04ab0b38ce9c02cadb93282eb90184' => 'Google Xenon2025h1',
                'cf16b53f2688f14cbc9b8ff4c66cfc0d76ffd6cfd1bd2fa2e9c5a30a27ab8a8' => 'Google Xenon2025h2',
                '5614069a2fd7c2ecd3f5e1bd44b23ec74676b9bc99115cc0ef949855d689d0dd' => 'Cloudflare Nimbus2025',
                'da2e930be39641f56718ef84c0e2d2f3a0cccd6ba19ceef52af4e54e9a0e880' => 'Sectigo Mammoth',
                'e866691d2b7a0f85c0f1afbde3fd6ef5a6f3e7b0fec02e37a6f43a3ba5f6e1f' => 'Sectigo Sabre',
                '3b5374bd9d61e2d0006a42d0a3ef7cbf7c939c33daa4a5b4c0baef55f834d1f' => "Let's Encrypt Oak2024H2",
                'a2e9978f98dab62a4c0e43a45c18e50bdb9cf0c0c38c0c14e4c51f90ab4e3f1' => "Let's Encrypt Oak2025H1",
                '6cfe501943a85ea916bc52d133e4dcc91ef1411c7d258420d173809e1818eb3a' => "Let's Encrypt Oak2025H2",
            ];

            $hash_names = [4 => 'sha256', 5 => 'sha384', 6 => 'sha512'];
            $sig_names  = [1 => 'rsa', 3 => 'ecdsa'];

            // Locate SCT list extension OID in DER.
            $sct_oid = "\x06\x0a\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02";
            $oid_pos = strpos($der, $sct_oid);
            if ($oid_pos === false) return xp_row('SCTs', '<span class="xp-muted">SCT extension not found in DER.</span>');

            $pos = $oid_pos + strlen($sct_oid);
            if (isset($der[$pos]) && ord($der[$pos]) === 0x01) $pos += 3;
            if (isset($der[$pos]) && ord($der[$pos]) === 0x04) {
                $pos++;
                $pos += (ord($der[$pos]) & 0x80) ? (ord($der[$pos]) & 0x7f) + 1 : 1;
            }
            if (isset($der[$pos]) && ord($der[$pos]) === 0x04) {
                $pos++;
                $pos += (ord($der[$pos]) & 0x80) ? (ord($der[$pos]) & 0x7f) + 1 : 1;
            }
            if ($pos + 2 > strlen($der)) return xp_row('SCTs', '<span class="xp-muted">Could not locate SCT list in DER.</span>');

            $list_len = unpack('n', substr($der, $pos, 2))[1];
            $pos += 2;
            $end  = $pos + $list_len;
            $scts = [];

            while ($pos + 2 <= $end) {
                $sct_len = unpack('n', substr($der, $pos, 2))[1];
                $pos    += 2;
                $sct_end = $pos + $sct_len;
                if ($pos + $sct_len > strlen($der)) break;

                $version   = ord($der[$pos]); $pos++;
                $log_id    = substr($der, $pos, 32); $pos += 32;
                $log_hex   = bin2hex($log_id);

                [$hi, $lo] = array_values(unpack('N2', substr($der, $pos, 8))); $pos += 8;
                $ts_ms  = ($hi * 4294967296.0) + ($lo < 0 ? $lo + 4294967296.0 : $lo);
                $ts_sec = (int)($ts_ms / 1000);
                $ts_fmt = gmdate('Y-m-d H:i:s', $ts_sec) . '.' . str_pad((int)($ts_ms % 1000), 3, '0', STR_PAD_LEFT) . ' UTC';

                $ext_len = unpack('n', substr($der, $pos, 2))[1]; $pos += 2;
                $pos    += $ext_len;

                $hash_alg = ord($der[$pos]); $pos++;
                $sig_alg  = ord($der[$pos]); $pos++;
                $sig_len  = unpack('n', substr($der, $pos, 2))[1]; $pos += 2;
                $pos     += $sig_len;

                $sig_str = ($sig_names[$sig_alg] ?? '?') . '-with-' . strtoupper($hash_names[$hash_alg] ?? '?');

                $scts[] = [
                    'log_hex'  => strtoupper($log_hex),
                    'log_name' => $known_logs[$log_hex] ?? null,
                    'ts_fmt'   => $ts_fmt,
                    'sig'      => $sig_str,
                    'version'  => 'v' . ($version + 1),
                ];
                $pos = $sct_end;
            }

            if (empty($scts)) return xp_row('SCTs', '<span class="xp-muted">No SCTs decoded.</span>');

            $out = '<div class="xp-sct-list">';
            foreach ($scts as $i => $sct) {
                $log_label = $sct['log_name']
                    ? '<span class="xp-sct-log-name">' . xpe($sct['log_name']) . '</span>'
                    : '<span class="xp-muted">Unknown log</span>';
                $out .= '<div class="xp-sct-block">'
                      . '<div class="xp-sct-num">SCT ' . ($i + 1) . ' ' . $log_label . '</div>'
                      . '<table class="xp-sct-table">'
                      . '<tr><td>Log ID</td><td><code class="xp-code xp-sct-logid">' . xpe($sct['log_hex']) . '</code></td></tr>'
                      . '<tr><td>Timestamp</td><td><code class="xp-code">' . xpe($sct['ts_fmt']) . '</code></td></tr>'
                      . '<tr><td>Signature</td><td><code class="xp-code">' . xpe($sct['sig']) . '</code></td></tr>'
                      . '<tr><td>Version</td><td><code class="xp-code">' . xpe($sct['version']) . '</code></td></tr>'
                      . '</table>'
                      . '</div>';
            }
            $out .= '</div>';
            return $out;
        },

        '1.3.6.1.5.5.7.1.24' => function(string $v): string {
            $has_must_staple = str_contains($v, '5') || str_contains(strtolower($v), 'status_request');
            return xp_row('Must-Staple', xp_badge($has_must_staple ? 'Present' : 'Not set', $has_must_staple ? 'warn' : 'neutral'));
        },

        'nameConstraints' => function(string $v): string {
            $out = '';
            foreach (array_filter(array_map('trim', explode("\n", $v))) as $line) {
                if (str_contains($line, 'Permitted')) {
                    $out .= '<div class="xp-nc-header xp-good">Permitted</div>';
                } elseif (str_contains($line, 'Excluded')) {
                    $out .= '<div class="xp-nc-header xp-danger">Excluded</div>';
                } elseif ($line !== '') {
                    $out .= '<div class="xp-nc-entry">' . xpe($line) . '</div>';
                }
            }
            return $out ?: xp_row('', xpe($v));
        },
    ];

    // Render each extension
    $known_ext_colours = [
        'subjectKeyIdentifier'    => '#5588aa',
        'authorityKeyIdentifier'  => '#5588aa',
        'basicConstraints'        => '#cc8844',
        'keyUsage'                => '#8866cc',
        'extendedKeyUsage'        => '#8866cc',
        'subjectAltName'          => '#44aa88',
        'certificatePolicies'     => '#aa6644',
        'crlDistributionPoints'   => '#887755',
        'authorityInfoAccess'     => '#557788',
        'ct_precert_scts'         => '#668844',
        'nameConstraints'         => '#cc4444',
        '1.3.6.1.5.5.7.1.24'     => '#dd9933',
    ];

    foreach ($exts as $name => $value) {
        $is_critical = str_ends_with($name, '_critical') || str_contains((string)$value, 'critical');
        $clean_name  = str_ends_with($name, '_critical') ? substr($name, 0, -9) : $name;
        $oid_label   = x509_oid_name($clean_name);
        $color       = $known_ext_colours[$clean_name] ?? '#4a5568';

        $inner = '';
        if (isset($ext_handlers[$clean_name])) {
            $inner = ($ext_handlers[$clean_name])((string)$value);
        } else {
            // Raw value — truncate very long hex blobs
            $raw = (string)$value;
            if (strlen($raw) > 800) {
                $raw = substr($raw, 0, 800) . '… (' . strlen($raw) . ' chars total)';
            }
            $inner = '<div class="xp-raw-value"><code class="xp-code">' . xpe($raw) . '</code></div>';
        }

        $crit_badge = $is_critical
            ? ' <span class="xp-badge xp-badge-danger xp-critical-badge">CRITICAL</span>'
            : ' <span class="xp-badge xp-badge-neutral">non-critical</span>';

        $ext_html .= '<div class="xp-ext-block" style="border-left-color:' . $color . '">'
                   . '<div class="xp-ext-header">'
                   . '<span class="xp-ext-name">' . xpe($oid_label) . '</span>'
                   . ($oid_label !== $clean_name ? ' <code class="xp-code xp-oid">' . xpe($clean_name) . '</code>' : '')
                   . $crit_badge
                   . '</div>'
                   . '<div class="xp-ext-body">' . $inner . '</div>'
                   . '</div>';
    }

    if ($ext_html === '') {
        $ext_html = '<div class="xp-muted">No extensions present.</div>';
    }

    // ── Assemble output ───────────────────────────────────────────────────────

    $styles = <<<CSS
<style>
.xp-wrap {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
    animation: fadein 0.35s ease;
}
.xp-section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
}
.xp-section-header {
    padding: 0.6rem 1rem;
    border-bottom: 1px solid var(--border);
    border-left: 3px solid;
    background: rgba(255,255,255,0.02);
    display: flex;
    align-items: center;
    gap: 0.75rem;
}
.xp-section-label {
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--muted);
}
.xp-section-body {
    padding: 0.75rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
}
.xp-code {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.68rem;
    color: #a8c0e8;
    word-break: break-all;
}
.xp-oid {
    color: var(--muted);
    font-size: 0.62rem;
}
.xp-oid-name { color: var(--text); }
.xp-muted { color: var(--muted); font-style: italic; }
.xp-small { font-size: 0.65rem; }
.xp-link {
    color: var(--accent2);
    text-decoration: none;
    word-break: break-all;
}
.xp-link:hover { text-decoration: underline; }
.xp-badge {
    display: inline-flex;
    align-items: center;
    font-size: 0.58rem;
    font-weight: 700;
    letter-spacing: 0.09em;
    padding: 0.12em 0.5em;
    border-radius: 2px;
    white-space: nowrap;
}
.xp-badge-neutral  { background: rgba(107,122,144,0.15); color: #8899aa; border: 1px solid rgba(107,122,144,0.25); }
.xp-badge-info     { background: rgba(0,153,255,0.12);   color: #4db8ff; border: 1px solid rgba(0,153,255,0.25); }
.xp-badge-good     { background: rgba(0,212,100,0.1);    color: #3ddc7a; border: 1px solid rgba(0,212,100,0.25); }
.xp-badge-warn     { background: rgba(245,166,35,0.1);   color: #f5a623; border: 1px solid rgba(245,166,35,0.25); }
.xp-badge-danger   { background: rgba(224,92,92,0.12);   color: #e05c5c; border: 1px solid rgba(224,92,92,0.25); }
.xp-critical-badge { font-size: 0.56rem; }
.xp-tag {
    display: inline-block;
    font-size: 0.62rem;
    padding: 0.1em 0.5em;
    border-radius: 3px;
    background: rgba(0,153,255,0.08);
    color: #88aacc;
    border: 1px solid rgba(0,153,255,0.15);
    margin: 0.1em 0.2em 0.1em 0;
    white-space: nowrap;
}
/* DN table */
.dn-table { border-collapse: collapse; width: 100%; }
.dn-table tr { border-bottom: 1px solid rgba(42,48,64,0.5); }
.dn-table tr:last-child { border-bottom: none; }
.dn-table td { padding: 0.2rem 0; vertical-align: top; }
.dn-key { color: var(--muted); width: 6rem; font-size: 0.68rem; padding-right: 0.75rem; white-space: nowrap; }
.dn-val { color: var(--text); word-break: break-word; overflow-wrap: anywhere; }
/* xp-row — stack on narrow screens */
.xp-row { display: flex; align-items: baseline; gap: 0.75rem; padding: 0.2rem 0; border-bottom: 1px solid rgba(42,48,64,0.5); flex-wrap: wrap; }
.xp-row:last-child { border-bottom: none; }
.xp-label { flex-shrink: 0; width: 8rem; color: var(--muted); font-size: 0.68rem; }
.xp-value { color: var(--text); flex: 1; min-width: 0; word-break: break-word; overflow-wrap: anywhere; line-height: 1.6; }
@media (max-width: 480px) {
  .xp-label { width: 100%; }
  .xp-value { width: 100%; flex: none; }
  .xp-row   { flex-direction: column; gap: 0.15rem; }
  .dn-key   { width: 100%; display: block; }
  .dn-table, .dn-table tbody, .dn-table tr, .dn-table td { display: block; width: 100%; }
  .dn-table tr { padding: 0.25rem 0; }
}
/* SAN */
.xp-san-list { display: flex; flex-direction: column; gap: 0.2rem; }
.xp-san-entry { display: flex; align-items: baseline; gap: 0.5rem; }
.xp-san-type {
    flex-shrink: 0; width: 3.5rem; text-align: center;
    font-size: 0.58rem; font-weight: 700; letter-spacing: 0.1em;
    padding: 0.1em 0.4em; border-radius: 2px;
}
.xp-san-type.dns   { background: rgba(0,212,170,0.1);  color: #00d4aa; border: 1px solid rgba(0,212,170,0.2); }
.xp-san-type.ip    { background: rgba(0,153,255,0.1);  color: #4db8ff; border: 1px solid rgba(0,153,255,0.2); }
.xp-san-type.email { background: rgba(245,166,35,0.1); color: #f5a623; border: 1px solid rgba(245,166,35,0.2); }
.xp-san-type.uri   { background: rgba(136,102,204,0.1);color: #aa88dd; border: 1px solid rgba(136,102,204,0.2); }
.xp-san-type.dir   { background: rgba(107,122,144,0.1);color: #8899aa; border: 1px solid rgba(107,122,144,0.2); }
.xp-san-type.other { background: rgba(107,122,144,0.1);color: #8899aa; border: 1px solid rgba(107,122,144,0.2); }
.xp-san-val { color: var(--text); word-break: break-all; }
/* Policies */
.xp-policy-block { margin-bottom: 0.5rem; padding-left: 0.5rem; border-left: 2px solid rgba(170,100,68,0.3); }
.xp-policy-oid   { margin-bottom: 0.2rem; }
.xp-policy-qual  { font-size: 0.68rem; color: var(--muted); padding-left: 0.5rem; margin-top: 0.1rem; }
/* URIs */
.xp-uri-entry { padding: 0.15rem 0; display: flex; align-items: baseline; gap: 0.5rem; flex-wrap: wrap; }
/* Name constraints */
.xp-nc-header { font-size: 0.62rem; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; padding: 0.2rem 0; }
.xp-nc-header.xp-good   { color: #3ddc7a; }
.xp-nc-header.xp-danger { color: #e05c5c; }
.xp-nc-entry { padding: 0.1rem 0.5rem; color: var(--text); }
/* Extensions */
.xp-ext-block {
    border: 1px solid var(--border);
    border-left: 3px solid;
    border-radius: var(--radius);
    margin-bottom: 0.5rem;
    overflow: hidden;
}
.xp-ext-block:last-child { margin-bottom: 0; }
.xp-ext-header {
    padding: 0.4rem 0.75rem;
    background: rgba(255,255,255,0.02);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
}
.xp-ext-name { font-weight: 600; color: var(--text); font-size: 0.7rem; }
.xp-ext-body { padding: 0.5rem 0.75rem; display: flex; flex-direction: column; gap: 0.25rem; }
.xp-raw-value { padding: 0.25rem 0; }
.xp-fp { font-family: 'IBM Plex Mono', monospace; font-size: 0.65rem; color: #8899aa; word-break: break-all; letter-spacing: 0.03em; }
.xp-serial { font-family: 'IBM Plex Mono', monospace; color: #a8c0e8; word-break: break-all; letter-spacing: 0.03em; }
.xp-ski { color: #55aacc; }
.xp-aki { color: #8899bb; }
.xp-error { color: var(--danger); padding: 1rem; }
/* SCTs */
.xp-sct-list { display: flex; flex-direction: column; gap: 0.6rem; width: 100%; }
.xp-sct-block { border: 1px solid var(--border); border-left: 3px solid #44aa88; border-radius: var(--radius); overflow: hidden; }
.xp-sct-num { font-size: 0.65rem; font-weight: 600; letter-spacing: 0.08em; padding: 0.35rem 0.75rem; background: rgba(68,170,136,0.06); border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.xp-sct-log-name { color: #00d4aa; font-weight: 600; }
.xp-sct-table { border-collapse: collapse; width: 100%; font-size: 0.68rem; }
.xp-sct-table tr { border-bottom: 1px solid rgba(42,48,64,0.4); }
.xp-sct-table tr:last-child { border-bottom: none; }
.xp-sct-table td { padding: 0.2rem 0.75rem; vertical-align: top; }
.xp-sct-table td:first-child { color: var(--muted); white-space: nowrap; width: 6rem; }
.xp-sct-logid { font-size: 0.6rem; color: #6699bb; word-break: break-all; }
@media (max-width: 480px) {
  .xp-sct-table td:first-child { width: auto; display: block; padding-bottom: 0; }
  .xp-sct-table td:last-child  { display: block; padding-top: 0.1rem; }
  .xp-sct-table tr { display: block; padding: 0.3rem 0; }
}
</style>
CSS;

    // ── 1. Identity ────────────────────────────────────────────────────────────
    $subject_html = x509_format_dn($d['subject'] ?? []);
    $issuer_html  = x509_format_dn($d['issuer']  ?? []);
    $self_signed  = ($d['subject'] == $d['issuer']);

    $identity_html  = '<div class="xp-row"><span class="xp-label">Subject</span><span class="xp-value">' . $subject_html . '</span></div>';
    $identity_html .= '<div class="xp-row"><span class="xp-label">Issuer</span><span class="xp-value">' . $issuer_html . '</span></div>';
    if ($self_signed) {
        $identity_html .= xp_row('Self-Signed', xp_badge('YES — Root CA or self-signed', 'warn'));
    }

    // ── 2. Validity ────────────────────────────────────────────────────────────
    $validity_html  = xp_row('Not Before', '<span class="xp-code">' . xpe($not_before) . '</span>');
    $validity_html .= xp_row('Not After',  '<span class="xp-code ' . ($is_expired ? 'xp-badge-danger' : '') . '">' . xpe($not_after) . '</span>');
    $validity_html .= xp_row('Validity Period', xp_badge($validity_days . ' days', 'neutral'));
    if ($is_expired) {
        $validity_html .= xp_row('Status', xp_badge('EXPIRED ' . abs($days_left) . ' days ago', 'danger'));
    } else {
        $validity_html .= xp_row('Remaining', xp_badge($days_left . ' days',
            $days_left <= 7 ? 'danger' : ($days_left <= 30 ? 'warn' : 'good')));
    }

    // ── 3. Certificate info ────────────────────────────────────────────────────
    $cert_html  = xp_row('Version',    xp_badge($version, 'neutral'));
    $cert_html .= xp_row('Serial',     '<span class="xp-serial">' . xpe($serial_fmt) . '</span>');
    $cert_html .= xp_row('Sig. Algorithm', '<span class="xp-code">' . xpe($sig_alg_name) . '</span>');
    $cert_html .= xp_row('SHA-256 Fingerprint', '<span class="xp-fp">' . xpe($fmt_fp($fp_sha256)) . '</span>');
    $cert_html .= xp_row('SHA-1 Fingerprint',   '<span class="xp-fp">' . xpe($fmt_fp($fp_sha1))   . '</span>');

    // ── Assemble sections ──────────────────────────────────────────────────────
    $html  = $styles;
    $html .= '<div class="xp-wrap">';
    $html .= xp_section('identity',  'Identity',         '#00d4aa', $identity_html);
    $html .= xp_section('validity',  'Validity',         '#f5a623', $validity_html);
    $html .= xp_section('cert',      'Certificate',      '#0099ff', $cert_html);
    $html .= xp_section('pubkey',    'Public Key',       '#8866cc', $key_html);
    $html .= xp_section('exts',      'Extensions (' . count($exts) . ')', '#44aa88', $ext_html);
    $html .= '</div>';

    return $html;
}

