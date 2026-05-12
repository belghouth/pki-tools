<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class CertificateModule extends ArtifactModule {

    // RFC 6962 §3.1 — CT Precertificate Poison OID
    private const POISON_OID = '1.3.6.1.4.1.11129.2.4.3';

    public function label(): string { return 'X.509 Certificate'; }

    public function recognize(string $bytes, string $ext): bool {
        if (artifact_has_pem_header($bytes, 'CERTIFICATE')) return true;
        if (artifact_is_der($bytes) && in_array($ext, ['crt', 'cer', 'der', 'pem'], true)) {
            $pem = artifact_to_pem($bytes, 'CERTIFICATE');
            return $pem !== null && (@openssl_x509_read($pem) !== false);
        }
        return false;
    }

    public function parse(string $bytes): array {
        $pem  = artifact_to_pem($bytes, 'CERTIFICATE');
        if ($pem === null) throw new \RuntimeException('Cannot normalise bytes to PEM.');
        $cert = @openssl_x509_read($pem);
        if ($cert === false) throw new \RuntimeException('openssl_x509_read failed — not a valid certificate.');
        openssl_x509_export($cert, $clean_pem);

        $d    = openssl_x509_parse($cert, false);
        $exts = $d['extensions'] ?? [];

        // Precertificate detection: RFC 6962 §3.1 poison OID or its OpenSSL short name.
        // Do NOT match 'precert' as a substring — ct_precert_scts (OID .2.4.2) is the
        // embedded SCT list present in every CT-compliant leaf cert, not the poison.
        $is_precert = isset($exts[self::POISON_OID])
            || (bool) preg_grep('/\bpoison\b/i', array_keys($exts));

        $bc  = strtolower($exts['basicConstraints'] ?? '');
        $sub = $d['subject'] ?? [];
        $iss = $d['issuer']  ?? [];
        ksort($sub); ksort($iss);

        return [
            'pem'         => $clean_pem,
            'is_precert'  => $is_precert,
            'is_ca'       => str_contains($bc, 'ca:true'),
            'self_signed' => ($sub === $iss),
            'eku'         => $exts['extendedKeyUsage'] ?? '',
        ];
    }

    public function render(array $parsed): string {
        $out = '';

        if ($parsed['is_precert']) {
            $out .= '<div class="xp-wrap" style="margin-bottom:.5rem">'
                  . '<div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.4);'
                  .      'border-radius:5px;padding:.65rem 1rem;font-size:.8rem;color:#f59e0b;'
                  .      'display:flex;align-items:center;gap:.6rem">'
                  . '<span style="font-size:1.1rem;flex-shrink:0">⚠</span>'
                  . '<span><strong>Precertificate</strong> — CT poison extension detected '
                  .       '(OID&nbsp;' . self::POISON_OID . ', RFC&nbsp;6962&nbsp;§3.1). '
                  .       'This artefact was submitted to Certificate Transparency logs and is '
                  .       '<em>not</em> a valid end-entity certificate.</span>'
                  . '</div></div>';
        }

        $out .= x509parse_render($parsed['pem']);
        return $out;
    }

    public function subtype(array $parsed): ?string {
        // CA certificates keep their own labels (precert CA is theoretically possible)
        if ($parsed['is_ca'] && $parsed['self_signed']) {
            return $parsed['is_precert'] ? 'Precertificate — Root CA'    : 'Root CA';
        }
        if ($parsed['is_ca']) {
            return $parsed['is_precert'] ? 'Precertificate — Issuing CA' : 'Issuing CA';
        }

        $eku  = $parsed['eku'];
        $type = match(true) {
            str_contains($eku, 'serverAuth')      => 'TLS Server',
            str_contains($eku, 'emailProtection') => 'S/MIME',
            str_contains($eku, 'codeSigning')     => 'Code Signing',
            str_contains($eku, 'OCSPSigning')     => 'OCSP Signer',
            str_contains($eku, 'timeStamping')    => 'Timestamping',
            default                               => '',
        };

        $label = $parsed['is_precert'] ? 'Precertificate' : 'Leaf';
        return $type ? "$label — $type" : $label;
    }
}

ArtifactRegistry::register(new CertificateModule());
