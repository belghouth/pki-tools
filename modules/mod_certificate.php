<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class CertificateModule extends ArtifactModule {

    public function label(): string { return 'X.509 Certificate'; }

    public function recognize(string $bytes, string $ext): bool {
        if (artifact_has_pem_header($bytes, 'CERTIFICATE')) return true;
        // DER with cert-friendly extension: try openssl_x509_read
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
        return ['pem' => $clean_pem];
    }

    public function render(array $parsed): string {
        return x509parse_render($parsed['pem']);
    }

    public function subtype(array $parsed): ?string {
        $cert = @openssl_x509_read($parsed['pem']);
        if (!$cert) return null;
        $d = openssl_x509_parse($cert, false);
        if (!$d) return null;

        $exts = $d['extensions'] ?? [];
        $bc   = strtolower($exts['basicConstraints'] ?? '');
        $isCA = str_contains($bc, 'ca:true');

        $sub = $d['subject'] ?? [];
        $iss = $d['issuer']  ?? [];
        ksort($sub); ksort($iss);
        $selfSigned = ($sub === $iss);

        if ($isCA && $selfSigned) return 'Root CA';
        if ($isCA)                return 'Issuing CA';

        $eku = $exts['extendedKeyUsage'] ?? '';
        if (str_contains($eku, 'serverAuth'))      return 'End-Entity — TLS Server';
        if (str_contains($eku, 'emailProtection')) return 'End-Entity — S/MIME';
        if (str_contains($eku, 'codeSigning'))     return 'End-Entity — Code Signing';
        if (str_contains($eku, 'OCSPSigning'))     return 'End-Entity — OCSP Signer';
        if (str_contains($eku, 'timeStamping'))    return 'End-Entity — Timestamping';
        return 'End-Entity (EE)';
    }
}

ArtifactRegistry::register(new CertificateModule());
