<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class PublicKeyModule extends ArtifactModule {

    public function label(): string { return 'Public Key (SubjectPublicKeyInfo)'; }

    public function recognize(string $bytes, string $ext): bool {
        return artifact_has_pem_header($bytes, 'PUBLIC KEY')
            || artifact_has_pem_header($bytes, 'RSA PUBLIC KEY');
    }

    public function parse(string $bytes): array {
        $pem = $bytes;

        // PKCS#1 RSA public key → try to convert to SPKI via shell
        if (str_contains($bytes, '-----BEGIN RSA PUBLIC KEY-----')) {
            $spki = artifact_openssl('rsa -RSAPublicKey_in -pubout', $bytes);
            if ($spki && str_contains($spki, '-----BEGIN PUBLIC KEY-----')) {
                $pem = $spki;
            }
        }

        $key = @openssl_pkey_get_public($pem);
        if (!$key) throw new \RuntimeException('Cannot parse public key.');

        $det  = openssl_pkey_get_details($key);
        $type = match($det['type'] ?? -1) {
            OPENSSL_KEYTYPE_RSA => 'RSA',
            OPENSSL_KEYTYPE_EC  => 'EC',
            OPENSSL_KEYTYPE_DSA => 'DSA',
            default             => 'Unknown',
        };

        $result = [
            'type'  => $type,
            'bits'  => $det['bits'] ?? 0,
            'curve' => $det['ec']['curve_name'] ?? null,
        ];

        if ($type === 'RSA' && isset($det['rsa']['e'])) {
            $e = 0;
            for ($i = 0, $l = strlen($det['rsa']['e']); $i < $l; $i++) {
                $e = ($e << 8) | ord($det['rsa']['e'][$i]);
            }
            $result['exponent'] = $e;
        }

        // SPKI SHA-256 fingerprint
        openssl_pkey_export_public($key, $pub_pem);
        $b64 = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/', '', $pub_pem);
        $der = base64_decode($b64, true);
        if ($der) {
            $result['spki_sha256'] = strtoupper(hash('sha256', $der));
        }

        return $result;
    }

    public function render(array $parsed): string {
        $html  = xp_row('Algorithm', xp_badge($parsed['type'], 'info'));
        $html .= xp_row('Key Size',  xp_badge($parsed['bits'] . ' bits',
            $parsed['bits'] >= 3072 ? 'good' : ($parsed['bits'] >= 2048 ? 'warn' : 'danger')));

        if (!empty($parsed['curve'])) {
            $html .= xp_row('Curve', '<code class="xp-code">' . xpe($parsed['curve']) . '</code>');
        }
        if (isset($parsed['exponent'])) {
            $html .= xp_row('Public Exponent',
                xp_badge((string) $parsed['exponent'], $parsed['exponent'] === 65537 ? 'good' : 'warn'));
        }
        if (!empty($parsed['spki_sha256'])) {
            $fp = implode(':', str_split($parsed['spki_sha256'], 2));
            $html .= xp_row('SPKI SHA-256', '<span class="xp-fp">' . xpe($fp) . '</span>');
        }

        return '<div class="xp-wrap">'
             . xp_section('pubkey', 'Public Key', '#8866cc', $html)
             . '</div>';
    }

    public function subtype(array $parsed): ?string {
        return $parsed['type'] . ($parsed['bits'] > 0 ? ' ' . $parsed['bits'] . '-bit' : '');
    }
}

ArtifactRegistry::register(new PublicKeyModule());
