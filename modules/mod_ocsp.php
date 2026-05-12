<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class OcspModule extends ArtifactModule {

    public function label(): string { return 'OCSP Response'; }

    public function recognize(string $bytes, string $ext): bool {
        return artifact_has_pem_header($bytes, 'OCSP RESPONSE')
            || $ext === 'ocsp';
    }

    public function parse(string $bytes): array {
        $pem = artifact_has_pem_header($bytes, 'OCSP RESPONSE')
            ? $bytes
            : artifact_to_pem($bytes, 'OCSP RESPONSE');

        // Use asn1parse — openssl has no dedicated ocsp-response display command
        $shell = artifact_openssl('asn1parse -inform PEM', $pem ?? $bytes);

        $data = ['shell_text' => $shell ?? ''];

        // OCSPResponseStatus ENUMERATED value
        $status_map = [
            '00' => 'successful',
            '01' => 'malformedRequest',
            '02' => 'internalError',
            '03' => 'tryLater',
            '05' => 'sigRequired',
            '06' => 'unauthorized',
        ];
        if ($shell && preg_match('/ENUMERATED\s*:([0-9A-Fa-f]+)/i', $shell, $m)) {
            $hex = strtolower(str_pad($m[1], 2, '0', STR_PAD_LEFT));
            $data['response_status'] = $status_map[$hex] ?? 'unknown';
        }

        // Cert status inside BasicOCSPResponse (good=NULL, revoked=ENUMERATED after certStatus)
        if ($shell) {
            // "good" is encoded as [0] IMPLICIT NULL
            if (preg_match('/cont \[ 0 \]/', $shell)) $data['cert_status'] = 'good';
            // "revoked" is [1], "unknown" is [2]
            elseif (preg_match('/cont \[ 1 \]/', $shell)) $data['cert_status'] = 'revoked';
            elseif (preg_match('/cont \[ 2 \]/', $shell)) $data['cert_status'] = 'unknown';
        }

        return $data;
    }

    public function render(array $parsed): string {
        $html = '';

        if (!empty($parsed['response_status'])) {
            $s     = $parsed['response_status'];
            $badge = $s === 'successful' ? 'good' : 'danger';
            $html .= xp_row('Response Status', xp_badge($s, $badge));
        }
        if (!empty($parsed['cert_status'])) {
            $cs    = $parsed['cert_status'];
            $badge = match($cs) { 'good' => 'good', 'revoked' => 'danger', default => 'warn' };
            $html .= xp_row('Certificate Status', xp_badge($cs, $badge));
        }

        if (!$html) {
            $html = '<div class="xp-muted">'
                  . (function_exists('shell_exec')
                      ? 'Could not extract status fields from OCSP response.'
                      : 'OCSP response identified. Full parsing requires openssl CLI.')
                  . '</div>';
        }

        // Show truncated ASN.1 dump
        if (!empty($parsed['shell_text'])) {
            $truncated = substr($parsed['shell_text'], 0, 1400);
            $html .= '<details style="margin-top:.6rem"><summary style="font-size:.68rem;color:var(--muted);cursor:pointer">ASN.1 structure</summary>'
                   . '<pre style="font-size:.62rem;color:#8899aa;overflow-x:auto;margin-top:.4rem">'
                   . xpe($truncated)
                   . (strlen($parsed['shell_text']) > 1400 ? "\n… truncated" : '')
                   . '</pre></details>';
        }

        return '<div class="xp-wrap">'
             . xp_section('ocsp', 'OCSP Response', '#3b82f6', $html)
             . '</div>';
    }

    public function subtype(array $parsed): ?string {
        return isset($parsed['cert_status'])
            ? 'cert status: ' . $parsed['cert_status']
            : null;
    }
}

ArtifactRegistry::register(new OcspModule());
