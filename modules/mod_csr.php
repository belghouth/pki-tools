<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class CsrModule extends ArtifactModule {

    public function label(): string { return 'Certificate Signing Request (CSR / PKCS#10)'; }

    public function recognize(string $bytes, string $ext): bool {
        if (artifact_has_pem_header($bytes, 'CERTIFICATE REQUEST'))     return true;
        if (artifact_has_pem_header($bytes, 'NEW CERTIFICATE REQUEST')) return true;
        if (in_array($ext, ['csr', 'p10', 'req'], true))                return true;
        return false;
    }

    public function parse(string $bytes): array {
        // Normalise: some tools emit "NEW CERTIFICATE REQUEST"
        $pem = str_replace(
            ['NEW CERTIFICATE REQUEST'],
            ['CERTIFICATE REQUEST'],
            $bytes
        );
        if (!str_contains($pem, '-----BEGIN CERTIFICATE REQUEST-----')) {
            $pem = artifact_to_pem($bytes, 'CERTIFICATE REQUEST');
        }
        if ($pem === null) throw new \RuntimeException('Cannot normalise CSR bytes.');

        $subject  = @openssl_csr_get_subject($pem, false) ?: [];
        $pubkey   = @openssl_csr_get_public_key($pem);

        $key_info = [];
        if ($pubkey) {
            $det = openssl_pkey_get_details($pubkey);
            $key_info = [
                'type'  => match($det['type'] ?? -1) {
                    OPENSSL_KEYTYPE_RSA => 'RSA',
                    OPENSSL_KEYTYPE_EC  => 'EC',
                    OPENSSL_KEYTYPE_DSA => 'DSA',
                    default             => 'Unknown',
                },
                'bits'  => $det['bits']  ?? 0,
                'curve' => $det['ec']['curve_name'] ?? null,
            ];
        }

        // Full text via openssl CLI for requested extensions
        $shell_text = artifact_openssl('req -text -noout -nameopt RFC2253', $pem);
        $extensions = self::parse_requested_extensions($shell_text ?? '');

        return [
            'pem'        => $pem,
            'subject'    => $subject,
            'key_info'   => $key_info,
            'extensions' => $extensions,
        ];
    }

    private static function parse_requested_extensions(string $text): array {
        $exts = [];
        // Block between "Requested Extensions:" and next blank line / "Signature Algorithm"
        if (!preg_match('/Requested Extensions:(.*?)(?=Signature Algorithm:|^\s*$|\Z)/sm', $text, $m)) {
            return $exts;
        }
        preg_match_all(
            '/X509v3\s+(.+?)(?:\s*critical)?\s*:\s*\n((?:\s+.+\n?)*)/m',
            $m[1],
            $matches,
            PREG_SET_ORDER
        );
        foreach ($matches as $match) {
            $exts[trim($match[1])] = trim($match[2]);
        }
        return $exts;
    }

    public function render(array $parsed): string {
        // Subject section
        $sub_html = '<div class="xp-row"><span class="xp-label">Subject DN</span>'
                  . '<span class="xp-value">' . x509_format_dn($parsed['subject']) . '</span></div>';

        // Public key section
        $ki = $parsed['key_info'];
        $key_html = '';
        if ($ki) {
            $key_html .= xp_row('Algorithm', xp_badge($ki['type'], 'info'));
            $key_html .= xp_row('Key Size',  xp_badge($ki['bits'] . ' bits',
                $ki['bits'] >= 3072 ? 'good' : ($ki['bits'] >= 2048 ? 'warn' : 'danger')));
            if ($ki['curve']) {
                $key_html .= xp_row('Curve', '<code class="xp-code">' . xpe($ki['curve']) . '</code>');
            }
        } else {
            $key_html = '<div class="xp-muted">Key details unavailable.</div>';
        }

        // Requested extensions
        $ext_html = '';
        foreach ($parsed['extensions'] as $name => $val) {
            $ext_html .= '<div class="xp-ext-block" style="border-left-color:#4a5568">'
                       . '<div class="xp-ext-header"><span class="xp-ext-name">' . xpe($name) . '</span></div>'
                       . '<div class="xp-ext-body"><div class="xp-raw-value">'
                       . '<code class="xp-code">' . xpe($val) . '</code>'
                       . '</div></div></div>';
        }
        if (!$ext_html) {
            $ext_html = '<div class="xp-muted">'
                      . (function_exists('shell_exec') ? 'No extensions requested.' : 'Shell unavailable — extensions require openssl CLI.')
                      . '</div>';
        }

        $html  = '<div class="xp-wrap">';
        $html .= xp_section('csr-subject', 'Subject', '#00d4aa', $sub_html);
        $html .= xp_section('csr-key',     'Public Key', '#8866cc', $key_html);
        $html .= xp_section('csr-exts',    'Requested Extensions', '#44aa88', $ext_html);
        $html .= '</div>';
        return $html;
    }

    public function subtype(array $parsed): ?string { return null; }
}

ArtifactRegistry::register(new CsrModule());
