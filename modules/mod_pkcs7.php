<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class Pkcs7Module extends ArtifactModule {

    public function label(): string { return 'CMS / PKCS#7'; }

    public function recognize(string $bytes, string $ext): bool {
        if (artifact_has_pem_header($bytes, 'PKCS7')
            || artifact_has_pem_header($bytes, 'CMS')
            || in_array($ext, ['p7b', 'p7c', 'p7s', 'p7m', 'cms'], true)) {
            return true;
        }
        // DER ContentInfo whose first child OID is pkcs7-signedData (1.2.840.113549.1.7.2).
        // The OID appears within the first 16 bytes regardless of outer SEQUENCE length encoding.
        return artifact_is_der($bytes) && strlen($bytes) > 13
            && str_contains(substr($bytes, 0, 16), "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02");
    }

    public function parse(string $bytes): array {
        // Normalise CMS header → PKCS7 for openssl compat
        $pem = str_replace(
            ['-----BEGIN CMS-----',  '-----END CMS-----'],
            ['-----BEGIN PKCS7-----', '-----END PKCS7-----'],
            $bytes
        );
        if (!str_contains($pem, '-----BEGIN PKCS7-----')) {
            $pem = artifact_to_pem($bytes, 'PKCS7') ?? $bytes;
        }

        // Extract embedded certificates (works without shell for p7b)
        $shell_certs = artifact_openssl('pkcs7 -print_certs -text -noout', $pem);
        $shell_info  = artifact_openssl('pkcs7 -print -noout', $pem);

        $data = ['certs' => [], 'content_type' => null];

        if ($shell_info && preg_match('/contentType:\s*(.+)/i', $shell_info, $m)) {
            $data['content_type'] = trim($m[1]);
        } elseif ($shell_certs !== null) {
            $data['content_type'] = 'signed-data / certificates-only';
        }

        if ($shell_certs) {
            preg_match_all(
                '/(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/s',
                $shell_certs, $cm
            );
            foreach ($cm[1] as $cert_pem) {
                $cert = @openssl_x509_read($cert_pem);
                if (!$cert) continue;
                $cd = openssl_x509_parse($cert, false);
                $data['certs'][] = [
                    'subject' => $cd['name']   ?? '(unknown)',
                    'issuer'  => implode(', ', array_map(
                        fn($k, $v) => "$k=$v",
                        array_keys($cd['issuer']   ?? []),
                        array_values($cd['issuer'] ?? [])
                    )),
                    'not_after' => isset($cd['validTo_time_t'])
                        ? gmdate('Y-m-d', (int) $cd['validTo_time_t']) . ' UTC'
                        : null,
                ];
            }
        }

        return $data;
    }

    public function render(array $parsed): string {
        $info  = xp_row('Content Type', '<code class="xp-code">' . xpe($parsed['content_type'] ?? 'Unknown') . '</code>');
        $info .= xp_row('Embedded Certs', xp_badge((string) count($parsed['certs']), 'neutral'));

        $certs_html = '';
        foreach ($parsed['certs'] as $i => $c) {
            $certs_html .= '<div class="xp-ext-block" style="border-left-color:#44aa88">'
                         . '<div class="xp-ext-header"><span class="xp-ext-name">Certificate ' . ($i + 1) . '</span></div>'
                         . '<div class="xp-ext-body">'
                         . xp_row('Subject', '<code class="xp-code">' . xpe($c['subject']) . '</code>')
                         . xp_row('Issuer',  '<code class="xp-code">' . xpe($c['issuer'])  . '</code>')
                         . ($c['not_after'] ? xp_row('Expires', '<span class="xp-code">' . xpe($c['not_after']) . '</span>') : '')
                         . '</div></div>';
        }
        if (!$certs_html) {
            $certs_html = '<div class="xp-muted">'
                        . (function_exists('shell_exec')
                            ? 'No embedded certificates found.'
                            : 'Shell unavailable — certificate extraction requires openssl CLI.')
                        . '</div>';
        }

        return '<div class="xp-wrap">'
             . xp_section('cms-info',  'CMS / PKCS#7',          '#8866cc', $info)
             . xp_section('cms-certs', 'Embedded Certificates',  '#44aa88', $certs_html)
             . '</div>';
    }

    public function subtype(array $parsed): ?string {
        return $parsed['content_type'] ?? null;
    }
}

ArtifactRegistry::register(new Pkcs7Module());
