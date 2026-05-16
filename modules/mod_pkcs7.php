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
        // Normalise to PKCS7 PEM for openssl input
        $pem = str_replace(
            ['-----BEGIN CMS-----',  '-----END CMS-----'],
            ['-----BEGIN PKCS7-----', '-----END PKCS7-----'],
            $bytes
        );
        if (!str_contains($pem, '-----BEGIN PKCS7-----')) {
            $pem = artifact_to_pem($bytes, 'PKCS7') ?? $bytes;
        }

        // openssl pkcs7 -print_certs -text -noout suppresses PEM output (only text), so the
        // certificate regex never matches. Use openssl cms which handles CMS unsigned attributes
        // and outputs PEM blocks when -text is omitted.
        $shell_certs = artifact_openssl('cms -cmsout -print_certs -noout', $pem);
        $shell_info  = artifact_openssl('cms -cmsout -print -noout', $pem);

        // Derive DER bytes for binary OID detection
        $der = artifact_is_der($bytes) ? $bytes : (function () use ($pem): string {
            $b64 = preg_replace('/\s+/', '', str_replace(
                ['-----BEGIN PKCS7-----', '-----END PKCS7-----'], '', $pem
            ));
            return base64_decode($b64, true) ?: '';
        })();

        // id-aa-signatureTimeStampToken OID: 1.2.840.113549.1.9.16.2.14
        $tst_oid    = "\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0e";
        $is_cades_t = strlen($der) > 20 && str_contains($der, $tst_oid);

        $data = ['certs' => [], 'content_type' => null, 'is_cades_t' => $is_cades_t];

        // Content type from cms -cmsout -print output
        if ($shell_info && preg_match('/contentType:\s*(\S+)/i', $shell_info, $m)) {
            $data['content_type'] = trim($m[1]);
        } elseif ($shell_info !== null || $shell_certs !== null) {
            $data['content_type'] = 'pkcs7-signedData';
        }

        // Extract embedded certificates from PEM blocks in cms -print_certs output
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
                    'subject'   => $cd['name'] ?? '(unknown)',
                    'issuer'    => implode(', ', array_map(
                        fn($k, $v) => "$k=$v",
                        array_keys($cd['issuer']   ?? []),
                        array_values($cd['issuer'] ?? [])
                    )),
                    'not_after' => isset($cd['validTo_time_t'])
                        ? gmdate('Y-m-d', (int) $cd['validTo_time_t']) . ' UTC'
                        : null,
                    'is_signer' => false,
                ];
            }
            // First cert is conventionally the signer cert
            if (isset($data['certs'][0])) $data['certs'][0]['is_signer'] = true;
        }

        return $data;
    }

    public function render(array $parsed): string {
        $ct  = $parsed['content_type'] ?? 'pkcs7-signedData';
        $ts  = $parsed['is_cades_t'];

        $ct_val = '<code class="xp-code">' . xpe($ct) . '</code>';
        if ($ts) {
            $ct_val .= '&nbsp;&nbsp;<span style="font-size:.75em;font-family:var(--mono,monospace);'
                     . 'background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.3);'
                     . 'color:#4ade80;border-radius:3px;padding:.1em .5em">CAdES-T ✓</span>';
        }

        $info  = xp_row('Content Type', $ct_val);
        $info .= xp_row('Signature Timestamp', $ts
            ? '<span style="color:#4ade80">Embedded (RFC 3161 TST)</span>'
            : xp_badge('None', 'neutral'));
        $info .= xp_row('Embedded Certs', xp_badge((string) count($parsed['certs']), 'neutral'));

        $certs_html = '';
        foreach ($parsed['certs'] as $i => $c) {
            $role  = $c['is_signer'] ? ' &nbsp;<span style="font-size:.72em;color:#a78bfa">[signer]</span>' : '';
            $certs_html .= '<div class="xp-ext-block" style="border-left-color:#8866cc">'
                         . '<div class="xp-ext-header"><span class="xp-ext-name">Certificate ' . ($i + 1) . $role . '</span></div>'
                         . '<div class="xp-ext-body">'
                         . xp_row('Subject', '<code class="xp-code">' . xpe($c['subject']) . '</code>')
                         . xp_row('Issuer',  '<code class="xp-code">' . xpe($c['issuer'])  . '</code>')
                         . ($c['not_after'] ? xp_row('Expires', '<code class="xp-code">' . xpe($c['not_after']) . '</code>') : '')
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
             . xp_section('cms-info',  'CMS / PKCS#7 SignedData', '#8866cc', $info)
             . xp_section('cms-certs', 'Embedded Certificates',   '#8866cc', $certs_html)
             . '</div>';
    }

    public function subtype(array $parsed): ?string {
        $s = $parsed['content_type'] ?? null;
        if ($parsed['is_cades_t']) $s = ($s ? $s . ' · ' : '') . 'CAdES-T';
        return $s;
    }
}

ArtifactRegistry::register(new Pkcs7Module());
