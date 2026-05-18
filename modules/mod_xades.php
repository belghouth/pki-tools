<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class XadesModule extends ArtifactModule {

    public function label(): string { return 'XAdES Signature'; }

    public function recognize(string $bytes, string $ext): bool {
        if ($ext === 'xades') return true;
        return str_contains($bytes, 'http://uri.etsi.org/01903/v1.3.2#')
            && str_contains($bytes, '<');
    }

    public function subtype(array $parsed): ?string { return $parsed['level'] ?? null; }

    // ── Parse ─────────────────────────────────────────────────────────────────

    public function parse(string $bytes): array {
        $out = [
            'level'              => 'XAdES-B-B',
            'signing_time'       => null,
            'sig_alg'            => null,
            'content_digest_alg' => null,
            'content_digest'     => null,
            'cert_pem'           => null,
            'cert_subject'       => null,
            'cert_issuer'        => null,
            'cert_valid_from'    => null,
            'cert_valid_to'      => null,
            'cert_sha256'        => null,
            'cert_digest'        => null,
            'tst_text'           => null,
            'error'              => null,
        ];

        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        if (!$dom->loadXML($bytes)) {
            libxml_clear_errors();
            $out['error'] = 'Failed to parse XML.';
            return $out;
        }
        libxml_clear_errors();

        $xp = new DOMXPath($dom);
        $xp->registerNamespace('ds',    'http://www.w3.org/2000/09/xmldsig#');
        $xp->registerNamespace('xades', 'http://uri.etsi.org/01903/v1.3.2#');

        $out['signing_time'] = ($v = $xp->evaluate('string(//xades:SigningTime)')) ? $v : null;
        $out['sig_alg']      = ($v = $xp->evaluate('string(//ds:SignatureMethod/@Algorithm)')) ? $v : null;

        $r1 = $xp->query('//ds:Reference[@Id="Ref-Content"]');
        if ($r1 && $r1->length > 0) {
            $ref = $r1->item(0);
            $out['content_digest_alg'] = ($v = $xp->evaluate('string(ds:DigestMethod/@Algorithm)', $ref)) ? $v : null;
            $out['content_digest']     = ($v = $xp->evaluate('string(ds:DigestValue)',             $ref)) ? trim($v) : null;
        }

        $cert_b64 = preg_replace('/\s+/', '', $xp->evaluate('string(//ds:X509Certificate)'));
        if ($cert_b64 !== '') {
            $der = base64_decode($cert_b64, true);
            if ($der !== false) {
                $pem  = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
                $info = openssl_x509_parse($pem) ?: [];
                $out['cert_pem']        = $pem;
                $out['cert_subject']    = $info['subject']  ?? null;
                $out['cert_issuer']     = $info['issuer']   ?? null;
                $out['cert_valid_from'] = isset($info['validFrom_time_t'])  ? gmdate('Y-m-d H:i:s \U\T\C', $info['validFrom_time_t'])  : null;
                $out['cert_valid_to']   = isset($info['validTo_time_t'])    ? gmdate('Y-m-d H:i:s \U\T\C', $info['validTo_time_t'])    : null;
                $out['cert_sha256']     = bin2hex(hash('sha256', $der, true));
            }
        }

        $cd = preg_replace('/\s+/', '', $xp->evaluate('string(//xades:CertDigest/ds:DigestValue)'));
        $out['cert_digest'] = $cd !== '' ? $cd : null;

        $tst_enc = preg_replace('/\s+/', '', $xp->evaluate('string(//xades:EncapsulatedTimeStamp)'));
        if ($tst_enc !== '') {
            $tst_der = base64_decode($tst_enc, true);
            if ($tst_der !== false) {
                $out['level']    = 'XAdES-B-T';
                $out['tst_text'] = $this->parse_tst($tst_der);
            }
        }

        return $out;
    }

    // ── Wrap TST → fake TSR → openssl ts -reply -text ─────────────────────────

    private function parse_tst(string $tst_der): ?string {
        $status = "\x30\x03\x02\x01\x00"; // PKIStatusInfo { granted }
        $tsr    = "\x30" . $this->enc_len(strlen($status) + strlen($tst_der)) . $status . $tst_der;
        return artifact_openssl('ts -reply -text', $tsr, 'tsr');
    }

    private function enc_len(int $n): string {
        if ($n < 128) return chr($n);
        $b = '';
        while ($n > 0) { $b = chr($n & 0xFF) . $b; $n >>= 8; }
        return chr(0x80 | strlen($b)) . $b;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function alg_short(string $uri): string {
        return match (true) {
            str_contains($uri, 'ecdsa-sha512') => 'ECDSA-SHA512',
            str_contains($uri, 'ecdsa-sha384') => 'ECDSA-SHA384',
            str_contains($uri, 'ecdsa-sha256') => 'ECDSA-SHA256',
            str_contains($uri, 'rsa-sha512')   => 'RSA-SHA512',
            str_contains($uri, 'rsa-sha384')   => 'RSA-SHA384',
            str_contains($uri, 'rsa-sha256')   => 'RSA-SHA256',
            str_contains($uri, 'sha512')        => 'SHA-512',
            str_contains($uri, 'sha384')        => 'SHA-384',
            str_contains($uri, 'sha256')        => 'SHA-256',
            default                             => $uri,
        };
    }

    private function dn_line(array $dn): string {
        $parts = [];
        foreach (['CN', 'O', 'OU', 'C', 'ST', 'L'] as $k) {
            if (!empty($dn[$k])) $parts[] = $k . '=' . $dn[$k];
        }
        return $parts ? implode(', ', $parts) : implode(', ', array_map(
            fn($k, $v) => "$k=$v", array_keys($dn), array_values($dn)
        ));
    }

    // ── Render ────────────────────────────────────────────────────────────────

    public function render(array $parsed): string {
        $h     = fn(string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $level = $parsed['level'] ?? 'XAdES-B-B';
        $is_t  = $level === 'XAdES-B-T';

        $badge = $is_t
            ? '<span class="xp-badge xp-badge-good">' . $h($level) . ' ✓</span>'
            : '<span class="xp-badge xp-badge-neutral">' . $h($level) . '</span>';

        $o  = '<div class="xp-wrap">';

        // ── Overview ──────────────────────────────────────────────────────────
        $o .= '<div class="xp-section">';
        $o .= '<div class="xp-section-header" style="border-left-color:#a78bfa">';
        $o .= '<span class="xp-section-label">XAdES Signature</span>' . $badge;
        if ($parsed['error']) $o .= '<span class="xp-badge xp-badge-danger">Error</span>';
        $o .= '</div><div class="xp-section-body">';

        if ($parsed['signing_time']) {
            $o .= '<div class="xp-row"><span class="xp-label">Signing Time</span><span class="xp-value">' . $h($parsed['signing_time']) . '</span></div>';
        }
        if ($parsed['sig_alg']) {
            $short = $this->alg_short($parsed['sig_alg']);
            $o .= '<div class="xp-row"><span class="xp-label">Algorithm</span><span class="xp-value">'
                . '<span class="xp-code">' . $h($short) . '</span> '
                . '<span class="xp-oid">' . $h($parsed['sig_alg']) . '</span>'
                . '</span></div>';
        }
        if ($parsed['content_digest']) {
            $alg = $parsed['content_digest_alg'] ? ' <span class="xp-oid">' . $h($this->alg_short($parsed['content_digest_alg'])) . '</span>' : '';
            $o .= '<div class="xp-row"><span class="xp-label">Doc Digest</span><span class="xp-value">'
                . '<span class="xp-fp">' . $h($parsed['content_digest']) . '</span>' . $alg
                . '</span></div>';
        }
        $o .= '<div class="xp-row"><span class="xp-label">Timestamp</span><span class="xp-value">'
            . ($is_t
                ? '<span class="xp-badge xp-badge-good">✓ RFC 3161 SignatureTimeStamp</span>'
                : '<span class="xp-badge xp-badge-neutral">None (B-B level)</span>')
            . '</span></div>';

        if ($parsed['error']) {
            $o .= '<div class="xp-row"><span class="xp-label">Error</span><span class="xp-value xp-error">' . $h($parsed['error']) . '</span></div>';
        }

        $o .= '</div></div>';

        // ── Signer certificate ────────────────────────────────────────────────
        if ($parsed['cert_pem']) {
            $o .= '<div class="xp-section">';
            $o .= '<div class="xp-section-header" style="border-left-color:#4db8ff">';
            $o .= '<span class="xp-section-label">Signer Certificate</span>';
            $o .= '</div><div class="xp-section-body">';

            if ($parsed['cert_subject']) {
                $o .= '<div class="xp-row"><span class="xp-label">Subject</span><span class="xp-value">' . $h($this->dn_line($parsed['cert_subject'])) . '</span></div>';
            }
            if ($parsed['cert_issuer']) {
                $o .= '<div class="xp-row"><span class="xp-label">Issuer</span><span class="xp-value">' . $h($this->dn_line($parsed['cert_issuer'])) . '</span></div>';
            }
            if ($parsed['cert_valid_from']) {
                $o .= '<div class="xp-row"><span class="xp-label">Valid From</span><span class="xp-value">' . $h($parsed['cert_valid_from']) . '</span></div>';
            }
            if ($parsed['cert_valid_to']) {
                $o .= '<div class="xp-row"><span class="xp-label">Valid To</span><span class="xp-value">' . $h($parsed['cert_valid_to']) . '</span></div>';
            }
            if ($parsed['cert_sha256']) {
                $o .= '<div class="xp-row"><span class="xp-label">Cert SHA-256</span><span class="xp-value xp-fp">' . $h(implode(':', str_split($parsed['cert_sha256'], 2))) . '</span></div>';
            }
            if ($parsed['cert_digest']) {
                $hex = bin2hex((string) base64_decode($parsed['cert_digest'], true));
                $o .= '<div class="xp-row"><span class="xp-label">Signed Digest</span><span class="xp-value xp-fp">' . $h(implode(':', str_split($hex, 2))) . '</span></div>';
            }

            $o .= artifactCertActions($parsed['cert_pem']);

            $o .= '</div></div>';
        }

        // ── SignatureTimeStamp ────────────────────────────────────────────────
        if ($is_t && $parsed['tst_text']) {
            $o .= '<div class="xp-section">';
            $o .= '<div class="xp-section-header" style="border-left-color:#00d4aa">';
            $o .= '<span class="xp-section-label">SignatureTimeStamp (RFC 3161)</span>';
            $o .= '<span class="xp-badge xp-badge-info">xades:EncapsulatedTimeStamp</span>';
            $o .= '</div>';
            $o .= '<pre style="margin:0;padding:.75rem 1rem;font-family:var(--mono);font-size:.62rem;color:#8899aa;overflow-x:auto;white-space:pre;line-height:1.55;max-height:360px;overflow-y:auto">'
                . $h($parsed['tst_text'])
                . '</pre>';
            $o .= '</div>';
        }

        $o .= '</div>';
        return $o;
    }
}

ArtifactRegistry::register(new XadesModule());
