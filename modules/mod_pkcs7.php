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
        // Checked within first 16 bytes regardless of outer SEQUENCE length encoding.
        return artifact_is_der($bytes) && strlen($bytes) > 13
            && str_contains(substr($bytes, 0, 16), "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02");
    }

    // ── DER helpers ───────────────────────────────────────────────────────────────

    private static function tlv(string $d, int $off): array {
        $tag = ord($d[$off]);
        $i   = $off + 1;
        $lb  = ord($d[$i++]);
        if ($lb < 128) {
            $len = $lb;
        } else {
            $n = $lb & 0x7F; $len = 0;
            for ($j = 0; $j < $n; $j++) $len = ($len << 8) | ord($d[$i++]);
        }
        return ['tag' => $tag, 'val' => $i, 'len' => $len, 'end' => $i + $len];
    }

    private static function enc_len(int $n): string {
        if ($n < 128) return chr($n);
        $b = '';
        while ($n > 0) { $b = chr($n & 0xFF) . $b; $n >>= 8; }
        return chr(0x80 | strlen($b)) . $b;
    }

    // Find the id-aa-signatureTimeStampToken unsigned attribute and return the
    // raw DER of its ContentInfo value (the TimeStampToken = CMS SignedData).
    private function extract_tst(string $der): ?string {
        // OID 1.2.840.113549.1.9.16.2.14
        $tst_oid = "\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0e";
        $pos     = strpos($der, $tst_oid);
        if ($pos === false) return null;

        // After OID: SET { ContentInfo } (the attrValues SET)
        $set_off = $pos + strlen($tst_oid);
        if ($set_off >= strlen($der) || ord($der[$set_off]) !== 0x31) return null;
        $set = self::tlv($der, $set_off);

        // First element of SET is the ContentInfo SEQUENCE
        if ($set['val'] >= strlen($der) || ord($der[$set['val']]) !== 0x30) return null;
        $ci = self::tlv($der, $set['val']);
        return substr($der, $set['val'], $ci['end'] - $set['val']);
    }

    // Wrap a raw TimeStampToken (ContentInfo) in a minimal PKIStatusInfo
    // to produce a valid TimeStampResp parseable by `openssl ts -reply -text`.
    private function make_fake_tsr(string $tst_der): string {
        $pki_status = "\x30\x03\x02\x01\x00"; // SEQUENCE { INTEGER 0 (granted) }
        $inner      = $pki_status . $tst_der;
        return "\x30" . self::enc_len(strlen($inner)) . $inner;
    }

    // ── Main parse ────────────────────────────────────────────────────────────────

    public function parse(string $bytes): array {
        // Normalise to PKCS7 PEM (openssl pkcs7 accepts this for any CMS SignedData)
        $pem = str_replace(
            ['-----BEGIN CMS-----',  '-----END CMS-----'],
            ['-----BEGIN PKCS7-----', '-----END PKCS7-----'],
            $bytes
        );
        if (!str_contains($pem, '-----BEGIN PKCS7-----')) {
            $pem = artifact_to_pem($bytes, 'PKCS7') ?? $bytes;
        }

        // Resolve DER bytes (needed for binary OID searches)
        if (artifact_is_der($bytes)) {
            $der = $bytes;
        } else {
            $b64 = preg_replace('/\s+/', '', str_replace(
                ['-----BEGIN PKCS7-----', '-----END PKCS7-----'], '', $pem
            ));
            $der = (string) (base64_decode($b64, true) ?: '');
        }

        // ── Certificates ──────────────────────────────────────────────────────────
        // pkcs7 -print_certs (without -text -noout) outputs PEM blocks the regex can match.
        // The -text -noout combo that was here before suppressed all PEM output.
        $shell_certs = artifact_openssl('pkcs7 -print_certs', $pem);

        $data = ['certs' => [], 'content_type' => 'pkcs7-signedData', 'is_cades_t' => false];

        // Content type: try cms -cmsout -print; fall back to hardcoded since we know it
        // from recognize() — we only get here for pkcs7-signedData ContentInfo.
        $shell_info = artifact_openssl('cms -cmsout -print -noout', $pem);
        if ($shell_info && preg_match('/contentType:\s*(\S+)/i', $shell_info, $m)) {
            $data['content_type'] = trim($m[1]);
        }

        // Cert extraction: regex finds -----BEGIN CERTIFICATE----- blocks in print_certs output
        if ($shell_certs) {
            preg_match_all(
                '/(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/s',
                $shell_certs, $cm
            );
            foreach ($cm[1] as $i => $cert_pem) {
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
                    'is_signer' => $i === 0, // first cert is the signer by OpenSSL convention
                    'pem'       => $cert_pem,
                ];
            }
        }

        // ── Embedded signature timestamp (CAdES-T) ────────────────────────────────
        // id-aa-signatureTimeStampToken OID: 1.2.840.113549.1.9.16.2.14
        $tst_oid        = "\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0e";
        $data['is_cades_t'] = strlen($der) > 20 && str_contains($der, $tst_oid);

        if ($data['is_cades_t']) {
            $tst_der = $this->extract_tst($der);
            if ($tst_der !== null) {
                // Wrap in fake PKIStatusInfo so openssl ts -reply -text can parse it
                $fake_tsr   = $this->make_fake_tsr($tst_der);
                $tst_shell  = artifact_openssl('ts -reply -text', $fake_tsr, 'tsr');
                $data['tst_shell'] = $tst_shell;

                if ($tst_shell && !str_contains($tst_shell, 'wrong tag')) {
                    if (preg_match('/Policy OID:\s*(.+)/i',        $tst_shell, $m)) $data['tst_policy']  = trim($m[1]);
                    if (preg_match('/Hash Algorithm:\s*(.+)/i',    $tst_shell, $m)) $data['tst_hash_alg']= trim($m[1]);
                    if (preg_match('/Serial number:\s*(.+)/i',     $tst_shell, $m)) $data['tst_serial']  = trim($m[1]);
                    if (preg_match('/Time stamp:\s*(.+)/i',        $tst_shell, $m)) $data['tst_time']    = trim($m[1]);
                    if (preg_match('/Accuracy:\s*(.+)/i',          $tst_shell, $m)) $data['tst_accuracy']= trim($m[1]);
                    if (preg_match('/TSA:\s*DirName:\s*(.+)/i',    $tst_shell, $m)) $data['tst_tsa']     = trim($m[1]);
                    if (preg_match('/Signature Algorithm:\s*(.+)/i',$tst_shell,$m)) $data['tst_sig_alg'] = trim($m[1]);
                    $data['tst_imprint'] = self::extract_hex_dump($tst_shell, 'Message data');
                }
            }
        }

        return $data;
    }

    private static function extract_hex_dump(string $text, string $label): string {
        if (!preg_match('/' . preg_quote($label, '/') . ':?\s*\n((?:\s+[0-9a-f]+ - .+\n?)+)/i', $text, $m)) {
            return '';
        }
        $hex = '';
        foreach (explode("\n", $m[1]) as $line) {
            if (preg_match('/^\s+[0-9a-f]+\s*-\s*([0-9a-f -]+?)(?:\s{3,}|$)/i', $line, $lm)) {
                $hex .= preg_replace('/[^0-9a-f]/i', '', $lm[1]);
            }
        }
        return strtolower($hex);
    }

    // ── Render ────────────────────────────────────────────────────────────────────

    public function render(array $parsed): string {
        $ct = $parsed['content_type'] ?? 'pkcs7-signedData';
        $ts = $parsed['is_cades_t'];

        $ct_val = '<code class="xp-code">' . xpe($ct) . '</code>';
        if ($ts) {
            $ct_val .= '&nbsp;&nbsp;<span style="font-size:.75em;font-family:var(--mono,monospace);'
                     . 'background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.3);'
                     . 'color:#4ade80;border-radius:3px;padding:.1em .5em">CAdES-T ✓</span>';
        }

        $info  = xp_row('Content Type', $ct_val);
        $info .= xp_row('Embedded Certs', xp_badge((string) count($parsed['certs']), 'neutral'));

        // ── TST section ───────────────────────────────────────────────────────────
        $tst_section = '';
        if ($ts) {
            $tst_html = '';
            if (!empty($parsed['tst_time']))    $tst_html .= xp_row('Time Stamp',     '<span class="xp-code">'   . xpe($parsed['tst_time'])    . '</span>');
            if (!empty($parsed['tst_hash_alg']))$tst_html .= xp_row('Hash Algorithm', xp_badge($parsed['tst_hash_alg'], 'info'));
            if (!empty($parsed['tst_imprint'])) {
                $fmt = implode(' ', str_split($parsed['tst_imprint'], 2));
                $tst_html .= xp_row('Msg Imprint', '<span class="xp-fp">' . xpe($fmt) . '</span>');
            }
            if (!empty($parsed['tst_policy']))  $tst_html .= xp_row('Policy OID',    '<code class="xp-code">'   . xpe($parsed['tst_policy'])  . '</code>');
            if (!empty($parsed['tst_serial']))  $tst_html .= xp_row('Serial Number', '<code class="xp-code">'   . xpe($parsed['tst_serial'])  . '</code>');
            if (!empty($parsed['tst_accuracy']))$tst_html .= xp_row('Accuracy',      '<span class="xp-code">'   . xpe($parsed['tst_accuracy']). '</span>');
            if (!empty($parsed['tst_tsa']))     $tst_html .= xp_row('TSA',           '<code class="xp-code">'   . xpe($parsed['tst_tsa'])     . '</code>');
            if (!empty($parsed['tst_sig_alg'])) $tst_html .= xp_row('Sig. Algorithm',xp_badge($parsed['tst_sig_alg'], 'info'));

            $fallback = empty($tst_html) ? '<div class="xp-muted">TST extraction failed — ASN.1 structure may be non-standard.</div>' : $tst_html;
            $tst_section = xp_section('cms-tst', 'Embedded Signature Timestamp (RFC 3161 TST)', '#3b82f6', $fallback);
        }

        // ── Certificates section ──────────────────────────────────────────────────
        $certs_html = '';
        foreach ($parsed['certs'] as $i => $c) {
            $role = $c['is_signer']
                ? '&nbsp;<span style="font-size:.72em;color:#a78bfa;font-family:var(--mono,monospace)">[signer]</span>'
                : '';
            $certs_html .= '<div class="xp-ext-block" style="border-left-color:#8866cc">'
                         . '<div class="xp-ext-header"><span class="xp-ext-name">Certificate ' . ($i + 1) . $role . '</span></div>'
                         . '<div class="xp-ext-body">'
                         . xp_row('Subject', '<code class="xp-code">' . xpe($c['subject'])   . '</code>')
                         . xp_row('Issuer',  '<code class="xp-code">' . xpe($c['issuer'])    . '</code>')
                         . (!empty($c['not_after']) ? xp_row('Expires', '<code class="xp-code">' . xpe($c['not_after']) . '</code>') : '')
                         . (!empty($c['pem']) ? artifactCertActions($c['pem']) : '')
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
             . $tst_section
             . xp_section('cms-certs', 'Embedded Certificates',   '#8866cc', $certs_html)
             . '</div>';
    }

    public function subtype(array $parsed): ?string {
        $s = $parsed['content_type'] ?? null;
        if ($parsed['is_cades_t'] && !empty($parsed['tst_time'])) {
            $s = ($s ? $s . ' · ' : '') . 'CAdES-T · ' . $parsed['tst_time'];
        } elseif ($parsed['is_cades_t']) {
            $s = ($s ? $s . ' · ' : '') . 'CAdES-T';
        }
        return $s;
    }
}

ArtifactRegistry::register(new Pkcs7Module());
