<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class TsrModule extends ArtifactModule {

    public function label(): string { return 'Timestamp Response (RFC 3161)'; }

    public function recognize(string $bytes, string $ext): bool {
        if (artifact_has_pem_header($bytes, 'TIME STAMP TOKEN')
            || artifact_has_pem_header($bytes, 'TIME STAMP RESPONSE')
            || artifact_has_pem_header($bytes, 'TIMESTAMP TOKEN')
            || in_array($ext, ['tsr', 'tst'], true)) {
            return true;
        }
        // DER: presence of id-ct-TSTInfo OID (1.2.840.113549.1.9.16.1.4)
        // uniquely identifies a TimeStampToken inside a TSR.
        return artifact_is_der($bytes)
            && str_contains($bytes, "\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04");
    }

    public function parse(string $bytes): array {
        $shell = artifact_openssl('ts -reply -text', $bytes, 'tsr');

        if (!$shell || str_contains($shell, 'wrong tag') || str_contains($shell, 'no start line')) {
            $asn1 = artifact_openssl('asn1parse', $bytes, 'tsr');
            return ['shell_text' => $asn1 ?? '', 'asn1_fallback' => true];
        }

        $data = ['shell_text' => $shell];

        // Status block
        if (preg_match('/Status:\s*(.+)/i', $shell, $m)) {
            $data['status']    = trim($m[1]);
            $data['status_ok'] = stripos($data['status'], 'Granted') !== false;
        }
        if (preg_match('/Status description:\s*(.+)/i', $shell, $m)) {
            $desc = trim($m[1]);
            if ($desc !== 'unspecified') $data['status_desc'] = $desc;
        }
        if (preg_match('/Failure info:\s*(.+)/i', $shell, $m)) {
            $info = trim($m[1]);
            if ($info !== 'unspecified') $data['failure_info'] = $info;
        }

        // TSTInfo fields
        if (preg_match('/Version:\s*(\d+)/i', $shell, $m))
            $data['version']   = 'v' . $m[1];
        if (preg_match('/Policy OID:\s*(.+)/i', $shell, $m))
            $data['policy']    = trim($m[1]);
        if (preg_match('/Hash Algorithm:\s*(.+)/i', $shell, $m))
            $data['hash_alg']  = trim($m[1]);
        if (preg_match('/Serial number:\s*(.+)/i', $shell, $m))
            $data['serial']    = trim($m[1]);
        if (preg_match('/Time stamp:\s*(.+)/i', $shell, $m))
            $data['timestamp'] = trim($m[1]);
        if (preg_match('/Accuracy:\s*(.+)/i', $shell, $m))
            $data['accuracy']  = trim($m[1]);
        if (preg_match('/Ordering:\s*(.+)/i', $shell, $m))
            $data['ordering']  = trim($m[1]);
        if (preg_match('/Nonce:\s*(0x[0-9A-Fa-f]+)/i', $shell, $m))
            $data['nonce']     = $m[1];
        if (preg_match('/TSA:\s*DirName:\s*(.+)/i', $shell, $m))
            $data['tsa']       = trim($m[1]);
        if (preg_match('/Signature Algorithm:\s*(.+)/i', $shell, $m))
            $data['sig_alg']   = trim($m[1]);

        $data['message_imprint'] = self::extract_hex_dump($shell, 'Message data');

        return $data;
    }

    // Extract hex bytes from an openssl-style hex dump section (e.g. "Message data:\n    0000 - ...")
    private static function extract_hex_dump(string $text, string $label): string {
        if (!preg_match('/' . preg_quote($label, '/') . ':?\s*\n((?:\s+[0-9a-f]+ - .+\n?)+)/i', $text, $m)) {
            return '';
        }
        $hex = '';
        foreach (explode("\n", $m[1]) as $line) {
            // Capture hex pairs up to the 3-space ASCII gap
            if (preg_match('/^\s+[0-9a-f]+\s*-\s*([0-9a-f -]+?)(?:\s{3,}|$)/i', $line, $lm)) {
                $hex .= preg_replace('/[^0-9a-f]/i', '', $lm[1]);
            }
        }
        return strtolower($hex);
    }

    public function subtype(array $parsed): ?string {
        if (!empty($parsed['status_ok']) && !empty($parsed['timestamp'])) {
            return 'Granted · ' . $parsed['timestamp'];
        }
        return $parsed['status'] ?? null;
    }

    public function render(array $parsed): string {
        if (!empty($parsed['asn1_fallback'])) {
            $content = !empty($parsed['shell_text'])
                ? '<pre style="font-size:.62rem;color:#8899aa;overflow-x:auto;margin:0">' . xpe(substr($parsed['shell_text'], 0, 3000)) . '</pre>'
                : '<div class="xp-muted">Could not parse timestamp response (openssl ts unavailable or malformed input).</div>';
            return '<div class="xp-wrap">'
                 . xp_section('tsr-raw', 'Timestamp Response (ASN.1)', '#3b82f6', $content)
                 . '</div>';
        }

        // ── Status section ────────────────────────────────────────────────────────
        $statusHtml = '';
        if (isset($parsed['status'])) {
            $ok = $parsed['status_ok'] ?? false;
            $statusHtml .= xp_row('Status', xp_badge($parsed['status'], $ok ? 'good' : 'danger'));
        }
        if (!empty($parsed['status_desc'])) {
            $statusHtml .= xp_row('Description', xpe($parsed['status_desc']));
        }
        if (!empty($parsed['failure_info'])) {
            $statusHtml .= xp_row('Failure Info', xp_badge($parsed['failure_info'], 'danger'));
        }

        // ── TSTInfo section ───────────────────────────────────────────────────────
        $tstHtml = '';
        if (!empty($parsed['version']))
            $tstHtml .= xp_row('Version',        xp_badge($parsed['version'], 'neutral'));
        if (!empty($parsed['timestamp']))
            $tstHtml .= xp_row('Time Stamp',     '<span class="xp-code">' . xpe($parsed['timestamp']) . '</span>');
        if (!empty($parsed['hash_alg']))
            $tstHtml .= xp_row('Hash Algorithm', xp_badge($parsed['hash_alg'], 'info'));
        if (!empty($parsed['message_imprint'])) {
            $formatted = implode(' ', str_split($parsed['message_imprint'], 2));
            $tstHtml .= xp_row('Msg Imprint', '<span class="xp-fp">' . xpe($formatted) . '</span>');
        }
        if (!empty($parsed['policy']))
            $tstHtml .= xp_row('Policy OID',     '<code class="xp-code">' . xpe($parsed['policy']) . '</code>');
        if (!empty($parsed['serial']))
            $tstHtml .= xp_row('Serial Number',  '<code class="xp-code">' . xpe($parsed['serial']) . '</code>');
        if (!empty($parsed['accuracy']))
            $tstHtml .= xp_row('Accuracy',       '<span class="xp-code">' . xpe($parsed['accuracy']) . '</span>');
        if (!empty($parsed['ordering']))
            $tstHtml .= xp_row('Ordering',       xp_badge($parsed['ordering'], 'neutral'));
        if (!empty($parsed['nonce']))
            $tstHtml .= xp_row('Nonce',          '<code class="xp-code">' . xpe($parsed['nonce']) . '</code>');
        if (!empty($parsed['tsa']))
            $tstHtml .= xp_row('TSA',            '<code class="xp-code">' . xpe($parsed['tsa']) . '</code>');
        if (!empty($parsed['sig_alg']))
            $tstHtml .= xp_row('Sig. Algorithm', xp_badge($parsed['sig_alg'], 'info'));

        $ok    = $parsed['status_ok'] ?? false;
        $color = $ok ? '#22c55e' : '#e05c5c';

        $out = '<div class="xp-wrap">'
             . xp_section('tsr-status', 'Response Status', $color,
                   $statusHtml ?: '<div class="xp-muted">No status information found.</div>')
             . xp_section('tsr-tst', 'Timestamp Info (TSTInfo)', '#3b82f6',
                   $tstHtml ?: '<div class="xp-muted">No TSTInfo fields extracted.</div>');

        if (!empty($parsed['shell_text'])) {
            $text      = $parsed['shell_text'];
            $truncated = strlen($text) > 3000 ? substr($text, 0, 3000) . "\n… truncated" : $text;
            $out .= '<div class="xp-section">'
                  . '<div class="xp-section-header" style="border-left-color:#4b5563">'
                  . '<span class="xp-section-label">Raw Output (openssl ts -reply -text)</span>'
                  . '</div>'
                  . '<div class="xp-section-body">'
                  . '<pre style="font-size:.62rem;color:#8899aa;overflow-x:auto;margin:0;white-space:pre-wrap">'
                  . xpe($truncated)
                  . '</pre>'
                  . '</div>'
                  . '</div>';
        }

        return $out . '</div>';
    }
}

ArtifactRegistry::register(new TsrModule());
