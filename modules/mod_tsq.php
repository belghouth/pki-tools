<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class TsqModule extends ArtifactModule {

    public function label(): string { return 'Timestamp Request (RFC 3161)'; }

    public function recognize(string $bytes, string $ext): bool {
        return $ext === 'tsq'
            || artifact_has_pem_header($bytes, 'TIME STAMP REQUEST')
            || artifact_has_pem_header($bytes, 'TIMESTAMP REQUEST');
    }

    public function parse(string $bytes): array {
        $shell = artifact_openssl('ts -query -text', $bytes, 'tsq');
        $data  = ['shell_text' => $shell ?? ''];

        if (!$shell) return $data;

        if (preg_match('/Version:\s*(\d+)/i', $shell, $m))
            $data['version']      = 'v' . $m[1];
        if (preg_match('/Hash Algorithm:\s*(.+)/i', $shell, $m))
            $data['hash_algorithm'] = trim($m[1]);
        if (preg_match('/Policy OID:\s*(.+)/i', $shell, $m)) {
            $pol = trim($m[1]);
            if ($pol !== 'unspecified') $data['policy'] = $pol;
        }
        if (preg_match('/Nonce:\s*(0x[0-9A-Fa-f]+)/i', $shell, $m))
            $data['nonce']        = $m[1];
        if (preg_match('/Certificate required:\s*(.+)/i', $shell, $m))
            $data['cert_req']     = strtolower(trim($m[1])) === 'yes';

        $data['message_imprint'] = self::extract_hex_dump($shell, 'Message data');

        return $data;
    }

    // Extract hex bytes from an openssl-style hex dump section
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

    public function subtype(array $parsed): ?string {
        return !empty($parsed['hash_algorithm'])
            ? strtoupper($parsed['hash_algorithm'])
            : null;
    }

    public function render(array $parsed): string {
        $html = '';

        if (!empty($parsed['version']))
            $html .= xp_row('Version',         xp_badge($parsed['version'], 'neutral'));
        if (!empty($parsed['hash_algorithm']))
            $html .= xp_row('Hash Algorithm',  xp_badge($parsed['hash_algorithm'], 'info'));
        if (!empty($parsed['message_imprint'])) {
            $formatted = implode(' ', str_split($parsed['message_imprint'], 2));
            $html .= xp_row('Msg Imprint', '<span class="xp-fp">' . xpe($formatted) . '</span>');
        }
        if (!empty($parsed['policy']))
            $html .= xp_row('Policy OID',      '<code class="xp-code">' . xpe($parsed['policy']) . '</code>');
        if (!empty($parsed['nonce']))
            $html .= xp_row('Nonce',           '<code class="xp-code">' . xpe($parsed['nonce']) . '</code>');
        if (isset($parsed['cert_req']))
            $html .= xp_row('Cert Required',   xp_badge($parsed['cert_req'] ? 'yes' : 'no', $parsed['cert_req'] ? 'good' : 'neutral'));

        if (!$html) {
            $html = !empty($parsed['shell_text'])
                ? '<div class="xp-muted">Could not extract structured fields from this request.</div>'
                : '<div class="xp-muted">Timestamp request identified but openssl CLI is unavailable for parsing.</div>';
        }

        if (!empty($parsed['shell_text'])) {
            $text      = $parsed['shell_text'];
            $truncated = strlen($text) > 2000 ? substr($text, 0, 2000) . "\n… truncated" : $text;
            $html .= '<div class="xp-section" style="margin-top:.6rem;border:1px solid var(--border);border-left:3px solid #4b5563;border-radius:var(--radius);overflow:hidden">'
                   . '<div class="xp-section-header" style="border-left-color:#4b5563">'
                   . '<span class="xp-section-label">Raw Output (openssl ts -query -text)</span>'
                   . '</div>'
                   . '<div class="xp-section-body">'
                   . '<pre style="font-size:.62rem;color:#8899aa;overflow-x:auto;margin:0;white-space:pre-wrap">'
                   . xpe($truncated)
                   . '</pre>'
                   . '</div>'
                   . '</div>';
        }

        return '<div class="xp-wrap">'
             . xp_section('tsq', 'Timestamp Request (TSQ)', '#f59e0b', $html)
             . '</div>';
    }
}

ArtifactRegistry::register(new TsqModule());
