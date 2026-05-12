<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class TsrModule extends ArtifactModule {

    public function label(): string { return 'Timestamp Token / Response (RFC 3161)'; }

    public function recognize(string $bytes, string $ext): bool {
        return artifact_has_pem_header($bytes, 'TIME STAMP TOKEN')
            || artifact_has_pem_header($bytes, 'TIME STAMP RESPONSE')
            || artifact_has_pem_header($bytes, 'TIMESTAMP TOKEN')
            || in_array($ext, ['tsr', 'tst'], true);
    }

    public function parse(string $bytes): array {
        // Try openssl ts (reply display)
        $shell = artifact_openssl('ts -reply -text', $bytes, 'tsr')
              ?? artifact_openssl('asn1parse', $bytes, 'tsr');

        $data = ['shell_text' => $shell ?? ''];

        if ($shell) {
            if (preg_match('/Time stamp:\s*(.+)/i',   $shell, $m)) $data['timestamp']      = trim($m[1]);
            if (preg_match('/TSA:\s*(.+)/i',          $shell, $m)) $data['tsa']            = trim($m[1]);
            if (preg_match('/Policy OID:\s*(.+)/i',   $shell, $m)) $data['policy']         = trim($m[1]);
            if (preg_match('/Hash Algorithm:\s*(.+)/i',$shell,$m)) $data['hash_algorithm'] = trim($m[1]);
            if (preg_match('/Serial number:\s*(.+)/i, $shell, $m)) $data['serial']         = trim($m[1]);
            if (preg_match('/Ordering:\s*(.+)/i,      $shell, $m)) $data['ordering']       = trim($m[1]);
            // Message imprint is on the line after "Message data:"
            if (preg_match('/Message data:\s*\n\s*0000\s*-\s*(.+)/i', $shell, $m)) {
                $data['message_imprint'] = trim($m[1]);
            }
        }

        return $data;
    }

    public function render(array $parsed): string {
        $html = '';
        if (!empty($parsed['timestamp']))      $html .= xp_row('Timestamp',       '<span class="xp-code">' . xpe($parsed['timestamp'])      . '</span>');
        if (!empty($parsed['tsa']))            $html .= xp_row('TSA',             '<code class="xp-code">' . xpe($parsed['tsa'])            . '</code>');
        if (!empty($parsed['policy']))         $html .= xp_row('Policy OID',      '<code class="xp-code">' . xpe($parsed['policy'])         . '</code>');
        if (!empty($parsed['hash_algorithm'])) $html .= xp_row('Hash Algorithm',  xp_badge($parsed['hash_algorithm'], 'info'));
        if (!empty($parsed['serial']))         $html .= xp_row('Serial Number',   '<code class="xp-code">' . xpe($parsed['serial'])         . '</code>');
        if (!empty($parsed['ordering']))       $html .= xp_row('Ordering',        xp_badge($parsed['ordering'], 'neutral'));
        if (!empty($parsed['message_imprint'])) $html .= xp_row('Msg Imprint',    '<span class="xp-fp">' . xpe($parsed['message_imprint'])  . '</span>');

        if (!$html) {
            $html = '<div class="xp-muted">'
                  . (function_exists('shell_exec')
                      ? 'Could not extract fields from timestamp token.'
                      : 'Timestamp token identified. Full parsing requires openssl CLI.')
                  . '</div>';
        }

        if (!empty($parsed['shell_text'])) {
            $truncated = substr($parsed['shell_text'], 0, 1400);
            $html .= '<details style="margin-top:.6rem"><summary style="font-size:.68rem;color:var(--muted);cursor:pointer">Raw output</summary>'
                   . '<pre style="font-size:.62rem;color:#8899aa;overflow-x:auto;margin-top:.4rem">'
                   . xpe($truncated)
                   . (strlen($parsed['shell_text']) > 1400 ? "\n… truncated" : '')
                   . '</pre></details>';
        }

        return '<div class="xp-wrap">'
             . xp_section('tsr', 'Timestamp Token (RFC 3161)', '#3b82f6', $html)
             . '</div>';
    }

    public function subtype(array $parsed): ?string { return null; }
}

ArtifactRegistry::register(new TsrModule());
