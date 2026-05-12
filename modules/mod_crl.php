<?php
if (!defined('ARTIFACT_PARSER')) { http_response_code(403); exit; }

class CrlModule extends ArtifactModule {

    public function label(): string { return 'Certificate Revocation List (CRL)'; }

    public function recognize(string $bytes, string $ext): bool {
        return artifact_has_pem_header($bytes, 'X509 CRL')
            || $ext === 'crl'
            || (artifact_is_der($bytes) && $ext === 'crl');
    }

    public function parse(string $bytes): array {
        $pem = artifact_has_pem_header($bytes, 'X509 CRL')
            ? $bytes
            : artifact_to_pem($bytes, 'X509 CRL');

        $shell = artifact_openssl('crl -text -noout', $pem ?? $bytes);
        if (!$shell) {
            return ['shell_unavailable' => true];
        }

        $data = ['revoked' => []];

        if (preg_match('/Issuer:\s*(.+)/i',              $shell, $m)) $data['issuer']      = trim($m[1]);
        if (preg_match('/Last Update:\s*(.+)/i',          $shell, $m)) $data['last_update'] = trim($m[1]);
        if (preg_match('/Next Update:\s*(.+)/i',          $shell, $m)) $data['next_update'] = trim($m[1]);
        if (preg_match('/Signature Algorithm:\s*(.+)/i',  $shell, $m)) $data['sig_alg']     = trim($m[1]);

        // Version appears in the CRL header or extensions block
        if (preg_match('/^(\s*)Version\s+(\d)/im', $shell, $m)) {
            $data['version'] = 'v' . $m[2];
        }

        // Count revoked serials
        $data['revoked_count'] = preg_match_all('/Serial Number:\s*[0-9A-Fa-f:]+/i', $shell);

        // First 5 revoked entries
        preg_match_all(
            '/Serial Number:\s*([0-9A-Fa-f:]+)\s*\n\s*Revocation Date:\s*(.+)/i',
            $shell, $rm, PREG_SET_ORDER
        );
        foreach (array_slice($rm, 0, 5) as $r) {
            $data['revoked'][] = ['serial' => trim($r[1]), 'date' => trim($r[2])];
        }

        return $data;
    }

    public function render(array $parsed): string {
        if (!empty($parsed['shell_unavailable'])) {
            $msg = '<div class="xp-muted">CRL recognised but shell (openssl CLI) is unavailable on this server — detailed parsing requires it.</div>';
            return '<div class="xp-wrap">' . xp_section('crl-info', 'CRL Information', '#cc8844', $msg) . '</div>';
        }

        $info  = '';
        if (!empty($parsed['version']))     $info .= xp_row('Version',             xp_badge($parsed['version'], 'neutral'));
        if (!empty($parsed['issuer']))      $info .= xp_row('Issuer',              '<code class="xp-code">' . xpe($parsed['issuer']) . '</code>');
        if (!empty($parsed['sig_alg']))     $info .= xp_row('Signature Algorithm', '<code class="xp-code">' . xpe($parsed['sig_alg']) . '</code>');
        if (!empty($parsed['last_update'])) $info .= xp_row('This Update',         '<span class="xp-code">' . xpe($parsed['last_update']) . '</span>');
        if (!empty($parsed['next_update'])) $info .= xp_row('Next Update',         '<span class="xp-code">' . xpe($parsed['next_update']) . '</span>');

        $count    = $parsed['revoked_count'] ?? 0;
        $rev_html = xp_row('Total Entries', xp_badge((string) $count, $count > 0 ? 'warn' : 'good'));
        foreach ($parsed['revoked'] as $r) {
            $rev_html .= '<div class="xp-row">'
                       . '<span class="xp-label">Serial</span>'
                       . '<span class="xp-value"><code class="xp-code">' . xpe(strtoupper($r['serial'])) . '</code>'
                       . ' <span class="xp-muted">· revoked ' . xpe($r['date']) . '</span></span>'
                       . '</div>';
        }
        if ($count > 5) {
            $rev_html .= '<div class="xp-muted" style="padding:.3rem 0">… and ' . ($count - 5) . ' more entries not shown</div>';
        }

        return '<div class="xp-wrap">'
             . xp_section('crl-info', 'CRL Information',       '#cc8844', $info    ?: '<div class="xp-muted">No header data parsed.</div>')
             . xp_section('crl-rev',  'Revoked Certificates',  '#cc4444', $rev_html)
             . '</div>';
    }

    public function subtype(array $parsed): ?string { return null; }
}

ArtifactRegistry::register(new CrlModule());
