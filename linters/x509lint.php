<?php
/**
 * linters/x509lint.php — x509lint module for linters.php
 *
 * Requires: x509lint compiled binary in $PATH or /usr/local/bin/x509lint,
 *           executable by the web server user.
 * Source:   https://github.com/kroeckx/x509lint
 *
 * Usage:    x509lint <pem-file>
 * Output:   one finding per line, prefixed with severity:
 *             E: <description>   — Error
 *             W: <description>   — Warning
 *             I: <description>   — Info
 *
 * x509lint does not accept an issuer/root certificate.
 * It does not have a -version flag; version is detected from the binary
 * itself (not available) so we omit the version from the button label.
 *
 * Install on Ubuntu:
 *   apt install libssl-dev
 *   git clone https://github.com/kroeckx/x509lint
 *   cd x509lint && make
 *   cp x509lint /usr/local/bin/
 *
 * This file must only be included by linters.php, never accessed directly.
 */

// ── Direct access guard ──────────────────────────────────────────────────────
if (!isset($linters_dir)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('403 Forbidden: this file must not be accessed directly.');
}

// ── Binary detection ─────────────────────────────────────────────────────────

function x509lint_binary(): ?string {
    $override = getenv('X509LINT_BIN');
    if ($override !== false && $override !== '') {
        return is_executable($override) ? $override : null;
    }
    foreach (['/usr/local/bin', '/usr/bin', '/bin'] as $dir) {
        $path = $dir . '/x509lint';
        if (is_executable($path)) {
            return $path;
        }
    }
    return null;
}

// ── Output renderer ──────────────────────────────────────────────────────────
// x509lint output: one line per finding, prefix E:/W:/I:
// Some lines may lack a prefix (continuation or parse errors) — treat as info.

function x509lint_render_html(string $raw): string {
    $e = fn(string $s): string => htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8');

    $lines = array_filter(array_map('trim', explode("\n", $raw)));

    $colours = [
        'error'   => ['bg' => 'rgba(224,92,92,0.08)',   'border' => 'rgba(224,92,92,0.28)',   'text' => '#e05c5c', 'badge_bg' => 'rgba(224,92,92,0.15)'],
        'warning' => ['bg' => 'rgba(245,166,35,0.08)',  'border' => 'rgba(245,166,35,0.28)',  'text' => '#f5a623', 'badge_bg' => 'rgba(245,166,35,0.15)'],
        'info'    => ['bg' => 'rgba(107,122,144,0.07)', 'border' => 'rgba(107,122,144,0.20)', 'text' => '#8899aa', 'badge_bg' => 'rgba(107,122,144,0.14)'],
    ];
    $default_colour = ['bg' => 'rgba(58,68,88,0.10)', 'border' => '#2a3040', 'text' => '#d4dae6', 'badge_bg' => 'rgba(58,68,88,0.20)'];

    $counts = ['error' => 0, 'warning' => 0, 'info' => 0];

    $findings = [];
    foreach ($lines as $line) {
        if (preg_match('/^([EWI]):\s*(.+)$/i', $line, $m)) {
            $sev = match(strtoupper($m[1])) {
                'E' => 'error',
                'W' => 'warning',
                default => 'info',
            };
            $findings[] = ['severity' => $sev, 'description' => $m[2]];
            if (isset($counts[$sev])) $counts[$sev]++;
        } else {
            // Unprefixed line — treat as info.
            $findings[] = ['severity' => 'info', 'description' => $line];
            $counts['info']++;
        }
    }

    if (empty($findings)) {
        return '<div class="x509lint-output">'
            . '<div class="x509lint-clean">✓ No findings reported by x509lint.</div>'
            . '</div>';
    }

    $rows = '';
    foreach ($findings as $f) {
        $sev = $f['severity'];
        $c   = $colours[$sev] ?? $default_colour;
        $rows .= sprintf(
            '<div class="x509lint-row" style="background:%s;border-left:3px solid %s;">'
            . '<span class="x509lint-badge" style="color:%s;background:%s;">%s</span>'
            . '<span class="x509lint-description">%s</span>'
            . '</div>',
            $c['bg'], $c['border'],
            $c['text'], $c['badge_bg'],
            $e(strtoupper($sev)),
            $e($f['description'])
        );
    }

    // Summary bar.
    $total = array_sum($counts);
    $summary = '<div class="x509lint-summary">';
    $summary .= '<span class="x509lint-summary-total"><strong>' . $total . '</strong> finding' . ($total !== 1 ? 's' : '') . '</span>';
    $summary_meta = ['error' => '#e05c5c', 'warning' => '#f5a623', 'info' => '#8899aa'];
    foreach ($summary_meta as $sev => $color) {
        if ($counts[$sev] > 0) {
            $summary .= sprintf(
                '<span class="x509lint-summary-item" style="color:%s"><strong>%d</strong> %s</span>',
                $color, $counts[$sev], strtoupper($sev)
            );
        }
    }
    $summary .= '</div>';

    $styles = '
<style>
.x509lint-output { font-family: "IBM Plex Mono", monospace; font-size: 0.72rem; }
.x509lint-clean {
    padding: 1rem; color: #3ddc7a;
    background: rgba(0,212,100,0.06);
    border: 1px solid rgba(0,212,100,0.2);
    border-radius: 4px; font-weight: 500;
}
.x509lint-summary {
    display: flex; align-items: center; gap: 1.25rem; flex-wrap: wrap;
    padding: 0.6rem 0.9rem;
    background: rgba(29,35,48,0.8);
    border: 1px solid #2a3040; border-radius: 4px;
    margin-bottom: 0.75rem;
    font-size: 0.7rem; letter-spacing: 0.05em;
}
.x509lint-summary-total { color: #d4dae6; }
.x509lint-summary-total strong { font-size: 0.85rem; }
.x509lint-summary-item { display: flex; align-items: center; gap: 0.3rem; }
.x509lint-summary-item strong { font-size: 0.82rem; }
.x509lint-rows {
    display: flex; flex-direction: column; gap: 2px;
    max-height: 560px; overflow-y: auto;
    border: 1px solid #2a3040; border-radius: 4px;
    background: #161a21;
}
.x509lint-row {
    display: flex; align-items: baseline; gap: 0.75rem;
    padding: 0.3rem 0.75rem; line-height: 1.6;
    transition: filter 80ms ease;
}
.x509lint-row:hover { filter: brightness(1.18); }
.x509lint-badge {
    flex-shrink: 0; width: 5rem; text-align: center;
    font-weight: 600; font-size: 0.6rem; letter-spacing: 0.1em;
    border-radius: 2px; padding: 0.15em 0.3em;
}
.x509lint-description { color: #d4dae6; word-break: break-all; flex: 1; }
</style>';

    return $styles
        . '<div class="x509lint-output">'
        . $summary
        . '<div class="x509lint-rows">' . $rows . '</div>'
        . '</div>';
}

// ── Run function ─────────────────────────────────────────────────────────────

$x509lint_bin       = x509lint_binary();
$x509lint_available = $x509lint_bin !== null;

$x509lint_run = function (string $ee_pem, ?string $root_pem) use ($x509lint_bin): string {
    if ($x509lint_bin === null) {
        throw new RuntimeException(
            'x509lint binary not found. '
            . 'Compile from https://github.com/kroeckx/x509lint and copy to /usr/local/bin/x509lint.'
        );
    }

    // Re-export through OpenSSL for a clean, normalised PEM.
    $cert = openssl_x509_read($ee_pem);
    if ($cert === false) {
        throw new RuntimeException(
            'End-entity certificate: failed to read via openssl_x509_read.'
        );
    }
    openssl_x509_export($cert, $pem_clean);

    $tmp = tempnam(sys_get_temp_dir(), 'x509lint_');
    if ($tmp === false) {
        throw new RuntimeException('Failed to create temporary file.');
    }

    try {
        if (file_put_contents($tmp, $pem_clean) === false) {
            throw new RuntimeException('Failed to write PEM certificate to temporary file.');
        }

        $cmd = escapeshellarg($x509lint_bin) . ' ' . escapeshellarg($tmp) . ' 2>&1';

        $lines     = [];
        $exit_code = null;
        exec($cmd, $lines, $exit_code);
        $output = implode("\n", $lines);

        // x509lint exits 0 when no errors, non-zero when errors found — both valid.
        // Empty output with a non-zero exit usually means a parse failure.
        if ($output === '' && $exit_code !== 0) {
            throw new RuntimeException(
                "x509lint exited with code {$exit_code} and produced no output. "
                . 'The certificate may be too malformed to parse.'
            );
        }

        if ($output === '') {
            return x509lint_render_html('');
        }

        return x509lint_render_html($output);

    } finally {
        @unlink($tmp);
    }
};

// ── Module descriptor ────────────────────────────────────────────────────────

$module = [
    'id'      => 'x509lint',
    'label'   => 'x509lint',
    'actions' => [
        [
            'id'          => 'x509lint_lint',
            'label'       => $x509lint_available
                                 ? 'x509lint'
                                 : 'x509lint — not installed',
            'needs_root'  => false,
            'available'   => $x509lint_available,
            'output_html' => true,
            'run'         => $x509lint_run,
        ],
    ],
];

