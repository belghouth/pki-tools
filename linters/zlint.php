<?php
/**
 * linters/zlint.php — ZLint module for linters.php
 *
 * Requires: zlint binary in $PATH, executable by the web server user.
 * ZLint docs: https://github.com/zmap/zlint
 *
 * zlint accepts a PEM-encoded certificate as a file argument.
 * We write the normalised PEM (re-exported via openssl_x509_export) to a
 * temp file and pass it as the sole argument.
 * The root/issuer is not used by zlint.
 *
 * This file must only be included by linters.php, never accessed directly.
 */

// ── Direct access guard ──────────────────────────────────────────────────────
// linters.php sets $linters_dir before including modules. If this constant
// is absent we are being hit directly via HTTP — reject immediately.
if (!isset($linters_dir)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('403 Forbidden: this file must not be accessed directly.');
}

// ── Availability check ───────────────────────────────────────────────────────

function zlint_binary(): ?string {
    $override = getenv('ZLINT_BIN');
    if ($override !== false && $override !== '') {
        return is_executable($override) ? $override : null;
    }
    $bin = trim(shell_exec('command -v zlint 2>/dev/null') ?? '');
    return ($bin !== '' && is_executable($bin)) ? $bin : null;
}

function zlint_version(string $bin): string {
    $raw = trim(shell_exec(escapeshellarg($bin) . ' -version 2>/dev/null') ?? '');
    return preg_match('/v\d+\.\d+\.\d+\S*/', $raw, $m) ? $m[0] : ($raw ?: 'unknown');
}

// ── Output renderer ──────────────────────────────────────────────────────────
// zlint -pretty emits one JSON object per line (JSON Lines / NDJSON).
// Each line is: {"lintName": {...result object...}}
// The result object contains a "result" key: pass | warn | error | fatal | na | nle | reserved
// We parse line by line and wrap each in a coloured <div>.

function zlint_render_html(string $raw): string {
    // Colour map — keys match zlint result values (lowercase).
    $colours = [
        'pass'     => ['bg' => 'rgba(0,212,100,0.08)',  'border' => 'rgba(0,212,100,0.25)',  'text' => '#3ddc7a', 'badge_bg' => 'rgba(0,212,100,0.15)'],
        'warn'     => ['bg' => 'rgba(245,166,35,0.08)', 'border' => 'rgba(245,166,35,0.28)', 'text' => '#f5a623', 'badge_bg' => 'rgba(245,166,35,0.15)'],
        'error'    => ['bg' => 'rgba(224,92,92,0.08)',  'border' => 'rgba(224,92,92,0.28)',  'text' => '#e05c5c', 'badge_bg' => 'rgba(224,92,92,0.15)'],
        'fatal'    => ['bg' => 'rgba(224,60,60,0.13)',  'border' => 'rgba(224,60,60,0.45)',  'text' => '#ff4444', 'badge_bg' => 'rgba(224,60,60,0.22)'],
        'na'       => ['bg' => 'rgba(107,122,144,0.06)','border' => 'rgba(107,122,144,0.2)', 'text' => '#6b7a90', 'badge_bg' => 'rgba(107,122,144,0.12)'],
        'nle'      => ['bg' => 'rgba(107,122,144,0.06)','border' => 'rgba(107,122,144,0.2)', 'text' => '#8899aa', 'badge_bg' => 'rgba(107,122,144,0.12)'],
        'reserved' => ['bg' => 'rgba(107,122,144,0.06)','border' => 'rgba(107,122,144,0.2)', 'text' => '#8899aa', 'badge_bg' => 'rgba(107,122,144,0.12)'],
    ];
    $default_colour = ['bg' => 'rgba(58,68,88,0.15)', 'border' => '#2a3040', 'text' => '#d4dae6', 'badge_bg' => 'rgba(58,68,88,0.25)'];

    $e = fn(string $s): string => htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8');

    $lines = explode("\n", trim($raw));
    $counts = ['pass' => 0, 'warn' => 0, 'error' => 0, 'fatal' => 0, 'na' => 0];

    $rows = '';
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') continue;

        $decoded = json_decode($line, true);
        if (!is_array($decoded)) {
            // Non-JSON line (e.g. a log message) — render as plain text.
            $rows .= '<div class="zlint-row zlint-plain">' . $e($line) . '</div>';
            continue;
        }

        foreach ($decoded as $lint_name => $result_obj) {
            $result_val = strtolower(trim($result_obj['result'] ?? ''));
            $details    = $result_obj['details'] ?? '';
            $c = $colours[$result_val] ?? $default_colour;

            if (isset($counts[$result_val])) $counts[$result_val]++;

            $rows .= sprintf(
                '<div class="zlint-row" style="background:%s;border-left:3px solid %s;">'
                . '<span class="zlint-badge" style="color:%s;background:%s;">%s</span>'
                . '<span class="zlint-name">%s</span>'
                . ($details !== '' ? '<span class="zlint-details">%s</span>' : '%s')
                . '</div>',
                $c['bg'],
                $c['border'],
                $c['text'],
                $c['badge_bg'],
                $e(strtoupper($result_val)),
                $e($lint_name),
                $details !== '' ? $e($details) : ''
            );
        }
    }

    // Summary bar.
    $summary = '<div class="zlint-summary">';
    $summary_items = [
        'pass'  => ['label' => 'PASS',  'color' => '#3ddc7a'],
        'warn'  => ['label' => 'WARN',  'color' => '#f5a623'],
        'error' => ['label' => 'ERROR', 'color' => '#e05c5c'],
        'fatal' => ['label' => 'FATAL', 'color' => '#ff4444'],
        'na'    => ['label' => 'N/A',   'color' => '#6b7a90'],
    ];
    foreach ($summary_items as $key => $meta) {
        $summary .= sprintf(
            '<span class="zlint-summary-item" style="color:%s"><strong>%d</strong> %s</span>',
            $meta['color'], $counts[$key], $meta['label']
        );
    }
    $summary .= '</div>';

    $styles = '
<style>
.zlint-output { font-family: "IBM Plex Mono", monospace; font-size: 0.72rem; }
.zlint-summary {
    display: flex; gap: 1.5rem; flex-wrap: wrap;
    padding: 0.6rem 0.9rem;
    background: rgba(29,35,48,0.8);
    border: 1px solid #2a3040;
    border-radius: 4px;
    margin-bottom: 0.75rem;
    font-size: 0.7rem;
    letter-spacing: 0.06em;
}
.zlint-summary-item { display: flex; align-items: center; gap: 0.35rem; }
.zlint-summary-item strong { font-weight: 600; font-size: 0.82rem; }
.zlint-rows {
    display: flex; flex-direction: column; gap: 2px;
    max-height: 520px; overflow-y: auto;
    border: 1px solid #2a3040; border-radius: 4px;
    background: #161a21;
}
.zlint-row {
    display: flex; align-items: baseline; gap: 0.75rem;
    padding: 0.3rem 0.75rem;
    line-height: 1.6;
    transition: filter 80ms ease;
}
.zlint-row:hover { filter: brightness(1.15); }
.zlint-plain { color: #6b7a90; font-style: italic; padding: 0.3rem 0.75rem; }
.zlint-badge {
    flex-shrink: 0;
    width: 4.5rem;
    text-align: center;
    font-weight: 600;
    font-size: 0.62rem;
    letter-spacing: 0.1em;
    border-radius: 2px;
    padding: 0.1em 0.3em;
}
.zlint-name { color: #d4dae6; flex: 1; word-break: break-all; }
.zlint-details { color: #8899aa; font-style: italic; font-size: 0.68rem; }
</style>';

    return $styles
        . '<div class="zlint-output">'
        . $summary
        . '<div class="zlint-rows">' . $rows . '</div>'
        . '</div>';
}

// ── Run function ─────────────────────────────────────────────────────────────

$zlint_bin       = zlint_binary();
$zlint_available = $zlint_bin !== null;
$zlint_version   = $zlint_available ? zlint_version($zlint_bin) : null;

$zlint_run = function (string $ee_pem, ?string $root_pem) use ($zlint_bin): string {
    if ($zlint_bin === null) {
        throw new RuntimeException(
            'zlint binary not found in PATH and ZLINT_BIN is not set. '
            . 'Install zlint and ensure it is executable by the web server.'
        );
    }

    $cert = openssl_x509_read($ee_pem);
    if ($cert === false) {
        throw new RuntimeException(
            'End-entity certificate: failed to read via openssl_x509_read. '
            . 'Verify the PEM in the end-entity field is a valid X.509 certificate.'
        );
    }

    openssl_x509_export($cert, $pem_clean);

    $tmp = tempnam(sys_get_temp_dir(), 'zlint_');
    if ($tmp === false) {
        throw new RuntimeException('Failed to create temporary file.');
    }

    try {
        if (file_put_contents($tmp, $pem_clean) === false) {
            throw new RuntimeException('Failed to write PEM certificate to temporary file.');
        }

        // No -pretty: we want raw JSON Lines for parsing and rendering.
        $cmd = escapeshellarg($zlint_bin) . ' ' . escapeshellarg($tmp) . ' 2>&1';

        $lines     = [];
        $exit_code = null;
        exec($cmd, $lines, $exit_code);
        $output = implode("\n", $lines);

        if (str_contains($output, 'level=fatal')) {
            throw new RuntimeException(
                "zlint could not parse the end-entity certificate.\nzlint output:\n" . $output
            );
        }

        if ($output === '') {
            throw new RuntimeException(
                "zlint exited with code {$exit_code} and produced no output. "
                . "Check that the binary is functional: run `zlint -version` as the web server user."
            );
        }

        return zlint_render_html($output);

    } finally {
        @unlink($tmp);
    }
};

// ── Module descriptor ────────────────────────────────────────────────────────

$module = [
    'id'      => 'zlint',
    'label'   => 'ZLint',
    'actions' => [
        [
            'id'          => 'zlint_lint',
            'label'       => $zlint_available
                                 ? 'zlint ' . $zlint_version
                                 : 'zlint — not installed',
            'needs_root'  => false,
            'available'   => $zlint_available,
            'output_html' => true,
            'run'         => $zlint_run,
        ],
    ],
];

