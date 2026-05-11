<?php
/**
 * linters/pkilint.php — pkilint module for linters.php
 *
 * Requires: pkilint installed via pipx (or system pip), commands in $PATH,
 *           executable by the web server user.
 * pkilint docs: https://github.com/digicert/pkilint
 *
 * Bundled command-line linters and their argument signatures:
 *
 *   lint_pkix_cert              lint <file>               — EE only
 *   lint_cabf_serverauth_cert   lint -d <file>            — EE only (auto-detect profile)
 *   lint_cabf_smime_cert        lint -d <file>            — EE only (auto-detect profile)
 *   lint_etsi_cert              lint -d <file>            — EE only (auto-detect profile)
 *   lint_pkix_signer_signee_cert_chain  lint <signer> <signee>  — requires issuer/root
 *
 * All linters:
 *   - Accept PEM- or DER-encoded input (we always write normalised PEM).
 *   - Return the number of findings as the exit code (0 = no findings).
 *   - Output format: -f JSON for machine-parseable structured output.
 *   - Common flags: -s INFO (report all severities)
 *
 * This file must only be included by linters.php, never accessed directly.
 */

// ── Direct access guard ──────────────────────────────────────────────────────
if (!isset($linters_dir)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('403 Forbidden: this file must not be accessed directly.');
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Resolves a pkilint command binary.
 * Checks PKILINT_BIN_<UPPERCASE_CMD> env override first, then known paths.
 */
function pkilint_binary(string $cmd): ?string {
    $env_key = 'PKILINT_BIN_' . strtoupper($cmd);
    $override = getenv($env_key);
    if ($override !== false && $override !== '') {
        return is_executable($override) ? $override : null;
    }
    // Search explicit directories rather than relying on shell built-ins
    // (command -v is bash-only; /bin/sh on Ubuntu is dash).
    $search = ['/usr/local/bin', '/usr/bin', '/bin'];
    foreach ($search as $dir) {
        $path = $dir . '/' . $cmd;
        if (is_executable($path)) {
            return $path;
        }
    }
    return null;
}

/**
 * Returns the pkilint version string, or ''.
 */
function pkilint_version(?string $bin): string {
    if ($bin === null) return '';
    // pip show is reliable and doesn't require executing the linter itself.
    foreach (['/usr/local/bin/pip', '/usr/bin/pip', '/usr/local/bin/pip3', '/usr/bin/pip3'] as $pip) {
        if (!is_executable($pip)) continue;
        $raw = trim(shell_exec(escapeshellarg($pip) . ' show pkilint 2>/dev/null | grep -i ^Version:') ?? '');
        if (preg_match('/\d+\.\d+\.\d+\S*/', $raw, $m)) {
            return 'v' . $m[0];
        }
    }
    return '';
}

// ── Temp file helper ─────────────────────────────────────────────────────────

/**
 * Writes a normalised PEM to a temp file and returns the path.
 * The caller must unlink() it in a finally block.
 */
function pkilint_write_pem(string $pem): string {
    $tmp = tempnam(sys_get_temp_dir(), 'pkilint_');
    if ($tmp === false) {
        throw new RuntimeException('Failed to create temporary file.');
    }
    if (file_put_contents($tmp, $pem) === false) {
        @unlink($tmp);
        throw new RuntimeException('Failed to write PEM to temporary file.');
    }
    return $tmp;
}

// ── Output renderer ──────────────────────────────────────────────────────────
// pkilint -f JSON emits a JSON array of finding objects.
// Each object has at minimum: "validator", "code", "severity", "message".
// Severity levels: DEBUG < INFO < NOTICE < WARNING < ERROR < CRITICAL < FATAL
// We map these to colour bands.

function pkilint_render_html(string $raw, string $cmd_label): string {
    $e = fn(string $s): string => htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8');

    // pkilint may mix a plain-text error line before/after JSON (e.g. "Could not
    // determine validation level and generation" from lint_cabf_smime_cert).
    // Separate JSON lines from plain-text lines first.
    $lines      = explode("\n", trim($raw));
    $json_line  = null;
    $plain_msgs = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') continue;
        if ($line[0] === '{' || $line[0] === '[') {
            $json_line = $line;   // take the last JSON line if there are multiple
        } else {
            $plain_msgs[] = $line;
        }
    }

    // Surface any plain-text messages (warnings/errors from the tool itself).
    $notices = '';
    foreach ($plain_msgs as $msg) {
        $notices .= '<div class="pkilint-parse-error">⚠ ' . $e($msg) . '</div>';
    }

    if ($json_line === null) {
        return '<div class="pkilint-output">'
            . ($notices ?: '<div class="pkilint-parse-error">⚠ pkilint produced no JSON output.</div>')
            . '<pre class="pkilint-raw">' . $e($raw) . '</pre>'
            . '</div>';
    }

    $decoded = json_decode($json_line, true);

    // Actual structure: {"results": [ {node_path, validator, finding_descriptions: [{severity, code, message}]} ]}
    if (!is_array($decoded) || !isset($decoded['results']) || !is_array($decoded['results'])) {
        return '<div class="pkilint-output">'
            . $notices
            . '<div class="pkilint-parse-error">⚠ Unexpected JSON structure from pkilint.</div>'
            . '<pre class="pkilint-raw">' . $e($json_line) . '</pre>'
            . '</div>';
    }

    $results = $decoded['results'];

    // Severity → colour map.
    $colours = [
        'DEBUG'    => ['bg' => 'rgba(107,122,144,0.05)', 'border' => 'rgba(107,122,144,0.15)', 'text' => '#556070', 'badge_bg' => 'rgba(107,122,144,0.10)'],
        'INFO'     => ['bg' => 'rgba(107,122,144,0.07)', 'border' => 'rgba(107,122,144,0.20)', 'text' => '#8899aa', 'badge_bg' => 'rgba(107,122,144,0.14)'],
        'NOTICE'   => ['bg' => 'rgba(0,153,255,0.07)',   'border' => 'rgba(0,153,255,0.22)',   'text' => '#4db8ff', 'badge_bg' => 'rgba(0,153,255,0.13)'],
        'WARNING'  => ['bg' => 'rgba(245,166,35,0.08)',  'border' => 'rgba(245,166,35,0.28)',  'text' => '#f5a623', 'badge_bg' => 'rgba(245,166,35,0.15)'],
        'ERROR'    => ['bg' => 'rgba(224,92,92,0.08)',   'border' => 'rgba(224,92,92,0.28)',   'text' => '#e05c5c', 'badge_bg' => 'rgba(224,92,92,0.15)'],
        'CRITICAL' => ['bg' => 'rgba(224,60,60,0.12)',   'border' => 'rgba(224,60,60,0.40)',   'text' => '#ff4444', 'badge_bg' => 'rgba(224,60,60,0.20)'],
        'FATAL'    => ['bg' => 'rgba(200,30,30,0.18)',   'border' => 'rgba(200,30,30,0.55)',   'text' => '#ff2222', 'badge_bg' => 'rgba(200,30,30,0.28)'],
    ];
    $default_colour = ['bg' => 'rgba(58,68,88,0.10)', 'border' => '#2a3040', 'text' => '#d4dae6', 'badge_bg' => 'rgba(58,68,88,0.20)'];

    $severity_order = ['DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL'];
    $counts = array_fill_keys($severity_order, 0);

    if (count($results) === 0) {
        return '<div class="pkilint-output">'
            . $notices
            . '<div class="pkilint-clean">✓ No findings reported by ' . $e($cmd_label) . '.</div>'
            . '</div>';
    }

    $rows = '';
    foreach ($results as $result) {
        $node_path = trim($result['node_path'] ?? '');
        $validator = trim($result['validator'] ?? '');
        $findings  = $result['finding_descriptions'] ?? [];

        foreach ($findings as $finding) {
            $severity = strtoupper(trim($finding['severity'] ?? 'INFO'));
            $code     = trim($finding['code'] ?? '');
            $message  = trim($finding['message'] ?? '');

            $c = $colours[$severity] ?? $default_colour;
            if (isset($counts[$severity])) $counts[$severity]++;

            $rows .= sprintf(
                '<div class="pkilint-row" style="background:%s;border-left:3px solid %s;">'
                . '<span class="pkilint-badge" style="color:%s;background:%s;">%s</span>'
                . '<span class="pkilint-body">'
                . '<span class="pkilint-code">%s</span>'
                . ($message !== '' ? '<span class="pkilint-message">%s</span>' : '')
                . ($node_path !== '' ? '<span class="pkilint-path">@ %s</span>' : '')
                . ($validator !== '' ? '<span class="pkilint-validator">%s</span>' : '')
                . '</span>'
                . '</div>',
                $c['bg'], $c['border'],
                $c['text'], $c['badge_bg'],
                $e($severity),
                $e($code !== '' ? $code : '—'),
                $message !== '' ? $e($message) : '',
                $node_path !== '' ? $e($node_path) : '',
                $validator !== '' ? $e($validator) : ''
            );
        }
    }

    // Summary bar.
    $summary_meta = [
        'FATAL'    => '#ff2222',
        'CRITICAL' => '#ff4444',
        'ERROR'    => '#e05c5c',
        'WARNING'  => '#f5a623',
        'NOTICE'   => '#4db8ff',
        'INFO'     => '#8899aa',
        'DEBUG'    => '#556070',
    ];
    $total = array_sum($counts);
    $summary = '<div class="pkilint-summary">';
    $summary .= '<span class="pkilint-summary-total"><strong>' . $total . '</strong> finding' . ($total !== 1 ? 's' : '') . '</span>';
    foreach ($summary_meta as $sev => $color) {
        if ($counts[$sev] > 0) {
            $summary .= sprintf(
                '<span class="pkilint-summary-item" style="color:%s"><strong>%d</strong> %s</span>',
                $color, $counts[$sev], $sev
            );
        }
    }
    $summary .= '</div>';

    $styles = '
<style>
.pkilint-output { font-family: "IBM Plex Mono", monospace; font-size: 0.72rem; }
.pkilint-clean {
    padding: 1rem; color: #3ddc7a;
    background: rgba(0,212,100,0.06);
    border: 1px solid rgba(0,212,100,0.2);
    border-radius: 4px;
    font-weight: 500;
}
.pkilint-parse-error {
    padding: 0.6rem 0.9rem; color: #f5a623;
    background: rgba(245,166,35,0.08);
    border: 1px solid rgba(245,166,35,0.25);
    border-radius: 4px;
    margin-bottom: 0.5rem;
}
.pkilint-raw {
    font-family: "IBM Plex Mono", monospace; font-size: 0.7rem;
    color: #d4dae6; background: #161a21;
    border: 1px solid #2a3040; border-radius: 4px;
    padding: 0.9rem; white-space: pre-wrap; word-break: break-all;
    max-height: 400px; overflow-y: auto;
}
.pkilint-summary {
    display: flex; align-items: center; gap: 1.25rem; flex-wrap: wrap;
    padding: 0.6rem 0.9rem;
    background: rgba(29,35,48,0.8);
    border: 1px solid #2a3040; border-radius: 4px;
    margin-bottom: 0.75rem;
    font-size: 0.7rem; letter-spacing: 0.05em;
}
.pkilint-summary-total { color: #d4dae6; }
.pkilint-summary-total strong { font-size: 0.85rem; }
.pkilint-summary-item { display: flex; align-items: center; gap: 0.3rem; }
.pkilint-summary-item strong { font-size: 0.82rem; }
.pkilint-rows {
    display: flex; flex-direction: column; gap: 2px;
    max-height: 560px; overflow-y: auto;
    border: 1px solid #2a3040; border-radius: 4px;
    background: #161a21;
}
.pkilint-row {
    display: flex; align-items: flex-start; gap: 0.75rem;
    padding: 0.35rem 0.75rem;
    line-height: 1.6;
    transition: filter 80ms ease;
}
.pkilint-row:hover { filter: brightness(1.18); }
.pkilint-badge {
    flex-shrink: 0;
    width: 5.5rem;
    text-align: center;
    font-weight: 600;
    font-size: 0.6rem;
    letter-spacing: 0.1em;
    border-radius: 2px;
    padding: 0.15em 0.3em;
    margin-top: 0.15em;
}
.pkilint-body {
    display: flex; flex-direction: column; gap: 0.1rem; flex: 1;
    word-break: break-all;
}
.pkilint-code    { color: #d4dae6; font-weight: 500; }
.pkilint-message { color: #a8b4c8; font-size: 0.69rem; }
.pkilint-path    { color: #6b7a90; font-size: 0.67rem; font-style: italic; }
.pkilint-validator { color: #4a5568; font-size: 0.65rem; }
</style>';

    return $styles
        . '<div class="pkilint-output">'
        . $notices
        . $summary
        . '<div class="pkilint-rows">' . $rows . '</div>'
        . '</div>';
}

// ── Generic run factory ───────────────────────────────────────────────────────
// Builds a run callable for a single-file pkilint command.
// $extra_args: array of flags to prepend before the file argument.

function pkilint_make_run(string $cmd, array $extra_args, bool $needs_issuer): callable {
    $bin = pkilint_binary($cmd);

    return function (string $ee_pem, ?string $root_pem) use ($cmd, $bin, $extra_args, $needs_issuer): string {
        if ($bin === null) {
            throw new RuntimeException(
                "'{$cmd}' binary not found in PATH. "
                . "Install pkilint via pipx and ensure the commands are executable by the web server."
            );
        }

        // Re-export EE through OpenSSL for a clean, normalised PEM.
        $cert = openssl_x509_read($ee_pem);
        if ($cert === false) {
            throw new RuntimeException(
                'End-entity certificate: failed to read via openssl_x509_read.'
            );
        }
        openssl_x509_export($cert, $ee_clean);

        $tmp_ee     = null;
        $tmp_issuer = null;

        try {
            $tmp_ee = pkilint_write_pem($ee_clean);

            if ($needs_issuer) {
                if ($root_pem === null) {
                    throw new RuntimeException(
                        'Issuer/root certificate: this linter requires it.'
                    );
                }
                $issuer_cert = openssl_x509_read($root_pem);
                if ($issuer_cert === false) {
                    throw new RuntimeException(
                        'Issuer/root certificate: failed to read via openssl_x509_read.'
                    );
                }
                openssl_x509_export($issuer_cert, $issuer_clean);
                $tmp_issuer = pkilint_write_pem($issuer_clean);
            }

            // Build command:
            //   lint_pkix_signer_signee_cert_chain lint <signer> <signee>
            //   all others: lint [extra_args] <file>
            $arg_parts = array_map('escapeshellarg', $extra_args);

            if ($needs_issuer) {
                // signer = issuer/root, signee = EE
                $file_args = escapeshellarg($tmp_issuer) . ' ' . escapeshellarg($tmp_ee);
            } else {
                $file_args = escapeshellarg($tmp_ee);
            }

            $cmd_str = escapeshellarg($bin)
                . ' lint'
                . ' -f JSON -s INFO'
                . ($arg_parts ? ' ' . implode(' ', $arg_parts) : '')
                . ' ' . $file_args
                . ' 2>&1';

            $lines     = [];
            $exit_code = null;
            exec($cmd_str, $lines, $exit_code);
            $output = implode("\n", $lines);

            if ($output === '') {
                throw new RuntimeException(
                    "'{$cmd}' produced no output (exit code: {$exit_code}). "
                    . "Verify the binary is functional and accessible by the web server."
                );
            }

            return pkilint_render_html($output, $cmd);

        } finally {
            if ($tmp_ee !== null)     @unlink($tmp_ee);
            if ($tmp_issuer !== null) @unlink($tmp_issuer);
        }
    };
}

// ── Binary availability ───────────────────────────────────────────────────────
// Probe each command independently — a partial install is possible.

$cmds = [
    'lint_pkix_cert',
    'lint_cabf_serverauth_cert',
    'lint_cabf_smime_cert',
    'lint_etsi_cert',
    'lint_pkix_signer_signee_cert_chain',
];

$bins = [];
foreach ($cmds as $cmd) {
    $bins[$cmd] = pkilint_binary($cmd);
}

// Version — probe once using lint_pkix_cert (or any available binary).
$probe_bin = null;
foreach ($cmds as $cmd) {
    if ($bins[$cmd] !== null) { $probe_bin = $bins[$cmd]; break; }
}
$pkilint_version = pkilint_version($probe_bin);
$version_suffix  = $pkilint_version !== '' ? ' ' . $pkilint_version : '';

// ── Action definitions ────────────────────────────────────────────────────────

$actions = [
    [
        'id'          => 'pkilint_pkix_cert',
        'label'       => 'lint_pkix_cert' . $version_suffix,
        'cmd'         => 'lint_pkix_cert',
        'extra_args'  => [],
        'needs_root'  => false,
        'output_html' => true,
        'description' => 'RFC 5280 — base PKIX certificate linter',
    ],
    [
        'id'          => 'pkilint_cabf_serverauth',
        'label'       => 'lint_cabf_serverauth_cert' . $version_suffix,
        'cmd'         => 'lint_cabf_serverauth_cert',
        'extra_args'  => ['-d'],   // --detect: auto-detect TLS certificate profile
        'needs_root'  => false,
        'output_html' => true,
        'description' => 'CAB Forum TLS Baseline Requirements — auto-detect profile',
    ],
    [
        'id'          => 'pkilint_cabf_smime',
        'label'       => 'lint_cabf_smime_cert' . $version_suffix,
        'cmd'         => 'lint_cabf_smime_cert',
        'extra_args'  => ['-d'],   // --detect: auto-detect S/MIME profile
        'needs_root'  => false,
        'output_html' => true,
        'description' => 'CAB Forum S/MIME Baseline Requirements — auto-detect profile',
    ],
    [
        'id'          => 'pkilint_etsi',
        'label'       => 'lint_etsi_cert' . $version_suffix,
        'cmd'         => 'lint_etsi_cert',
        'extra_args'  => ['-d'],   // --detect: auto-detect ETSI profile
        'needs_root'  => false,
        'output_html' => true,
        'description' => 'ETSI EN 319 412 / TS 119 495 — auto-detect profile',
    ],
    [
        'id'          => 'pkilint_signer_signee',
        'label'       => 'lint_pkix_signer_signee_cert_chain' . $version_suffix,
        'cmd'         => 'lint_pkix_signer_signee_cert_chain',
        'extra_args'  => [],
        // Takes two positional args: signer (issuer) then signee (EE).
        // The run factory handles this when needs_root=true.
        'needs_root'  => true,
        'output_html' => true,
        'description' => 'RFC 5280 signer/signee chain — requires issuer/root',
    ],
];

// ── Build module actions ──────────────────────────────────────────────────────

$module_actions = [];
foreach ($actions as $def) {
    $available = $bins[$def['cmd']] !== null;
    $module_actions[] = [
        'id'          => $def['id'],
        'label'       => $available
                            ? $def['label']
                            : $def['label'] . ' — not installed',
        'needs_root'  => $def['needs_root'],
        'available'   => $available,
        'output_html' => $def['output_html'],
        'run'         => pkilint_make_run($def['cmd'], $def['extra_args'], $def['needs_root']),
    ];
}

// ── Module descriptor ────────────────────────────────────────────────────────

$module = [
    'id'      => 'pkilint',
    'label'   => 'pkilint',
    'actions' => $module_actions,
];

