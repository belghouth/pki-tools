<?php
/**
 * linters/pkimetal.php — pkimetal module for linters.php
 *
 * pkimetal is a REST API meta-linter that aggregates certlint, pkilint,
 * x509lint, zlint and others behind a single HTTP endpoint.
 * Docs: https://github.com/pkimetal/pkimetal
 *
 * This module calls a pkimetal instance via HTTP — either a local Docker
 * container or a remote instance. The endpoint is configured via the
 * PKIMETAL_URL environment variable (default: http://127.0.0.1:8080).
 *
 * API:
 *   POST /lintcert
 *   Form fields:
 *     b64cert   — PEM or base64 DER of the EE certificate (required)
 *     b64issuer — PEM or base64 DER of the issuer certificate (optional)
 *     format    — response format: "json" (we always request this)
 *
 *   JSON response: array of objects, each with:
 *     "linter"   — linter name (e.g. "zlint", "pkilint", "x509lint")
 *     "severity" — "debug"|"info"|"notice"|"warning"|"error"|"fatal"
 *     "finding"  — finding code / description string
 *
 * This file must only be included by linters.php, never accessed directly.
 */

// ── Direct access guard ──────────────────────────────────────────────────────
if (!isset($linters_dir)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('403 Forbidden: this file must not be accessed directly.');
}

// ── Configuration ────────────────────────────────────────────────────────────

function pkimetal_base_url(): string {
    $env = getenv('PKIMETAL_URL');
    if ($env !== false && $env !== '') {
        return rtrim($env, '/');
    }
    return 'http://127.0.0.1:8080';
}

// ── Availability check ───────────────────────────────────────────────────────
// Probe the pkimetal instance with a lightweight GET /. A 200 or any HTTP
// response (even an error page) means the service is reachable. We use a
// short timeout so a missing instance fails fast rather than hanging the page.

function pkimetal_check(string $base_url): bool {
    if (!function_exists('curl_init')) {
        return false;
    }
    $ch = curl_init($base_url . '/');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 3,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_FOLLOWLOCATION => false,
    ]);
    curl_exec($ch);
    $http_code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return $http_code > 0;
}

// ── Version detection ────────────────────────────────────────────────────────
// pkimetal embeds its version in the X-Pkimetal-Version response header
// on every endpoint, and also in a /version JSON endpoint.

function pkimetal_version(string $base_url): string {
    if (!function_exists('curl_init')) return '';
    $ch = curl_init($base_url . '/');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 3,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_HEADER         => true,
    ]);
    $response = curl_exec($ch);
    curl_close($ch);
    if ($response === false) return '';
    // Extract X-Pkimetal-Version header value.
    if (preg_match('/X-Pkimetal-Version:\s*(\S+)/i', $response, $m)) {
        return $m[1];
    }
    return '';
}

// ── Output renderer ──────────────────────────────────────────────────────────
// pkimetal JSON response: array of {linter, severity, finding} objects.
// Severity values: debug, info, notice, warning, error, fatal
// (lowercase, unlike pkilint which uses uppercase).

function pkimetal_render_html(string $raw): string {
    $e = fn(string $s): string => htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8');

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return '<div class="pkimetal-output">'
            . '<div class="pkimetal-parse-error">⚠ pkimetal did not return valid JSON. Raw output below.</div>'
            . '<pre class="pkimetal-raw">' . $e($raw) . '</pre>'
            . '</div>';
    }

    // Keys are PascalCase: Linter, Finding, Severity, Field (optional), Code (optional).
    // Severity values: meta | debug | info | notice | warning | error | fatal
    // "meta" rows are timing/version lines — shown collapsed under each linter, not counted.

    $colours = [
        'debug'   => ['bg' => 'rgba(107,122,144,0.05)', 'border' => 'rgba(107,122,144,0.15)', 'text' => '#556070', 'badge_bg' => 'rgba(107,122,144,0.10)'],
        'info'    => ['bg' => 'rgba(107,122,144,0.07)', 'border' => 'rgba(107,122,144,0.20)', 'text' => '#8899aa', 'badge_bg' => 'rgba(107,122,144,0.14)'],
        'notice'  => ['bg' => 'rgba(0,153,255,0.07)',   'border' => 'rgba(0,153,255,0.22)',   'text' => '#4db8ff', 'badge_bg' => 'rgba(0,153,255,0.13)'],
        'warning' => ['bg' => 'rgba(245,166,35,0.08)',  'border' => 'rgba(245,166,35,0.28)',  'text' => '#f5a623', 'badge_bg' => 'rgba(245,166,35,0.15)'],
        'error'   => ['bg' => 'rgba(224,92,92,0.08)',   'border' => 'rgba(224,92,92,0.28)',   'text' => '#e05c5c', 'badge_bg' => 'rgba(224,92,92,0.15)'],
        'fatal'   => ['bg' => 'rgba(200,30,30,0.18)',   'border' => 'rgba(200,30,30,0.55)',   'text' => '#ff2222', 'badge_bg' => 'rgba(200,30,30,0.28)'],
    ];
    $default_colour = ['bg' => 'rgba(58,68,88,0.10)', 'border' => '#2a3040', 'text' => '#d4dae6', 'badge_bg' => 'rgba(58,68,88,0.20)'];

    $severity_order = ['fatal', 'error', 'warning', 'notice', 'info', 'debug'];
    $counts = array_fill_keys($severity_order, 0);

    // Group by linter, separate meta from real findings.
    $by_linter = [];
    foreach ($decoded as $f) {
        $linter   = trim($f['Linter']   ?? $f['linter']   ?? 'unknown');
        $severity = strtolower(trim($f['Severity'] ?? $f['severity'] ?? 'info'));
        $finding  = trim($f['Finding']  ?? $f['finding']  ?? '');
        $field    = trim($f['Field']    ?? $f['field']    ?? '');
        $code     = trim($f['Code']     ?? $f['code']     ?? '');

        if ($finding === '[EndOfResults]') continue;

        if ($severity === 'meta') {
            $by_linter[$linter]['meta'][] = $finding;
        } else {
            $by_linter[$linter]['findings'][] = [
                'severity' => $severity,
                'finding'  => $finding,
                'field'    => $field,
                'code'     => $code,
            ];
            if (isset($counts[$severity])) $counts[$severity]++;
        }
    }

    $real_findings = array_sum($counts);

    $rows = '';
    foreach ($by_linter as $linter => $data) {
        $findings = $data['findings'] ?? [];
        $meta     = $data['meta']     ?? [];

        $rows .= '<div class="pkimetal-linter-group">'
               . '<div class="pkimetal-linter-label">'
               . $e($linter)
               . (count($meta) > 0
                   ? ' <span class="pkimetal-meta">' . $e(implode(' · ', $meta)) . '</span>'
                   : '')
               . '</div>';

        if (count($findings) === 0) {
            $rows .= '<div class="pkimetal-row-clean">✓ No findings</div>';
        }

        foreach ($findings as $item) {
            $sev = $item['severity'];
            $c   = $colours[$sev] ?? $default_colour;
            $rows .= sprintf(
                '<div class="pkimetal-row" style="background:%s;border-left:3px solid %s;">'
                . '<span class="pkimetal-badge" style="color:%s;background:%s;">%s</span>'
                . '<span class="pkimetal-body">'
                . '<span class="pkimetal-finding">%s</span>'
                . ($item['code']  !== '' ? '<span class="pkimetal-code">%s</span>'  : '%s')
                . ($item['field'] !== '' ? '<span class="pkimetal-field">@ %s</span>' : '%s')
                . '</span>'
                . '</div>',
                $c['bg'], $c['border'],
                $c['text'], $c['badge_bg'],
                $e(strtoupper($sev)),
                $e($item['finding']),
                $item['code']  !== '' ? $e($item['code'])  : '',
                $item['field'] !== '' ? $e($item['field']) : ''
            );
        }
        $rows .= '</div>';
    }

    // Summary bar — exclude meta from counts.
    $summary_meta = [
        'fatal'   => '#ff2222',
        'error'   => '#e05c5c',
        'warning' => '#f5a623',
        'notice'  => '#4db8ff',
        'info'    => '#8899aa',
        'debug'   => '#556070',
    ];
    $summary = '<div class="pkimetal-summary">';
    $summary .= '<span class="pkimetal-summary-total"><strong>' . $real_findings . '</strong> finding' . ($real_findings !== 1 ? 's' : '') . '</span>';
    foreach ($summary_meta as $sev => $color) {
        if ($counts[$sev] > 0) {
            $summary .= sprintf(
                '<span class="pkimetal-summary-item" style="color:%s"><strong>%d</strong> %s</span>',
                $color, $counts[$sev], strtoupper($sev)
            );
        }
    }
    $summary .= '</div>';

    $styles = '
<style>
.pkimetal-output { font-family: "IBM Plex Mono", monospace; font-size: 0.72rem; }
.pkimetal-clean {
    padding: 1rem; color: #3ddc7a;
    background: rgba(0,212,100,0.06);
    border: 1px solid rgba(0,212,100,0.2);
    border-radius: 4px; font-weight: 500;
}
.pkimetal-parse-error {
    padding: 0.6rem 0.9rem; color: #f5a623;
    background: rgba(245,166,35,0.08);
    border: 1px solid rgba(245,166,35,0.25);
    border-radius: 4px; margin-bottom: 0.5rem;
}
.pkimetal-raw {
    font-family: "IBM Plex Mono", monospace; font-size: 0.7rem;
    color: #d4dae6; background: #161a21;
    border: 1px solid #2a3040; border-radius: 4px;
    padding: 0.9rem; white-space: pre-wrap; word-break: break-all;
    max-height: 400px; overflow-y: auto;
}
.pkimetal-summary {
    display: flex; align-items: center; gap: 1.25rem; flex-wrap: wrap;
    padding: 0.6rem 0.9rem;
    background: rgba(29,35,48,0.8);
    border: 1px solid #2a3040; border-radius: 4px;
    margin-bottom: 0.75rem;
    font-size: 0.7rem; letter-spacing: 0.05em;
}
.pkimetal-summary-total { color: #d4dae6; }
.pkimetal-summary-total strong { font-size: 0.85rem; }
.pkimetal-summary-item { display: flex; align-items: center; gap: 0.3rem; }
.pkimetal-summary-item strong { font-size: 0.82rem; }
.pkimetal-rows {
    display: flex; flex-direction: column; gap: 4px;
    max-height: 560px; overflow-y: auto;
    border: 1px solid #2a3040; border-radius: 4px;
    background: #161a21; padding: 0.5rem;
}
.pkimetal-linter-group { display: flex; flex-direction: column; gap: 2px; }
.pkimetal-linter-label {
    font-size: 0.62rem; font-weight: 600; letter-spacing: 0.12em;
    text-transform: uppercase; color: #3a4458;
    padding: 0.4rem 0.75rem 0.2rem;
    border-bottom: 1px solid #1d2330;
    margin-top: 0.25rem;
    display: flex; align-items: baseline; gap: 0.75rem;
}
.pkimetal-linter-group:first-child .pkimetal-linter-label { margin-top: 0; }
.pkimetal-meta {
    font-size: 0.58rem; font-weight: 400; letter-spacing: 0.04em;
    text-transform: none; color: #2a3040; font-style: italic;
}
.pkimetal-row-clean {
    padding: 0.25rem 0.75rem;
    font-size: 0.68rem; color: #3ddc7a; font-style: italic;
}
.pkimetal-row {
    display: flex; align-items: flex-start; gap: 0.75rem;
    padding: 0.3rem 0.75rem; line-height: 1.6;
    transition: filter 80ms ease;
}
.pkimetal-row:hover { filter: brightness(1.18); }
.pkimetal-badge {
    flex-shrink: 0; width: 5rem; text-align: center;
    font-weight: 600; font-size: 0.6rem; letter-spacing: 0.1em;
    border-radius: 2px; padding: 0.15em 0.3em; margin-top: 0.15em;
}
.pkimetal-body { display: flex; flex-direction: column; gap: 0.08rem; flex: 1; word-break: break-all; }
.pkimetal-finding { color: #d4dae6; }
.pkimetal-code    { color: #6b7a90; font-size: 0.67rem; }
.pkimetal-field   { color: #4a5568; font-size: 0.65rem; font-style: italic; }
</style>';

    return $styles
        . '<div class="pkimetal-output">'
        . $summary
        . '<div class="pkimetal-rows">' . $rows . '</div>'
        . '</div>';
}

// ── Run function ─────────────────────────────────────────────────────────────

$pkimetal_base_url  = pkimetal_base_url();
$pkimetal_available = pkimetal_check($pkimetal_base_url);
$pkimetal_version   = $pkimetal_available ? pkimetal_version($pkimetal_base_url) : '';
$version_suffix     = $pkimetal_version !== '' ? ' ' . $pkimetal_version : '';

$pkimetal_run = function (string $ee_pem, ?string $root_pem) use ($pkimetal_base_url): string {

    if (!function_exists('curl_init')) {
        throw new RuntimeException('PHP cURL extension is not available.');
    }

    // Re-export through OpenSSL for a clean, normalised PEM.
    $cert = openssl_x509_read($ee_pem);
    if ($cert === false) {
        throw new RuntimeException('End-entity certificate: failed to read via openssl_x509_read.');
    }
    openssl_x509_export($cert, $ee_clean);

    $issuer_clean = '';
    if ($root_pem !== null) {
        $issuer = openssl_x509_read($root_pem);
        if ($issuer === false) {
            throw new RuntimeException('Issuer/root certificate: failed to read via openssl_x509_read.');
        }
        openssl_x509_export($issuer, $issuer_clean);
    }

    $post_fields = http_build_query([
        'b64cert'   => $ee_clean,
        'b64issuer' => $root_pem !== null ? $issuer_clean : '',
        'format'    => 'json',
    ]);

    $ch = curl_init($pkimetal_base_url . '/lintcert');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $post_fields,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_CONNECTTIMEOUT => 5,
    ]);

    $response  = curl_exec($ch);
    $http_code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_err  = curl_error($ch);
    curl_close($ch);

    if ($response === false || $curl_err !== '') {
        throw new RuntimeException(
            'Failed to reach pkimetal at ' . $pkimetal_base_url . ': ' . $curl_err
        );
    }

    if ($http_code !== 200) {
        throw new RuntimeException(
            "pkimetal returned HTTP {$http_code}. "
            . "Check that the instance at {$pkimetal_base_url} is running."
        );
    }

    return pkimetal_render_html($response);
};

// ── Module descriptor ────────────────────────────────────────────────────────

$module = [
    'id'      => 'pkimetal',
    'label'   => 'pkimetal',
    'actions' => [
        [
            'id'          => 'pkimetal_lintcert',
            'label'       => $pkimetal_available
                                 ? 'pkimetal' . $version_suffix
                                 : 'pkimetal — not running',
            'needs_root'  => false,
            'available'   => $pkimetal_available,
            'output_html' => true,
            'run'         => $pkimetal_run,
        ],
    ],
];

