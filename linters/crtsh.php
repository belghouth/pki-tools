<?php
/**
 * linters/crtsh.php — crt.sh lintcert module for linters.php
 *
 * Calls the public crt.sh certificate linting API:
 *   POST https://crt.sh/lintcert
 *   Field: b64cert — base64 DER-encoded certificate (no PEM headers)
 *
 * Response: tab-separated text, one line per finding:
 *   linter \t severity \t description
 *
 * Linters run by crt.sh: certlint, cablint, x509lint
 * Root/issuer is not accepted by this API.
 *
 * This is an external service — availability depends on crt.sh uptime.
 * It is NOT recommended for production CA pre-issuance linting (no SLA).
 *
 * This file must only be included by linters.php, never accessed directly.
 */

// ── Direct access guard ──────────────────────────────────────────────────────
if (!isset($linters_dir)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('403 Forbidden: this file must not be accessed directly.');
}

// ── Severity map ─────────────────────────────────────────────────────────────
// crt.sh uses: B (bug/fatal), E (error), W (warning), N (notice), I (info)
// certlint/cablint use single-letter codes; x509lint uses words.
// We normalise everything to a common severity string.

function crtsh_normalise_severity(string $raw): string {
    $r = strtoupper(trim($raw));
    return match(true) {
        in_array($r, ['B', 'BUG', 'FATAL'])          => 'fatal',
        in_array($r, ['E', 'ERROR'])                  => 'error',
        in_array($r, ['W', 'WARNING', 'WARN'])        => 'warning',
        in_array($r, ['N', 'NOTICE'])                 => 'notice',
        in_array($r, ['I', 'INFO', 'INFORMATION'])    => 'info',
        default                                        => 'info',
    };
}

// ── Output renderer ──────────────────────────────────────────────────────────

function crtsh_render_html(string $raw): string {
    $e = fn(string $s): string => htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8');

    $lines = array_filter(array_map('trim', explode("\n", $raw)));

    if (empty($lines)) {
        return '<div class="crtsh-output">'
            . '<div class="crtsh-clean">✓ No findings reported by crt.sh.</div>'
            . '</div>';
    }

    $colours = [
        'fatal'   => ['bg' => 'rgba(200,30,30,0.18)',   'border' => 'rgba(200,30,30,0.55)',   'text' => '#ff2222', 'badge_bg' => 'rgba(200,30,30,0.28)'],
        'error'   => ['bg' => 'rgba(224,92,92,0.08)',   'border' => 'rgba(224,92,92,0.28)',   'text' => '#e05c5c', 'badge_bg' => 'rgba(224,92,92,0.15)'],
        'warning' => ['bg' => 'rgba(245,166,35,0.08)',  'border' => 'rgba(245,166,35,0.28)',  'text' => '#f5a623', 'badge_bg' => 'rgba(245,166,35,0.15)'],
        'notice'  => ['bg' => 'rgba(0,153,255,0.07)',   'border' => 'rgba(0,153,255,0.22)',   'text' => '#4db8ff', 'badge_bg' => 'rgba(0,153,255,0.13)'],
        'info'    => ['bg' => 'rgba(107,122,144,0.07)', 'border' => 'rgba(107,122,144,0.20)', 'text' => '#8899aa', 'badge_bg' => 'rgba(107,122,144,0.14)'],
    ];
    $default_colour = ['bg' => 'rgba(58,68,88,0.10)', 'border' => '#2a3040', 'text' => '#d4dae6', 'badge_bg' => 'rgba(58,68,88,0.20)'];

    $severity_order = ['fatal', 'error', 'warning', 'notice', 'info'];
    $counts = array_fill_keys($severity_order, 0);

    // Group by linter.
    $by_linter = [];
    foreach ($lines as $line) {
        $parts = explode("\t", $line, 3);
        if (count($parts) < 3) {
            // Malformed line — put in a catch-all group.
            $by_linter['crt.sh'][] = ['severity' => 'info', 'description' => $line];
            continue;
        }
        [$linter, $severity_raw, $description] = $parts;
        $linter      = trim($linter);
        $severity    = crtsh_normalise_severity($severity_raw);
        $description = trim($description);

        $by_linter[$linter][] = ['severity' => $severity, 'description' => $description];
        if (isset($counts[$severity])) $counts[$severity]++;
    }

    $rows = '';
    foreach ($by_linter as $linter => $items) {
        $rows .= '<div class="crtsh-linter-group">'
               . '<div class="crtsh-linter-label">' . $e($linter) . '</div>';
        foreach ($items as $item) {
            $sev = $item['severity'];
            $c   = $colours[$sev] ?? $default_colour;
            $rows .= sprintf(
                '<div class="crtsh-row" style="background:%s;border-left:3px solid %s;">'
                . '<span class="crtsh-badge" style="color:%s;background:%s;">%s</span>'
                . '<span class="crtsh-description">%s</span>'
                . '</div>',
                $c['bg'], $c['border'],
                $c['text'], $c['badge_bg'],
                $e(strtoupper($sev)),
                $e($item['description'])
            );
        }
        $rows .= '</div>';
    }

    // Summary bar.
    $summary_meta = [
        'fatal'   => '#ff2222',
        'error'   => '#e05c5c',
        'warning' => '#f5a623',
        'notice'  => '#4db8ff',
        'info'    => '#8899aa',
    ];
    $total = array_sum($counts);
    $summary = '<div class="crtsh-summary">';
    $summary .= '<span class="crtsh-summary-total"><strong>' . $total . '</strong> finding' . ($total !== 1 ? 's' : '') . '</span>';
    foreach ($summary_meta as $sev => $color) {
        if ($counts[$sev] > 0) {
            $summary .= sprintf(
                '<span class="crtsh-summary-item" style="color:%s"><strong>%d</strong> %s</span>',
                $color, $counts[$sev], strtoupper($sev)
            );
        }
    }
    $summary .= '</div>';

    $styles = '
<style>
.crtsh-output { font-family: "IBM Plex Mono", monospace; font-size: 0.72rem; }
.crtsh-clean {
    padding: 1rem; color: #3ddc7a;
    background: rgba(0,212,100,0.06);
    border: 1px solid rgba(0,212,100,0.2);
    border-radius: 4px; font-weight: 500;
}
.crtsh-summary {
    display: flex; align-items: center; gap: 1.25rem; flex-wrap: wrap;
    padding: 0.6rem 0.9rem;
    background: rgba(29,35,48,0.8);
    border: 1px solid #2a3040; border-radius: 4px;
    margin-bottom: 0.75rem;
    font-size: 0.7rem; letter-spacing: 0.05em;
}
.crtsh-summary-total { color: #d4dae6; }
.crtsh-summary-total strong { font-size: 0.85rem; }
.crtsh-summary-item { display: flex; align-items: center; gap: 0.3rem; }
.crtsh-summary-item strong { font-size: 0.82rem; }
.crtsh-rows {
    display: flex; flex-direction: column; gap: 4px;
    max-height: 560px; overflow-y: auto;
    border: 1px solid #2a3040; border-radius: 4px;
    background: #161a21; padding: 0.5rem;
}
.crtsh-linter-group { display: flex; flex-direction: column; gap: 2px; }
.crtsh-linter-label {
    font-size: 0.62rem; font-weight: 600; letter-spacing: 0.12em;
    text-transform: uppercase; color: #3a4458;
    padding: 0.4rem 0.75rem 0.2rem;
    border-bottom: 1px solid #1d2330;
    margin-top: 0.25rem;
}
.crtsh-linter-group:first-child .crtsh-linter-label { margin-top: 0; }
.crtsh-row {
    display: flex; align-items: baseline; gap: 0.75rem;
    padding: 0.3rem 0.75rem; line-height: 1.6;
    transition: filter 80ms ease;
}
.crtsh-row:hover { filter: brightness(1.18); }
.crtsh-badge {
    flex-shrink: 0; width: 5rem; text-align: center;
    font-weight: 600; font-size: 0.6rem; letter-spacing: 0.1em;
    border-radius: 2px; padding: 0.15em 0.3em;
}
.crtsh-description { color: #d4dae6; word-break: break-all; flex: 1; }
</style>';

    return $styles
        . '<div class="crtsh-output">'
        . $summary
        . '<div class="crtsh-rows">' . $rows . '</div>'
        . '</div>';
}

// ── Run function ─────────────────────────────────────────────────────────────

$crtsh_run = function (string $ee_pem, ?string $root_pem): string {
    if (!function_exists('curl_init')) {
        throw new RuntimeException('PHP cURL extension is not available.');
    }

    // crt.sh expects base64 DER with no PEM headers and no whitespace.
    $cert = openssl_x509_read($ee_pem);
    if ($cert === false) {
        throw new RuntimeException(
            'End-entity certificate: failed to read via openssl_x509_read.'
        );
    }
    openssl_x509_export($cert, $pem_clean);

    // Strip PEM headers and whitespace to get raw base64 DER.
    $b64 = preg_replace(
        '/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/',
        '',
        $pem_clean
    );

    $ch = curl_init('https://crt.sh/lintcert');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query(['b64cert' => $b64]),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => 'PKI-Linters/1.0',
    ]);

    $response  = curl_exec($ch);
    $http_code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_err  = curl_error($ch);
    curl_close($ch);

    if ($response === false || $curl_err !== '') {
        throw new RuntimeException(
            'Failed to reach crt.sh: ' . $curl_err
        );
    }

    if ($http_code !== 200) {
        throw new RuntimeException(
            "crt.sh returned HTTP {$http_code}. The service may be temporarily unavailable."
        );
    }

    // crt.sh returns an HTML page if the input is rejected (e.g. not valid base64).
    if (str_starts_with(ltrim($response), '<')) {
        throw new RuntimeException(
            'crt.sh returned an HTML response — the certificate may not have been accepted. '
            . 'Check that the input is a valid X.509 certificate.'
        );
    }

    return crtsh_render_html($response);
};

// ── Module descriptor ────────────────────────────────────────────────────────

$module = [
    'id'      => 'crtsh',
    'label'   => 'crt.sh',
    'actions' => [
        [
            'id'          => 'crtsh_lintcert',
            'label'       => 'crt.sh lintcert',
            'needs_root'  => false,
            'available'   => true,
            'output_html' => true,
            'recaptcha'   => 'crtsh_lint',
            'run'         => $crtsh_run,
        ],
    ],
];

