<?php
/**
 * linters.php — PKI Certificate Linting Portal
 *
 * Module contract (./linters/*.php):
 *   Each module must define a $module array before this page includes it.
 *   Required keys:
 *     'id'       (string)  — machine identifier, e.g. 'zlint'
 *     'label'    (string)  — display name, e.g. 'ZLint'
 *     'actions'  (array)   — one or more action descriptors (see below)
 *
 *   Action descriptor keys:
 *     'id'           (string)  — unique within module, e.g. 'zlint_tls'
 *     'label'        (string)  — button label
 *     'needs_root'   (bool)    — whether issuer/root PEM is required
 *     'output_html'  (bool)    — optional; if true, run() returns trusted HTML
 *                                (the module is responsible for its own escaping)
 *     'run'          (callable)— function(string $ee_pem, ?string $root_pem): string
 *                                Returns plain text (escaped here) or HTML when
 *                                output_html is true.
 */

// ── Security headers ─────────────────────────────────────────────────────────
// Sent before any output. Adjust CSP if you load external resources.
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: "
    . "default-src 'self'; "
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    . "font-src https://fonts.gstatic.com; "
    . "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; "
    . "frame-src https://www.google.com; "
    . "connect-src 'self' https://www.google.com; "
    . "object-src 'none'; "
    . "base-uri 'self'; "
    . "form-action 'self';"
);

// ── Session (CSRF) ───────────────────────────────────────────────────────────
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// ── reCAPTCHA ────────────────────────────────────────────────────────────────
require_once __DIR__ . '/recaptcha.php';

// ── Certificate parser ───────────────────────────────────────────────────────
$x509parse_invoked = true;
require_once __DIR__ . '/x509parse.php';

// ── Revocation checker ───────────────────────────────────────────────────────
$revocation_invoked = true;
require_once __DIR__ . '/revocation.php';

// ── Discover modules ────────────────────────────────────────────────────────

$modules = [];
$linters_dir = __DIR__ . '/linters';

if (is_dir($linters_dir)) {
    foreach (glob($linters_dir . '/*.php') as $module_file) {
        $module = null;
        include $module_file;
        if (
            isset($module) &&
            is_array($module) &&
            isset($module['id'], $module['label'], $module['actions']) &&
            is_array($module['actions']) &&
            count($module['actions']) > 0
        ) {
            $modules[$module['id']] = $module;
        }
    }
}

$has_modules = count($modules) > 0;

// ── Certificate validation helpers ─────────────────────────────────────────

/**
 * Validates and normalises a PEM certificate.
 * Returns the normalised PEM string, or null on failure.
 */
function parse_pem(string $raw): ?string {
    $raw = trim($raw);
    // Strip and re-wrap: accept with or without headers, handle line breaks
    $stripped = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $raw);
    if (!preg_match('/^[A-Za-z0-9+\/]+=*$/', $stripped) || strlen($stripped) === 0) {
        return null;
    }
    $pem = "-----BEGIN CERTIFICATE-----\n"
         . chunk_split($stripped, 64, "\n")
         . "-----END CERTIFICATE-----\n";
    // Verify openssl can parse it
    $cert = openssl_x509_read($pem);
    if ($cert === false) {
        return null;
    }
    return $pem;
}

// ── Domain sanitiser ─────────────────────────────────────────────────────────

/**
 * Extracts a clean hostname from arbitrary user input.
 * Strips scheme, credentials, port, path, query, fragment.
 * Returns null if the result is not a valid hostname.
 */
function sanitise_domain(string $input): ?string {
    $input = trim($input);
    if ($input === '') return null;

    // Prepend a scheme if absent so parse_url works reliably.
    if (!preg_match('#^[a-zA-Z][a-zA-Z0-9+\-.]*://#', $input)) {
        $input = 'https://' . $input;
    }

    $host = parse_url($input, PHP_URL_HOST);
    if (!is_string($host) || $host === '') return null;

    // Strip surrounding brackets from IPv6 literals — then reject IPs entirely.
    $host = trim($host, '[]');

    // Reject bare IPv4.
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return null;
    // Reject IPv6.
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return null;

    // Validate hostname: labels of 1–63 chars, only alnum and hyphens,
    // no leading/trailing hyphens, at least one dot (not a bare name).
    $host = strtolower($host);
    if (strlen($host) > 253) return null;
    $labels = explode('.', $host);
    if (count($labels) < 2) return null;
    foreach ($labels as $label) {
        if ($label === '') return null;
        if (strlen($label) > 63) return null;
        if (!preg_match('/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$/', $label)) return null;
    }

    return $host;
}

/**
 * Connects to $host:443 via TLS and retrieves the EE certificate and
 * the chain (intermediate + root) presented by the server.
 * Returns ['ee' => PEM, 'chain' => [PEM, ...], 'error' => null]
 * or      ['ee' => null, 'chain' => [], 'error' => 'message']
 * Connects regardless of certificate validity (expired, revoked, etc.).
 */
function fetch_tls_certs(string $host): array {
    $result = ['ee' => null, 'chain' => [], 'error' => null];

    $ctx = stream_context_create([
        'ssl' => [
            'capture_peer_cert'       => true,
            'capture_peer_cert_chain' => true,
            'verify_peer'             => false,   // connect regardless of validity
            'verify_peer_name'        => false,
            'SNI_enabled'             => true,
            'peer_name'               => $host,
        ],
    ]);

    $addr   = 'ssl://' . $host . ':443';
    $errno  = 0;
    $errstr = '';
    $conn   = @stream_socket_client($addr, $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $ctx);

    if ($conn === false) {
        // Map common errno values to human-readable messages.
        $msg = match(true) {
            $errstr !== ''       => $errstr,
            $errno === 110       => 'Connection timed out.',
            $errno === 111       => 'Connection refused — port 443 may not be open.',
            $errno === 113       => 'No route to host.',
            default              => "Connection failed (errno {$errno}).",
        };
        $result['error'] = "Could not connect to {$host}:443 — {$msg}";
        return $result;
    }

    $params = stream_context_get_params($conn);
    fclose($conn);

    $chain_resources = $params['options']['ssl']['peer_certificate_chain'] ?? [];
    $ee_resource     = $params['options']['ssl']['peer_certificate']       ?? null;

    if ($ee_resource === null && !empty($chain_resources)) {
        $ee_resource = $chain_resources[0];
    }

    if ($ee_resource === null) {
        $result['error'] = "Connected to {$host}:443 but no certificate was presented.";
        return $result;
    }

    // Export EE.
    openssl_x509_export($ee_resource, $ee_pem);
    $result['ee'] = $ee_pem;

    // Export chain (skip index 0 = EE, keep intermediates and root).
    foreach ($chain_resources as $i => $res) {
        if ($i === 0) continue;
        openssl_x509_export($res, $chain_pem);
        $result['chain'][] = $chain_pem;
    }

    return $result;
}

// ── Handle domain fetch (separate from linting POST) ─────────────────────────

$fetch_error    = null;
$fetch_success  = null;
// Persist domain value across all POST types.
$fetched_domain = trim($_POST['domain'] ?? '');
$prefill_ee     = '';
$prefill_root   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['fetch_domain'])) {

    // CSRF — same token, same check.
    $submitted_token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($csrf_token, $submitted_token)) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $csrf_token = $_SESSION['csrf_token'];
        $fetch_error = 'Invalid or expired form token. Please try again.';
    } else {
        // reCAPTCHA verification for domain fetch.
        if (recaptcha_configured()) {
            $recap_token = trim($_POST['g_recaptcha_token'] ?? '');
            if (!recaptcha_verify($recap_token, 'fetch_domain')) {
                $fetch_error = 'reCAPTCHA verification failed. Please try again.';
            }
        }
    }

    if ($fetch_error === null) {
        $raw_domain     = trim($_POST['domain'] ?? '');
        $fetched_domain = $raw_domain;
        $clean_host     = sanitise_domain($raw_domain);

        if ($clean_host === null) {
            $fetch_error = 'Invalid domain name. Enter a hostname like example.com — no IP addresses, no bare names.';
        } else {
            $fetched_domain = $clean_host;
            $tls = fetch_tls_certs($clean_host);

            if ($tls['error'] !== null) {
                $fetch_error = $tls['error'];
            } else {
                $prefill_ee   = trim($tls['ee']);
                // Populate root field with the first chain cert (direct issuer / intermediate).
                // If the server sends multiple intermediates, use the first one —
                // it is the direct issuer of the EE.
                $prefill_root = !empty($tls['chain']) ? trim($tls['chain'][0]) : '';
                $chain_count  = count($tls['chain']);
                $fetch_success = "Retrieved certificate from {$clean_host}"
                    . ($chain_count > 0 ? " + {$chain_count} chain certificate" . ($chain_count > 1 ? 's' : '') : '')
                    . '. Fields populated below.';
            }
        }
    }
}



$result_output      = null;
$result_output_html = false;
$result_action      = null;
$result_module      = null;
$form_error         = null;
$revoc_output       = null;
$revoc_action_label = null;
// Pre-populate from a domain fetch if one just completed successfully.
$posted_ee_pem   = $prefill_ee;
$posted_root_pem = $prefill_root;

// ── Handle revocation POST ───────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['revoc_action'])
    && revocation_is_action(trim($_POST['revoc_action']))
) {
    $submitted_token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($csrf_token, $submitted_token)) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $csrf_token = $_SESSION['csrf_token'];
        $form_error = 'Invalid or expired form token. Please try again.';
    } else {
        $posted_ee_pem   = trim($_POST['ee_pem']   ?? '') ?: $prefill_ee;
        $posted_root_pem = trim($_POST['root_pem'] ?? '') ?: $prefill_root;
        $revoc_action    = trim($_POST['revoc_action']);

        $ee_parsed = parse_pem($posted_ee_pem);
        if ($ee_parsed === null) {
            $form_error = 'End-entity certificate: not valid PEM or could not be parsed by OpenSSL.';
        } else {
            $root_parsed = $posted_root_pem !== '' ? parse_pem($posted_root_pem) : null;
            if ($posted_root_pem !== '' && $root_parsed === null) {
                $form_error = 'Issuer/root certificate: not valid PEM or could not be parsed by OpenSSL.';
            } else {
                try {
                    $revoc_output = revocation_handle_post($revoc_action, $ee_parsed, $root_parsed);
                    $revoc_action_label = match($revoc_action) {
                        'revoc_ocsp'  => 'OCSP',
                        'revoc_crl'   => 'CRL',
                        'revoc_delta' => 'Delta CRL',
                        default       => 'Revocation',
                    };
                } catch (Throwable $e) {
                    $form_error = 'Revocation error: ' . $e->getMessage();
                }
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $has_modules && !isset($_POST['fetch_domain']) && !isset($_POST['revoc_action'])) {

    // CSRF validation — must be first.
    $submitted_token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($csrf_token, $submitted_token)) {
        // Rotate token after a failed check to prevent fixation.
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $csrf_token = $_SESSION['csrf_token'];
        $form_error = 'Invalid or expired form token. Please try again.';
    }

    if ($form_error === null) {
        // Use whatever is in the POST fields; fall back to prefill only if absent.
        $posted_ee_pem   = trim($_POST['ee_pem']   ?? '') ?: $prefill_ee;
        $posted_root_pem = trim($_POST['root_pem'] ?? '') ?: $prefill_root;

        // Button value is "module_id:action_id" — split on the first colon only.
        $linter_action = trim($_POST['linter_action'] ?? '');
        $colon_pos     = strpos($linter_action, ':');
        $module_id     = $colon_pos !== false ? substr($linter_action, 0, $colon_pos)      : '';
        $action_id     = $colon_pos !== false ? substr($linter_action, $colon_pos + 1) : '';

        // Locate the requested action.
        $action_def = null;
        $module_def = null;
        if (isset($modules[$module_id])) {
            $module_def = $modules[$module_id];
            foreach ($module_def['actions'] as $a) {
                if ($a['id'] === $action_id) {
                    $action_def = $a;
                    break;
                }
            }
        }

        if ($action_def === null) {
            $form_error = 'Unknown action submitted.';
        } elseif (isset($action_def['available']) && $action_def['available'] === false) {
            $form_error = 'This linter is not installed or cannot be executed on this server.';
        } else {
            // reCAPTCHA check for protected actions — runs before certificate validation.
            if (!empty($action_def['recaptcha']) && recaptcha_configured()) {
                $recap_token = trim($_POST['g_recaptcha_token'] ?? '');
                if (!recaptcha_verify($recap_token, $action_def['recaptcha'])) {
                    $form_error = 'reCAPTCHA verification failed. Please try again.';
                }
            }

            if ($form_error === null) {
                // Validate EE certificate (always required).
                if ($posted_ee_pem === '') {
                    $form_error = 'End-entity certificate is required.';
                } else {
                    $ee_pem = parse_pem($posted_ee_pem);
                    if ($ee_pem === null) {
                        $form_error = 'End-entity certificate: not valid PEM or could not be parsed by OpenSSL.';
                    } else {
                        // Validate root/issuer.
                        $root_pem = null;
                        if ($action_def['needs_root']) {
                            if ($posted_root_pem === '') {
                                $form_error = 'Issuer/root certificate: this linter requires it.';
                            } else {
                                $root_pem = parse_pem($posted_root_pem);
                                if ($root_pem === null) {
                                    $form_error = 'Issuer/root certificate: not valid PEM or could not be parsed by OpenSSL.';
                                }
                            }
                        } elseif ($posted_root_pem !== '') {
                            // Optional root supplied — validate it anyway.
                            $root_pem = parse_pem($posted_root_pem);
                            if ($root_pem === null) {
                                $form_error = 'Issuer/root certificate: not valid PEM or could not be parsed by OpenSSL.';
                            }
                        }

                        if ($form_error === null) {
                            try {
                                $result_output      = call_user_func($action_def['run'], $ee_pem, $root_pem);
                                $result_output_html = !empty($action_def['output_html']);
                                $result_action      = $action_def['label'];
                                $result_module      = $module_def['label'];
                            } catch (Throwable $e) {
                                $form_error = 'Linter error: ' . $e->getMessage();
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Auto-fill domain from certificate when field is empty ────────────────────
// If the domain field is blank but we have a valid EE cert, extract the
// most useful hostname: first SAN DNS entry, falling back to CN.

if ($fetched_domain === '') {
    $cert_for_domain = $posted_ee_pem !== '' ? parse_pem($posted_ee_pem) : null;
    if ($cert_for_domain !== null) {
        $cert_res = openssl_x509_read($cert_for_domain);
        $cert_dat = $cert_res ? openssl_x509_parse($cert_res) : null;
        if ($cert_dat) {
            // Try first DNS SAN.
            $san_raw = $cert_dat['extensions']['subjectAltName'] ?? '';
            if ($san_raw !== '') {
                foreach (array_map('trim', explode(',', $san_raw)) as $san) {
                    if (str_starts_with($san, 'DNS:')) {
                        $candidate = trim(substr($san, 4));
                        // Skip wildcards — not usable as a fetch target.
                        if ($candidate !== '' && !str_starts_with($candidate, '*.')) {
                            $fetched_domain = $candidate;
                            break;
                        }
                    }
                }
            }
            // Fall back to CN.
            if ($fetched_domain === '') {
                $cn = $cert_dat['subject']['CN'] ?? '';
                // CN may be an org name, not a hostname — validate it.
                if ($cn !== '' && sanitise_domain($cn) !== null) {
                    $fetched_domain = $cn;
                }
            }
        }
    }
}

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<?php
require_once __DIR__ . '/includes/seo.php';
seo_head([
  'title'       => 'Meerkat Multi-Linter — zlint, pkilint, x509lint, and crt.sh  | thameur.org',
  'description' => 'Run any X.509 certificate through zlint, pkilint, and x509lint simultaneously. Flags CA/Browser Forum Baseline Requirement violations and RFC 5280 issues with direct requirement references.',
  'url'         => 'https://thameur.org/linters.php',
  'jsonld'      => json_encode([
    '@context'            => 'https://schema.org',
    '@type'               => 'WebApplication',
    'name'                => 'Meerkat Multi-Linter',
    'url'                 => 'https://thameur.org/linters.php',
    'description'         => 'Run any X.509 certificate through zlint, pkilint, and x509lint simultaneously.',
    'applicationCategory' => 'SecurityApplication',
    'operatingSystem'     => 'Any',
    'isAccessibleForFree' => true,
    'author'              => ['@id' => 'https://thameur.org/#person', 'name' => 'Thameur Belghith'],
  ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
]);
?>
<?php if (recaptcha_configured()): ?>
<?= recaptcha_head() ?>
<?php endif; ?>
<style>
  /* ── Fonts ── */
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,400;0,500;0,600;1,400&family=IBM+Plex+Sans:wght@300;400;500&display=swap');

  /* ── Tokens ── */
  :root {
    --bg:        #0e1014;
    --surface:   #161a21;
    --surface2:  #1d2330;
    --border:    #2a3040;
    --border2:   #3a4458;
    --accent:    #00d4aa;
    --accent2:   #0099ff;
    --warn:      #f5a623;
    --danger:    #e05c5c;
    --text:      #d4dae6;
    --muted:     #6b7a90;
    --mono:      'IBM Plex Mono', monospace;
    --sans:      'IBM Plex Sans', sans-serif;
    --radius:    4px;
    --transition: 140ms ease;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  html { font-size: 15px; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-weight: 300;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }

  /* ── Layout ── */
  .site-header {
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    display: flex;
    align-items: stretch;
    gap: 2rem;
    height: 52px;
    position: sticky;
    top: 0;
    background: var(--bg);
    z-index: 10;
  }

  .home-link {
    font-family: var(--mono);
    font-size: 1rem;
    color: var(--muted);
    text-decoration: none;
    display: flex;
    align-items: center;
    padding: 0 0.25rem;
    transition: color var(--transition);
  }

  .home-link:hover {
    color: var(--accent);
  }

  .site-header .logo {
    font-family: var(--mono);
    font-size: 0.8rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--accent);
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  .site-header .logo::before {
    content: '';
    display: inline-block;
    width: 8px; height: 8px;
    background: var(--accent);
    border-radius: 50%;
    animation: pulse 2.4s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50%       { opacity: 0.4; transform: scale(0.85); }
  }

  .site-header .version {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--muted);
    display: flex;
    align-items: center;
  }

  main {
    flex: 1;
    max-width: 920px;
    width: 100%;
    margin: 0 auto;
    padding: 2.5rem 2rem 4rem;
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }

  /* ── Page title ── */
  .page-title {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .page-title h1 {
    font-family: var(--mono);
    font-size: 1.1rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    color: var(--text);
  }

  .page-title p {
    font-size: 0.82rem;
    color: var(--muted);
    font-weight: 300;
  }

  /* ── Empty state ── */
  .empty-state {
    border: 1px dashed var(--border2);
    border-radius: var(--radius);
    padding: 3rem 2rem;
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.75rem;
    animation: fadein 0.4s ease;
  }

  .empty-state .icon {
    font-size: 2rem;
    opacity: 0.35;
  }

  .empty-state h2 {
    font-family: var(--mono);
    font-size: 0.85rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--muted);
  }

  .empty-state p {
    font-size: 0.8rem;
    color: var(--muted);
    max-width: 380px;
    line-height: 1.6;
  }

  .empty-state code {
    font-family: var(--mono);
    font-size: 0.75rem;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.15em 0.5em;
    color: var(--accent);
  }

  /* ── Form card ── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    animation: fadein 0.35s ease;
  }

  .card-header {
    padding: 0.75rem 1.25rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  .card-header h2 {
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
  }

  .card-header .dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--accent2);
    flex-shrink: 0;
  }

  .card-body {
    padding: 1.5rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  /* ── Form fields ── */
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
  }

  .field label {
    font-family: var(--mono);
    font-size: 0.7rem;
    font-weight: 500;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .field label .badge {
    font-size: 0.62rem;
    font-weight: 600;
    padding: 0.1em 0.45em;
    border-radius: 2px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  .badge-required {
    background: rgba(224, 92, 92, 0.15);
    color: var(--danger);
    border: 1px solid rgba(224, 92, 92, 0.3);
  }

  .badge-optional {
    background: rgba(107, 122, 144, 0.15);
    color: var(--muted);
    border: 1px solid var(--border);
  }

  .field textarea {
    font-family: var(--mono);
    font-size: 0.72rem;
    line-height: 1.7;
    background: var(--surface2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.8rem 1rem;
    resize: vertical;
    min-height: 130px;
    width: 100%;
    transition: border-color var(--transition), box-shadow var(--transition);
    outline: none;
    caret-color: var(--accent);
  }

  .field textarea::placeholder {
    color: var(--muted);
    opacity: 0.6;
    font-style: italic;
  }

  .field textarea:focus {
    border-color: var(--accent2);
    box-shadow: 0 0 0 2px rgba(0, 153, 255, 0.1);
  }

  .field textarea.error {
    border-color: var(--danger);
    box-shadow: 0 0 0 2px rgba(224, 92, 92, 0.1);
  }

  .field-hint {
    font-size: 0.7rem;
    color: var(--muted);
    font-weight: 300;
    line-height: 1.5;
  }

  /* ── Domain fetch field ── */
  .domain-field {
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
  }

  .domain-row {
    display: flex;
    gap: 0.5rem;
    align-items: stretch;
  }

  .domain-input {
    font-family: var(--mono);
    font-size: 0.78rem;
    background: var(--surface2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.55rem 0.9rem;
    flex: 1;
    outline: none;
    caret-color: var(--accent);
    transition: border-color var(--transition), box-shadow var(--transition);
  }

  .domain-input::placeholder { color: var(--muted); opacity: 0.6; }

  .domain-input:focus {
    border-color: var(--accent2);
    box-shadow: 0 0 0 2px rgba(0,153,255,0.1);
  }

  .domain-input.error {
    border-color: var(--danger);
    box-shadow: 0 0 0 2px rgba(224,92,92,0.1);
  }

  .btn-fetch {
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    background: rgba(0,153,255,0.1);
    color: var(--accent2);
    border: 1px solid rgba(0,153,255,0.3);
    border-radius: var(--radius);
    padding: 0.55rem 1.1rem;
    cursor: pointer;
    white-space: nowrap;
    transition: background var(--transition), border-color var(--transition);
  }

  .btn-fetch:hover {
    background: rgba(0,153,255,0.18);
    border-color: rgba(0,153,255,0.55);
  }

  .alert-success {
    background: rgba(0,212,100,0.07);
    border: 1px solid rgba(0,212,100,0.25);
    color: #3ddc7a;
  }

  /* ── Divider ── */
  .divider {
    height: 1px;
    background: var(--border);
    margin: 0.25rem 0;
  }

  /* ── Alert ── */
  .alert {
    display: flex;
    gap: 0.75rem;
    align-items: flex-start;
    padding: 0.75rem 1rem;
    border-radius: var(--radius);
    font-size: 0.78rem;
    line-height: 1.55;
    animation: fadein 0.25s ease;
  }

  .alert-error {
    background: rgba(224, 92, 92, 0.08);
    border: 1px solid rgba(224, 92, 92, 0.3);
    color: #e88;
  }

  .alert-icon {
    font-size: 0.9rem;
    flex-shrink: 0;
    margin-top: 0.05em;
  }

  /* ── Linter buttons section ── */
  .linters-section {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .linter-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .linter-group-label {
    font-family: var(--mono);
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--muted);
    padding-bottom: 0.25rem;
    border-bottom: 1px solid var(--border);
  }

  .linter-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .btn-linter {
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 500;
    letter-spacing: 0.06em;
    color: var(--text);
    background: var(--surface2);
    border: 1px solid var(--border2);
    border-radius: var(--radius);
    padding: 0.5rem 1.1rem;
    cursor: pointer;
    transition:
      background var(--transition),
      border-color var(--transition),
      color var(--transition),
      transform var(--transition),
      box-shadow var(--transition);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .btn-linter:hover {
    background: rgba(0, 212, 170, 0.08);
    border-color: var(--accent);
    color: var(--accent);
    transform: translateY(-1px);
    box-shadow: 0 3px 10px rgba(0, 212, 170, 0.12);
  }

  .btn-linter:active {
    transform: translateY(0);
    box-shadow: none;
  }

  .btn-linter .arrow {
    opacity: 0;
    transform: translateX(-4px);
    transition: opacity var(--transition), transform var(--transition);
    font-size: 0.7rem;
  }

  .btn-linter:hover .arrow {
    opacity: 1;
    transform: translateX(0);
  }

  .btn-linter:disabled {
    opacity: 0.38;
    cursor: not-allowed;
    border-color: var(--border);
    color: var(--muted);
  }

  .btn-linter:disabled:hover {
    background: var(--surface2);
    border-color: var(--border);
    color: var(--muted);
    transform: none;
    box-shadow: none;
  }

  .btn-linter:disabled .arrow {
    display: none;
  }

  .unavailable-icon {
    font-size: 0.65rem;
    color: var(--danger);
  }

  /* ── Results card ── */
  .result-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    animation: slidein 0.3s ease;
  }

  .result-header {
    padding: 0.75rem 1.25rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    background: rgba(0, 212, 170, 0.04);
  }

  .result-header-left {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  .result-header h3 {
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--accent);
  }

  .result-header .dot-result {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--accent);
    flex-shrink: 0;
    box-shadow: 0 0 6px var(--accent);
  }

  .result-action-badge {
    font-family: var(--mono);
    font-size: 0.65rem;
    font-weight: 600;
    color: var(--muted);
    letter-spacing: 0.08em;
  }

  .result-body {
    padding: 1.25rem;
  }

  .result-body pre {
    font-family: var(--mono);
    font-size: 0.72rem;
    line-height: 1.8;
    color: var(--text);
    white-space: pre-wrap;
    word-break: break-all;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1rem;
    max-height: 480px;
    overflow-y: auto;
  }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: var(--surface2); }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--muted); }

  /* ── Footer ── */
  footer {
    border-top: 1px solid var(--border);
    padding: 0.9rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
  }

  footer p {
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--muted);
    letter-spacing: 0.05em;
  }

  footer .module-count {
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--muted);
  }

  footer .module-count span {
    color: var(--accent);
    font-weight: 600;
  }

  /* ── Animations ── */
  @keyframes fadein {
    from { opacity: 0; transform: translateY(6px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  @keyframes slidein {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
  }
</style>
  <?php require __DIR__ . '/includes/adsense_head.php'; ?>
</head>
<body>

<?php $navLabel = 'Certificate Linters'; require __DIR__ . '/includes/site_nav.php'; ?>

<main>

  <div class="page-title">
    <h1>Certificate Linting</h1>
    <p>Post-issuance linting of X.509 certificates against WebPKI requirements.</p>
  </div>

<?php if (!$has_modules): ?>

  <div class="empty-state">
    <div class="icon">⬡</div>
    <h2>No modules installed</h2>
    <p>
      Place linter modules in the <code>./linters/</code> directory to get started.
      Each <code>.php</code> file in that directory is loaded as a linting module.
    </p>
  </div>

<?php else: ?>

  <?php if ($form_error): ?>
  <div class="alert alert-error">
    <span class="alert-icon">✕</span>
    <span><?= htmlspecialchars($form_error) ?></span>
  </div>
  <?php endif; ?>

  <form method="POST" action="<?= htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?>">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?>">
    <?php if (recaptcha_configured()): ?>
    <input type="hidden" name="g_recaptcha_token" id="g_recaptcha_token">
    <?php endif; ?>
    <div class="card">
      <div class="card-header">
        <div class="dot"></div>
        <h2>Certificate Input</h2>
      </div>
      <div class="card-body">

        <div class="field">
          <label>
            End-Entity Certificate
            <span class="badge badge-required">Required</span>
          </label>
          <textarea
            name="ee_pem"
            rows="7"
            spellcheck="false"
            autocomplete="off"
            placeholder="-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
...
-----END CERTIFICATE-----"
            class="<?= ($form_error && str_contains($form_error, 'End-entity')) ? 'error' : '' ?>"
          ><?= htmlspecialchars($posted_ee_pem, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?></textarea>
          <span class="field-hint">PEM-encoded X.509 certificate, including the <code>-----BEGIN / END CERTIFICATE-----</code> headers.</span>
        </div>

        <div class="field">
          <label>
            Issuer / Root CA Certificate
            <span class="badge badge-optional">Optional — required by some linters</span>
          </label>
          <textarea
            name="root_pem"
            rows="5"
            spellcheck="false"
            autocomplete="off"
            placeholder="-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADCBjjEL
...
-----END CERTIFICATE-----"
            class="<?= ($form_error && str_contains($form_error, 'Issuer/root')) ? 'error' : '' ?>"
          ><?= htmlspecialchars($posted_root_pem, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?></textarea>
          <span class="field-hint">Direct issuer of the end-entity certificate. Required when a linter button indicates chain validation. Leave blank if not available.</span>
        </div>

        <?php if ($fetch_error): ?>
        <div class="alert alert-error">
          <span class="alert-icon">✕</span>
          <span><?= htmlspecialchars($fetch_error, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?></span>
        </div>
        <?php endif; ?>

        <?php if ($fetch_success): ?>
        <div class="alert alert-success">
          <span class="alert-icon">✓</span>
          <span><?= htmlspecialchars($fetch_success, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?></span>
        </div>
        <?php endif; ?>

        <div class="domain-field">
          <label class="field" style="flex-direction:row;align-items:center;gap:0.5rem;margin-bottom:0;">
            <span style="font-family:var(--mono);font-size:0.7rem;font-weight:500;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);">
              Fetch from Domain
            </span>
            <span class="badge badge-optional">optional</span>
          </label>
          <div class="domain-row">
            <input
              type="text"
              name="domain"
              class="domain-input <?= $fetch_error && isset($_POST['fetch_domain']) ? 'error' : '' ?>"
              placeholder="example.com or https://example.com/path"
              value="<?= htmlspecialchars($fetched_domain, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?>"
              spellcheck="false"
              autocomplete="off"
              autocapitalize="none"
            >
            <button type="submit" name="fetch_domain" value="1" class="btn-fetch">
              Fetch Certificate →
            </button>
          </div>
          <span class="field-hint">
            Connects to port 443 regardless of certificate validity (expired, revoked, untrusted).
            Populates the fields above with the EE and first chain certificate.
          </span>
        </div>

        <div class="divider"></div>

        <div class="linters-section">
          <?php foreach ($modules as $mod): ?>
          <div class="linter-group">
            <div class="linter-group-label"><?= htmlspecialchars($mod['label'], ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?></div>
            <div class="linter-buttons">
              <?php foreach ($mod['actions'] as $action):
                $available = !isset($action['available']) || $action['available'] === true;
                $title = $available
                    ? ($action['needs_root'] ? 'Requires issuer/root certificate' : 'Root certificate optional')
                    : 'This linter is not installed or cannot be executed';
                // Encode both IDs into a single value: "module_id:action_id"
                $btn_value = $mod['id'] . ':' . $action['id'];
              ?>
              <button
                type="submit"
                name="linter_action"
                value="<?= htmlspecialchars($btn_value, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?>"
                class="btn-linter"
                title="<?= htmlspecialchars($title, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?>"
                formaction="<?= htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?>"
                <?= !$available ? 'disabled' : '' ?>
              >
                <?php if (!$available): ?>
                  <span class="unavailable-icon">✕</span>
                <?php endif; ?>
                <?= htmlspecialchars($action['label'], ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?>
                <?php if ($available): ?><span class="arrow">→</span><?php endif; ?>
              </button>
              <?php endforeach; ?>
            </div>
          </div>
          <?php endforeach; ?>
        </div>

        <?php
        // Render revocation buttons when a valid EE cert is present.
        $revoc_ee = $posted_ee_pem !== '' ? parse_pem($posted_ee_pem) : null;
        if ($revoc_ee !== null):
        ?>
        <div class="divider"></div>
        <?= revocation_buttons($revoc_ee, $posted_root_pem !== '' ? parse_pem($posted_root_pem) : null) ?>
        <?php endif; ?>

      </div>
    </div>
  </form>

<?php endif; ?>

<?php if ($result_output !== null): ?>
  <div class="result-card">
    <div class="result-header">
      <div class="result-header-left">
        <div class="dot-result"></div>
        <h3><?= htmlspecialchars($result_module, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?></h3>
      </div>
      <span class="result-action-badge"><?= htmlspecialchars($result_action, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?></span>
    </div>
    <div class="result-body">
      <?php if ($result_output_html): ?>
        <?= $result_output ?>
      <?php else: ?>
        <pre><?= htmlspecialchars($result_output, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?></pre>
      <?php endif; ?>
    </div>
  </div>
<?php endif; ?>

<?php if ($revoc_output !== null): ?>
  <div class="result-card">
    <div class="result-header">
      <div class="result-header-left">
        <div class="dot-result" style="background:var(--warn);box-shadow:0 0 6px var(--warn);"></div>
        <h3>Revocation</h3>
      </div>
      <span class="result-action-badge"><?= htmlspecialchars($revoc_action_label, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') ?></span>
    </div>
    <div class="result-body">
      <?= $revoc_output ?>
    </div>
  </div>
<?php endif; ?>

<?php
// Render the certificate parser whenever a valid EE cert is present —
// either just fetched, just linted, or re-submitted from a previous state.
$parse_pem = $posted_ee_pem;
if ($parse_pem === '' && isset($_POST['ee_pem'])) {
    $parse_pem = trim($_POST['ee_pem']);
}
if ($parse_pem !== '' && parse_pem($parse_pem) !== null):
?>
  <div class="result-card">
    <div class="result-header">
      <div class="result-header-left">
        <div class="dot-result" style="background:var(--accent);box-shadow:0 0 6px var(--accent);"></div>
        <h3>Certificate Details</h3>
      </div>
      <span class="result-action-badge">X.509 Structure</span>
    </div>
    <div class="result-body">
      <?= x509parse_render(parse_pem($parse_pem)) ?>
    </div>
  </div>
<?php endif; ?>

</main>

<?php require __DIR__ . '/includes/adsense_unit.php'; ?>

<footer>
  <p>PKI Certificate Linting Portal</p>
  <?php if ($has_modules): ?>
  <p class="module-count"><span><?= count($modules) ?></span> module<?= count($modules) !== 1 ? 's' : '' ?> loaded</p>
  <?php else: ?>
  <p class="module-count"><span>0</span> modules loaded</p>
  <?php endif; ?>
</footer>

<?php if (recaptcha_configured()): ?>
<?= recaptcha_bind_js([
    ['button_name' => 'fetch_domain',  'button_value' => '1',              'action' => 'fetch_domain'],
    ['button_name' => 'linter_action', 'button_value' => 'crtsh:crtsh_lintcert', 'action' => 'crtsh_lint'],
]) ?>
<?php endif; ?>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>
<script>
(function () {
  // Cert prefill from cert factory (Lint button)
  var cert   = sessionStorage.getItem('pki_prefill_cert');
  var issuer = sessionStorage.getItem('pki_prefill_issuer');
  if (!cert) return;
  sessionStorage.removeItem('pki_prefill_cert');
  sessionStorage.removeItem('pki_prefill_issuer');
  var taEE   = document.querySelector('[name=ee_pem]');
  var taRoot = document.querySelector('[name=root_pem]');
  if (taEE   && !taEE.value.trim())   taEE.value   = cert;
  if (taRoot && !taRoot.value.trim() && issuer) taRoot.value = issuer;
}());
</script>
</body>
</html>

