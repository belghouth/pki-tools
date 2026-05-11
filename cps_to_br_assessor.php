<?php
// ── Security headers ──────────────────────────────────────────────────────────
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

require_once __DIR__ . '/recaptcha.php';
require_once __DIR__ . '/includes/br_fetcher.php';

$brCachePath = __DIR__ . '/includes/br_cache.json';
$fetcher     = new BRFetcher($brCachePath);

// ── Auto-bootstrap cache on first run ──────────────────────────────────────────
if (!file_exists($brCachePath)) {
    $fetcher->refresh(true);
}

// ── AJAX endpoint — must respond before any HTML ──────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['action'])) {

    ini_set('display_errors', '0'); // never let PHP warnings corrupt the JSON response
    header('Content-Type: application/json; charset=utf-8');

    try {

    $action = $_POST['action'];

    // ── Refresh cache ───────────────────────────────────────────────────────
    if ($action === 'refresh_cache') {
        if (recaptcha_configured()) {
            $rcToken = trim($_POST['g_recaptcha_token'] ?? '');
            if (!recaptcha_verify($rcToken, 'refresh_br_cache')) {
                echo json_encode(['error' => 'reCAPTCHA verification failed. Please try again.', 'ok' => false]);
                exit;
            }
        }
        echo json_encode($fetcher->refresh(true));
        exit;
    }

    // ── Run assessment ──────────────────────────────────────────────────────
    if ($action === 'assess') {

        $method = $_POST['input_method'] ?? 'pdf';

        // Load BR sections
        $cache = $fetcher->loadCache();
        if (!$cache || empty($cache['sections'])) {
            echo json_encode(['error' => 'Cannot fetch BR. Check network or upload br_cache.json manually.']);
            exit;
        }
        $brSections = $cache['sections'];
        $brVersion  = $cache['meta']['version'] ?? 'unknown';

        // Extract CPS text
        $cpsText  = '';
        $cpsPages = 0;
        $cpsFile  = '';

        if ($method === 'url') {
            // ── URL input ───────────────────────────────────────────────────
            $rawUrl = trim($_POST['cps_url'] ?? '');
            if ($rawUrl === '') {
                echo json_encode(['error' => 'No URL provided.']);
                exit;
            }
            $parsed = parse_url($rawUrl);
            $host   = $parsed['host'] ?? '';
            if ($host === '') {
                echo json_encode(['error' => 'Invalid URL.']);
                exit;
            }

            // SSRF prevention — block private/loopback IP ranges
            $ips = @gethostbynamel($host);
            if ($ips === false) $ips = [$host];
            foreach ($ips as $ip) {
                if (isPrivateIp($ip)) {
                    echo json_encode(['error' => 'URL resolves to a private or loopback address.']);
                    exit;
                }
            }

            $ctx  = stream_context_create(['http' => ['timeout' => 10, 'follow_location' => 1, 'max_redirects' => 3, 'user_agent' => 'PKI-Tools/CPS-Assessor']]);
            $body = @file_get_contents($rawUrl, false, $ctx);
            if ($body === false) {
                echo json_encode(['error' => 'URL did not respond within 10 seconds.']);
                exit;
            }
            if (strlen($body) > 20 * 1024 * 1024) {
                echo json_encode(['error' => 'File exceeds 20 MB limit.']);
                exit;
            }

            // If it looks like a PDF, write to uploads/ with a safe name then extract
            $isPdf = str_starts_with($body, '%PDF') || str_ends_with(strtolower(parse_url($rawUrl, PHP_URL_PATH) ?? ''), '.pdf');
            if ($isPdf) {
                $tmp = __DIR__ . '/uploads/' . bin2hex(random_bytes(8)) . '.upload';
                file_put_contents($tmp, $body);
                register_shutdown_function('unlink', $tmp);
                $extracted = extractPdfText($tmp);
                if ($extracted['error']) {
                    echo json_encode(['error' => $extracted['error']]);
                    exit;
                }
                $cpsText  = $extracted['text'];
                $cpsPages = $extracted['pages'];
            } else {
                $cpsText  = $body;
                $cpsPages = 0;
            }
            $cpsFile = $host . (parse_url($rawUrl, PHP_URL_PATH) ?? '');

        } else {
            // ── File upload ────────────────────────────────────────────────
            $key = ($method === 'md') ? 'cps_md' : 'cps_pdf';
            if (empty($_FILES[$key]) || $_FILES[$key]['error'] !== UPLOAD_ERR_OK) {
                $uploadErr = $_FILES[$key]['error'] ?? UPLOAD_ERR_NO_FILE;
                if ($uploadErr === UPLOAD_ERR_INI_SIZE || $uploadErr === UPLOAD_ERR_FORM_SIZE) {
                    echo json_encode(['error' => 'File exceeds 20 MB limit.']);
                } else {
                    echo json_encode(['error' => 'No file uploaded or upload error (' . $uploadErr . ').']);
                }
                exit;
            }

            $file = $_FILES[$key];

            // Size check (20 MB)
            if ($file['size'] > 20 * 1024 * 1024) {
                echo json_encode(['error' => 'File exceeds 20 MB limit.']);
                exit;
            }

            // MIME validation — never trust $_FILES['type'], use finfo on the actual bytes
            $finfo    = new finfo(FILEINFO_MIME_TYPE);
            $mimeType = $finfo->file($file['tmp_name']);

            if ($method === 'pdf') {
                if ($mimeType !== 'application/pdf') {
                    echo json_encode(['error' => 'Only PDF and Markdown files are accepted.']);
                    exit;
                }
            } else {
                $allowedMimes = ['text/plain', 'text/markdown', 'text/x-markdown', 'application/octet-stream'];
                if (!in_array($mimeType, $allowedMimes, true)) {
                    echo json_encode(['error' => 'Only PDF and Markdown files are accepted.']);
                    exit;
                }
            }

            // Move to uploads/ with a random, non-executable filename.
            // The .upload extension has no registered handler so the web server
            // cannot execute it even if the uploads directory becomes reachable.
            $safeFilename = bin2hex(random_bytes(8)) . '.upload';
            $safePath     = __DIR__ . '/uploads/' . $safeFilename;

            if (!move_uploaded_file($file['tmp_name'], $safePath)) {
                echo json_encode(['error' => 'Failed to save uploaded file.']);
                exit;
            }
            register_shutdown_function('unlink', $safePath);

            if ($method === 'pdf') {
                $extracted = extractPdfText($safePath);
                if ($extracted['error']) {
                    echo json_encode(['error' => $extracted['error']]);
                    exit;
                }
                $cpsText  = $extracted['text'];
                $cpsPages = $extracted['pages'];
            } else {
                $cpsText  = (string) file_get_contents($safePath);
                $cpsPages = 0;
            }
            $cpsFile = $file['name'];
        }

        if (empty(trim($cpsText))) {
            echo json_encode(['error' => 'Could not extract any text from the document.']);
            exit;
        }

        // ── Run matching ────────────────────────────────────────────────────
        $wordCount = str_word_count(strip_tags($cpsText));
        $sections  = assessCPS($cpsText, $brSections);

        $counts   = array_count_values(array_column($sections, 'status'));
        $total    = count($sections);
        $covered  = ($counts['present'] ?? 0) + ($counts['thin'] ?? 0);
        $coverage = $total > 0 ? round(($covered / $total) * 100, 1) : 0;

        $result = [
            'meta' => [
                'cps_filename'     => $cpsFile,
                'cps_pages'        => $cpsPages,
                'cps_word_count'   => $wordCount,
                'br_version'       => $brVersion,
                'assessed_at'      => gmdate('Y-m-d\TH:i:s\Z'),
                'coverage_percent' => $coverage,
            ],
            'sections' => $sections,
        ];

        echo json_encode($result);
        exit;
    }

        echo json_encode(['error' => 'Unknown action.']);

    } catch (Throwable $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function isPrivateIp(string $ip): bool
{
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) return true;
    $privateRanges = [
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
        '127.0.0.0/8', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10',
        '100.64.0.0/10', '0.0.0.0/8',
    ];
    foreach ($privateRanges as $cidr) {
        if (ipInCidr($ip, $cidr)) return true;
    }
    return false;
}

function ipInCidr(string $ip, string $cidr): bool
{
    [$net, $bits] = explode('/', $cidr);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // IPv6 handled simply for loopback/ula
        if ($ip === '::1' && str_starts_with($cidr, '::1')) return true;
        return false;
    }
    $ipLong   = ip2long($ip);
    $netLong  = ip2long($net);
    if ($ipLong === false || $netLong === false) return false;
    $mask = -1 << (32 - (int)$bits);
    return ($ipLong & $mask) === ($netLong & $mask);
}

function extractPdfText(string $filePath): array
{
    $which = trim((string)shell_exec('which pdftotext 2>/dev/null'));
    if ($which === '') {
        return ['text' => '', 'pages' => 0, 'error' => 'Could not extract text. Ensure pdftotext is installed or upload as Markdown.'];
    }

    $escaped = escapeshellarg($filePath);
    $text    = (string)shell_exec("pdftotext {$escaped} - 2>/dev/null");

    // Page count from pdfinfo
    $pages = 0;
    $pdfinfo = shell_exec("pdfinfo {$escaped} 2>/dev/null");
    if ($pdfinfo && preg_match('/Pages:\s+(\d+)/i', $pdfinfo, $m)) {
        $pages = (int)$m[1];
    } elseif (preg_match_all('/%%Page:/', $text, $pm)) {
        $pages = count($pm[0]);
    }

    return ['text' => $text, 'pages' => $pages, 'error' => null];
}

/**
 * Extract section IDs actually present as headings in the CPS body.
 * Skips TOC entries (dotted leaders, or trailing page number with no other text).
 * Returns an array like ["1", "1.1", "3.1", "3.2.2", ...].
 */
function detectCPSSectionIds(string $text): array
{
    $found = [];
    foreach (explode("\n", $text) as $line) {
        $line = trim($line);
        if (strlen($line) < 3 || strlen($line) > 150) continue;
        // Skip lines with TOC dotted leaders
        if (preg_match('/\.{4,}/', $line)) continue;
        // Must start with a digit-dot section number pattern
        if (!preg_match('/^(\d+(?:\.\d+){0,5})(?:\s+|\.|$)/', $line, $m)) continue;
        $id   = rtrim($m[1], '.');
        $rest = trim(substr($line, strlen($m[0])));
        // Skip if remainder is just a page number (TOC without dotted leaders)
        if (preg_match('/^\d{1,4}$/', $rest)) continue;
        $found[$id] = true;
    }
    return array_keys($found);
}

/**
 * Returns structural confidence (0.0–0.75) based on whether the CPS body
 * contains a heading that matches the BR section ID.
 * Exact match → 0.75; parent section present → 0.35 (section exists but is merged).
 */
function structuralConfidence(string $brId, array $cpsSectionIds): float
{
    if (empty($cpsSectionIds)) return 0.0;
    $idSet = array_flip($cpsSectionIds);
    if (isset($idSet[$brId])) return 0.75;
    $parts = explode('.', $brId);
    while (count($parts) > 1) {
        array_pop($parts);
        if (isset($idSet[implode('.', $parts)])) return 0.35;
    }
    return 0.0;
}

function assessCPS(string $cpsText, array $brSections): array
{
    $lowerText  = strtolower($cpsText);
    // Split into paragraphs for reference finding
    $paragraphs = array_filter(
        array_map('trim', preg_split('/\n{2,}/', $cpsText)),
        fn($p) => strlen($p) >= 20
    );
    $paraList = array_values($paragraphs);

    // Pre-compute structural section IDs present in the CPS body
    $cpsSectionIds = detectCPSSectionIds($cpsText);

    $results = [];

    foreach ($brSections as $section) {
        $keywords = $section['keywords'] ?? [];

        // ── Keyword confidence ──────────────────────────────────────────────
        $matched    = 0;
        $matchedKws = [];
        if (!empty($keywords)) {
            foreach ($keywords as $kw) {
                if (str_contains($lowerText, strtolower($kw))) {
                    $matched++;
                    $matchedKws[] = $kw;
                }
            }
        }
        $kwConf = !empty($keywords) ? $matched / count($keywords) : 0.0;

        // ── Structural confidence ───────────────────────────────────────────
        $structConf = structuralConfidence($section['id'], $cpsSectionIds);

        // Final confidence: take the better signal
        $confidence = max($kwConf, $structConf);

        $status = 'missing';
        if ($confidence >= 0.6)      $status = 'present';
        elseif ($confidence >= 0.25) $status = 'thin';

        // Build notes explaining the signal source
        $notesParts = [];
        if ($structConf >= 0.6) {
            $notesParts[] = 'Section heading found in body text.';
        } elseif ($structConf > 0) {
            $notesParts[] = 'Parent section heading found.';
        }
        if ($matched > 0) {
            $notesParts[] = 'Keywords matched: ' . implode(', ', $matchedKws) . '.';
        }
        $notes = implode(' ', $notesParts);

        // Find best-matching paragraph for the reference field
        $reference = '';
        if (!empty($matchedKws) && !empty($paraList)) {
            $bestScore = 0;
            $bestPara  = '';
            foreach ($paraList as $para) {
                $lowerPara = strtolower($para);
                $score = 0;
                foreach ($matchedKws as $kw) {
                    if (str_contains($lowerPara, strtolower($kw))) $score++;
                }
                if ($score > $bestScore) {
                    $bestScore = $score;
                    $bestPara  = $para;
                }
            }
            if ($bestPara !== '') {
                $snippet   = mb_substr(strip_tags($bestPara), 0, 120);
                $reference = rtrim($snippet, ' .,;') . '…';
            }
        }

        $results[] = [
            'br_section'    => $section['id'],
            'br_title'      => $section['title'],
            'status'        => $status,
            'confidence'    => round($confidence, 3),
            'cps_reference' => $reference,
            'notes'         => $notes,
        ];
    }

    return $results;
}

// ── Load cache info for page display ─────────────────────────────────────────
$cache         = $fetcher->loadCache();
$cacheVersion  = $cache['meta']['version']   ?? 'not loaded';
$cacheFetchedAt = $cache['meta']['fetched_at'] ?? null;
$cacheDateFmt  = $cacheFetchedAt ? date('Y-m-d', strtotime($cacheFetchedAt)) : 'never';
$brSectionCount = count($cache['sections'] ?? []);

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CP/CPS to BR Assessor</title>
<?php if (recaptcha_configured()): ?>
<?= recaptcha_head() ?>
<script>window.RECAPTCHA_SITE_KEY = <?= json_encode(RECAPTCHA_SITE_KEY) ?>;</script>
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

    --status-present: #22c55e;
    --status-thin:    #f59e0b;
    --status-missing: #ef4444;
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
  .home-link:hover { color: var(--accent); }

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
    max-width: 960px;
    width: 100%;
    margin: 0 auto;
    padding: 2.5rem 2rem 4rem;
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }

  /* ── Page title ── */
  .page-title { display: flex; flex-direction: column; gap: 0.25rem; }
  .page-title h1 {
    font-family: var(--mono);
    font-size: 1.1rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    color: var(--text);
  }
  .page-title p { font-size: 0.82rem; color: var(--muted); font-weight: 300; }

  /* ── Card ── */
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
  .alert-icon { font-size: 0.9rem; flex-shrink: 0; margin-top: 0.05em; }

  /* ── Input tabs ── */
  .input-tabs {
    display: flex;
    gap: 0.35rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1rem;
  }
  .input-tab {
    font-family: var(--mono);
    font-size: 0.7rem;
    font-weight: 500;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 0.4rem 0.9rem;
    border-radius: var(--radius);
    border: 1px solid var(--border2);
    background: var(--surface2);
    color: var(--muted);
    cursor: pointer;
    transition: background var(--transition), border-color var(--transition), color var(--transition);
  }
  .input-tab:hover { background: rgba(0,212,170,0.06); border-color: rgba(0,212,170,0.3); color: var(--accent); }
  .input-tab--active {
    background: rgba(0,212,170,0.1);
    border-color: var(--accent);
    color: var(--accent);
  }

  .input-pane--hidden { display: none !important; }

  /* ── Field ── */
  .field { display: flex; flex-direction: column; gap: 0.45rem; }
  .field label {
    font-family: var(--mono);
    font-size: 0.7rem;
    font-weight: 500;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    display: flex; align-items: center; gap: 0.5rem;
  }
  .field input[type="file"],
  .field input[type="url"] {
    font-family: var(--mono);
    font-size: 0.78rem;
    background: var(--surface2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.55rem 0.9rem;
    width: 100%;
    outline: none;
    caret-color: var(--accent);
    transition: border-color var(--transition), box-shadow var(--transition);
  }
  .field input:focus {
    border-color: var(--accent2);
    box-shadow: 0 0 0 2px rgba(0,153,255,0.1);
  }
  .field-hint { font-size: 0.7rem; color: var(--muted); font-weight: 300; line-height: 1.5; }

  /* ── BR version bar ── */
  .br-meta-row {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.6rem 0.9rem;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-family: var(--mono);
    font-size: 0.72rem;
    flex-wrap: wrap;
  }
  .br-meta-row .br-meta-label { color: var(--muted); }
  .br-meta-row .br-meta-val   { color: var(--accent); font-weight: 600; }

  .btn-refresh-cache {
    font-family: var(--mono);
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    background: rgba(0,153,255,0.08);
    color: var(--accent2);
    border: 1px solid rgba(0,153,255,0.3);
    border-radius: var(--radius);
    padding: 0.35rem 0.8rem;
    cursor: pointer;
    white-space: nowrap;
    transition: background var(--transition), border-color var(--transition);
    margin-left: auto;
  }
  .btn-refresh-cache:hover { background: rgba(0,153,255,0.16); border-color: rgba(0,153,255,0.55); }

  .cache-status-msg { font-family: var(--mono); font-size: 0.68rem; }
  .cache-status-ok  { color: var(--status-present); }
  .cache-status-err { color: var(--danger); }

  /* ── Run button ── */
  .btn-row { display: flex; align-items: center; gap: 1rem; padding-top: 0.25rem; }
  .btn-assess {
    font-family: var(--mono);
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    background: rgba(0,212,170,0.12);
    color: var(--accent);
    border: 1px solid rgba(0,212,170,0.4);
    border-radius: var(--radius);
    padding: 0.6rem 1.4rem;
    cursor: pointer;
    transition: background var(--transition), border-color var(--transition);
  }
  .btn-assess:hover    { background: rgba(0,212,170,0.2); border-color: var(--accent); }
  .btn-assess:disabled { opacity: 0.45; cursor: not-allowed; }

  .assess-spinner {
    display: none;
    width: 14px; height: 14px;
    border: 2px solid rgba(0,212,170,0.2);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Stats bar ── */
  #stats-bar {
    display: none;
    grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
    gap: 1px;
    background: var(--border);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .stat-cell {
    background: var(--surface);
    padding: 0.9rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .stat-label {
    font-family: var(--mono);
    font-size: 0.62rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
  }
  .stat-value {
    font-family: var(--mono);
    font-size: 1.15rem;
    font-weight: 600;
    color: var(--text);
  }
  .stat-value--present { color: var(--status-present); }
  .stat-value--thin    { color: var(--status-thin); }
  .stat-value--missing { color: var(--status-missing); }
  .stat-value--accent  { color: var(--accent); }

  /* Coverage progress bar below stats */
  .coverage-bar-wrap { grid-column: 1 / -1; background: var(--surface); padding: 0.5rem 1rem 0.8rem; }
  .coverage-bar-track {
    background: var(--surface2);
    border-radius: 3px;
    height: 5px;
    overflow: hidden;
    border: 1px solid var(--border);
  }
  .coverage-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.6s ease;
  }
  .coverage-fill--good { background: var(--status-present); }
  .coverage-fill--warn { background: var(--status-thin); }
  .coverage-fill--bad  { background: var(--status-missing); }

  /* ── Result card (mirrors linters.php) ── */
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
    flex-wrap: wrap;
  }
  .result-header-left { display: flex; align-items: center; gap: 0.6rem; }
  .result-header h3 {
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--accent);
  }
  .dot-result {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--accent);
    flex-shrink: 0;
    box-shadow: 0 0 6px var(--accent);
  }
  .result-meta-badges {
    display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center;
  }
  .meta-badge {
    font-family: var(--mono);
    font-size: 0.65rem;
    font-weight: 600;
    color: var(--muted);
    letter-spacing: 0.06em;
  }
  .result-body { padding: 1.25rem; display: flex; flex-direction: column; gap: 1rem; }

  /* ── Toolbar (filter + expand + download) ── */
  .report-toolbar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    padding-bottom: 0.75rem;
    border-bottom: 1px solid var(--border);
  }
  .filter-btn {
    font-family: var(--mono);
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    padding: 0.3rem 0.75rem;
    border-radius: var(--radius);
    border: 1px solid var(--border2);
    background: var(--surface2);
    color: var(--muted);
    cursor: pointer;
    transition: background var(--transition), border-color var(--transition), color var(--transition);
  }
  .filter-btn:hover             { border-color: var(--accent2); color: var(--accent2); }
  .filter-btn--active           { border-color: var(--accent); color: var(--accent); background: rgba(0,212,170,0.08); }
  .filter-btn[data-filter="present"].filter-btn--active { border-color: var(--status-present); color: var(--status-present); background: rgba(34,197,94,0.08); }
  .filter-btn[data-filter="thin"].filter-btn--active    { border-color: var(--status-thin);    color: var(--status-thin);    background: rgba(245,158,11,0.08); }
  .filter-btn[data-filter="missing"].filter-btn--active { border-color: var(--status-missing); color: var(--status-missing); background: rgba(239,68,68,0.08); }

  .toolbar-sep { color: var(--border2); margin: 0 0.15rem; }

  .toolbar-btn {
    font-family: var(--mono);
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    padding: 0.3rem 0.75rem;
    border-radius: var(--radius);
    border: 1px solid var(--border2);
    background: transparent;
    color: var(--muted);
    cursor: pointer;
    transition: background var(--transition), border-color var(--transition), color var(--transition);
  }
  .toolbar-btn:hover { background: var(--surface2); border-color: var(--border2); color: var(--text); }
  .toolbar-btn--dl { color: var(--accent2); border-color: rgba(0,153,255,0.3); }
  .toolbar-btn--dl:hover { background: rgba(0,153,255,0.08); border-color: rgba(0,153,255,0.5); }

  /* ── JSON Tree ── */
  #json-tree { display: flex; flex-direction: column; gap: 2px; }

  .tree-row {
    border-radius: var(--radius);
    overflow: hidden;
    border: 1px solid transparent;
    transition: border-color var(--transition);
  }
  .tree-row--present { border-color: rgba(34,197,94,0.15);  background: rgba(34,197,94,0.04); }
  .tree-row--thin    { border-color: rgba(245,158,11,0.15); background: rgba(245,158,11,0.04); }
  .tree-row--missing { border-color: rgba(239,68,68,0.15);  background: rgba(239,68,68,0.04); }
  .tree-row:hover { border-color: var(--border2); }

  .tree-row-header {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.55rem 0.9rem;
    cursor: pointer;
    user-select: none;
    flex-wrap: wrap;
  }

  .tree-toggle {
    font-size: 0.6rem;
    color: var(--muted);
    flex-shrink: 0;
    width: 12px;
    transition: transform var(--transition);
  }

  .status-badge {
    font-family: var(--mono);
    font-size: 0.58rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    padding: 0.15em 0.55em;
    border-radius: 2px;
    flex-shrink: 0;
  }
  .status-badge--present { background: rgba(34,197,94,0.15);  color: var(--status-present); border: 1px solid rgba(34,197,94,0.3); }
  .status-badge--thin    { background: rgba(245,158,11,0.15); color: var(--status-thin);    border: 1px solid rgba(245,158,11,0.3); }
  .status-badge--missing { background: rgba(239,68,68,0.15);  color: var(--status-missing); border: 1px solid rgba(239,68,68,0.3); }

  .tree-section-id {
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 600;
    color: var(--accent2);
    flex-shrink: 0;
    min-width: 3rem;
  }
  .tree-section-title {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--text);
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .tree-conf-wrap { display: flex; align-items: center; gap: 0.4rem; margin-left: auto; flex-shrink: 0; }
  .tree-conf-bar  { width: 60px; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }
  .tree-conf-fill { height: 100%; border-radius: 2px; }
  .tree-conf-fill--present { background: var(--status-present); }
  .tree-conf-fill--thin    { background: var(--status-thin); }
  .tree-conf-fill--missing { background: var(--status-missing); }
  .tree-conf-pct {
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--muted);
    width: 2.8rem;
    text-align: right;
  }

  .tree-row-detail {
    padding: 0 0.9rem 0.75rem 2.4rem;
    animation: fadein 0.18s ease;
  }

  .tree-detail-table { width: 100%; border-collapse: collapse; }
  .tree-detail-table tr { border-bottom: 1px solid rgba(42,48,64,0.6); }
  .tree-detail-table tr:last-child { border-bottom: none; }
  .td-key {
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--muted);
    padding: 0.35rem 0.75rem 0.35rem 0;
    white-space: nowrap;
    vertical-align: top;
    width: 130px;
  }
  .td-val {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--text);
    padding: 0.35rem 0;
    vertical-align: top;
    word-break: break-word;
  }
  .td-ref { font-style: italic; color: var(--muted); font-size: 0.67rem; }

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
  footer p { font-family: var(--mono); font-size: 0.65rem; color: var(--muted); letter-spacing: 0.05em; }

  /* ── Animations ── */
  @keyframes fadein  { from { opacity: 0; transform: translateY(6px);  } to { opacity: 1; transform: translateY(0); } }
  @keyframes slidein { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
</style>
</head>
<body>

<header class="site-header">
  <a href="/" class="home-link" title="Home">&#8592;</a>
  <div class="logo">CP/CPS &rarr; BR Assessor</div>
  <div class="version">CAB Forum Baseline Requirements</div>
</header>

<main>

  <div class="page-title">
    <h1>CP/CPS Coverage Assessment</h1>
    <p>Upload or link a CP/CPS document and map its content against the CAB Forum Baseline Requirements to identify coverage gaps.</p>
  </div>

  <div id="assess-error" class="alert alert-error" style="display:none;">
    <span class="alert-icon">&#x2715;</span>
    <span></span>
  </div>

  <form id="assess-form" method="POST" action="<?= htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8') ?>" enctype="multipart/form-data">
    <div class="card">
      <div class="card-header">
        <div class="dot"></div>
        <h2>Document Input</h2>
      </div>
      <div class="card-body">

        <!-- Tab selector -->
        <div class="input-tabs">
          <button type="button" class="input-tab input-tab--active" data-tab="pdf">Upload PDF</button>
          <button type="button" class="input-tab" data-tab="md">Upload Markdown</button>
          <button type="button" class="input-tab" data-tab="url">URL</button>
        </div>

        <!-- PDF pane -->
        <div class="input-pane" id="pane-pdf">
          <div class="field">
            <label>PDF File</label>
            <input type="file" name="cps_pdf" accept=".pdf" id="input-pdf">
            <span class="field-hint">PDF format &mdash; text is extracted server-side via pdftotext. Max 20&nbsp;MB.</span>
          </div>
        </div>

        <!-- Markdown pane -->
        <div class="input-pane input-pane--hidden" id="pane-md">
          <div class="field">
            <label>Markdown / Plain Text File</label>
            <input type="file" name="cps_md" accept=".md,.txt,.markdown" id="input-md">
            <span class="field-hint">.md, .txt, or .markdown. Max 20&nbsp;MB.</span>
          </div>
        </div>

        <!-- URL pane -->
        <div class="input-pane input-pane--hidden" id="pane-url">
          <div class="field">
            <label>Document URL</label>
            <input type="url" name="cps_url" id="input-url" placeholder="https://ca.example.com/cps.pdf" autocomplete="off" spellcheck="false">
            <span class="field-hint">Must be publicly reachable. PDF URLs are piped through pdftotext. Private/loopback addresses are blocked.</span>
          </div>
        </div>

        <!-- BR version indicator -->
        <div class="br-meta-row">
          <span class="br-meta-label">BR index</span>
          <span class="br-meta-val" id="br-version-indicator">v<?= htmlspecialchars($cacheVersion) ?></span>
          <span class="br-meta-label">&bull;</span>
          <span class="br-meta-label"><?= $brSectionCount ?> sections</span>
          <span class="br-meta-label">&bull; fetched</span>
          <span class="br-meta-val"><?= htmlspecialchars($cacheDateFmt) ?></span>
          <button type="button" class="btn-refresh-cache" id="btn-refresh-cache">Refresh BR Cache</button>
        </div>
        <span class="cache-status-msg" id="cache-status-msg"></span>

        <!-- Run button -->
        <div class="btn-row">
          <button type="submit" class="btn-assess" id="btn-assess">Run Assessment</button>
          <span class="assess-spinner" id="assess-spinner"></span>
        </div>

      </div>
    </div>
  </form>

  <!-- Stats bar (shown after assessment) -->
  <div id="stats-bar">
    <div class="stat-cell">
      <span class="stat-label">CPS Pages</span>
      <span class="stat-value" id="stat-pages">—</span>
    </div>
    <div class="stat-cell">
      <span class="stat-label">CPS Words</span>
      <span class="stat-value" id="stat-words">—</span>
    </div>
    <div class="stat-cell">
      <span class="stat-label">BR Version</span>
      <span class="stat-value stat-value--accent" id="stat-br-version">—</span>
    </div>
    <div class="stat-cell">
      <span class="stat-label">BR Sections</span>
      <span class="stat-value" id="stat-br-total">—</span>
    </div>
    <div class="stat-cell">
      <span class="stat-label">Covered</span>
      <span class="stat-value stat-value--present" id="stat-covered">—</span>
    </div>
    <div class="stat-cell">
      <span class="stat-label">Thin</span>
      <span class="stat-value stat-value--thin" id="stat-thin">—</span>
    </div>
    <div class="stat-cell">
      <span class="stat-label">Missing</span>
      <span class="stat-value stat-value--missing" id="stat-missing">—</span>
    </div>
    <div class="stat-cell">
      <span class="stat-label">Coverage %</span>
      <span class="stat-value stat-value--accent" id="stat-coverage">—</span>
    </div>
    <div class="coverage-bar-wrap">
      <div class="coverage-bar-track">
        <div class="coverage-fill" id="coverage-fill" style="width:0%"></div>
      </div>
    </div>
  </div>

  <!-- Coverage Report (shown after assessment) -->
  <div id="report-card" style="display:none;">
    <div class="result-card">
      <div class="result-header">
        <div class="result-header-left">
          <div class="dot-result"></div>
          <h3>Coverage Report</h3>
        </div>
        <div class="result-meta-badges">
          <span class="meta-badge" id="report-filename"></span>
          <span class="meta-badge">&bull;</span>
          <span class="meta-badge" id="report-coverage"></span>
          <span class="meta-badge">&bull;</span>
          <span class="meta-badge" id="report-assessed-at"></span>
        </div>
      </div>
      <div class="result-body">

        <!-- Toolbar -->
        <div class="report-toolbar">
          <button type="button" class="filter-btn filter-btn--active" data-filter="all">All</button>
          <button type="button" class="filter-btn" data-filter="present">&#x25CF; Present</button>
          <button type="button" class="filter-btn" data-filter="thin">&#x25CF; Thin</button>
          <button type="button" class="filter-btn" data-filter="missing">&#x25CF; Missing</button>
          <span class="toolbar-sep">|</span>
          <button type="button" class="toolbar-btn" id="btn-expand-all">Expand All</button>
          <button type="button" class="toolbar-btn" id="btn-collapse-all">Collapse All</button>
          <span class="toolbar-sep">|</span>
          <button type="button" class="toolbar-btn toolbar-btn--dl" id="btn-dl-json">&#8595; JSON</button>
          <button type="button" class="toolbar-btn toolbar-btn--dl" id="btn-dl-csv">&#8595; CSV</button>
        </div>

        <!-- Tree -->
        <div id="json-tree"></div>

      </div>
    </div>
  </div>

</main>

<footer>
  <p>CP/CPS to BR Assessor &mdash; Coverage gap detection for auditors</p>
  <p>BR index: <?= htmlspecialchars($brSectionCount) ?> sections &bull; v<?= htmlspecialchars($cacheVersion) ?></p>
</footer>

<script src="assets/js/cps_assessor.js"></script>
</body>
</html>
