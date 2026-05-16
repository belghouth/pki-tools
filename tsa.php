<?php
// ── Meerkat Testing TSA — RFC 3161 compliant Time Stamping Authority
//
// GET  /tsa → redirect to tsa_doc.php
// POST /tsa  Content-Type: application/timestamp-query
//            → openssl ts -reply → application/timestamp-reply (binary DER)
//
// Errors return plain text with the appropriate HTTP status code.

require_once __DIR__ . '/config.php';

define('TSA_SIGN_DIR', MPCA_CA_DIR . '/tsa_sign');
define('TSA_CNF',      TSA_SIGN_DIR . '/tsa.cnf');
define('TSA_CERT',     TSA_SIGN_DIR . '/tsa_signing.crt');

function tsa_error(int $code, string $msg): void
{
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $msg . "\n";
}

function tsa_run(array $cmd): array
{
    $desc = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $desc, $pipes);
    if (!$proc) return ['ok' => false, 'out' => '', 'err' => 'proc_open failed'];
    $out  = stream_get_contents($pipes[1]);
    $err  = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return ['ok' => $code === 0, 'out' => (string) $out, 'err' => (string) $err];
}

// ── Router ────────────────────────────────────────────────────────────────────

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Location: /tsa_doc.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: GET, POST');
    tsa_error(405, 'Method Not Allowed — use POST with Content-Type: application/timestamp-query');
    exit;
}

// Verify Content-Type (PHP-FPM exposes it as CONTENT_TYPE, not HTTP_CONTENT_TYPE)
$rawCt = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
$ct    = strtolower(trim(explode(';', $rawCt)[0]));
if ($ct !== 'application/timestamp-query') {
    tsa_error(415, 'Unsupported Media Type — Content-Type must be application/timestamp-query');
    exit;
}

// Check TSA is initialized
if (!file_exists(TSA_CNF) || !file_exists(TSA_CERT)) {
    tsa_error(503, 'TSA not initialized — run scripts/mpca_init.sh first');
    exit;
}

// Read request body
$body = (string) file_get_contents('php://input');
if ($body === '') {
    tsa_error(400, 'Empty request body — POST a DER-encoded TimeStampReq (RFC 3161 §2.4)');
    exit;
}

// Write TSQ to temp file, invoke openssl ts -reply, read TSR back
$tsq = tempnam(sys_get_temp_dir(), 'tsa_tsq_');
$tsr = tempnam(sys_get_temp_dir(), 'tsa_tsr_');
try {
    file_put_contents($tsq, $body);

    $r = tsa_run([OPENSSL_BIN, 'ts', '-reply', '-config', TSA_CNF, '-queryfile', $tsq, '-out', $tsr]);

    if (!$r['ok']) {
        tsa_error(500, 'TSA reply failed: ' . trim($r['err']));
        exit;
    }

    $reply = (string) file_get_contents($tsr);
    if ($reply === '') {
        tsa_error(500, 'TSA produced an empty TimeStampResp');
        exit;
    }

    header('Content-Type: application/timestamp-reply');
    header('Content-Length: ' . strlen($reply));
    echo $reply;
} finally {
    @unlink($tsq);
    @unlink($tsr);
}
