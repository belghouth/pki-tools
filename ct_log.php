<?php
// ── Meerkat Testing CT Log — RFC 6962 compliant, ephemeral (no persistence)
// Routes via .htaccess: /ct/v1/* → ct_log.php?_ep=*
//
// Endpoints:
//   POST /ct/v1/add-pre-chain   — submit precertificate chain, receive SCT
//   GET  /ct/v1/get-sth         — signed tree head (empty tree, fresh timestamp)
//   GET  /ct/v1/get-roots       — accepted root certificates
//   GET  /ct/v1/get-entries     — always returns empty list (no persistence)

require_once __DIR__ . '/config.php';

const CT_MAX_CHAIN   = 10;   // max certs in submitted chain (implementation limit)

// CT poison OID value bytes (tag 0x06 len 0x0a value…) — RFC 6962 §3.1, not deployment-specific
const POISON_OID_VAL = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x03";

// ── DER utilities ─────────────────────────────────────────────────────────────

function der_read(string $data, int $offset): array
{
    $start = $offset;
    $len   = strlen($data);
    if ($offset + 2 > $len) throw new \RuntimeException('DER underflow at offset ' . $offset);

    $tag = ord($data[$offset++]);
    $lb  = ord($data[$offset++]);

    if ($lb < 0x80) {
        $vlen = $lb;
    } elseif ($lb === 0x81) {
        if ($offset + 1 > $len) throw new \RuntimeException('DER length underflow');
        $vlen = ord($data[$offset++]);
    } elseif ($lb === 0x82) {
        if ($offset + 2 > $len) throw new \RuntimeException('DER length underflow');
        $vlen = (ord($data[$offset]) << 8) | ord($data[$offset + 1]);
        $offset += 2;
    } else {
        throw new \RuntimeException(sprintf('DER length form 0x%02x not supported', $lb));
    }

    $vstart = $offset;
    $end    = $vstart + $vlen;
    if ($end > $len) throw new \RuntimeException('DER value exceeds data length');

    return [
        'tag'    => $tag,
        'len'    => $vlen,
        'start'  => $start,
        'vstart' => $vstart,
        'end'    => $end,
        'raw'    => substr($data, $start, $end - $start),
        'val'    => substr($data, $vstart, $vlen),
    ];
}

function der_encode(int $tag, string $val): string
{
    $n = strlen($val);
    if ($n < 0x80)    return chr($tag) . chr($n) . $val;
    if ($n < 0x100)   return chr($tag) . "\x81" . chr($n) . $val;
    if ($n < 0x10000) return chr($tag) . "\x82" . chr($n >> 8) . chr($n & 0xff) . $val;
    throw new \RuntimeException('DER value too large (' . $n . ' bytes)');
}

// Returns the raw TBSCertificate bytes (tag + length + value) from a cert DER blob
function cert_tbs_raw(string $cert_der): string
{
    $cert = der_read($cert_der, 0);        // outer Certificate SEQUENCE
    $tbs  = der_read($cert['val'], 0);     // first child = TBSCertificate
    return $tbs['raw'];
}

// Returns a new TBSCertificate DER with the CT poison extension removed
function tbs_strip_poison(string $tbs_raw): string
{
    $tbs      = der_read($tbs_raw, 0);
    $inner    = $tbs['val'];
    $pos      = 0;
    $new_body = '';
    $stripped = false;

    while ($pos < strlen($inner)) {
        $elem = der_read($inner, $pos);

        if ($elem['tag'] === 0xA3) {
            // [3] EXPLICIT extensions — walk the inner SEQUENCE and drop the poison entry
            $seq      = der_read($elem['val'], 0);
            $epos     = 0;
            $new_exts = '';

            while ($epos < strlen($seq['val'])) {
                $ext     = der_read($seq['val'], $epos);
                $oid_tlv = der_read($ext['val'], 0);          // first child = OID
                if ($oid_tlv['val'] !== POISON_OID_VAL) {
                    $new_exts .= $ext['raw'];
                } else {
                    $stripped = true;
                }
                $epos = $ext['end'];
            }

            // Rebuild [3] EXPLICIT containing the filtered SEQUENCE (omit if empty)
            if ($new_exts !== '') {
                $new_body .= der_encode(0xA3, der_encode(0x30, $new_exts));
            }
        } else {
            $new_body .= $elem['raw'];
        }

        $pos = $elem['end'];
    }

    if (!$stripped) {
        throw new \RuntimeException('CT poison extension not found in TBSCertificate');
    }

    return der_encode(0x30, $new_body);
}

// Returns 32 raw bytes: SHA-256 of the issuer's SubjectPublicKeyInfo DER
function issuer_spki_hash(string $issuer_der): string
{
    // OpenSSL 3.x routes `-in -` through the STORE API which breaks under PHP-FPM;
    // write to a temp file to avoid that entirely.
    $tmp = tempnam(sys_get_temp_dir(), 'ct_iss_') . '.der';
    try {
        file_put_contents($tmp, $issuer_der);
        $r = ct_run([OPENSSL_BIN, 'x509', '-inform', 'DER', '-in', $tmp, '-noout', '-pubkey']);
        if (!$r['ok']) throw new \RuntimeException('Failed to extract issuer public key: ' . $r['err']);

        // `openssl x509 -pubkey` emits the SubjectPublicKeyInfo as a PEM block
        // (-----BEGIN PUBLIC KEY-----).  Strip the headers and base64-decode to get
        // the raw SPKI DER — no second openssl call needed.
        if (!preg_match('/-----BEGIN PUBLIC KEY-----\s*(.*?)\s*-----END PUBLIC KEY-----/s', $r['out'], $m)) {
            throw new \RuntimeException('Could not locate SPKI PEM block in pubkey output');
        }
        $spki_der = base64_decode(preg_replace('/\s+/', '', $m[1]), true);
        if ($spki_der === false) {
            throw new \RuntimeException('SPKI base64 decode failed');
        }
        return hash('sha256', $spki_der, true);
    } finally {
        @unlink($tmp);
    }
}

function ct_run(array $cmd, ?string $stdin = null): array
{
    $desc = [
        0 => $stdin !== null ? ['pipe', 'r'] : ['file', '/dev/null', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = proc_open($cmd, $desc, $pipes);
    if (!$proc) return ['ok' => false, 'out' => '', 'err' => 'proc_open failed'];

    if ($stdin !== null) {
        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);
    }
    $out  = stream_get_contents($pipes[1]);
    $err  = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return ['ok' => $code === 0, 'out' => (string) $out, 'err' => (string) $err];
}

// ── Log identity ──────────────────────────────────────────────────────────────

function load_random_log(): array
{
    $names = array_keys(CT_LOG_META);
    shuffle($names);
    foreach ($names as $name) {
        $kf = PKI_CT_KEYS_DIR . $name . '.pem';
        $if = PKI_CT_KEYS_DIR . $name . '.id';
        if (file_exists($kf) && file_exists($if)) {
            return [
                'name'    => $name,
                'meta'    => CT_LOG_META[$name],
                'key_pem' => (string) file_get_contents($kf),
                'log_id'  => hex2bin(trim((string) file_get_contents($if))),
            ];
        }
    }
    throw new \RuntimeException('No CT log keys found — run scripts/gen_ct_log_keys.php first');
}

// ── SCT construction ──────────────────────────────────────────────────────────

function build_sct(string $tbs_clean, string $spki_hash, array $log): array
{
    $ts  = (int) (microtime(true) * 1000);
    $tbl = strlen($tbs_clean);

    // RFC 6962 §3.2 — data signed by the log for a precert entry
    $blob = "\x00"                                              // version v1
          . "\x00"                                              // signature_type certificate_timestamp
          . pack('J', $ts)                                      // uint64 timestamp (ms, big-endian)
          . "\x00\x01"                                          // LogEntryType precert_entry
          . $spki_hash                                          // issuer_key_hash[32]
          . chr(($tbl >> 16) & 0xff)                           // uint24 tbs length
          . chr(($tbl >> 8)  & 0xff)
          . chr($tbl         & 0xff)
          . $tbs_clean                                          // TBSCertificate (poison stripped)
          . "\x00\x00";                                         // extensions length = 0

    $pkey = openssl_pkey_get_private($log['key_pem']);
    if ($pkey === false) throw new \RuntimeException('Failed to load CT log private key');

    if (!openssl_sign($blob, $sig_der, $pkey, OPENSSL_ALGO_SHA256)) {
        throw new \RuntimeException('ECDSA signing failed: ' . openssl_error_string());
    }

    // DigitallySigned §3.2: hash_alg(1) + sig_alg(1) + sig_len(2) + sig
    $ds = "\x04\x03" . pack('n', strlen($sig_der)) . $sig_der;

    return [
        'sct_version'     => 0,
        'id'              => base64_encode($log['log_id']),
        'timestamp'       => $ts,
        'extensions'      => '',
        'signature'       => base64_encode($ds),
        // Non-standard fields — for display in tooling; RFC 6962 clients ignore unknown fields
        'log_description' => $log['meta'][0],
        'log_operator'    => $log['meta'][1],
    ];
}

// ── API handlers ──────────────────────────────────────────────────────────────

function handle_add_pre_chain(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        ct_error(405, 'Method Not Allowed — use POST');
        return;
    }

    $body = (string) file_get_contents('php://input');
    $data = json_decode($body, true);

    if (!is_array($data) || empty($data['chain']) || !is_array($data['chain'])) {
        ct_error(400, 'Expected JSON body: {"chain": ["<base64-DER-precert>", "<base64-DER-issuer>", ...]}');
        return;
    }

    if (count($data['chain']) > CT_MAX_CHAIN) {
        ct_error(400, 'Chain too long — maximum ' . CT_MAX_CHAIN . ' certificates');
        return;
    }

    // Decode chain
    $ders = [];
    foreach ($data['chain'] as $i => $b64) {
        if (!is_string($b64)) { ct_error(400, "chain[$i] must be a base64 string"); return; }
        $der = base64_decode($b64, true);
        if ($der === false || strlen($der) < 30) {
            ct_error(400, "chain[$i] is not valid base64 DER");
            return;
        }
        $ders[] = $der;
    }

    $precert_der = $ders[0];
    $issuer_der  = $ders[1] ?? null;

    // Parse the precert and strip the CT poison extension using the pure-PHP DER parser.
    // Do NOT use `openssl x509` here — OpenSSL 3.x rejects certificates that carry an
    // unknown critical extension (the CT poison OID), so that command always fails on
    // valid precerts.  cert_tbs_raw() throws if the DER is structurally invalid, and
    // tbs_strip_poison() throws if the poison extension is absent — both give us the
    // validation we need without touching the openssl CLI.
    try {
        $tbs_raw   = cert_tbs_raw($precert_der);
    } catch (\Throwable $e) {
        ct_error(400, 'chain[0] could not be parsed as an X.509 certificate: ' . $e->getMessage());
        return;
    }

    try {
        $tbs_clean = tbs_strip_poison($tbs_raw);
    } catch (\Throwable $e) {
        ct_error(400, 'chain[0] does not contain the CT poison extension (OID 1.3.6.1.4.1.11129.2.4.3, RFC 6962 §3.1) — submit a precertificate, not a final certificate');
        return;
    }

    // Fall back to the known issuing CA if chain only has the precert
    if ($issuer_der === null) {
        if (!file_exists(ISSUING_CRT)) {
            ct_error(500, 'Issuer certificate unavailable on this server — include it as chain[1]');
            return;
        }
        $pem = (string) file_get_contents(ISSUING_CRT);
        if (!preg_match('/-----BEGIN CERTIFICATE-----\s*([\s\S]+?)\s*-----END CERTIFICATE-----/', $pem, $m)) {
            ct_error(500, 'Could not parse issuing CA certificate');
            return;
        }
        $issuer_der = base64_decode(preg_replace('/\s+/', '', $m[1]));
    }

    try {
        $spki_hash = issuer_spki_hash($issuer_der);
        $log       = load_random_log();
        $sct       = build_sct($tbs_clean, $spki_hash, $log);
        echo json_encode($sct, JSON_UNESCAPED_SLASHES);
    } catch (\Throwable $e) {
        ct_error(500, $e->getMessage());
    }
}

function handle_get_sth(): void
{
    try {
        $log = load_random_log();
    } catch (\Throwable $e) {
        ct_error(500, $e->getMessage());
        return;
    }

    $ts        = (int) (microtime(true) * 1000);
    $root_hash = hash('sha256', '', true); // MTH({}) per RFC 6962 §2.1

    // STH signed data: version(1) + sig_type(1=tree_hash) + timestamp(8) + tree_size(8) + root_hash(32)
    $blob = "\x00\x01" . pack('J', $ts) . pack('J', 0) . $root_hash;
    $pkey = openssl_pkey_get_private($log['key_pem']);
    openssl_sign($blob, $sig_der, $pkey, OPENSSL_ALGO_SHA256);
    $ds = "\x04\x03" . pack('n', strlen($sig_der)) . $sig_der;

    echo json_encode([
        'tree_size'           => 0,
        'timestamp'           => $ts,
        'sha256_root_hash'    => base64_encode($root_hash),
        'tree_head_signature' => base64_encode($ds),
    ]);
}

function handle_get_roots(): void
{
    $certs = [];
    foreach ([ROOT_CRT, ISSUING_CRT] as $f) {
        if (!file_exists($f)) continue;
        $pem = (string) file_get_contents($f);
        if (preg_match('/-----BEGIN CERTIFICATE-----\s*([\s\S]+?)\s*-----END CERTIFICATE-----/', $pem, $m)) {
            $certs[] = preg_replace('/\s+/', '', $m[1]);
        }
    }
    echo json_encode(['certificates' => $certs]);
}

function handle_get_entries(): void
{
    $start = max(0, (int) ($_GET['start'] ?? 0));
    $end   = max($start, (int) ($_GET['end']   ?? $start));
    echo json_encode(['entries' => [], 'tree_size' => 0, 'note' => 'This log is ephemeral and does not persist entries']);
}

function ct_error(int $code, string $msg): void
{
    http_response_code($code);
    echo json_encode(['error_code' => $code, 'error_message' => $msg], JSON_UNESCAPED_UNICODE);
}

// ── Router ────────────────────────────────────────────────────────────────────

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Resolve endpoint from .htaccess rewrite param or from URI path directly
$endpoint = trim($_GET['_ep'] ?? '');
if ($endpoint === '') {
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
    if (preg_match('#/ct/v1/([a-z\-]+)#', (string) $path, $m)) {
        $endpoint = $m[1];
    }
}

// Direct browser hit — redirect to documentation
if ($endpoint === '' && !isset($_SERVER['HTTP_ACCEPT']) ||
    (isset($_SERVER['HTTP_ACCEPT']) && str_contains($_SERVER['HTTP_ACCEPT'], 'text/html') && $endpoint === '')) {
    header('Location: /ct_log_doc.php');
    exit;
}

try {
    match ($endpoint) {
        'add-pre-chain'      => handle_add_pre_chain(),
        'get-sth'            => handle_get_sth(),
        'get-roots'          => handle_get_roots(),
        'get-entries'        => handle_get_entries(),
        'get-proof-by-hash',
        'get-consistency-proof',
        'get-entry-and-proof' => ct_error(400, 'This log is ephemeral and does not support proof endpoints'),
        default               => ct_error(404, "Unknown endpoint '$endpoint'. Available: add-pre-chain, get-sth, get-roots, get-entries"),
    };
} catch (\Throwable $e) {
    ct_error(500, $e->getMessage());
}
