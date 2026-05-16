<?php
// ── Meerkat e-Seal — CMS / CAdES-T signing endpoint
//
// GET  /eseal → redirect to eseal_doc.php
// POST /eseal  Content-Type: application/json
//              Body: {"hash": "<hex|base64>", "alg": "sha256|sha384|sha512"}
//              → application/cms  (DER CMS SignedData with embedded RFC 3161 signature timestamp)
//
// The endpoint produces CAdES-B + signature timestamp (CAdES-T):
//   1. Sign the hash bytes with the e-Seal P-256 key → CMS SignedData
//   2. Hash the CMS signature value (SHA-256)
//   3. Obtain a TimeStampToken from the local Meerkat TSA
//   4. Inject the TST as an unsigned attribute (id-aa-signatureTimeStampToken)
//
// Errors return JSON {"error": "..."} with the matching HTTP status code.

require_once __DIR__ . '/config.php';

define('ESEAL_SIGN_DIR',  MPCA_CA_DIR    . '/eseal_sign');
define('ESEAL_KEY',       ESEAL_SIGN_DIR . '/eseal_signing.key');
define('ESEAL_CERT',      ESEAL_SIGN_DIR . '/eseal_signing.crt');
define('ESEAL_CA_CHAIN',  ESEAL_SIGN_DIR . '/ca_chain.pem');  // CA + Root only (no signer cert)
define('TSA_SIGN_DIR',    MPCA_CA_DIR    . '/tsa_sign');
define('TSA_CNF',         TSA_SIGN_DIR   . '/tsa.cnf');

// ── DER helpers ───────────────────────────────────────────────────────────────

function eseal_der_tlv(string $data, int $offset): array
{
    $tag  = ord($data[$offset]);
    $off  = $offset + 1;
    $lb   = ord($data[$off++]);
    if ($lb < 128) {
        $len    = $lb;
        $len_sz = 1;
    } else {
        $n      = $lb & 0x7F;
        $len_sz = 1 + $n;
        $len    = 0;
        for ($i = 0; $i < $n; $i++) $len = ($len << 8) | ord($data[$off++]);
    }
    return [
        'tag'     => $tag,
        'tag_off' => $offset,
        'len_off' => $offset + 1,
        'len_sz'  => $len_sz,
        'val_off' => $off,
        'val_len' => $len,
        'end'     => $off + $len,
    ];
}

function eseal_encode_len(int $len): string
{
    if ($len < 128) return chr($len);
    $b = '';
    while ($len > 0) { $b = chr($len & 0xFF) . $b; $len >>= 8; }
    return chr(0x80 | strlen($b)) . $b;
}

// Navigate to the signerInfos SET in a CMS SignedData DER.
// Returns ['ci', 'exp', 'sd', 'sd_prefix_len', 'signerinfos', 'si']
// or null on parse failure.
function eseal_nav_cms(string $der): ?array
{
    $ci = eseal_der_tlv($der, 0);
    if ($ci['tag'] !== 0x30) return null;

    $oid_ci = eseal_der_tlv($der, $ci['val_off']);
    $exp    = eseal_der_tlv($der, $oid_ci['end']);
    if ($exp['tag'] !== 0xA0) return null;

    $sd = eseal_der_tlv($der, $exp['val_off']);
    if ($sd['tag'] !== 0x30) return null;

    // Find signerInfos SET: a SET whose first element is a SEQUENCE whose
    // first child is an INTEGER (SignerInfo version field).
    $cursor       = $sd['val_off'];
    $signerinfos  = null;
    $prefix_len   = 0;

    while ($cursor < $sd['end']) {
        $node = eseal_der_tlv($der, $cursor);
        if ($node['tag'] === 0x31 && $node['val_len'] > 0) {
            $first = eseal_der_tlv($der, $node['val_off']);
            if ($first['tag'] === 0x30 && $first['val_len'] > 0) {
                $fc = eseal_der_tlv($der, $first['val_off']);
                if ($fc['tag'] === 0x02) {
                    $signerinfos = $node;
                    $prefix_len  = $cursor - $sd['val_off'];
                    break;
                }
            }
        }
        $cursor = $node['end'];
    }

    if ($signerinfos === null) return null;

    $si = eseal_der_tlv($der, $signerinfos['val_off']);
    if ($si['tag'] !== 0x30) return null;

    return compact('ci', 'exp', 'sd', 'prefix_len', 'signerinfos', 'si');
}

// Extract the raw ECDSA signature bytes from the first SignerInfo.
function eseal_extract_sig_bytes(string $cms_der): ?string
{
    $nav = eseal_nav_cms($cms_der);
    if (!$nav) return null;
    ['si' => $si] = $nav;

    $cursor    = $si['val_off'];
    $sig_bytes = null;
    while ($cursor < $si['end']) {
        $node = eseal_der_tlv($cms_der, $cursor);
        if ($node['tag'] === 0x04) {
            $sig_bytes = substr($cms_der, $node['val_off'], $node['val_len']);
        }
        $cursor = $node['end'];
    }
    return $sig_bytes;
}

// Extract the TimeStampToken (CMS SignedData) from a DER TimeStampResp.
function eseal_extract_tst(string $tsr_der): ?string
{
    $tsr = eseal_der_tlv($tsr_der, 0);
    if ($tsr['tag'] !== 0x30) return null;

    $status = eseal_der_tlv($tsr_der, $tsr['val_off']);
    if ($status['tag'] !== 0x30) return null;
    if ($status['end'] >= $tsr['end']) return null; // no TST (failure response)

    return substr($tsr_der, $status['end'], $tsr['end'] - $status['end']);
}

// Rebuild the CMS DER with the TST injected as unsigned attribute (CAdES-T).
// OID id-aa-signatureTimeStampToken: 1.2.840.113549.1.9.16.2.14
function eseal_inject_tst(string $cms_der, string $tst_der): ?string
{
    $oid_tst  = "\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0e";
    $attr_set = "\x31" . eseal_encode_len(strlen($tst_der)) . $tst_der;
    $attr_seq = "\x30" . eseal_encode_len(strlen($oid_tst) + strlen($attr_set)) . $oid_tst . $attr_set;
    $u_attrs  = "\xa1" . eseal_encode_len(strlen($attr_seq)) . $attr_seq;

    $nav = eseal_nav_cms($cms_der);
    if (!$nav) return null;
    ['ci' => $ci, 'exp' => $exp, 'sd' => $sd, 'prefix_len' => $prefix_len,
     'signerinfos' => $si_set, 'si' => $si] = $nav;

    // Build new SignerInfo (original value + unsigned attrs)
    $new_si_val = substr($cms_der, $si['val_off'], $si['val_len']) . $u_attrs;
    $new_si     = "\x30" . eseal_encode_len(strlen($new_si_val)) . $new_si_val;

    $new_si_set  = "\x31" . eseal_encode_len(strlen($new_si)) . $new_si;
    $sd_prefix   = substr($cms_der, $sd['val_off'], $prefix_len);
    $new_sd_val  = $sd_prefix . $new_si_set;
    $new_sd      = "\x30" . eseal_encode_len(strlen($new_sd_val)) . $new_sd_val;
    $new_exp     = "\xa0" . eseal_encode_len(strlen($new_sd)) . $new_sd;
    $ci_oid_part = substr($cms_der, $ci['val_off'], $exp['tag_off'] - $ci['val_off']);
    $new_ci_val  = $ci_oid_part . $new_exp;

    return "\x30" . eseal_encode_len(strlen($new_ci_val)) . $new_ci_val;
}

// ── Hash normalisation ────────────────────────────────────────────────────────

function eseal_normalize_hash(string $input): array
{
    $clean = preg_replace('/[\s:\-]+/', '', $input);
    if ($clean === '') return ['error' => 'No hash provided.'];

    if (preg_match('/^[0-9a-fA-F]+$/', $clean)) {
        $hex = strtolower($clean);
        return match (strlen($hex)) {
            64  => ['hex' => $hex, 'alg' => 'sha256'],
            96  => ['hex' => $hex, 'alg' => 'sha384'],
            128 => ['hex' => $hex, 'alg' => 'sha512'],
            default => ['error' => sprintf('Hex string is %d bytes — expected 32/48/64.', intdiv(strlen($hex), 2))],
        };
    }

    $b64     = str_replace(['-', '_'], ['+', '/'], $clean);
    $b64    .= str_repeat('=', (4 - strlen($b64) % 4) % 4);
    $decoded = base64_decode($b64, true);
    if ($decoded !== false && $decoded !== '') {
        $bytes = strlen($decoded);
        return match ($bytes) {
            32 => ['hex' => bin2hex($decoded), 'alg' => 'sha256'],
            48 => ['hex' => bin2hex($decoded), 'alg' => 'sha384'],
            64 => ['hex' => bin2hex($decoded), 'alg' => 'sha512'],
            default => ['error' => sprintf('Base64 decodes to %d bytes — expected 32/48/64.', $bytes)],
        };
    }

    return ['error' => 'Could not parse the hash — expected hex or base64 (32/48/64 bytes).'];
}

// ── Process runner ────────────────────────────────────────────────────────────

function eseal_run(array $cmd): array
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

function eseal_error(int $code, string $msg): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => $msg]);
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
    header('Location: /eseal_doc.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: GET, POST');
    eseal_error(405, 'Method Not Allowed — use POST with Content-Type: application/json');
    exit;
}

$rawCt = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
$ct    = strtolower(trim(explode(';', $rawCt)[0]));
if ($ct !== 'application/json') {
    eseal_error(415, 'Unsupported Media Type — Content-Type must be application/json');
    exit;
}

if (!file_exists(ESEAL_KEY) || !file_exists(ESEAL_CERT)) {
    eseal_error(503, 'e-Seal not initialized — run scripts/mpca_init.sh first');
    exit;
}

$body = (string) file_get_contents('php://input');
if ($body === '') {
    eseal_error(400, 'Empty request body — POST a JSON object with "hash" field');
    exit;
}

$req = json_decode($body, true);
if (!is_array($req)) {
    eseal_error(400, 'Invalid JSON');
    exit;
}

$hashInput = trim((string) ($req['hash'] ?? ''));
if ($hashInput === '') {
    eseal_error(400, 'Missing "hash" field — provide the hex or base64 digest of the document to seal');
    exit;
}

$hashInfo = eseal_normalize_hash($hashInput);
if (isset($hashInfo['error'])) {
    eseal_error(400, $hashInfo['error']);
    exit;
}

// ── Step 1: Create basic CMS SignedData ───────────────────────────────────────

$tmpIn  = tempnam(sys_get_temp_dir(), 'eseal_in_');
$tmpCms = tempnam(sys_get_temp_dir(), 'eseal_cms_');
$tmpTsq = tempnam(sys_get_temp_dir(), 'eseal_tsq_');
$tmpTsr = tempnam(sys_get_temp_dir(), 'eseal_tsr_');

try {
    file_put_contents($tmpIn, hex2bin($hashInfo['hex']));

    // -signer adds the signer cert automatically; -certfile must be CA+Root only
    // to avoid "certificate already present" when chain.pem includes the signer cert.
    $cmd = [
        OPENSSL_BIN, 'cms', '-sign',
        '-binary',
        '-signer',  ESEAL_CERT,
        '-inkey',   ESEAL_KEY,
        '-md',      $hashInfo['alg'],
        '-outform', 'DER',
        '-out',     $tmpCms,
        '-in',      $tmpIn,
    ];
    if (file_exists(ESEAL_CA_CHAIN)) {
        array_splice($cmd, 3, 0, ['-certfile', ESEAL_CA_CHAIN]);
    }
    $r = eseal_run($cmd);

    if (!$r['ok']) {
        eseal_error(500, 'CMS signing failed: ' . trim($r['err']));
        exit;
    }

    $cms = (string) file_get_contents($tmpCms);
    if ($cms === '') {
        eseal_error(500, 'e-Seal produced an empty CMS SignedData');
        exit;
    }

    // ── Step 2: Timestamp the signature value (CAdES-T) ──────────────────────

    $timestamped = false;

    if (file_exists(TSA_CNF)) {
        $sig_bytes = eseal_extract_sig_bytes($cms);

        if ($sig_bytes !== null) {
            $sig_hex = bin2hex(hash('sha256', $sig_bytes, true));

            // Create TSQ for the signature value hash
            $r2 = eseal_run([
                OPENSSL_BIN, 'ts', '-query',
                '-digest', $sig_hex,
                '-sha256',
                '-cert',
                '-out', $tmpTsq,
            ]);

            if ($r2['ok']) {
                // Get TSR from local TSA
                $r3 = eseal_run([
                    OPENSSL_BIN, 'ts', '-reply',
                    '-config', TSA_CNF,
                    '-queryfile', $tmpTsq,
                    '-out', $tmpTsr,
                ]);

                if ($r3['ok']) {
                    $tsr = (string) file_get_contents($tmpTsr);
                    $tst = eseal_extract_tst($tsr);

                    if ($tst !== null) {
                        $cms_t = eseal_inject_tst($cms, $tst);
                        if ($cms_t !== null) {
                            $cms         = $cms_t;
                            $timestamped = true;
                        }
                    }
                }
            }
        }
    }

    header('Content-Type: application/cms');
    header('Content-Length: ' . strlen($cms));
    header('X-Eseal-Timestamped: ' . ($timestamped ? 'yes' : 'no'));
    echo $cms;

} finally {
    foreach ([$tmpIn, $tmpCms, $tmpTsq, $tmpTsr] as $f) @unlink($f);
}
