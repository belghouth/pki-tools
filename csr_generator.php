<?php
// ── CSR Generator ─────────────────────────────────────────────────────────────
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/recaptcha.php';

// ── Allowed values ────────────────────────────────────────────────────────────

const ALLOWED_ALGOS     = ['rsa', 'ec', 'ed25519', 'dsa'];
const ALLOWED_HASHES    = ['md5', 'sha1', 'sha256', 'sha384', 'sha512'];
const ALLOWED_RSA_SIZES = [512, 1024, 2048, 3072, 4096];
const ALLOWED_DSA_SIZES = [1024, 2048, 3072];
const ALLOWED_EC_CURVES = ['P-192', 'P-224', 'P-256', 'P-384', 'P-521'];

// ── Known-vulnerable key library (CA rejection testing) ───────────────────────
// mode='generate': key created fresh with intentionally bad parameters.
// mode='preloaded': key PEM embedded below; populate from the noted public source.

// Source: https://github.com/g0tmi1k/debian-ssh — common_keys/debian_ssh_rsa_2048_x86.tar.bz2
// Entry: rsa/2048/0bdcea11b2c628c7fd8bc4b04ca43668-12474 (PID=12474 used as RNG seed)
// Converted from PKCS#1 to PKCS#8 with: openssl pkcs8 -topk8 -nocrypt
const DEBIAN_WEAK_RSA2048_PEM = <<<'PEM'
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQD6PYD5IJYUsN4x
Pa4UMF4hHoedfZgvRpYQpABLX6LYIrzfq5DqzQKxI8khu55Ubebt+iQ7u8G5/4jp
QCB9XsyINrDBWZ8/S4fPL4VSwTgWVW3MnKcnd0EtUoUf9OsvAPAxRIFSoZEVOut4
yCPBvNXPg0rp43xb1WTPsmXAJ2vqyNzNPe6YWbT6TZwG32rJ0N5E5GhKVvBRP91z
0bTRn20FE685ZsQy+Ad8YH6UXD5VfwBUQ8jF8XNqu2nONHSckZ/tDr9HPNuDUPRz
Vw+dpSkc5R9KVYFae/9b5ZkXCkB/ASw577y4NV7/qDCDKxcEGNgREiG57MHvP+Ih
GGlyY9AJAgEjAoIBAQDPV4ge4HxaSWelJHpLPgTZnPQGJjxEba+KIXyWOUxp8OWj
YkTfzm/x29KJqhV5J9yZS5pdYQ47Bu3IlDgtXS0gZ9RIbtRnpPt/yEnle4Y+ZAqE
9tOkW38ljYQ/DMLdzZPRDOAuhd6cj+etOB2ghoVFigrfDPIC8qP8jIAxf7/RKHKb
PePpwnn6F9nyFsZES5EUsEC0SgbnRzoqPNjcKyNUggV00sAXCQ0Ry8OkXW1Fid4V
bVlsOOnFuxirDvEbpP12xXz9vxNocqYBvKNrnn1e2A5dEQ0mtGnahLF54wvi20eY
2Eug+G98JodGCM3Y4QahrL1okrx7ye3rdd83Bb93AoGBAP1gyWw02hV7ydiFN/H1
0iYsmrz4zxHSgZEa75yiVv9qUC/MdA3uprvYEIdGcL/a7Iv4FWiK+lFh7um1veMO
jtGRLCzckxPqZgsD2vVVqr7IFamEjhwjO62Uha1R4H9TLI81ZiNwpxNhnRNlyNZm
n+kB/6pQJO0dpT9zlM44QviXAoGBAPzUZ5t1g0E/Bd/HaKzZ2HvBhpsFLoa3EA75
xMvWHTFPQQ7oyDhde1ZZ3nUdngxBIQc5fkPBLgflMVCrHeomBrbv2b3FqLAsg9p2
N1UMtriKEVLINzrcZpQ7O1wyDufKlv/8nwkJsehge4KuYHRRGecOJ4EpXVtFCAfy
cO7u5OBfAoGAQSeEQGVcpnBJ2JdI5nJpPQQnyjFZ0WIED16ypJ7F6egjP323cUv+
/RpNZJ0Vra1SxOgFgUhO/vvs+kStK8HqNeOAY06peiZUwQD9yg624JnZrz9Xvhew
QpPn3BxeTKBb6k+PSvEVBPvX7wuLalTnSot8QbzWS5noqeqFWZlwTo0CgYEArV5y
7kHzmnRbzKX+oml+gL83usG5gPKOqy7tWJLSMHDcJ3sM83NNQobEbZCm49TjcqsU
wL76/hmA5tu8vdDuqVQDBclduqIuhyx9tqmh3aCA6E7GyUasvWpx2NHeVcy/UHK2
MhVGyzrYWZwk4gu5/YYMddM4s50M0j/YaVNbKHsCgYACvVji5Oh3l6fulzJ+GdTB
Cpt0OwNXp7iNmIm15bpp/6oPr4qKWor+RQsVGH5Ok7VjPE+xPv1/R+jnXyTNe3vE
TtmLq3tpqsx8QEMCJDRppPSOHwW1xkDST26cWCVhAn8CAGF1C4KUJLK4oHHf+sWr
UdK9Z0zMvDR7lXTh8rOeOQ==
-----END PRIVATE KEY-----
PEM;

// Source: https://github.com/crocs-muni/roca — roca/tests/data/privkey03.pem
// RSA-2048 key with ROCA-detectable Infineon TPM modulus structure (Nemec et al., 2017)
const ROCA_RSA2048_PEM = <<<'PEM'
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6aPxfu2BsTUKK
uYs1XWYhTbT35HW19//dw0nHP31lmWUSGrFqQBTmxGXBEdhQIFhT0RP3EhJ+SiMK
qX9IHu1kEPbDRfSOJfuBxC7GgV3DXN2Dng3pH7K+yEjQkQ+nfiwx+Z7JvMftFngS
vXJDGLCt9JLWtHxc4FAYTod+pkBF+VAb9wVpz/0QLbcpn0npwAIir5EV0Kraln3+
dZt+RXboXDpP9ZQDkjG5C0SLkMMjYIO8+Bm8MY1TogGOybQB8QK6nuE93lkqQrAy
3xNmidnFYZ21XVGYU6Qi0xAGJNLZ5Hghg3X0YMJpMO2ozQ2Uflj/6be+JEU1bert
mIIj4+0dAgMBAAECggEASUje9y/uP4W8RFefn/JBJZSsMczSbiC6qc+N4NRYEypU
LuLpnvDkhrjtnBLM7OtablFDPR4QwS+aSSXL0Wm/QFje+nQ1KfFKyIB9NzNCznxi
5cysgVsh5ZlN7xkog1u6Okd9oqgiHVZ5DD0If9JkG2+MjvZT8huJwZSV9jecCyXG
EdNOeFtWFAIltpy4EyPeZB0bq1ZwWbbERRsYDCin5HOpZ7AF7qPB8rl7OsK8aN0K
sqrG56fquAx3IkR4CRZXyXepeke/oRa4At+OVGa1aSfu1pQd66iwuPb0MFdBkN9T
XnA5w/e1U4pSSk4TLY0E+mOE+eKKHiUs3sz6/Cw9oQKBgQDa5sERRX8Nd4iveHNe
vIGuDuMcKhdwHJSCONQgDqBg/0+xoB/GySXWVEvdVh7281Tj3flvbxQwhIZ6BxmG
ceU7eaw+u4O4Y31wUwwyGTBGJMezKuncfhionvzG0Tbe8FoE8qwyQSkKBC3Lv2Pd
+VzshxxWxygMLmN4FpTtCD39KQKBgQDaAJD5XJDHszD4isjexKNkSHbXOQY02ULL
wLV4x9v4qGZtDS3jQnRhIbmwwJkVK9kTHwRzxLSnVsf++Q0vfBdBcCYpybEkLl6K
XkXoG9QmBm500w2yxGrZowTxlqpFG488llPy45TJmeekL5MzSTdvwbKMTSolkOtR
rxAfru061QKBgQDSqwFj/d4ot8F0HhfqNMEZInqvwFKOMvM54DdGIs12jD/GUrRC
O5OOkdHxUdC7GbO5GQfVlrF3gBNrnSmTmkli09ZRCWXbLuSqFULHdDZhS0RlygcH
jNNudJQRQ4frRqVb3bCbLNqyKRNp4ufZ2QL1H5LGcSS5lGtmR1VMSYJfAQKBgCUt
3Yu5nrOAOwTYXoOnk5ohxarU/dr7hqnLNuffZgOVbMqCaeYNSl3aa5nabwEuVjot
mwvHa2vyn+87OGV1y12Mq+WKkVxzUApXI6L/RAIsLKBd8kMfvn1ZkRlGsclRdu9F
UBHngFOVnOzidD9V6E92AGZvLpXzjj6DFcPhiHH1AoGAH7uKnGvX5eykLyWhgyEE
kleQI48ykVm4k9vUwy0O3kdX5TNXdlj9D4nfqg+/hbnRMlfMxzF6+KugP98pvNz2
BnywtcDU/CAw1rjyVH8JBd9e/gq9QR2rqZHKIOUAHRVmeO/G7z0J8WgnPA8X9MyC
R7DpDlcIpIJDWGxQSPpHH8g=
-----END PRIVATE KEY-----
PEM;

const BAD_KEY_CATALOG = [
    'rsa_e3' => [
        'label' => 'RSA-2048, e=3',
        'cve'   => null,
        'ref'   => 'NIST SP 800-78-5 §3.1',
        'desc'  => 'Public exponent e=3. Cube-root attacks apply to unpadded messages; many CA policies and linters require e ≥ 65537.',
        'mode'  => 'generate',
        'bits'  => 2048,
        'exp'   => 3,
    ],
    'rsa_512' => [
        'label' => 'RSA-512',
        'cve'   => null,
        'ref'   => 'BR §6.1.5',
        'desc'  => '512-bit RSA moduli can be factored in hours with publicly available tools. All modern CAs reject keys below 2048 bits.',
        'mode'  => 'generate',
        'bits'  => 512,
        'exp'   => 65537,
    ],
    'debian_rsa2048' => [
        'label' => 'Debian Weak RSA-2048',
        'cve'   => 'CVE-2008-0166',
        'ref'   => null,
        'desc'  => 'Debian OpenSSL (2006–2008) seeded its RNG only with the process PID, producing at most 32,767 distinct keys per type. Published in CA blacklists.',
        'mode'  => 'preloaded',
        'key'   => DEBIAN_WEAK_RSA2048_PEM,
    ],
    'roca_rsa2048' => [
        'label' => 'ROCA RSA-2048',
        'cve'   => 'CVE-2017-15361',
        'ref'   => null,
        'desc'  => 'Infineon TPM key with the ROCA-detectable modulus structure (Nemec et al., 2017). CAs and linters implementing the ROCA fingerprint check will reject this key.',
        'mode'  => 'preloaded',
        'key'   => ROCA_RSA2048_PEM,
    ],
];

// Known DN attribute names → [oid, encoding, maxLen, deprecated]
// encoding: utf8 | print | ia5
const DN_ATTR_META = [
    'CN'                  => ['2.5.4.3',                       'utf8',  64,    false],
    'C'                   => ['2.5.4.6',                       'print', 2,     false],
    'ST'                  => ['2.5.4.8',                       'utf8',  128,   false],
    'L'                   => ['2.5.4.7',                       'utf8',  128,   false],
    'O'                   => ['2.5.4.10',                      'utf8',  64,    false],
    'street'              => ['2.5.4.9',                       'utf8',  128,   false],
    'postalCode'          => ['2.5.4.17',                      'utf8',  40,    false],
    'serialNumber'        => ['2.5.4.5',                       'print', 64,    false],
    'businessCategory'    => ['2.5.4.15',                      'utf8',  128,   false],
    'SN'                  => ['2.5.4.4',                       'utf8',  64,    false],
    'GN'                  => ['2.5.4.42',                      'utf8',  64,    false],
    'initials'            => ['2.5.4.43',                      'utf8',  20,    false],
    'generationQualifier' => ['2.5.4.44',                      'utf8',  64,    false],
    'jurisdictionC'       => ['1.3.6.1.4.1.311.60.2.1.3',     'print', 2,     false],
    'jurisdictionST'      => ['1.3.6.1.4.1.311.60.2.1.2',     'utf8',  128,   false],
    'jurisdictionL'       => ['1.3.6.1.4.1.311.60.2.1.1',     'utf8',  128,   false],
    'OU'                  => ['2.5.4.11',                      'utf8',  64,    true],
    'emailAddress'        => ['1.2.840.113549.1.9.1',          'ia5',   255,   true],
    'DC'                  => ['0.9.2342.19200300.100.1.25',    'ia5',   64,    false],
    'UID'                 => ['0.9.2342.19200300.100.1.1',     'utf8',  256,   false],
    'title'               => ['2.5.4.12',                      'utf8',  64,    true],
    'description'         => ['2.5.4.13',                      'utf8',  1024,  true],
    'pseudonym'           => ['2.5.4.65',                      'utf8',  128,   false],
    'dnQualifier'         => ['2.5.4.46',                      'print', 64,    false],
    'name'                => ['2.5.4.41',                      'utf8',  32768, false],
    'unstructuredName'    => ['1.2.840.113549.1.9.2',          'utf8',  255,   false],
];

const ALLOWED_SAN_TYPES = ['DNS', 'IP', 'email', 'URI'];

// ── Server-side field validation ──────────────────────────────────────────────

function validate_dn_field(string $attr, string $value): ?string
{
    if (!isset(DN_ATTR_META[$attr])) return "Unknown attribute: $attr";
    [, $enc, $maxLen] = DN_ATTR_META[$attr];

    // Strip newlines — would break the config file
    if (preg_match('/[\r\n]/', $value)) return "$attr: newlines not allowed in DN values";

    $len = mb_strlen($value, 'UTF-8');
    if ($len === 0) return "$attr: value must not be empty";
    if ($len > $maxLen) return "$attr: value exceeds maximum length of $maxLen characters";

    if ($attr === 'C' || $attr === 'jurisdictionC') {
        if (!preg_match('/^[A-Z]{2}$/', $value))
            return "$attr: must be exactly 2 uppercase ISO 3166-1 alpha-2 letters";
    }

    if ($enc === 'print') {
        // PrintableString: A-Za-z0-9 space '()+,-./:=?
        if (!preg_match("/^[A-Za-z0-9 '()+,\\-.\\/:=?]*$/", $value))
            return "$attr: only PrintableString characters allowed (A-Z a-z 0-9 space '()+,-./:=?)";
    } elseif ($enc === 'ia5') {
        // IA5String: ASCII 0x20-0x7E
        if (!preg_match('/^[\x20-\x7E]*$/', $value))
            return "$attr: only ASCII printable characters allowed (IA5String)";
        if ($attr === 'emailAddress' || $attr === 'email') {
            if (!filter_var($value, FILTER_VALIDATE_EMAIL))
                return "$attr: must be a valid email address";
        }
    }
    // utf8: any valid UTF-8 is allowed (PHP strings are already validated)
    if ($enc === 'utf8' && !mb_check_encoding($value, 'UTF-8'))
        return "$attr: value is not valid UTF-8";

    return null;
}

function validate_san(string $type, string $value): ?string
{
    if (!in_array($type, ALLOWED_SAN_TYPES, true)) return "Unknown SAN type: $type";
    if (preg_match('/[\r\n]/', $value)) return "SAN $type: newlines not allowed";
    if ($value === '') return "SAN $type: value must not be empty";

    if ($type === 'DNS') {
        // Wildcard only as first label, no double wildcards, valid hostname chars
        $host = ltrim($value, '*.');
        if (!preg_match('/^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/', $value))
            return "DNS SAN '$value': not a valid hostname or wildcard";
        if (strlen($value) > 253) return "DNS SAN: hostname too long (max 253)";
    } elseif ($type === 'IP') {
        if (filter_var($value, FILTER_VALIDATE_IP) === false)
            return "IP SAN '$value': not a valid IPv4 or IPv6 address";
    } elseif ($type === 'email') {
        if (!filter_var($value, FILTER_VALIDATE_EMAIL))
            return "Email SAN '$value': not a valid email address";
    } elseif ($type === 'URI') {
        $parsed = parse_url($value);
        if (!$parsed || !isset($parsed['scheme']) || !isset($parsed['host']))
            return "URI SAN '$value': not a valid URI";
    }
    return null;
}

// ── CSR generation ────────────────────────────────────────────────────────────

function generate_csr(array $p): array
{
    $openssl = OPENSSL_BIN;
    $tmp = sys_get_temp_dir() . '/meerkat_csr_' . bin2hex(random_bytes(8));
    mkdir($tmp, 0700);

    register_shutdown_function(function () use ($tmp) {
        foreach (glob("$tmp/*") as $f) @unlink($f);
        @rmdir($tmp);
    });

    $keyFile = "$tmp/key.pem";
    $csrFile = "$tmp/csr.pem";
    $cnfFile = "$tmp/req.cnf";

    // Generate key
    $algo = $p['algo'];
    if ($algo === 'rsa') {
        $bits = (int) $p['keySize'];
        $r = run_proc([$openssl, 'genpkey', '-algorithm', 'RSA',
            '-pkeyopt', "rsa_keygen_bits:$bits", '-out', $keyFile]);
    } elseif ($algo === 'ec') {
        $curve = $p['curve'];
        $r = run_proc([$openssl, 'genpkey', '-algorithm', 'EC',
            '-pkeyopt', "ec_paramgen_curve:$curve", '-out', $keyFile]);
    } elseif ($algo === 'dsa') {
        $bits = (int) $p['keySize'];
        $paramsFile = "$tmp/dsa_params.pem";
        $r = run_proc([$openssl, 'genpkey', '-genparam', '-algorithm', 'DSA',
            '-pkeyopt', "dsa_paramgen_bits:$bits", '-out', $paramsFile]);
        if (!$r['ok']) return ['error' => 'DSA param generation failed: ' . trim($r['err'])];
        $r = run_proc([$openssl, 'genpkey', '-paramfile', $paramsFile, '-out', $keyFile]);
    } else {
        $r = run_proc([$openssl, 'genpkey', '-algorithm', 'Ed25519', '-out', $keyFile]);
    }
    if (!$r['ok']) return ['error' => 'Key generation failed: ' . trim($r['err'])];

    // Build config
    $dn  = $p['dn']  ?? [];
    $san = $p['san'] ?? [];
    $hash = $p['hash'] ?? 'sha256';

    // For MD5/SHA-1, activate the OpenSSL legacy provider via config (openssl_conf must
    // appear before any section header to be picked up at library init time).
    $needsLegacy = in_array($hash, ['md5', 'sha1'], true);
    $cnf  = $needsLegacy
        ? "openssl_conf = openssl_init\n\n"
          . "[openssl_init]\nproviders = provider_sect\n\n"
          . "[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n\n"
          . "[default_sect]\nactivate = 1\n\n"
          . "[legacy_sect]\nactivate = 1\n\n"
        : '';

    $cnf .= "[req]\n";
    $cnf .= "prompt = no\n";
    $cnf .= "default_md = $hash\n";
    $cnf .= "distinguished_name = req_dn\n";
    $cnf .= "string_mask = utf8only\n";
    if ($san) $cnf .= "req_extensions = v3_req\n";
    $cnf .= "\n[req_dn]\n";

    $attrIdx = [];
    foreach ($dn as $field) {
        $attr = $field['attr'];
        $val  = str_replace(['\\', "\n", "\r"], ['\\\\', '', ''], $field['value']);
        $n = $attrIdx[$attr] ?? 0;
        $key = $n === 0 ? $attr : "$attr.$n";
        $attrIdx[$attr] = $n + 1;
        $cnf .= "$key = $val\n";
    }

    if ($san) {
        $cnf .= "\n[v3_req]\nsubjectAltName = \@san_section\n\n[san_section]\n";
        $typeIdx = [];
        foreach ($san as $entry) {
            $t = $entry['type'];
            $v = $entry['value'];
            $n = ($typeIdx[$t] ?? 0) + 1;
            $typeIdx[$t] = $n;
            $cnf .= "$t.$n = $v\n";
        }
    }

    file_put_contents($cnfFile, $cnf);

    // Build openssl req command
    $cmd = [$openssl, 'req', '-new', '-key', $keyFile, '-out', $csrFile, '-config', $cnfFile];
    if ($algo !== 'ed25519') $cmd = array_merge($cmd, ["-$hash"]);

    $r = run_proc($cmd);
    if (!$r['ok']) return ['error' => 'CSR generation failed: ' . trim($r['err'])];

    $key = trim((string) file_get_contents($keyFile));
    $csr = trim((string) file_get_contents($csrFile));

    return ['key' => $key, 'csr' => $csr];
}

function generate_badkey_csr(string $keyId, array $p): array
{
    if (!array_key_exists($keyId, BAD_KEY_CATALOG))
        return ['error' => "Unknown bad key type: $keyId"];

    $entry   = BAD_KEY_CATALOG[$keyId];
    $openssl = OPENSSL_BIN;
    $tmp     = sys_get_temp_dir() . '/meerkat_badcsr_' . bin2hex(random_bytes(8));
    mkdir($tmp, 0700);

    register_shutdown_function(function () use ($tmp) {
        foreach (glob("$tmp/*") as $f) @unlink($f);
        @rmdir($tmp);
    });

    $keyFile = "$tmp/key.pem";
    $csrFile = "$tmp/csr.pem";
    $cnfFile = "$tmp/req.cnf";

    if ($entry['mode'] === 'generate') {
        $r = run_proc([$openssl, 'genpkey', '-algorithm', 'RSA',
            '-pkeyopt', 'rsa_keygen_bits:' . $entry['bits'],
            '-pkeyopt', 'rsa_keygen_pubexp:' . $entry['exp'],
            '-out', $keyFile]);
        if (!$r['ok']) return ['error' => 'Key generation failed: ' . trim($r['err'])];
    } else {
        $pem = trim($entry['key']);
        if ($pem === '')
            return ['error' => "Key for '$keyId' is not configured — populate the PEM constant in csr_generator.php (see source comment for where to obtain it)"];
        file_put_contents($keyFile, $pem . "\n", LOCK_EX);
    }

    $dn  = $p['dn']  ?? [];
    $san = $p['san'] ?? [];

    $cnf  = "[req]\nprompt = no\ndefault_md = sha256\ndistinguished_name = req_dn\nstring_mask = utf8only\n";
    if ($san) $cnf .= "req_extensions = v3_req\n";
    $cnf .= "\n[req_dn]\n";
    $attrIdx = [];
    foreach ($dn as $field) {
        $attr = $field['attr'];
        $val  = str_replace(['\\', "\n", "\r"], ['\\\\', '', ''], $field['value']);
        $n    = $attrIdx[$attr] ?? 0;
        $k    = $n === 0 ? $attr : "$attr.$n";
        $attrIdx[$attr] = $n + 1;
        $cnf .= "$k = $val\n";
    }
    if ($san) {
        $cnf .= "\n[v3_req]\nsubjectAltName = \@san_section\n\n[san_section]\n";
        $typeIdx = [];
        foreach ($san as $s) {
            $t = $s['type']; $v = $s['value'];
            $n = ($typeIdx[$t] ?? 0) + 1;
            $typeIdx[$t] = $n;
            $cnf .= "$t.$n = $v\n";
        }
    }
    file_put_contents($cnfFile, $cnf);

    $r = run_proc([$openssl, 'req', '-new', '-key', $keyFile, '-out', $csrFile,
        '-config', $cnfFile, '-sha256']);
    if (!$r['ok']) return ['error' => 'CSR generation failed: ' . trim($r['err'])];

    return [
        'key'         => trim((string) file_get_contents($keyFile)),
        'csr'         => trim((string) file_get_contents($csrFile)),
        'badKeyLabel' => $entry['label'],
        'badKeyCve'   => $entry['cve'],
    ];
}

function run_proc(array $cmd): array
{
    $proc = proc_open($cmd, [1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
    if (!$proc) return ['ok' => false, 'out' => '', 'err' => 'proc_open failed'];
    $out  = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $err  = stream_get_contents($pipes[2]); fclose($pipes[2]);
    $code = proc_close($proc);
    return ['ok' => $code === 0, 'out' => $out, 'err' => $err];
}

// ── AJAX handler ──────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=UTF-8');

    $body = json_decode(file_get_contents('php://input'), true);
    if (!is_array($body)) { echo json_encode(['error' => 'Invalid JSON']); exit; }

    if (recaptcha_configured()) {
        $token = trim($body['g_recaptcha_token'] ?? '');
        if (!recaptcha_verify($token, 'generate_csr'))
            { echo json_encode(['error' => 'reCAPTCHA verification failed. Please try again.']); exit; }
    }

    // ── Bad key CSR action ────────────────────────────────────────────────────
    if (($body['action'] ?? '') === 'badkey') {
        $keyId = $body['keyId'] ?? '';
        if (!array_key_exists($keyId, BAD_KEY_CATALOG))
            { echo json_encode(['error' => "Unknown bad key type: $keyId"]); exit; }
        $dn  = $body['dn']  ?? [];
        $san = $body['san'] ?? [];
        if (!is_array($dn) || !is_array($san))
            { echo json_encode(['error' => 'DN and SAN must be arrays']); exit; }
        if (empty($dn))
            { echo json_encode(['error' => 'At least one DN field is required']); exit; }
        foreach ($dn as $i => $field) {
            if (!isset($field['attr'], $field['value']))
                { echo json_encode(['error' => "DN field $i missing attr or value"]); exit; }
            $err = validate_dn_field((string)$field['attr'], (string)$field['value']);
            if ($err) { echo json_encode(['error' => $err]); exit; }
        }
        foreach ($san as $i => $entry) {
            if (!isset($entry['type'], $entry['value']))
                { echo json_encode(['error' => "SAN $i missing type or value"]); exit; }
            $err = validate_san((string)$entry['type'], (string)$entry['value']);
            if ($err) { echo json_encode(['error' => $err]); exit; }
        }
        echo json_encode(generate_badkey_csr($keyId, compact('dn', 'san')));
        exit;
    }

    $algo    = $body['algo']    ?? '';
    $hash    = strtolower($body['hash'] ?? 'sha256');
    $keySize = (int) ($body['keySize'] ?? 2048);
    $curve   = $body['curve']   ?? 'P-256';
    $dn      = $body['dn']      ?? [];
    $san     = $body['san']     ?? [];

    // Validate top-level params
    if (!in_array($algo, ALLOWED_ALGOS, true))
        { echo json_encode(['error' => "Invalid algorithm: $algo"]); exit; }
    if ($algo !== 'ed25519' && !in_array($hash, ALLOWED_HASHES, true))
        { echo json_encode(['error' => "Invalid hash: $hash"]); exit; }
    if (in_array($algo, ['rsa', 'dsa'], true) && !in_array($keySize, $algo === 'dsa' ? ALLOWED_DSA_SIZES : ALLOWED_RSA_SIZES, true))
        { echo json_encode(['error' => "Invalid key size: $keySize"]); exit; }
    if ($algo === 'ec' && !in_array($curve, ALLOWED_EC_CURVES, true))
        { echo json_encode(['error' => "Invalid curve: $curve"]); exit; }
    if (!is_array($dn) || !is_array($san))
        { echo json_encode(['error' => 'DN and SAN must be arrays']); exit; }
    if (empty($dn))
        { echo json_encode(['error' => 'At least one DN field is required']); exit; }

    // Validate each DN field
    foreach ($dn as $i => $field) {
        if (!isset($field['attr'], $field['value']))
            { echo json_encode(['error' => "DN field $i missing attr or value"]); exit; }
        $err = validate_dn_field((string)$field['attr'], (string)$field['value']);
        if ($err) { echo json_encode(['error' => $err]); exit; }
    }

    // Validate each SAN
    foreach ($san as $i => $entry) {
        if (!isset($entry['type'], $entry['value']))
            { echo json_encode(['error' => "SAN $i missing type or value"]); exit; }
        $err = validate_san((string)$entry['type'], (string)$entry['value']);
        if ($err) { echo json_encode(['error' => $err]); exit; }
    }

    $result = generate_csr(compact('algo', 'hash', 'keySize', 'curve', 'dn', 'san'));
    echo json_encode($result);
    exit;
}

// ── Page render ───────────────────────────────────────────────────────────────
$navLabel = 'CSR Generator';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'CSR Generator — Build Certificate Signing Requests | ' . SITE_DOMAIN,
    'description' => 'Generate a CSR with full control over key algorithm (RSA, ECDSA, Ed25519), curve, key size, and signature hash. Compose Subject DN and SANs field-by-field with per-field validation and UTF-8 support.',
    'url'         => SITE_BASE_URL . '/csr_generator.php',
  ]);
  ?>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
  <?= recaptcha_head() ?>
  <style>
    :root {
      --bg: #0e1014; --surface: #13171e; --surface2: #191e28;
      --border: #2a3040; --accent: #00d4aa; --danger: #f87171;
      --warn: #fb923c; --text: #d4dae6; --muted: #6b7a90;
      --mono: 'IBM Plex Mono','Fira Mono',monospace;
      --sans: 'IBM Plex Sans',system-ui,sans-serif;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    [hidden] { display: none !important; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans);
           font-weight: 300; line-height: 1.7; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }
    .wrap { max-width: 780px; margin: 0 auto; padding: 3.5rem 2rem 6rem; }

    /* ── Footer ── */
    .site-footer {
      border-top: 1px solid var(--border); padding: 1.4rem 2rem;
      display: flex; align-items: center; justify-content: space-between;
      flex-wrap: wrap; gap: 1rem;
      font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
    }
    .site-footer a { color: var(--muted); }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }

    h1 { font-size: 1.55rem; font-weight: 600; color: #fff; margin-bottom: .2rem; }
    .sub { font-family: var(--mono); font-size: .7rem; color: var(--muted);
           letter-spacing: .05em; margin-bottom: 2rem; }
    h2 { font-size: .68rem; font-family: var(--mono); text-transform: uppercase;
         letter-spacing: .1em; color: var(--muted); margin: 2rem 0 .8rem; }

    .card { background: var(--surface); border: 1px solid var(--border);
            border-radius: 8px; padding: 1.2rem 1.4rem; margin-bottom: 1rem; }

    /* Key params row */
    .params-row { display: flex; flex-wrap: wrap; gap: .75rem; align-items: flex-end; }
    .param-group { display: flex; flex-direction: column; gap: .3rem; }
    .param-group label { font-size: .68rem; color: var(--muted); font-family: var(--mono); }
    select, input[type=text], input[type=number] {
      background: var(--bg); border: 1px solid var(--border); color: var(--text);
      border-radius: 5px; padding: .38em .7em; font-family: var(--mono); font-size: .78rem;
      appearance: none; -webkit-appearance: none; outline: none;
    }
    select:focus, input:focus { border-color: var(--accent); }
    select { padding-right: 1.8em; background-image:
      url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%236b7a90' stroke-width='1.5' fill='none'/%3E%3C/svg%3E");
      background-repeat: no-repeat; background-position: right .6em center; }

    /* DN / SAN builder */
    .builder-add-row { display: flex; gap: .5rem; align-items: center; margin-bottom: .8rem; }
    .builder-add-row select { flex: 1; min-width: 0; }
    .btn-add { background: none; border: 1px solid var(--accent); color: var(--accent);
               border-radius: 5px; padding: .35em .9em; font-family: var(--mono);
               font-size: .72rem; cursor: pointer; white-space: nowrap;
               transition: background .15s; }
    .btn-add:hover { background: rgba(0,212,170,.1); }
    .btn-add:disabled { border-color: var(--border); color: var(--muted); cursor: default; }

    /* Field rows */
    .field-list { display: flex; flex-direction: column; gap: .5rem; }
    .field-row { display: flex; gap: .5rem; align-items: center;
                 background: var(--surface2); border: 1px solid var(--border);
                 border-radius: 6px; padding: .45rem .7rem; }
    .field-warn { color: var(--warn); font-size: .82rem; flex-shrink: 0; cursor: help; }
    .field-label { font-family: var(--mono); font-size: .68rem; color: var(--muted);
                   white-space: nowrap; flex-shrink: 0; min-width: 120px; }
    .field-input { flex: 1; min-width: 0; background: transparent; border: none;
                   border-bottom: 1px solid var(--border); border-radius: 0;
                   color: var(--text); font-family: var(--mono); font-size: .76rem;
                   padding: .2em 0; }
    .field-input:focus { border-color: var(--accent); outline: none; }
    .field-input.invalid { border-color: var(--danger); }
    .field-err { font-size: .65rem; color: var(--danger); margin-top: .15rem;
                 display: none; font-family: var(--mono); }
    .field-err.show { display: block; }
    .btn-del { background: none; border: none; color: var(--muted); cursor: pointer;
               font-size: .9rem; padding: .1em .3em; flex-shrink: 0;
               transition: color .15s; }
    .btn-del:hover { color: var(--danger); }

    .san-type-badge { font-family: var(--mono); font-size: .62rem; color: var(--accent);
                      background: rgba(0,212,170,.08); border: 1px solid rgba(0,212,170,.2);
                      border-radius: 3px; padding: .1em .4em; white-space: nowrap; flex-shrink: 0; }

    /* Deprecated / retired options in selects */
    option.deprecated, option.retired { color: var(--warn); }

    /* Buttons */
    .btn-primary { background: var(--accent); color: #000; border: none; border-radius: 5px;
                   padding: .55em 1.4em; font-family: var(--mono); font-size: .8rem;
                   font-weight: 600; cursor: pointer; transition: opacity .15s; }
    .btn-primary:hover { opacity: .88; }
    .btn-primary:disabled { opacity: .4; cursor: default; }

    /* Result */
    .result-section { display: none; }
    .result-section.show { display: block; }
    .pem-wrap { position: relative; margin-bottom: .7rem; }
    .pem-label { font-family: var(--mono); font-size: .62rem; color: var(--muted);
                 text-transform: uppercase; letter-spacing: .08em; margin-bottom: .3rem; }
    .pem-area { width: 100%; background: var(--bg); border: 1px solid var(--border);
                border-radius: 6px; color: var(--muted); font-family: var(--mono);
                font-size: .63rem; line-height: 1.5; padding: .7rem .9rem;
                resize: vertical; min-height: 90px; }
    .pem-area:focus { outline: none; }
    .key-area { border-color: rgba(251,146,60,.25); }

    .action-row { display: flex; gap: .5rem; flex-wrap: wrap; margin-top: .3rem; }
    .btn-action { font-family: var(--mono); font-size: .68rem; letter-spacing: .06em;
                  text-transform: uppercase; border: 1px solid var(--border);
                  background: none; color: var(--muted); border-radius: 4px;
                  padding: .3em .85em; cursor: pointer; transition: border-color .15s, color .15s; }
    .btn-action:hover { border-color: var(--accent); color: var(--accent); }
    .btn-action.accent { border-color: var(--accent); color: var(--accent); }
    .btn-action.accent:hover { background: rgba(0,212,170,.08); color: #fff; }

    .key-warning { font-size: .72rem; color: var(--warn); margin-bottom: .6rem;
                   background: rgba(251,146,60,.07); border: 1px solid rgba(251,146,60,.2);
                   border-radius: 5px; padding: .5rem .8rem; }

    .error-box { background: rgba(248,113,113,.08); border: 1px solid rgba(248,113,113,.3);
                 border-radius: 5px; padding: .6rem .9rem; color: var(--danger);
                 font-family: var(--mono); font-size: .75rem; margin-top: .8rem;
                 display: none; }
    .error-box.show { display: block; }

    /* ── Bad key / CA rejection testing accordion ── */
    .bad-key-section {
      margin-top: .75rem;
      border: 1px solid rgba(248,113,113,.2);
      border-left: 3px solid var(--danger);
      border-radius: 8px; overflow: hidden;
    }
    .bad-key-toggle {
      width: 100%; display: flex; align-items: center; justify-content: space-between;
      background: rgba(248,113,113,.04); border: none; padding: .72rem 1.1rem;
      cursor: pointer; transition: background .15s; text-align: left;
    }
    .bad-key-toggle:hover { background: rgba(248,113,113,.09); }
    .bad-key-toggle-label {
      font-family: var(--mono); font-size: .74rem; font-weight: 600;
      color: var(--danger); display: flex; align-items: center; gap: .45rem;
    }
    .bad-key-toggle-arrow {
      font-size: .6rem; color: var(--muted); transition: transform .2s; flex-shrink: 0;
    }
    .bad-key-toggle-arrow.open { transform: rotate(90deg); }
    .bad-key-body { padding: .85rem 1.1rem 1.1rem; border-top: 1px solid rgba(248,113,113,.12); }
    .bad-key-note { font-size: .71rem; color: var(--muted); line-height: 1.6; margin-bottom: .85rem; }
    .bad-key-grid {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: .7rem;
    }
    .bad-key-card {
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 6px; padding: .8rem .95rem;
      display: flex; flex-direction: column; gap: .4rem;
      cursor: pointer; transition: border-color .15s;
    }
    .bad-key-card:hover { border-color: rgba(248,113,113,.35); }
    .bad-key-card:has(input[type=radio]:checked) {
      border-color: var(--danger); background: rgba(248,113,113,.06);
    }
    .bad-key-card-head { display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
    .bad-key-radio { accent-color: var(--danger); width: 13px; height: 13px; flex-shrink: 0; cursor: pointer; }
    .bad-key-name { font-family: var(--mono); font-size: .75rem; color: var(--text); font-weight: 600; }
    .bad-key-cve {
      font-family: var(--mono); font-size: .58rem; font-weight: 700; letter-spacing: .06em;
      color: #fff; background: rgba(248,113,113,.55); border-radius: 3px; padding: .1em .5em; white-space: nowrap;
    }
    .bad-key-ref {
      font-family: var(--mono); font-size: .58rem; color: var(--muted);
      background: rgba(255,255,255,.05); border: 1px solid var(--border);
      border-radius: 3px; padding: .1em .45em; white-space: nowrap;
    }
    .bad-key-desc { font-size: .71rem; color: var(--muted); line-height: 1.55; }
    .bad-key-unavail-note { font-family: var(--mono); font-size: .62rem; color: rgba(107,122,144,.55); font-style: italic; }
    /* Key params card dimmed while test-key accordion is open */
    .card.params-disabled { opacity: .38; pointer-events: none; user-select: none; }
  </style>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<main>
<div class="wrap">

  <h1>CSR Generator</h1>
  <p class="sub">meerkat pki tools &nbsp;·&nbsp; keys generated server-side, never stored</p>

  <!-- 1. Key parameters -->
  <h2>Key Parameters</h2>
  <div class="card" id="keyParamsCard">
    <div class="params-row">
      <div class="param-group">
        <label>Algorithm</label>
        <select id="algo">
          <optgroup label="Current">
            <option value="rsa">RSA</option>
            <option value="ec" selected>ECDSA</option>
            <option value="ed25519">Ed25519</option>
          </optgroup>
          <optgroup label="⚠ Retired">
            <option value="dsa" class="retired">DSA — withdrawn from BR</option>
          </optgroup>
        </select>
      </div>
      <div class="param-group" id="rsaSizeGroup" style="display:none">
        <label>Key size</label>
        <select id="rsaSize">
          <optgroup label="Current">
            <option value="2048" selected>2048 bit &nbsp;(recommended)</option>
            <option value="3072">3072 bit</option>
            <option value="4096">4096 bit</option>
          </optgroup>
          <optgroup label="⚠ Retired">
            <option value="1024" class="retired">1024 bit — broken</option>
            <option value="512"  class="retired">512 bit — severely broken</option>
          </optgroup>
        </select>
      </div>
      <div class="param-group" id="dsaSizeGroup" style="display:none">
        <label>Key size</label>
        <select id="dsaSize">
          <optgroup label="⚠ Retired — DSA not in BR">
            <option value="2048" selected>2048 bit</option>
            <option value="1024" class="retired">1024 bit — broken</option>
            <option value="3072">3072 bit</option>
          </optgroup>
        </select>
      </div>
      <div class="param-group" id="ecCurveGroup">
        <label>Curve</label>
        <select id="ecCurve">
          <optgroup label="Current (BR §7.1.3.1)">
            <option value="P-256" selected>P-256 &nbsp;(recommended)</option>
            <option value="P-384">P-384</option>
            <option value="P-521">P-521</option>
          </optgroup>
          <optgroup label="⚠ Retired">
            <option value="P-224" class="retired">P-224 — not in BR §7.1.3.1</option>
            <option value="P-192" class="retired">P-192 — too short, withdrawn</option>
          </optgroup>
        </select>
      </div>
      <div class="param-group" id="hashGroup">
        <label>Signature hash</label>
        <select id="hashAlgo">
          <optgroup label="Current">
            <option value="sha256" selected>SHA-256 &nbsp;(recommended)</option>
            <option value="sha384">SHA-384</option>
            <option value="sha512">SHA-512</option>
          </optgroup>
          <optgroup label="⚠ Retired">
            <option value="sha1" class="retired">SHA-1 — forbidden in TLS (BR §7.1.3.2)</option>
            <option value="md5"  class="retired">MD5 — cryptographically broken</option>
          </optgroup>
        </select>
      </div>
    </div>
  </div>

  <!-- Test Keys accordion (exclusive with Key Parameters above) -->
  <div class="bad-key-section" id="badKeySection">
    <button type="button" class="bad-key-toggle" onclick="toggleBadKeys()">
      <span class="bad-key-toggle-label">⛔ Test Keys — CA Rejection Mechanisms</span>
      <span class="bad-key-toggle-arrow" id="badKeyArrow">&#9654;</span>
    </button>
    <div class="bad-key-body" id="badKeyBody" hidden>
      <p class="bad-key-note">
        These keys are intentionally weak or blacklisted. Use one to verify that a CA,
        linter, or ACME server correctly refuses the CSR. Your DN and SANs are used as-is —
        only the key is the bad part. Key Parameters above are disabled while this panel is open.
      </p>
      <div class="bad-key-grid" id="badKeyGrid"><!-- rendered by JS --></div>
    </div>
  </div>

  <!-- 2. Subject DN -->
  <h2>Subject Distinguished Name</h2>
  <div class="card">
    <div class="builder-add-row">
      <select id="dnAttrSelect"></select>
      <button class="btn-add" id="dnAddBtn" onclick="addDnField()">+ Add Field</button>
    </div>
    <div class="field-list" id="dnList"></div>
  </div>

  <!-- 3. Subject Alternative Names -->
  <h2>Subject Alternative Names &nbsp;<span style="font-size:.65rem;font-weight:300;color:var(--muted)">(optional)</span></h2>
  <div class="card">
    <div class="builder-add-row">
      <select id="sanTypeSelect">
        <option value="DNS">DNS — dNSName</option>
        <option value="IP">IP — iPAddress</option>
        <option value="email">email — rfc822Name</option>
        <option value="URI">URI — uniformResourceIdentifier</option>
      </select>
      <button class="btn-add" onclick="addSanField()">+ Add SAN</button>
    </div>
    <div class="field-list" id="sanList"></div>
  </div>

  <div style="margin-top:1.2rem">
    <button class="btn-primary" id="generateBtn" onclick="generate()">Generate CSR</button>
    <div class="error-box" id="errorBox"></div>
  </div>

  <!-- 4. Result -->
  <div class="result-section" id="resultSection">
    <h2>Result</h2>
    <div class="card">
      <div class="key-warning" id="keyWarning">⚠ Save your private key now — it is not stored on the server.</div>

      <div class="pem-label">Private Key</div>
      <div class="pem-wrap">
        <textarea class="pem-area key-area" id="keyPem" readonly spellcheck="false"></textarea>
      </div>
      <div class="action-row" style="margin-bottom:1.2rem">
        <button class="btn-action" onclick="copyText('keyPem', this)">Copy Key</button>
        <button class="btn-action" onclick="dlText('keyPem', 'private.key')">Download Key</button>
      </div>

      <div class="pem-label">Certificate Signing Request</div>
      <div class="pem-wrap">
        <textarea class="pem-area" id="csrPem" readonly spellcheck="false"></textarea>
      </div>
      <div class="action-row">
        <button class="btn-action" onclick="copyText('csrPem', this)">Copy CSR</button>
        <button class="btn-action" onclick="dlText('csrPem', 'request.csr')">Download CSR</button>
        <button class="btn-action accent" onclick="parseIt()">Parse →</button>
        <button class="btn-action accent" id="btnIssueTls"  onclick="issueIt('tls')"  style="display:none">Issue TLS →</button>
        <button class="btn-action accent" id="btnIssueMpca" onclick="issueIt('mpca')" style="display:none">Issue MPCA →</button>
      </div>
    </div>
  </div>

</div>

<script>
var RECAPTCHA_SITE_KEY = <?= json_encode(RECAPTCHA_SITE_KEY) ?>;

function getRecaptchaToken(action) {
  return new Promise(function(resolve) {
    if (!RECAPTCHA_SITE_KEY) { resolve(''); return; }
    grecaptcha.ready(function() {
      grecaptcha.execute(RECAPTCHA_SITE_KEY, {action: action}).then(resolve);
    });
  });
}

// ── DN field definitions ──────────────────────────────────────────────────────
var DN_FIELDS = [
  // attr, oid, fullName, enc, maxLen, deprecated, note
  {a:'CN',                  oid:'2.5.4.3',                       n:'commonName',                    enc:'utf8',  max:64,    dep:false, note:''},
  {a:'C',                   oid:'2.5.4.6',                       n:'countryName',                   enc:'print', max:2,     dep:false, note:'2-letter ISO 3166-1 alpha-2'},
  {a:'ST',                  oid:'2.5.4.8',                       n:'stateOrProvinceName',           enc:'utf8',  max:128,   dep:false, note:''},
  {a:'L',                   oid:'2.5.4.7',                       n:'localityName',                  enc:'utf8',  max:128,   dep:false, note:''},
  {a:'O',                   oid:'2.5.4.10',                      n:'organizationName',              enc:'utf8',  max:64,    dep:false, note:''},
  {a:'street',              oid:'2.5.4.9',                       n:'streetAddress',                 enc:'utf8',  max:128,   dep:false, note:''},
  {a:'postalCode',          oid:'2.5.4.17',                      n:'postalCode',                    enc:'utf8',  max:40,    dep:false, note:''},
  {a:'serialNumber',        oid:'2.5.4.5',                       n:'serialNumber',                  enc:'print', max:64,    dep:false, note:'Registration number — EV'},
  {a:'businessCategory',    oid:'2.5.4.15',                      n:'businessCategory',              enc:'utf8',  max:128,   dep:false, note:'"Private Organization" / "Government Entity" / "Business Entity" — EV/OV'},
  {a:'SN',                  oid:'2.5.4.4',                       n:'surname',                       enc:'utf8',  max:64,    dep:false, note:'Individual EV'},
  {a:'GN',                  oid:'2.5.4.42',                      n:'givenName',                     enc:'utf8',  max:64,    dep:false, note:'Individual EV'},
  {a:'initials',            oid:'2.5.4.43',                      n:'initials',                      enc:'utf8',  max:20,    dep:false, note:''},
  {a:'generationQualifier', oid:'2.5.4.44',                      n:'generationQualifier',           enc:'utf8',  max:64,    dep:false, note:'e.g. Jr., Sr., III'},
  {a:'jurisdictionC',       oid:'1.3.6.1.4.1.311.60.2.1.3',     n:'jurisdictionCountry',           enc:'print', max:2,     dep:false, note:'EV — country of incorporation'},
  {a:'jurisdictionST',      oid:'1.3.6.1.4.1.311.60.2.1.2',     n:'jurisdictionStateOrProvince',   enc:'utf8',  max:128,   dep:false, note:'EV — state of incorporation'},
  {a:'jurisdictionL',       oid:'1.3.6.1.4.1.311.60.2.1.1',     n:'jurisdictionLocality',          enc:'utf8',  max:128,   dep:false, note:'EV — locality of incorporation'},
  {a:'OU',                  oid:'2.5.4.11',                      n:'organizationalUnitName',        enc:'utf8',  max:64,    dep:true,  note:'Removed from TLS certs — BR §7.1.4.2 effective Sep 2022'},
  {a:'emailAddress',        oid:'1.2.840.113549.1.9.1',          n:'emailAddress',                  enc:'ia5',   max:255,   dep:true,  note:'Use SAN rfc822Name instead'},
  {a:'DC',                  oid:'0.9.2342.19200300.100.1.25',    n:'domainComponent',               enc:'ia5',   max:64,    dep:false, note:'Rarely used in TLS — IA5 only'},
  {a:'UID',                 oid:'0.9.2342.19200300.100.1.1',     n:'userId',                        enc:'utf8',  max:256,   dep:false, note:'Rarely used in TLS'},
  {a:'title',               oid:'2.5.4.12',                      n:'title',                         enc:'utf8',  max:64,    dep:true,  note:'Not used in TLS certificates'},
  {a:'description',         oid:'2.5.4.13',                      n:'description',                   enc:'utf8',  max:1024,  dep:true,  note:'Not used in TLS certificates'},
  {a:'pseudonym',           oid:'2.5.4.65',                      n:'pseudonym',                     enc:'utf8',  max:128,   dep:false, note:'Rarely used'},
  {a:'dnQualifier',         oid:'2.5.4.46',                      n:'dnQualifier',                   enc:'print', max:64,    dep:false, note:'Rarely used'},
  {a:'name',                oid:'2.5.4.41',                      n:'name',                          enc:'utf8',  max:32768, dep:false, note:'Rarely used'},
  {a:'unstructuredName',    oid:'1.2.840.113549.1.9.2',          n:'unstructuredName',              enc:'utf8',  max:255,   dep:false, note:'PKCS#9 — rarely used'},
];

var dnFieldMap = {};
DN_FIELDS.forEach(function(f){ dnFieldMap[f.a] = f; });

// ── Populate DN dropdown ──────────────────────────────────────────────────────
(function(){
  var sel = document.getElementById('dnAttrSelect');
  var active = DN_FIELDS.filter(function(f){ return !f.dep; });
  var depr   = DN_FIELDS.filter(function(f){ return  f.dep; });

  function addGroup(label, fields) {
    var og = document.createElement('optgroup');
    og.label = label;
    fields.forEach(function(f){
      var o = document.createElement('option');
      o.value = f.a;
      o.textContent = f.a === f.n ? f.a : f.a + ' — ' + f.n;
      if (f.dep) o.className = 'deprecated';
      og.appendChild(o);
    });
    sel.appendChild(og);
  }
  addGroup('Standard fields', active);
  addGroup('⚠ Deprecated / rarely used', depr);
})();

// ── DN row counter ────────────────────────────────────────────────────────────
var dnRowId = 0;

function addDnField(presetAttr) {
  var sel  = document.getElementById('dnAttrSelect');
  var attr = presetAttr || sel.value;
  var meta = dnFieldMap[attr];
  if (!meta) return;

  var id   = 'dn_' + (dnRowId++);
  var list = document.getElementById('dnList');

  var row  = document.createElement('div');
  row.className = 'field-row';
  row.dataset.attr = attr;
  row.id = id;

  var encHint = meta.enc === 'utf8'  ? 'UTF-8 (Unicode OK)'
              : meta.enc === 'ia5'   ? 'ASCII only (IA5String)'
              : 'ASCII subset (PrintableString)';

  var tooltip = meta.n + '  ·  ' + meta.oid + '\n' + encHint
              + (meta.max ? '  ·  max ' + meta.max + ' chars' : '')
              + (meta.note ? '\n' + meta.note : '');

  var warnHtml = meta.dep
    ? '<span class="field-warn" title="' + escHtml(meta.note) + '">⚠</span>'
    : '';

  row.innerHTML =
    warnHtml +
    '<span class="field-label" title="' + escHtml(tooltip) + '">' +
      escHtml(attr) + ' <span style="color:var(--border);font-size:.6rem">[' + escHtml(meta.oid) + ']</span>' +
    '</span>' +
    '<div style="flex:1;min-width:0">' +
      '<input class="field-input" type="text" id="' + id + '_val" autocomplete="off" spellcheck="false"' +
        ' placeholder="' + escHtml(meta.note || meta.n) + '"' +
        ' maxlength="' + meta.max + '">' +
      '<div class="field-err" id="' + id + '_err"></div>' +
    '</div>' +
    '<button class="btn-del" title="Remove" onclick="removeRow(\'' + id + '\')">✕</button>';

  list.appendChild(row);

  var inp = document.getElementById(id + '_val');
  inp.addEventListener('input', function(){ validateDnInput(attr, inp, id + '_err'); });
  inp.addEventListener('blur',  function(){ validateDnInput(attr, inp, id + '_err'); });
  inp.focus();
}

function validateDnInput(attr, inp, errId) {
  var meta = dnFieldMap[attr];
  var val  = inp.value;
  var err  = '';

  if (val === '') {
    inp.classList.remove('invalid'); document.getElementById(errId).classList.remove('show');
    return true;
  }

  var len = [...val].length; // Unicode-aware length
  if (len > meta.max) err = 'Max ' + meta.max + ' characters (' + len + ' entered)';

  if (!err && (attr === 'C' || attr === 'jurisdictionC')) {
    if (!/^[A-Z]{2}$/.test(val)) err = 'Must be exactly 2 uppercase letters (ISO 3166-1)';
  }
  if (!err && meta.enc === 'print') {
    if (/[^A-Za-z0-9 '()+,\-./:=?]/.test(val))
      err = 'PrintableString: only A-Z a-z 0-9 and \' ( ) + , - . / : = ? allowed';
  }
  if (!err && meta.enc === 'ia5') {
    if (/[^\x20-\x7E]/.test(val)) err = 'IA5String: only printable ASCII characters allowed';
    if (!err && (attr === 'emailAddress')) {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) err = 'Must be a valid email address';
    }
    if (!err && attr === 'DC') {
      if (!/^[a-zA-Z0-9-]+$/.test(val)) err = 'domainComponent: letters, digits and hyphen only';
    }
  }

  var errEl = document.getElementById(errId);
  if (err) {
    inp.classList.add('invalid');
    errEl.textContent = err;
    errEl.classList.add('show');
    return false;
  } else {
    inp.classList.remove('invalid');
    errEl.classList.remove('show');
    return true;
  }
}

// ── SAN ───────────────────────────────────────────────────────────────────────
var sanRowId = 0;
var SAN_INFO = {
  DNS:   { hint: 'example.com or *.example.com',  validate: validateDns },
  IP:    { hint: '192.0.2.1 or 2001:db8::1',      validate: validateIp  },
  email: { hint: 'user@example.com',              validate: validateEmail},
  URI:   { hint: 'https://example.com',           validate: validateUri },
};

function addSanField() {
  var type = document.getElementById('sanTypeSelect').value;
  var info = SAN_INFO[type];
  var id   = 'san_' + (sanRowId++);
  var list = document.getElementById('sanList');

  var row = document.createElement('div');
  row.className = 'field-row';
  row.dataset.type = type;
  row.id = id;

  row.innerHTML =
    '<span class="san-type-badge">' + escHtml(type) + '</span>' +
    '<div style="flex:1;min-width:0">' +
      '<input class="field-input" type="text" id="' + id + '_val" autocomplete="off" spellcheck="false"' +
        ' placeholder="' + escHtml(info.hint) + '">' +
      '<div class="field-err" id="' + id + '_err"></div>' +
    '</div>' +
    '<button class="btn-del" title="Remove" onclick="removeRow(\'' + id + '\')">✕</button>';

  list.appendChild(row);

  var inp = document.getElementById(id + '_val');
  inp.addEventListener('input', function(){ validateSanInput(type, inp, id + '_err'); });
  inp.addEventListener('blur',  function(){ validateSanInput(type, inp, id + '_err'); });
  inp.focus();
}

function validateSanInput(type, inp, errId) {
  var val = inp.value.trim();
  if (val === '') {
    inp.classList.remove('invalid'); document.getElementById(errId).classList.remove('show');
    return true;
  }
  var err = SAN_INFO[type].validate(val);
  var errEl = document.getElementById(errId);
  if (err) {
    inp.classList.add('invalid');
    errEl.textContent = err; errEl.classList.add('show');
    return false;
  }
  inp.classList.remove('invalid'); errEl.classList.remove('show');
  return true;
}

function validateDns(v) {
  if (v.length > 253) return 'Hostname too long (max 253)';
  if (!/^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(v))
    return 'Not a valid hostname or wildcard (*.example.com)';
  return null;
}
function validateIp(v) {
  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
    var ok = v.split('.').every(function(b){ return +b <= 255; });
    return ok ? null : 'Invalid IPv4 address';
  }
  // IPv6 — basic check (presence of colons and hex chars)
  if (v.indexOf(':') !== -1 && /^[0-9a-fA-F:]+$/.test(v)) return null;
  return 'Not a valid IPv4 or IPv6 address';
}
function validateEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? null : 'Not a valid email address';
}
function validateUri(v) {
  try { var u = new URL(v); return u.host ? null : 'URI must have a host'; }
  catch(e) { return 'Not a valid URI (must include scheme, e.g. https://)'; }
}

function removeRow(id) {
  var el = document.getElementById(id);
  if (el) el.remove();
}

// ── Key param toggles ─────────────────────────────────────────────────────────
document.getElementById('algo').addEventListener('change', function(){
  var v = this.value;
  document.getElementById('rsaSizeGroup').style.display  = v === 'rsa'     ? '' : 'none';
  document.getElementById('dsaSizeGroup').style.display  = v === 'dsa'     ? '' : 'none';
  document.getElementById('ecCurveGroup').style.display  = v === 'ec'      ? '' : 'none';
  document.getElementById('hashGroup').style.display     = v !== 'ed25519' ? '' : 'none';
  if (v === 'ec') syncHashToCurve();
});
document.getElementById('ecCurve').addEventListener('change', syncHashToCurve);
function syncHashToCurve() {
  var curve   = document.getElementById('ecCurve').value;
  var hashSel = document.getElementById('hashAlgo');
  if ((curve === 'P-384' || curve === 'P-521') && hashSel.value === 'sha256')
    hashSel.value = 'sha384';
}

// ── Generate ──────────────────────────────────────────────────────────────────
function collectDn() {
  var rows = document.querySelectorAll('#dnList .field-row');
  var out = [], valid = true;
  rows.forEach(function(row){
    var attr = row.dataset.attr;
    var inp  = row.querySelector('.field-input');
    var errId = inp.id + '_err';  // actually use row id pattern
    // re-validate on submit
    if (!validateDnInput(attr, inp, row.id + '_err')) valid = false;
    var val = inp.value.trim();
    if (val) out.push({attr: attr, value: val});
  });
  return valid ? out : null;
}

function collectSan() {
  var rows = document.querySelectorAll('#sanList .field-row');
  var out = [], valid = true;
  rows.forEach(function(row){
    var type = row.dataset.type;
    var inp  = row.querySelector('.field-input');
    if (!validateSanInput(type, inp, row.id + '_err')) valid = false;
    var val = inp.value.trim();
    if (val) out.push({type: type, value: val});
  });
  return valid ? out : null;
}

function showError(msg) {
  var el = document.getElementById('errorBox');
  el.textContent = msg;
  el.classList.add('show');
}
function hideError() { document.getElementById('errorBox').classList.remove('show'); }

async function generate() {
  hideError();

  // If the test-key accordion is open, use the selected radio instead of key params
  if (!document.getElementById('badKeyBody').hidden) {
    var sel = document.querySelector('input[name="badKey"]:checked');
    if (!sel) { showError('Select a test key, or close the test-keys panel to use the key parameters.'); return; }
    await _runBadKeyCsr(sel.value);
    return;
  }

  var algo    = document.getElementById('algo').value;
  var keySize = algo === 'dsa' ? parseInt(document.getElementById('dsaSize').value)
                               : parseInt(document.getElementById('rsaSize').value);
  var curve   = document.getElementById('ecCurve').value;
  var hash    = document.getElementById('hashAlgo').value;

  var dn  = collectDn();
  var san = collectSan();
  if (dn === null || san === null) { showError('Fix validation errors above before generating.'); return; }
  if (dn.length === 0) { showError('Add at least one Subject DN field.'); return; }

  var btn = document.getElementById('generateBtn');
  btn.disabled = true; btn.textContent = 'Generating…';

  var token = await getRecaptchaToken('generate_csr');

  try {
    var resp = await fetch('csr_generator.php', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({algo, keySize, curve, hash, dn, san, g_recaptcha_token: token})
    });
    var data = await resp.json();
    if (data.error) { showError(data.error); return; }

    document.getElementById('keyPem').value = data.key;
    document.getElementById('csrPem').value = data.csr;
    setKeyWarning(null);
    updateIssueButtons();
    var rs = document.getElementById('resultSection');
    rs.classList.add('show');
    rs.scrollIntoView({behavior:'smooth', block:'start'});
  } catch(e) {
    showError('Request failed: ' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = 'Generate CSR';
  }
}

async function _runBadKeyCsr(keyId) {
  var dn  = collectDn();
  var san = collectSan();
  if (dn === null || san === null) { showError('Fix validation errors above before generating.'); return; }
  if (dn.length === 0) { showError('Add at least one Subject DN field.'); return; }

  var btn = document.getElementById('generateBtn');
  btn.disabled = true; btn.textContent = 'Generating…';

  var token = await getRecaptchaToken('generate_csr');

  try {
    var resp = await fetch('csr_generator.php', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action: 'badkey', keyId: keyId, dn: dn, san: san, g_recaptcha_token: token})
    });
    var data = await resp.json();
    if (data.error) { showError(data.error); return; }

    document.getElementById('keyPem').value = data.key;
    document.getElementById('csrPem').value = data.csr;
    setKeyWarning(data.badKeyLabel, data.badKeyCve);
    updateIssueButtons();
    var rs = document.getElementById('resultSection');
    rs.classList.add('show');
    rs.scrollIntoView({behavior: 'smooth', block: 'start'});
  } catch (e) {
    showError('Request failed: ' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = 'Generate CSR';
  }
}

// ── Actions ───────────────────────────────────────────────────────────────────
function copyText(id, btn) {
  var t = document.getElementById(id);
  navigator.clipboard.writeText(t.value).then(function(){
    var orig = btn.textContent; btn.textContent = 'Copied!';
    setTimeout(function(){ btn.textContent = orig; }, 1800);
  });
}
function dlText(id, filename) {
  var t = document.getElementById(id);
  var blob = new Blob([t.value], {type: 'text/plain'});
  var url = URL.createObjectURL(blob);
  var a = Object.assign(document.createElement('a'), {href: url, download: filename});
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}
function parseIt() {
  var csr = document.getElementById('csrPem').value;
  sessionStorage.removeItem('pki_prefill_cert');
  sessionStorage.removeItem('mkt_eseal_cms');
  sessionStorage.removeItem('mkt_eseal_xades');
  sessionStorage.setItem('meerkat_pem', csr);
  window.open('artifact_parser.php', '_blank');
}
function issueIt(factory) {
  var csr = document.getElementById('csrPem').value;
  sessionStorage.setItem('pki_prefill_csr', csr);
  window.open(factory === 'mpca' ? 'mpca_factory.php' : 'cert_factory.php', '_blank');
}

function updateIssueButtons() {
  var sanRows = document.querySelectorAll('#sanList .field-row');
  var hasDns = false, hasEmail = false, hasOrg = false;
  sanRows.forEach(function(row) {
    var t = row.dataset.type;
    if (t === 'DNS')   hasDns  = true;
    if (t === 'email') hasEmail = true;
  });
  var dnRows = document.querySelectorAll('#dnList .field-row');
  dnRows.forEach(function(row) {
    if (row.dataset.attr === 'O') {
      var val = row.querySelector('.field-input');
      if (val && val.value.trim()) hasOrg = true;
    }
  });
  var showTls  = hasDns  || (!hasEmail);
  var showMpca = hasEmail || (!hasDns);
  document.getElementById('btnIssueTls').style.display  = showTls  ? '' : 'none';
  document.getElementById('btnIssueMpca').style.display = showMpca ? '' : 'none';
}

// ── Key warning helper ────────────────────────────────────────────────────────
function setKeyWarning(badKeyLabel, badKeyCve) {
  var el = document.getElementById('keyWarning');
  if (badKeyLabel) {
    el.style.cssText = 'color:var(--danger);background:rgba(248,113,113,.07);border-color:rgba(248,113,113,.3)';
    el.textContent = '⛔ BAD KEY — ' + badKeyLabel
      + (badKeyCve ? ' (' + badKeyCve + ')' : '')
      + ' — For CA rejection testing only. Never use in production.';
  } else {
    el.style.cssText = '';
    el.textContent = '⚠ Save your private key now — it is not stored on the server.';
  }
}

// ── Bad key catalog ───────────────────────────────────────────────────────────
var BAD_KEY_JS_CATALOG = [
  {
    id:    'rsa_e3',
    label: 'RSA-2048, e=3',
    cve:   null,
    ref:   'NIST SP 800-78-5',
    desc:  'Public exponent e=3. Cube-root attacks apply to unpadded messages; many CA policies and linters require e ≥ 65537.',
    avail: true,
  },
  {
    id:    'rsa_512',
    label: 'RSA-512',
    cve:   null,
    ref:   'BR §6.1.5',
    desc:  '512-bit RSA moduli can be factored in hours with publicly available tools. All modern CAs reject keys below 2048 bits.',
    avail: true,
  },
  {
    id:    'debian_rsa2048',
    label: 'Debian Weak RSA-2048',
    cve:   'CVE-2008-0166',
    ref:   null,
    desc:  'Debian OpenSSL (2006–2008) seeded its RNG only with the PID, producing ≤ 32,767 distinct keys per type. Present in CA blacklists.',
    avail: <?= DEBIAN_WEAK_RSA2048_PEM !== '' ? 'true' : 'false' ?>,
  },
  {
    id:    'roca_rsa2048',
    label: 'ROCA RSA-2048',
    cve:   'CVE-2017-15361',
    ref:   null,
    desc:  'Infineon TPM key with the ROCA-detectable modulus structure (Nemec et al., 2017). CAs and linters with the ROCA check will reject this key.',
    avail: <?= ROCA_RSA2048_PEM !== '' ? 'true' : 'false' ?>,
  },
];

// Render bad key cards with radio buttons at the top
(function () {
  var grid = document.getElementById('badKeyGrid');
  BAD_KEY_JS_CATALOG.forEach(function (k) {
    var card = document.createElement('label');
    card.className = 'bad-key-card';
    var badges = '';
    if (k.cve) badges += '<span class="bad-key-cve">' + escHtml(k.cve) + '</span>';
    if (k.ref) badges += '<span class="bad-key-ref">' + escHtml(k.ref) + '</span>';
    var radioAttr = k.avail ? '' : ' disabled';
    var unavailNote = k.avail ? '' : '<div class="bad-key-unavail-note">Key not configured — see source comment in csr_generator.php</div>';
    card.innerHTML =
      '<div class="bad-key-card-head">' +
        '<input type="radio" class="bad-key-radio" name="badKey" value="' + escHtml(k.id) + '"' + radioAttr + '>' +
        '<span class="bad-key-name">' + escHtml(k.label) + '</span>' +
        badges +
      '</div>' +
      '<div class="bad-key-desc">' + escHtml(k.desc) + '</div>' +
      unavailNote;
    grid.appendChild(card);
  });
}());

// ── Bad key accordion toggle ──────────────────────────────────────────────────
function toggleBadKeys() {
  var body    = document.getElementById('badKeyBody');
  var arrow   = document.getElementById('badKeyArrow');
  var params  = document.getElementById('keyParamsCard');
  var opening = body.hidden;

  body.hidden = !opening;
  arrow.classList.toggle('open', opening);
  params.classList.toggle('params-disabled', opening);

  if (!opening) {  // closing: clear selection
    document.querySelectorAll('input[name="badKey"]').forEach(function (r) { r.checked = false; });
  }
}

// ── Utility ───────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Pre-populate with CN by default
addDnField('CN');
</script>

</div><!-- .wrap -->
</main>

<footer class="site-footer">
  <span>&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="/">Home</a>
    <a href="/references.php">PKI References</a>
    <a href="/privacy.php">Privacy Policy</a>
    <a href="<?= 'mailto:' . CONTACT_EMAIL ?>"><?= CONTACT_EMAIL ?></a>
  </div>
</footer>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>

</body>
</html>
