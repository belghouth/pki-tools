<?php
// ── XAdES-B-B / XAdES-B-T detached signature builder ─────────────────────────
// Produces a standalone ds:Signature XML over a pre-computed document digest.
//
// XAdES-B-B : ETSI EN 319 132-2 baseline (signature + qualifying properties)
// XAdES-B-T : B-B + RFC 3161 SignatureTimeStamp unsigned attribute
//
// The content ds:Reference uses URI="" as a placeholder — callers should note
// that validators need the original document to verify the content digest.

define('XA_DS',   'http://www.w3.org/2000/09/xmldsig#');
define('XA_XA',   'http://uri.etsi.org/01903/v1.3.2#');
define('XA_C14N', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');

// Algorithm URIs for XMLDSig
function xa_alg(string $hash_alg): array {
    return match ($hash_alg) {
        'sha384' => [
            'digest' => 'http://www.w3.org/2001/04/xmldsig-more#sha384',
            'sig'    => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
            'php'    => OPENSSL_ALGO_SHA384,
        ],
        'sha512' => [
            'digest' => 'http://www.w3.org/2001/04/xmlenc#sha512',
            'sig'    => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
            'php'    => OPENSSL_ALGO_SHA512,
        ],
        default => [
            'digest' => 'http://www.w3.org/2001/04/xmlenc#sha256',
            'sig'    => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
            'php'    => OPENSSL_ALGO_SHA256,
        ],
    };
}

// Convert DER-encoded ECDSA {r,s} to raw r||s required by XMLDSig.
// P-256 → kb=32, P-384 → kb=48.
function xa_der_to_raw(string $der, int $kb): string {
    $o = 0;
    if (ord($der[$o++]) !== 0x30) return '';
    $lb = ord($der[$o++]);
    if ($lb & 0x80) $o += ($lb & 0x7F);   // skip multi-byte length bytes
    if (ord($der[$o++]) !== 0x02) return '';
    $rl = ord($der[$o++]);
    $r  = substr($der, $o, $rl); $o += $rl;
    if (ord($der[$o++]) !== 0x02) return '';
    $sl = ord($der[$o++]);
    $s  = substr($der, $o, $sl);
    return str_pad(ltrim($r, "\x00"), $kb, "\x00", STR_PAD_LEFT)
         . str_pad(ltrim($s, "\x00"), $kb, "\x00", STR_PAD_LEFT);
}

// Strip PEM armor → raw DER bytes.
function xa_cert_der(string $pem): string {
    return (string) base64_decode(preg_replace('/\s|-----[A-Z ]+-----/', '', $pem), true);
}

// Minimal DER TLV parser used for TST extraction.
function xa_tlv(string $d, int $off): array {
    $tag = ord($d[$off++]);
    $lb  = ord($d[$off++]);
    if ($lb & 0x80) {
        $n = $lb & 0x7F; $len = 0;
        for ($i = 0; $i < $n; $i++) $len = ($len << 8) | ord($d[$off++]);
    } else { $len = $lb; }
    return ['tag' => $tag, 'val_off' => $off, 'val_len' => $len, 'end' => $off + $len];
}

// Extract TimeStampToken (CMS SignedData) from DER TimeStampResp.
function xa_extract_tst(string $tsr): ?string {
    if (strlen($tsr) < 4 || ord($tsr[0]) !== 0x30) return null;
    $outer  = xa_tlv($tsr, 0);
    $status = xa_tlv($tsr, $outer['val_off']);
    if ($status['tag'] !== 0x30 || $status['end'] >= $outer['end']) return null;
    return substr($tsr, $status['end'], $outer['end'] - $status['end']);
}

// Run a subprocess, return ['ok', 'err'].
function xa_run(array $cmd): array {
    $desc = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $desc, $pipes);
    if (!$proc) return ['ok' => false, 'err' => 'proc_open failed'];
    stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    return ['ok' => proc_close($proc) === 0, 'err' => (string) $err];
}

/**
 * Build a detached XAdES-B-B or XAdES-B-T XML signature.
 *
 * Steps:
 *  1. Build xades:SignedProperties → C14N → SHA-256 → ds:Reference DigestValue
 *  2. Build ds:SignedInfo with both References (content + SignedProperties)
 *  3. C14N ds:SignedInfo → openssl_sign() → convert DER→raw → ds:SignatureValue
 *  4. If with_ts: C14N ds:SignatureValue → TSQ → TSR → TST → xades:SignatureTimeStamp
 *
 * @param array  $hashInfo  ['hex' => hex-string, 'alg' => sha256|sha384|sha512]
 * @param string $cert_pem  PEM of the signing certificate
 * @param string $key_pem   PEM of the private key
 * @param bool   $with_ts   true → embed RFC 3161 SignatureTimeStamp (B-T)
 * @param string $tsa_cnf   Path to openssl tsa.cnf (ignored when !$with_ts)
 * @return string  XML bytes
 */
function xa_sign(array $hashInfo, string $cert_pem, string $key_pem,
                 bool $with_ts, string $tsa_cnf): string
{
    $alg    = xa_alg($hashInfo['alg']);
    $key_r  = openssl_pkey_get_private($key_pem);
    $kd     = openssl_pkey_get_details($key_r);
    $kb     = intdiv((int) $kd['bits'], 8);   // 32 for P-256, 48 for P-384
    $ds     = XA_DS;
    $xa     = XA_XA;
    $c14n   = XA_C14N;
    $now    = gmdate('Y-m-d\TH:i:s\Z');
    $sig_id = 'Sig-' . bin2hex(random_bytes(4));

    $cert_der  = xa_cert_der($cert_pem);
    $cert_hash = base64_encode(hash('sha256', $cert_der, true));
    $cert_b64  = base64_encode($cert_der);

    // ── 1. Build xades:SignedProperties in scratch doc → C14N → hash ─────────
    $tmp = new DOMDocument('1.0', 'UTF-8');
    $sp  = $tmp->createElementNS($xa, 'xades:SignedProperties');
    $sp->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', $ds);
    $sp->setAttribute('Id', 'SignedProperties');

    $ssp  = $tmp->createElementNS($xa, 'xades:SignedSignatureProperties');
    $ssp->appendChild($tmp->createElementNS($xa, 'xades:SigningTime', $now));
    $scv2 = $tmp->createElementNS($xa, 'xades:SigningCertificateV2');
    $cer  = $tmp->createElementNS($xa, 'xades:Cert');
    $cd   = $tmp->createElementNS($xa, 'xades:CertDigest');
    $e    = $tmp->createElementNS($ds, 'ds:DigestMethod');
    $e->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
    $cd->appendChild($e);
    $cd->appendChild($tmp->createElementNS($ds, 'ds:DigestValue', $cert_hash));
    $cer->appendChild($cd); $scv2->appendChild($cer); $ssp->appendChild($scv2);
    $sp->appendChild($ssp); $tmp->appendChild($sp);

    $sp_c14n   = $sp->C14N(false, false);
    $sp_digest = base64_encode(hash('sha256', $sp_c14n, true));

    // ── 2. Build main ds:Signature document ──────────────────────────────────
    $doc = new DOMDocument('1.0', 'UTF-8');
    $doc->formatOutput = true;

    $sig = $doc->createElementNS($ds, 'ds:Signature');
    $sig->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:xades', $xa);
    $sig->setAttribute('Id', $sig_id);
    $doc->appendChild($sig);

    // ds:SignedInfo
    $si = $doc->createElementNS($ds, 'ds:SignedInfo');
    $e  = $doc->createElementNS($ds, 'ds:CanonicalizationMethod');
    $e->setAttribute('Algorithm', $c14n); $si->appendChild($e);
    $e  = $doc->createElementNS($ds, 'ds:SignatureMethod');
    $e->setAttribute('Algorithm', $alg['sig']); $si->appendChild($e);

    // Reference 1: content (detached — user's hash bytes as DigestValue, URI="" is placeholder)
    $r1 = $doc->createElementNS($ds, 'ds:Reference');
    $r1->setAttribute('Id', 'Ref-Content'); $r1->setAttribute('URI', '');
    $e  = $doc->createElementNS($ds, 'ds:DigestMethod');
    $e->setAttribute('Algorithm', $alg['digest']); $r1->appendChild($e);
    $r1->appendChild($doc->createElementNS($ds, 'ds:DigestValue',
        base64_encode(hex2bin($hashInfo['hex']))));
    $si->appendChild($r1);

    // Reference 2: xades:SignedProperties
    $r2 = $doc->createElementNS($ds, 'ds:Reference');
    $r2->setAttribute('Id', 'Ref-SignedProperties');
    $r2->setAttribute('Type', 'http://uri.etsi.org/01903#SignedProperties');
    $r2->setAttribute('URI', '#SignedProperties');
    $e  = $doc->createElementNS($ds, 'ds:DigestMethod');
    $e->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256'); $r2->appendChild($e);
    $r2->appendChild($doc->createElementNS($ds, 'ds:DigestValue', $sp_digest));
    $si->appendChild($r2);
    $sig->appendChild($si);

    // ── 3. Sign C14N(ds:SignedInfo) ───────────────────────────────────────────
    $si_c14n = $si->C14N(false, false);
    $sig_der = '';
    openssl_sign($si_c14n, $sig_der, $key_r, $alg['php']);
    $sig_raw = xa_der_to_raw($sig_der, $kb);

    $sv = $doc->createElementNS($ds, 'ds:SignatureValue', base64_encode($sig_raw));
    $sv->setAttribute('Id', 'SignatureValue');
    $sig->appendChild($sv);

    // ds:KeyInfo
    $ki = $doc->createElementNS($ds, 'ds:KeyInfo');
    $x9 = $doc->createElementNS($ds, 'ds:X509Data');
    $x9->appendChild($doc->createElementNS($ds, 'ds:X509Certificate', $cert_b64));
    $ki->appendChild($x9); $sig->appendChild($ki);

    // ds:Object → xades:QualifyingProperties (import SignedProperties from scratch doc)
    $obj = $doc->createElementNS($ds, 'ds:Object');
    $qp  = $doc->createElementNS($xa, 'xades:QualifyingProperties');
    $qp->setAttribute('Target', '#' . $sig_id);
    $qp->appendChild($doc->importNode($sp, true));
    $obj->appendChild($qp); $sig->appendChild($obj);

    // ── 4. SignatureTimeStamp (XAdES-B-T) ─────────────────────────────────────
    // Per ETSI EN 319 132-1 §5.3.4: TST covers C14N of ds:SignatureValue element.
    if ($with_ts && $tsa_cnf !== '' && file_exists($tsa_cnf)) {
        $sv_c14n = $sv->C14N(false, false);
        $sv_hash = bin2hex(hash('sha256', $sv_c14n, true));

        $tmp_tsq = tempnam(sys_get_temp_dir(), 'xtsq_');
        $tmp_tsr = tempnam(sys_get_temp_dir(), 'xtsr_');
        try {
            $r = xa_run([OPENSSL_BIN, 'ts', '-query',
                         '-digest', $sv_hash, '-sha256', '-cert', '-out', $tmp_tsq]);
            if ($r['ok']) {
                $r = xa_run([OPENSSL_BIN, 'ts', '-reply', '-config', $tsa_cnf,
                             '-queryfile', $tmp_tsq, '-out', $tmp_tsr]);
                if ($r['ok']) {
                    $tst = xa_extract_tst((string) file_get_contents($tmp_tsr));
                    if ($tst !== null) {
                        $up  = $doc->createElementNS($xa, 'xades:UnsignedProperties');
                        $usp = $doc->createElementNS($xa, 'xades:UnsignedSignatureProperties');
                        $sts = $doc->createElementNS($xa, 'xades:SignatureTimeStamp');
                        $sts->setAttribute('Id', 'TS-1');
                        $e   = $doc->createElementNS($ds, 'ds:CanonicalizationMethod');
                        $e->setAttribute('Algorithm', $c14n); $sts->appendChild($e);
                        $sts->appendChild($doc->createElementNS($xa,
                            'xades:EncapsulatedTimeStamp', base64_encode($tst)));
                        $usp->appendChild($sts); $up->appendChild($usp);
                        $qp->appendChild($up);
                    }
                }
            }
        } finally {
            @unlink($tmp_tsq); @unlink($tmp_tsr);
        }
    }

    return (string) $doc->saveXML();
}
