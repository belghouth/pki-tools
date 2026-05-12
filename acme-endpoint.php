<?php
// ---------------------------------------------------------------------------
// Certificate + renewal data
// ---------------------------------------------------------------------------
$certInfo         = [];
$certExpiry       = null;
$certNotBefore    = null;
$certIssuer       = null;
$certSubject      = null;
$certPolicyOIDs   = [];
$secondsRemaining = null;
$daysRemaining    = null;
$hoursRemaining   = null;
$renewalStatus    = 'Active';
$scts             = [];
$certValidityDays  = null;
$certValidityHours = null;
$renewOffsetDays  = null;
$renewTriggerDays = null;
$certFingerprint  = null;

$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$streamContext = stream_context_create([
    'ssl' => [
        'capture_peer_cert' => true,
        'verify_peer'       => false,
        'verify_peer_name'  => false,
    ]
]);

$conn = @stream_socket_client(
    "ssl://{$host}:443",
    $errno, $errstr, 5,
    STREAM_CLIENT_CONNECT,
    $streamContext
);

if ($conn) {
    $params = stream_context_get_params($conn);
    $cert   = $params['options']['ssl']['peer_certificate'] ?? null;
    if ($cert) {
        $certInfo      = openssl_x509_parse($cert);
        $certSubject   = $certInfo['subject']['CN'] ?? $host;
        $certIssuer    = $certInfo['issuer']['CN'] ?? 'Unknown';
        $certNotBefore = date('Y-m-d H:i:s T', $certInfo['validFrom_time_t']);
        $certExpiry    = date('Y-m-d H:i:s T', $certInfo['validTo_time_t']);

        // High-resolution remaining time
        $secondsRemaining = $certInfo['validTo_time_t'] - time();
        $daysRemaining    = (int)($secondsRemaining / 86400);
        $hoursRemaining   = (int)(($secondsRemaining % 86400) / 3600);

        // Certificate total validity in days + leftover hours
        $validitySeconds   = $certInfo['validTo_time_t'] - $certInfo['validFrom_time_t'];
        $certValidityDays  = (int)($validitySeconds / 86400);
        $certValidityHours = (int)(($validitySeconds % 86400) / 3600);

        $certFingerprint = openssl_x509_fingerprint($cert, 'sha256');

        // Policy OIDs
        $rawPolicies = $certInfo['extensions']['certificatePolicies'] ?? '';
        if ($rawPolicies) {
            preg_match_all('/\d+(?:\.\d+){3,}/', $rawPolicies, $oidMatches);
            $certPolicyOIDs = array_unique($oidMatches[0] ?? []);
        }

        // ---------------------------------------------------------------------------
        // SCT parsing — RFC 6962 §3.3 binary decoder
        // ---------------------------------------------------------------------------
        $knownLogs = [
            'e83ed0da3ef5063532e75728bc896bc903d3cbd1116beceb69e1777d6d06bd6e' => ['name' => 'Google "Argon2024"',       'url' => 'https://ct.googleapis.com/logs/us1/argon2024/'],
            '7d3ef2f88fff88556824c2c0ca9e5289792bc50e78097f2e6a9768997e22f0d7' => ['name' => 'Google "Argon2025h1"',     'url' => 'https://ct.googleapis.com/logs/us1/argon2025h1/'],
            'eec095ee8d72640f92e3c3b91bc712a3696a097b4b6a1a1438e647b2cbedc5f' => ['name' => 'Google "Argon2025h2"',     'url' => 'https://ct.googleapis.com/logs/us1/argon2025h2/'],
            '19860004985b1fc8f7e27f2d79e89032cf8e4b82d4c65d0cca6e4f4003e7bc0' => ['name' => 'Google "Xenon2024"',      'url' => 'https://ct.googleapis.com/logs/eu1/xenon2024/'],
            '76ff88ba577778238e6dfcc9c7000a82e04ab0b38ce9c02cadb93282eb90184' => ['name' => 'Google "Xenon2025h1"',    'url' => 'https://ct.googleapis.com/logs/eu1/xenon2025h1/'],
            'cf16b53f2688f14cbc9b8ff4c66cfc0d76ffd6cfd1bd2fa2e9c5a30a27ab8a8' => ['name' => 'Google "Xenon2025h2"',    'url' => 'https://ct.googleapis.com/logs/eu1/xenon2025h2/'],
            'c165cb6ef6b803f8a02c30ca20a68eed40e3d58c3fa0e6e6e5b24d39dee76f8' => ['name' => 'Cloudflare "Nimbus2024"', 'url' => 'https://ct.cloudflare.com/logs/nimbus2024/'],
            '5614069a2fd7c2ecd3f5e1bd44b23ec74676b9bc99115cc0ef949855d689d0dd' => ['name' => 'Cloudflare "Nimbus2025"', 'url' => 'https://ct.cloudflare.com/logs/nimbus2025/'],
            'da2e930be39641f56718ef84c0e2d2f3a0cccd6ba19ceef52af4e54e9a0e880' => ['name' => 'Sectigo "Mammoth"',       'url' => 'https://mammoth.ct.comodo.com/'],
            'e866691d2b7a0f85c0f1afbde3fd6ef5a6f3e7b0fec02e37a6f43a3ba5f6e1f' => ['name' => 'Sectigo "Sabre"',        'url' => 'https://sabre.ct.comodo.com/'],
            '6ff141b5647e4222f7ef052cefae7c21fd608e27d2af5a6e9f4b8a37d6633ee' => ['name' => 'DigiCert "Yeti2024"',    'url' => 'https://yeti2024.ct.digicert.com/log/'],
            '4e75a3275c9a10c3385b6cd4df3f52eb1df0e08e1b8d69c0b1fa64b1629a39e' => ['name' => 'DigiCert "Yeti2025"',    'url' => 'https://yeti2025.ct.digicert.com/log/'],
            '7d59a0a38f61ae0abf04440e5b5754ceae5f05c59d8f9d15e9aad8b72c2c4b4' => ['name' => 'DigiCert "Nessie2024"', 'url' => 'https://nessie2024.ct.digicert.com/log/'],
            '8a328f1638be40c2c15a2c5f26e44a56e84e6f75e75f6ed8d64fede36484f7a' => ['name' => 'DigiCert "Nessie2025"', 'url' => 'https://nessie2025.ct.digicert.com/log/'],
            'b73efb24df9c4dba75f1daa174f5f9aef3de82bef8e3792e7dae070888bb81b' => ['name' => "Let's Encrypt \"Oak2024H1\"", 'url' => 'https://oak.ct.letsencrypt.org/2024h1/'],
            '3b5374bd9d61e2d0006a42d0a3ef7cbf7c939c33daa4a5b4c0baef55f834d1f' => ['name' => "Let's Encrypt \"Oak2024H2\"", 'url' => 'https://oak.ct.letsencrypt.org/2024h2/'],
            'a2e9978f98dab62a4c0e43a45c18e50bdb9cf0c0c38c0c14e4c51f90ab4e3f1' => ['name' => "Let's Encrypt \"Oak2025H1\"", 'url' => 'https://oak.ct.letsencrypt.org/2025h1/'],
            '6cfe501943a85ea916bc52d133e4dcc91ef1411c7d258420d173809e1818eb3a' => ['name' => "Let's Encrypt \"Oak2025H2\"", 'url' => 'https://oak.ct.letsencrypt.org/2025h2/'],
            'd76d7d10d1a7f577c2c7e95fd700bff982c9335a65e1d0b30173170c8c56977'  => ['name' => 'Google "Argon2026h1"',    'url' => 'https://ct.googleapis.com/logs/us1/argon2026h1/'],
        ];

        openssl_x509_export($cert, $pem);
        $der = base64_decode(implode('', array_filter(
            explode("\n", $pem),
            fn($l) => $l !== '' && strpos($l, '-----') === false
        )));

        $sctOid = "\x06\x0a\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02";
        $oidPos = strpos($der, $sctOid);

        if ($oidPos !== false) {
            $pos = $oidPos + strlen($sctOid);
            if (isset($der[$pos]) && ord($der[$pos]) === 0x01) $pos += 3;
            if (isset($der[$pos]) && ord($der[$pos]) === 0x04) {
                $pos++;
                $pos += (ord($der[$pos]) & 0x80) ? (ord($der[$pos]) & 0x7f) + 1 : 1;
            }
            if (isset($der[$pos]) && ord($der[$pos]) === 0x04) {
                $pos++;
                $pos += (ord($der[$pos]) & 0x80) ? (ord($der[$pos]) & 0x7f) + 1 : 1;
            }

            if ($pos + 2 <= strlen($der)) {
                $listLen = unpack('n', substr($der, $pos, 2))[1];
                $pos += 2;
                $end  = $pos + $listLen;

                while ($pos + 2 <= $end) {
                    $sctLen = unpack('n', substr($der, $pos, 2))[1];
                    $pos   += 2;
                    $sctEnd = $pos + $sctLen;
                    if ($pos + $sctLen > strlen($der)) break;

                    $version  = ord($der[$pos]); $pos++;
                    $logIdBin = substr($der, $pos, 32); $pos += 32;
                    $logIdHex = bin2hex($logIdBin);

                    [$hi, $lo] = array_values(unpack('N2', substr($der, $pos, 8))); $pos += 8;
                    $tsMsFloat = ($hi * 4294967296.0) + ($lo < 0 ? $lo + 4294967296.0 : $lo);
                    $tsSeconds = (int)($tsMsFloat / 1000);
                    $tsFmt     = gmdate('M j H:i:s.', $tsSeconds) . str_pad((int)($tsMsFloat % 1000), 3, '0', STR_PAD_LEFT) . ' ' . gmdate('Y', $tsSeconds) . ' GMT';

                    $extLen = unpack('n', substr($der, $pos, 2))[1]; $pos += 2;
                    $extBin = substr($der, $pos, $extLen); $pos += $extLen;
                    $extHex = $extLen > 0 ? implode(':', str_split(strtoupper(bin2hex($extBin)), 2)) : 'none';

                    $hashAlg = ord($der[$pos]); $pos++;
                    $sigAlg  = ord($der[$pos]); $pos++;
                    $sigLen  = unpack('n', substr($der, $pos, 2))[1]; $pos += 2;
                    $pos    += $sigLen;

                    $hashNames = [4 => 'sha256', 5 => 'sha384', 6 => 'sha512'];
                    $sigNames  = [1 => 'rsa', 3 => 'ecdsa'];
                    $sigAlgStr = ($sigNames[$sigAlg] ?? 'unknown') . '-with-' . strtoupper($hashNames[$hashAlg] ?? 'unknown');

                    $scts[] = [
                        'log_id_hex' => $logIdHex,
                        'log_name'   => $knownLogs[$logIdHex]['name'] ?? null,
                        'log_url'    => $knownLogs[$logIdHex]['url']  ?? null,
                        'timestamp'  => $tsFmt,
                        'sig_alg'    => $sigAlgStr,
                        'extensions' => $extHex,
                    ];

                    $pos = $sctEnd;
                }
            }
        }
    }
    fclose($conn);
}

// Renewal trigger from /etc/lego-renew.conf
$conf = @file_get_contents('/etc/lego-renew.conf');
if ($conf && preg_match('/RENEW_OFFSET_DAYS\s*=\s*(\d+)/', $conf, $m)) {
    $renewOffsetDays  = (int)$m[1];
    if ($certValidityDays !== null) {
        $renewTriggerDays = $certValidityDays - $renewOffsetDays;
    }
}

$now        = date('Y-m-d H:i:s T');
$protocol   = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'HTTPS' : 'HTTP';
$tlsVersion = $_SERVER['SSL_PROTOCOL'] ?? 'TLS (version unavailable)';
$serverSoft = $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown';

if ($secondsRemaining !== null) {
    if ($secondsRemaining <= 259200)     $renewalStatus = 'Critical'; // ≤3 days
    elseif ($secondsRemaining <= 604800) $renewalStatus = 'Warning';  // ≤7 days
    else                                 $renewalStatus = 'Valid';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ACME Automation Test Endpoint</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg:         #0a0e14;
            --surface:    #111620;
            --border:     #1e2a3a;
            --accent:     #00d4aa;
            --accent2:    #0088ff;
            --warn:       #ffb300;
            --danger:     #ff4455;
            --text:       #c8d6e8;
            --text-dim:   #556070;
            --text-bright:#e8f4ff;
            --mono:       'JetBrains Mono', monospace;
            --sans:       'Syne', sans-serif;
        }

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--mono);
            font-size: 13px;
            min-height: 100vh;
            overflow-x: hidden;
        }

.header-mascot {
    display: flex;
    align-items: flex-end;
    justify-content: center;
    flex-shrink: 0;
}

.header-mascot img {
    width: 120px;
    height: auto;
    object-fit: contain;
    filter: drop-shadow(0 0 12px rgba(0, 212, 170, 0.2));
}

        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(0,212,170,.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,212,170,.03) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
            z-index: 0;
        }

        .glow-orb {
            position: fixed; width: 500px; height: 500px; border-radius: 50%;
            background: radial-gradient(circle, rgba(0,136,255,.08) 0%, transparent 70%);
            top: -150px; right: -150px; pointer-events: none; z-index: 0;
            animation: drift 12s ease-in-out infinite alternate;
        }
        .glow-orb2 {
            position: fixed; width: 400px; height: 400px; border-radius: 50%;
            background: radial-gradient(circle, rgba(0,212,170,.06) 0%, transparent 70%);
            bottom: -100px; left: -100px; pointer-events: none; z-index: 0;
            animation: drift 15s ease-in-out infinite alternate-reverse;
        }
        @keyframes drift {
            from { transform: translate(0,0); }
            to   { transform: translate(30px,20px); }
        }

        .wrapper { position: relative; z-index: 1; max-width: 900px; margin: 0 auto; padding: 48px 24px; }

        .header {
            display: flex; align-items: flex-start; justify-content: space-between;
            flex-wrap: wrap; gap: 16px; margin-bottom: 48px;
            padding-bottom: 32px; border-bottom: 1px solid var(--border);
        }
        .logo-line {
            font-family: var(--sans); font-size: 11px; font-weight: 700;
            letter-spacing: .2em; text-transform: uppercase; color: var(--accent); margin-bottom: 8px;
        }
        h1 { font-family: var(--sans); font-size: clamp(22px,4vw,36px); font-weight: 800; color: var(--text-bright); line-height: 1.1; }
        h1 span { color: var(--accent); }
        .subtitle { margin-top: 8px; color: var(--text-dim); font-size: 12px; }

        .live-clock { text-align: right; }
        .clock-label { font-size: 10px; letter-spacing: .15em; text-transform: uppercase; color: var(--text-dim); margin-bottom: 4px; }
        #clock { font-size: 20px; font-weight: 600; color: var(--accent); letter-spacing: .05em; }
        .clock-date { font-size: 11px; color: var(--text-dim); margin-top: 2px; }

        .status-banner {
            display: flex; align-items: center; gap: 12px;
            padding: 14px 20px; border-radius: 6px; margin-bottom: 32px;
            border: 1px solid; animation: fadeSlide .5s ease forwards;
        }
        .status-banner.Valid    { background: rgba(0,212,170,.07);  border-color: rgba(0,212,170,.3); }
        .status-banner.Warning  { background: rgba(255,179,0,.07);  border-color: rgba(255,179,0,.3); }
        .status-banner.Critical { background: rgba(255,68,85,.07);  border-color: rgba(255,68,85,.3); }
        .status-banner.Active   { background: rgba(0,136,255,.07);  border-color: rgba(0,136,255,.3); }

        .status-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; animation: pulse 2s ease infinite; }
        .Valid    .status-dot { background: var(--accent);  box-shadow: 0 0 8px var(--accent); }
        .Warning  .status-dot { background: var(--warn);    box-shadow: 0 0 8px var(--warn); }
        .Critical .status-dot { background: var(--danger);  box-shadow: 0 0 8px var(--danger); }
        .Active   .status-dot { background: var(--accent2); box-shadow: 0 0 8px var(--accent2); }

        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.4; } }

        .status-text { font-weight: 600; color: var(--text-bright); }
        .status-sub  { margin-left: auto; font-size: 11px; color: var(--text-dim); }

        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px,1fr)); gap: 16px; margin-bottom: 16px; }

        .card {
            background: var(--surface); border: 1px solid var(--border);
            border-radius: 8px; padding: 20px 24px;
            animation: fadeSlide .6s ease forwards; transition: border-color .2s;
        }
        .card:hover { border-color: rgba(0,212,170,.25); }

        .card-label {
            font-size: 10px; letter-spacing: .18em; text-transform: uppercase;
            color: var(--text-dim); margin-bottom: 12px;
            display: flex; align-items: center; gap: 8px;
        }
        .card-label::before {
            content: ''; display: inline-block; width: 3px; height: 12px;
            background: var(--accent); border-radius: 2px;
        }
        .card-value { font-size: 15px; font-weight: 600; color: var(--text-bright); word-break: break-all; }
        .card-value.big { font-size: clamp(28px,5vw,42px); font-family: var(--sans); font-weight: 800; }
        .card-value.accent { color: var(--accent); }
        .card-value.warn   { color: var(--warn); }
        .card-value.danger { color: var(--danger); }
        .card-sub { font-size: 11px; color: var(--text-dim); margin-top: 4px; line-height: 1.6; }
        .card-full { grid-column: 1 / -1; }

        /* Days/hours expiry display */
        .expiry-row {
            display: flex; align-items: baseline; gap: 6px; flex-wrap: wrap;
            margin-bottom: 4px;
        }
        .expiry-days {
            font-size: clamp(28px,5vw,42px); font-family: var(--sans); font-weight: 800;
        }
        .expiry-days-label {
            font-size: 13px; font-weight: 600; color: var(--text-dim);
        }
        .expiry-sep {
            font-size: clamp(20px,3vw,28px); font-family: var(--sans); font-weight: 800;
            color: var(--text-dim); margin: 0 2px;
        }
        .expiry-hours {
            font-size: clamp(20px,3vw,30px); font-family: var(--sans); font-weight: 800;
            color: var(--accent2);
        }
        .expiry-hours.warn   { color: var(--warn); }
        .expiry-hours.danger { color: var(--danger); }
        .expiry-hours-label {
            font-size: 13px; font-weight: 600; color: var(--accent2);
        }
        .expiry-hours-label.warn   { color: var(--warn); }
        .expiry-hours-label.danger { color: var(--danger); }

        .renewal-bar-wrap  { margin-top: 12px; }
        .renewal-bar-track { background: var(--border); border-radius: 4px; height: 6px; overflow: hidden; }
        .renewal-bar-fill  { height: 100%; border-radius: 4px; transition: width .8s ease; }
        .renewal-bar-labels { display: flex; justify-content: space-between; font-size: 10px; color: var(--text-dim); margin-top: 6px; }

        .kv-table { width: 100%; border-collapse: collapse; }
        .kv-table tr { border-bottom: 1px solid var(--border); }
        .kv-table tr:last-child { border-bottom: none; }
        .kv-table td { padding: 9px 0; font-size: 12px; vertical-align: top; }
        .kv-table td:first-child { color: var(--text-dim); width: 180px; padding-right: 16px; white-space: nowrap; }
        .kv-table td:last-child  { color: var(--text-bright); word-break: break-all; }

        .badge {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;
            background: rgba(0,212,170,.12); color: var(--accent); border: 1px solid rgba(0,212,170,.25);
        }
        .tag {
            display: inline-block; padding: 2px 8px; border-radius: 3px;
            font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase;
            background: rgba(0,136,255,.15); color: var(--accent2); border: 1px solid rgba(0,136,255,.2);
        }

        .sct-block {
            border: 1px solid var(--border); border-radius: 6px;
            padding: 16px 20px; margin-bottom: 12px; background: rgba(0,0,0,.2);
        }
        .sct-block:last-child { margin-bottom: 0; }
        .sct-header {
            display: flex; align-items: center; justify-content: space-between;
            flex-wrap: wrap; gap: 8px; margin-bottom: 12px;
            padding-bottom: 10px; border-bottom: 1px solid var(--border);
        }
        .sct-number {
            font-family: var(--sans); font-size: 12px; font-weight: 700;
            color: var(--text-dim); text-transform: uppercase; letter-spacing: .1em;
        }
        .log-name-badge {
            display: inline-block; padding: 2px 10px; border-radius: 3px; font-size: 10px; font-weight: 600;
            background: rgba(0,212,170,.1); color: var(--accent); border: 1px solid rgba(0,212,170,.2);
        }
        .sct-table { width: 100%; border-collapse: collapse; }
        .sct-table tr { border-bottom: 1px solid rgba(30,42,58,.7); }
        .sct-table tr:last-child { border-bottom: none; }
        .sct-table td { padding: 8px 0; font-size: 11px; vertical-align: top; }
        .sct-table td:first-child { color: var(--text-dim); width: 110px; padding-right: 12px; white-space: nowrap; }
        .sct-table td:last-child  { color: var(--text-bright); word-break: break-all; font-family: var(--mono); }

        .logid-unknown { color: var(--accent); font-size: 11px; font-weight: 600; }

        .footer {
            margin-top: 40px; padding-top: 24px; border-top: 1px solid var(--border);
            display: flex; justify-content: space-between; flex-wrap: wrap;
            gap: 12px; font-size: 11px; color: var(--text-dim);
        }

        @keyframes fadeSlide {
            from { opacity: 0; transform: translateY(10px); }
            to   { opacity: 1; transform: translateY(0); }
        }
    </style>
       <link rel="icon" type="image/x-icon" href="/favicon.ico">
       <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">
       <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png">
</head>
<body>

<div class="glow-orb"></div>
<div class="glow-orb2"></div>

<div class="wrapper">

    <!--
    <header class="header">
        <div class="header-left">
            <div class="logo-line">Chrome Root Program</div>
            <h1>ACME Automation<br><span>Test Endpoint</span></h1>
            <p class="subtitle">RFC 8555 &bull; Automated Certificate Renewal Verification</p>
        </div>
        <div class="live-clock">
            <div class="clock-label">Server Time</div>
            <div id="clock">--:--:--</div>
            <div class="clock-date"><?= date('D, d M Y') ?></div>
        </div>
    </header>
    -->	
   
    <?php $navLabel = 'ACME Automation Test Endpoint'; require __DIR__ . '/includes/site_nav.php'; ?>

    <header class="header">
       <div class="header-left">
           <div class="logo-line">Chrome Root Program</div>
           <h1>ACME Automation<br><span>Test Endpoint</span></h1>
           <p class="subtitle">RFC 8555 &bull; Automated Certificate Renewal Verification</p>
       </div>

       <div class="live-clock">
            <div class="clock-label">Server Time</div>
            <div id="clock">--:--:--</div>
            <div class="clock-date"><?= date('D, d M Y') ?></div>
       </div>

       <div class="header-mascot">
          <img src="img/meerkat_240.png" alt="Meerkat sentry — Überwachung" width="120" height="120">
       </div>



<a href="linters.php" style="
    display: inline-flex; align-items: center; gap: 8px;
    align-self: flex-start;
    padding: 8px 16px;
    background: rgba(0,212,170,0.08);
    border: 1px solid rgba(0,212,170,0.3);
    border-radius: 6px;
    color: var(--accent);
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    text-decoration: none;
    transition: background 0.2s, border-color 0.2s;
" onmouseover="this.style.background='rgba(0,212,170,0.16)';this.style.borderColor='rgba(0,212,170,0.55)'"
   onmouseout="this.style.background='rgba(0,212,170,0.08)';this.style.borderColor='rgba(0,212,170,0.3)'">
    <span style="font-size:14px;">⬡</span> PKI Linters
</a>

<a href="cps_to_br_assessor.php" style="
    display: inline-flex; align-items: center; gap: 8px;
    align-self: flex-start;
    padding: 8px 16px;
    background: rgba(0,212,170,0.08);
    border: 1px solid rgba(0,212,170,0.3);
    border-radius: 6px;
    color: var(--accent);
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    text-decoration: none;
    transition: background 0.2s, border-color 0.2s;
" onmouseover="this.style.background='rgba(0,212,170,0.16)';this.style.borderColor='rgba(0,212,170,0.55)'"
   onmouseout="this.style.background='rgba(0,212,170,0.08)';this.style.borderColor='rgba(0,212,170,0.3)'"
   title="Upload or link a CP/CPS document and check coverage against the CAB Forum Baseline Requirements.">
    <span style="font-size:14px;">&#x2261;</span> CP/CPS to BR Assessor
</a>





   </header>

    <?php
    $statusMsg = match($renewalStatus) {
        'Valid'    => "Certificate is valid — automated renewal is operating normally.",
        'Warning'  => "Certificate expiring soon — renewal should trigger imminently.",
        'Critical' => "Certificate expiry imminent — check ACME client immediately.",
        default    => "Certificate monitoring active — TLS introspection unavailable.",
    };
    ?>
    <div class="status-banner <?= $renewalStatus ?>">
        <div class="status-dot"></div>
        <span class="status-text"><?= $renewalStatus ?></span>
        <span><?= $statusMsg ?></span>
        <span class="status-sub"><?= $now ?></span>
    </div>

    <div class="grid">

        <!-- Days / hours until expiry -->
        <div class="card">
            <div class="card-label">Days / Hours Until Expiry</div>
            <?php if ($secondsRemaining !== null): ?>
                <?php
                    $dayCls  = 'accent';
                    $hourCls = '';
                    if ($secondsRemaining <= 259200) { $dayCls = 'danger'; $hourCls = 'danger'; }
                    elseif ($secondsRemaining <= 604800) { $dayCls = 'warn'; $hourCls = 'warn'; }

                    $totalSeconds  = $certInfo['validTo_time_t'] - $certInfo['validFrom_time_t'];
                    $pct = max(0, min(100, round(($secondsRemaining / $totalSeconds) * 100)));
                    $barColor = $secondsRemaining <= 259200 ? 'var(--danger)' : ($secondsRemaining <= 604800 ? 'var(--warn)' : 'var(--accent)');
                ?>
                <div class="expiry-row">
                    <span class="expiry-days <?= $dayCls === 'danger' ? 'card-value big danger' : ($dayCls === 'warn' ? 'card-value big warn' : 'card-value big accent') ?>"><?= $daysRemaining ?></span>
                    <span class="expiry-days-label">d</span>
                    <span class="expiry-sep">&middot;</span>
                    <span class="expiry-hours <?= $hourCls ?>"><?= $hoursRemaining ?></span>
                    <span class="expiry-hours-label <?= $hourCls ?>">h</span>
                </div>
                <div class="card-sub">
                    of <?= $certValidityDays ?>d <?= $certValidityHours ?>h certificate lifecycle
                </div>
                <div class="renewal-bar-wrap">
                    <div class="renewal-bar-track">
                        <div class="renewal-bar-fill" style="width:<?= $pct ?>%; background:<?= $barColor ?>;"></div>
                    </div>
                    <div class="renewal-bar-labels">
                        <span>Expiry</span>
                        <span><?= $pct ?>% remaining</span>
                        <span>Issued</span>
                    </div>
                </div>
            <?php else: ?>
                <div class="card-value" style="color:var(--text-dim)">Unavailable</div>
                <div class="card-sub">TLS introspection not supported</div>
            <?php endif; ?>
        </div>

        <!-- Renewal trigger -->
        <div class="card">
            <div class="card-label">Renewal Trigger</div>
            <?php if ($renewTriggerDays !== null): ?>
                <div class="card-value big accent"><?= $renewTriggerDays ?></div>
                <div class="card-sub">
                    days remaining at trigger<br>
                    (<?= $certValidityDays ?>d validity &minus; <?= $renewOffsetDays ?>d offset)
                </div>
            <?php elseif ($certValidityDays !== null): ?>
                <div class="card-value big accent"><?= $certValidityDays ?></div>
                <div class="card-sub">day validity — offset conf unavailable</div>
            <?php else: ?>
                <div class="card-value big" style="color:var(--text-dim)">—</div>
                <div class="card-sub">conf and cert unavailable</div>
            <?php endif; ?>
            <div style="margin-top:12px;"><span class="badge">&#10003; Chrome Root Program</span></div>
        </div>

        <!-- Protocol -->
	<!--
	<div class="card">
            <div class="card-label">Connection</div>
            <div class="card-value big <?= $protocol === 'HTTPS' ? 'accent' : 'danger' ?>"><?= $protocol ?></div>
            <div class="card-sub"><?= htmlspecialchars($tlsVersion) ?></div>
            <div style="margin-top:12px;"><span class="tag">RFC 8555 ACME</span></div>
        </div>
	-->
    </div>

    <!-- Certificate Details -->
    <div class="grid">
        <div class="card card-full">
            <div class="card-label">Certificate Details</div>
            <table class="kv-table">
                <tr><td>Subject (CN)</td><td><?= htmlspecialchars($certSubject ?? 'Not available') ?></td></tr>
                <tr><td>Issuer (CN)</td><td><?= htmlspecialchars($certIssuer ?? 'Not available') ?></td></tr>
                <tr><td>Not Before</td><td><?= htmlspecialchars($certNotBefore ?? 'Not available') ?></td></tr>
                <tr><td>Not After</td><td><?= htmlspecialchars($certExpiry ?? 'Not available') ?></td></tr>
                <tr><td>Validity</td><td><?= $certValidityDays !== null ? $certValidityDays . 'd ' . $certValidityHours . 'h' : '<span style="color:var(--text-dim)">Not available</span>' ?></td></tr>
                <tr>
                    <td>SHA-256 Fingerprint</td>
                    <td><?php if ($certFingerprint): ?>
                        <span style="font-size:11px;"><?= htmlspecialchars(strtoupper($certFingerprint)) ?></span>
                    <?php else: ?>
                        <span style="color:var(--text-dim)">Not available</span>
                    <?php endif; ?></td>
                </tr>
                <tr>
                    <td>Policy OID(s)</td>
                    <td><?php
                        $oidLabels = [
                            '2.23.140.1.2.1' => 'DV — Domain Validated',
                            '2.23.140.1.2.2' => 'OV — Organization Validated',
                            '2.23.140.1.2.3' => 'IV — Individual Validated',
                            '2.23.140.1.1'   => 'EV — Extended Validation',
                            '2.23.140.1.3'   => 'EV Code Signing',
                            '2.23.140.1.4.1' => 'Non-EV Code Signing',
                            '2.5.29.32.0'    => 'Any Policy',
                        ];
                        if (!empty($certPolicyOIDs)) {
                            foreach ($certPolicyOIDs as $oid) {
                                $label = $oidLabels[$oid] ?? null;
                                echo '<div style="margin-bottom:4px;"><span style="color:var(--accent);font-weight:600;">' . htmlspecialchars($oid) . '</span>';
                                if ($label) echo ' <span style="color:var(--text-dim);font-size:11px;">— ' . htmlspecialchars($label) . '</span>';
                                echo '</div>';
                            }
                        } else { echo '<span style="color:var(--text-dim)">Not available</span>'; }
                    ?></td>
                </tr>
                <tr><td>Server Host</td><td><?= htmlspecialchars($host) ?></td></tr>
                <tr><td>Server Software</td><td><?= htmlspecialchars($serverSoft) ?></td></tr>
                <tr><td>Automation Standard</td><td>ACME — RFC 8555 (Automatic Certificate Management Environment)</td></tr>
                <tr><td>Policy Compliance</td><td>Chrome Root Program Policy v1.8 &bull; Section 1.3.3.1.1</td></tr>
                <tr><td>CCADB Disclosure</td><td>Required — disclose this URL on intermediate certificate record</td></tr>
            </table>
        </div>
    </div>

    <!-- SCTs -->
    <div class="grid">
        <div class="card card-full">
            <div class="card-label">Signed Certificate Timestamps (SCTs)</div>
            <?php if (!empty($scts)): ?>
                <?php foreach ($scts as $i => $sct): ?>
                <div class="sct-block">
                    <div class="sct-header">
                        <span class="sct-number">SCT <?= $i + 1 ?> of <?= count($scts) ?></span>
                        <?php if ($sct['log_name']): ?>
                            <span class="log-name-badge"><?= htmlspecialchars($sct['log_name']) ?></span>
                        <?php else: ?>
                            <span class="log-name-badge" style="color:var(--text-dim);border-color:rgba(85,96,112,.3);background:rgba(85,96,112,.08);">Unknown log</span>
                        <?php endif; ?>
                    </div>
                    <table class="sct-table">
                        <tr><td>Version</td><td>v1 (0x0)</td></tr>
                        <tr>
                            <td>Log ID</td>
                            <td><span class="logid-unknown"><?= htmlspecialchars(strtoupper($sct['log_id_hex'])) ?></span></td>
                        </tr>
                        <tr><td>Timestamp</td><td><?= htmlspecialchars($sct['timestamp']) ?></td></tr>
                        <tr><td>Extensions</td><td><?= htmlspecialchars($sct['extensions'] ?: 'none') ?></td></tr>
                        <tr><td>Signature</td><td><?= htmlspecialchars($sct['sig_alg'] ?: 'Unknown') ?></td></tr>
                    </table>
                </div>
                <?php endforeach; ?>
            <?php else: ?>
                <span style="color:var(--text-dim)">SCTs not available — <code>ct_precert_scts</code> extension absent or TLS introspection failed</span>
            <?php endif; ?>
        </div>
    </div>

    <footer class="footer">
        <span>
            Chrome Root Program &bull; ACME Automation Test Endpoint
            <?php if ($renewTriggerDays !== null): ?>
                &bull; Renewal triggers at &le;<?= $renewTriggerDays ?> days remaining
            <?php endif; ?>
        </span>
        <span>Generated <?= $now ?></span>
    </footer>

</div>

<script>
    function updateClock() {
        const now = new Date();
        const h = String(now.getHours()).padStart(2,'0');
        const m = String(now.getMinutes()).padStart(2,'0');
        const s = String(now.getSeconds()).padStart(2,'0');
        document.getElementById('clock').textContent = `${h}:${m}:${s}`;
    }
    updateClock();
    setInterval(updateClock, 1000);
</script>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>
</body>
</html>
