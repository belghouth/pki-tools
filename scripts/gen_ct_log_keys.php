#!/usr/bin/env php
<?php
// gen_ct_log_keys.php — Generate ECDSA P-256 key pairs for the Meerkat Testing CT Log
//
// Creates one key per log identity in $KEYS_DIR.
// Safe to re-run: existing keys are preserved.
// Run as root (or a user with write access to the PKI directory).
//
// Usage:  php /var/www/thameur.org/scripts/gen_ct_log_keys.php

require_once __DIR__ . '/../config.php';

$OPENSSL  = OPENSSL_BIN;
$KEYS_DIR = rtrim(PKI_CT_KEYS_DIR, '/');
$logs     = array_keys(CT_LOG_META);


// ─────────────────────────────────────────────────────────────────────────────

function run(array $cmd): array
{
    $proc = proc_open($cmd, [
        0 => ['file', '/dev/null', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes);
    if (!$proc) return ['ok' => false, 'out' => '', 'err' => 'proc_open failed'];
    $out  = stream_get_contents($pipes[1]);
    $err  = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return ['ok' => $code === 0, 'out' => (string) $out, 'err' => (string) $err];
}

// ─────────────────────────────────────────────────────────────────────────────

if (!is_dir($KEYS_DIR)) {
    mkdir($KEYS_DIR, 0750, true);
    @chgrp($KEYS_DIR, 'www-data');
    echo "Created $KEYS_DIR\n";
}

$all_ok = true;

foreach ($logs as $name) {
    $key_file = "$KEYS_DIR/$name.pem";
    $id_file  = "$KEYS_DIR/$name.id";

    if (file_exists($key_file) && file_exists($id_file)) {
        $log_id = trim(file_get_contents($id_file));
        echo "[$name] exists — Log ID: $log_id\n";
        continue;
    }

    echo "[$name] generating ECDSA P-256 key pair…";

    // Generate private key (traditional EC format, no passphrase)
    $tmp_key = sys_get_temp_dir() . "/ct_gen_{$name}_" . bin2hex(random_bytes(4)) . '.pem';
    $r = run([$OPENSSL, 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $tmp_key]);
    if (!$r['ok']) {
        echo " FAILED (ecparam): {$r['err']}\n";
        $all_ok = false;
        continue;
    }

    // Export SubjectPublicKeyInfo DER from the temp file so we can compute the Log ID.
    // Use 'openssl pkey' (not the legacy 'openssl ec') — OpenSSL 3.x STORE routines
    // reject '-' as a stdin specifier, so we read from the temp file directly.
    $r2 = run([$OPENSSL, 'pkey', '-in', $tmp_key, '-pubout', '-outform', 'DER']);
    $key_pem = (string) file_get_contents($tmp_key);
    @unlink($tmp_key);

    if (!$r2['ok']) {
        echo " FAILED (pkey -pubout): {$r2['err']}\n";
        $all_ok = false;
        continue;
    }

    $log_id = hash('sha256', $r2['out']); // hex string
    file_put_contents($key_file, $key_pem);
    file_put_contents($id_file,  $log_id . "\n");

    chmod($key_file, 0640);
    chmod($id_file,  0644);
    @chgrp($key_file, 'www-data');
    @chgrp($id_file,  'www-data');

    echo " done\n  Log ID: $log_id\n";
}

echo $all_ok ? "\nAll log keys ready.\n" : "\nSome keys failed — check output above.\n";
