<?php
$ch = curl_init('http://127.0.0.1:8080/');
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 3]);
$out = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$err = curl_error($ch);
curl_close($ch);
echo "HTTP: $code\nError: $err\nBody length: " . strlen($out) . "\n";
