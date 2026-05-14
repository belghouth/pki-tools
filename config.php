<?php
// ── Meerkat PKI — site configuration ─────────────────────────────────────────
// All deployment-specific values live here.
//
// Usage (from site root):   require_once __DIR__ . '/config.php';
//        (from scripts/):   require_once __DIR__ . '/../config.php';

// ── Domains ───────────────────────────────────────────────────────────────────
define('SITE_DOMAIN', 'thameur.org');
define('PKI_DOMAIN',  'pki.thameur.org');

// ── Binaries ──────────────────────────────────────────────────────────────────
define('OPENSSL_BIN', '/usr/bin/openssl');

// ── Filesystem paths ──────────────────────────────────────────────────────────
// Base directories
define('SITE_DATA_DIR',   '/var/www/thameur.org');
define('PKI_WEB_DIR',     '/var/www/pki.thameur.org');
define('PKI_CA_DIR',      SITE_DATA_DIR . '/pki-ca');
define('PKI_PRIVATE_DIR', PKI_CA_DIR    . '/private');
define('PKI_CT_KEYS_DIR', PKI_CA_DIR    . '/ct-log-keys/');

// Root CA
define('ROOT_KEY',        PKI_PRIVATE_DIR . '/root.key');
define('ROOT_CRT',        PKI_WEB_DIR     . '/meerkat-root.crt');
define('ROOT_CRL',        PKI_WEB_DIR     . '/meerkat-root.crl');
define('ROOT_DB_DIR',     PKI_CA_DIR      . '/root-db');

// Issuing CA
define('ISSUING_KEY',     PKI_PRIVATE_DIR . '/issuing.key');
define('ISSUING_CRT',     PKI_WEB_DIR     . '/meerkat-issuing.crt');
define('ISSUING_DB_DIR',  PKI_CA_DIR      . '/issuing-db');
define('ISSUING_DB_CNF',  ISSUING_DB_DIR  . '/openssl.cnf');
define('ISSUING_LOCK',    ISSUING_DB_DIR  . '/factory.lock');
define('ISSUING_DB_SRL',  ISSUING_DB_DIR  . '/cert.srl');
define('ISSUING_CRL_OUT', PKI_WEB_DIR     . '/meerkat-issuing.crl');

// ── URLs ──────────────────────────────────────────────────────────────────────
define('PKI_BASE_URL',    'http://'  . PKI_DOMAIN);
define('SITE_BASE_URL',   'https://' . SITE_DOMAIN);
define('AIA_URL',         PKI_BASE_URL  . '/meerkat-issuing.crt');
define('CDP_URL',         PKI_BASE_URL  . '/meerkat-issuing.crl');
define('ROOT_AIA_URL',    PKI_BASE_URL  . '/meerkat-root.crt');
define('ROOT_ARL_URL',    PKI_BASE_URL  . '/meerkat-root.crl');
define('CT_LOG_URL',      SITE_BASE_URL . '/ct/v1/add-pre-chain');
define('CT_LOG_BASE_URL', SITE_BASE_URL . '/ct/v1/');
// Route CT log requests directly to the local process (avoids an external round-trip)
define('CT_LOG_RESOLVE',  SITE_DOMAIN . ':443:127.0.0.1');

// ── CA distinguished names ────────────────────────────────────────────────────
define('ROOT_CA_DN', [
    'C'  => 'TN',
    'O'  => 'Thameur Belghith',
    'CN' => 'Meerkat Root CA',
]);
define('ISSUING_CA_DN', [
    'C'  => 'TN',
    'O'  => 'Thameur Belghith',
    'CN' => 'Meerkat Test Issuing CA 1',
]);
// Pre-built OpenSSL -subj strings (derived from the arrays above)
define('ROOT_CA_SUBJ',
    '/C=' . ROOT_CA_DN['C'] . '/O=' . ROOT_CA_DN['O'] . '/CN=' . ROOT_CA_DN['CN']);
define('ISSUING_CA_SUBJ',
    '/C=' . ISSUING_CA_DN['C'] . '/O=' . ISSUING_CA_DN['O'] . '/CN=' . ISSUING_CA_DN['CN']);

// ── Certificate policy ────────────────────────────────────────────────────────
define('CERT_DAYS',        90);    // subscriber cert validity
define('ROOT_CA_DAYS',   3650);    // ~10 years
define('ISSUING_CA_DAYS', 1825);   // ~5 years
define('ARL_DAYS',         365);   // Root ARL validity
define('CRL_DAYS',           7);   // Issuing CRL validity — CABF BR §4.9.7 max 10 days
define('ROOT_KEY_BITS',   4096);
define('ISSUING_KEY_BITS', 2048);
define('MIN_KEY_BITS',    2048);   // minimum accepted for subscriber certs
define('MAX_CSR_BYTES',  65536);   // 64 KB
define('MAX_SANS',         100);
define('CAA_ISSUER',  SITE_DOMAIN);

// ── Contact ───────────────────────────────────────────────────────────────────
define('CONTACT_EMAIL', 'me@thameur.org');
define('NOREPLY_EMAIL', 'no-reply@thameur.org');

// ── External services ─────────────────────────────────────────────────────────
define('PKIMETAL_URL',  'http://127.0.0.1:8080');

// ── CT log identities ─────────────────────────────────────────────────────────
// Key = filename stem in PKI_CT_KEYS_DIR (e.g. "kablouti" → kablouti.pem / kablouti.id)
// Value = [description, operator, mmd_seconds]
define('CT_LOG_META', [
    'kablouti'   => ['Meerkat Lynx CT 2025h1',   'Kablouti Certificate Services',       86400],
    'karkoub'    => ['Meerkat Osprey CT 2025h2',  'Karkoub Trust Infrastructure',        86400],
    'sal7ouf'    => ['Meerkat Kestrel CT 2026h1', 'Sal7ouf Digital Logs',                86400],
    'farhoud'    => ['Meerkat Merlin CT 2025',    'Farhoud CT Authority',                86400],
    'habhoub'    => ['Meerkat Harrier CT 2026',   'Habhoub Certificate Logs',            86400],
    'sardouk'    => ['Meerkat Falcon CT 2025h2',  'Sardouk Log Services',                86400],
    'dhibi'      => ['Meerkat Ibis CT 2026h1',    'Dhibi Digital Trust',                 86400],
    'bousannoun' => ['Meerkat Wren CT 2025',      'Bousannoun Certificate Transparency',  86400],
]);
