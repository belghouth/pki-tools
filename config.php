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

// ── ECC CA distinguished names ─────────────────────────────────────────────────
define('ECC_ROOT_CA_DN', [
    'C'  => 'TN',
    'O'  => 'Thameur Belghith',
    'CN' => 'Meerkat ECC Root CA',
]);
define('ECC_ISSUING_CA_DN', [
    'C'  => 'TN',
    'O'  => 'Thameur Belghith',
    'CN' => 'Meerkat Test ECC Issuing CA 1',
]);
define('ECC_ROOT_CA_SUBJ',
    '/C=' . ECC_ROOT_CA_DN['C'] . '/O=' . ECC_ROOT_CA_DN['O'] . '/CN=' . ECC_ROOT_CA_DN['CN']);
define('ECC_ISSUING_CA_SUBJ',
    '/C=' . ECC_ISSUING_CA_DN['C'] . '/O=' . ECC_ISSUING_CA_DN['O'] . '/CN=' . ECC_ISSUING_CA_DN['CN']);

// ECC CA curve selection — BR §7.1.3.1
define('ECC_ROOT_CURVE',    'P-384');  // secp384r1 — stronger root key
define('ECC_ISSUING_CURVE', 'P-256');  // prime256v1 — industry standard for issuing CAs

// ECC CA filesystem paths
define('ECC_ROOT_KEY',        PKI_PRIVATE_DIR . '/ecc-root.key');
define('ECC_ROOT_CRT',        PKI_WEB_DIR     . '/meerkat-ecc-root.crt');
define('ECC_ROOT_CRL',        PKI_WEB_DIR     . '/meerkat-ecc-root.crl');
define('ECC_ROOT_DB_DIR',     PKI_CA_DIR      . '/ecc-root-db');

define('ECC_ISSUING_KEY',     PKI_PRIVATE_DIR . '/ecc-issuing.key');
define('ECC_ISSUING_CRT',     PKI_WEB_DIR     . '/meerkat-ecc-issuing.crt');
define('ECC_ISSUING_DB_DIR',  PKI_CA_DIR      . '/ecc-issuing-db');
define('ECC_ISSUING_DB_CNF',  ECC_ISSUING_DB_DIR . '/openssl.cnf');
define('ECC_ISSUING_LOCK',    ECC_ISSUING_DB_DIR . '/factory.lock');
define('ECC_ISSUING_DB_SRL',  ECC_ISSUING_DB_DIR . '/cert.srl');
define('ECC_ISSUING_CRL_OUT', PKI_WEB_DIR     . '/meerkat-ecc-issuing.crl');

// ECC CA URLs
define('ECC_AIA_URL',      PKI_BASE_URL . '/meerkat-ecc-issuing.crt');
define('ECC_CDP_URL',      PKI_BASE_URL . '/meerkat-ecc-issuing.crl');
define('ECC_ROOT_AIA_URL', PKI_BASE_URL . '/meerkat-ecc-root.crt');
define('ECC_ROOT_ARL_URL', PKI_BASE_URL . '/meerkat-ecc-root.crl');

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

// ── DNS-over-HTTPS resolvers ───────────────────────────────────────────────────
// Used server-side for DCV verification and as browser links in the challenge UI.
// 'url'   — DoH JSON API base URL (append ?name=…&type=… to query).
//           Append ?ct=application/dns-json for endpoints that require it (e.g. Cloudflare).
// 'label' — Human-readable name shown in the challenge card.
// Tried in order; first successful response wins.
define('DNS_CHECKERS', [
    ['label' => 'Google DNS',    'url' => 'https://dns.google/resolve'],
    ['label' => 'Cloudflare DNS','url' => 'https://cloudflare-dns.com/dns-query?ct=application/dns-json'],
]);

// ── Contact ───────────────────────────────────────────────────────────────────
define('CONTACT_EMAIL', 'me@thameur.org');
define('NOREPLY_EMAIL', 'no-reply@thameur.org');

// ── External services ─────────────────────────────────────────────────────────
define('PKIMETAL_URL',  'http://127.0.0.1:8080');

// ── MPCA — Multi-Purpose CA ───────────────────────────────────────────────────
define('MPCA_CA_DIR',       PKI_CA_DIR      . '/mpca');
define('MPCA_PROFILES_DIR', MPCA_CA_DIR     . '/profiles');
define('MPCA_WEB_DIR',      PKI_WEB_DIR     . '/mpca');
define('MPCA_BASE_URL',     'https://' . PKI_DOMAIN . '/mpca');
define('MPCA_TSA_URL',      'https://thameur.org/tsa');
define('MPCA_ESEAL_URL',    'https://thameur.org/eseal');

// ── Admin database ────────────────────────────────────────────────────────────
define('ADMIN_DB_HOST', 'localhost');
define('ADMIN_DB_NAME', 'pki_tools');
define('ADMIN_DB_USER', 'pki_tools_XEwWTATB');
define('ADMIN_DB_PASS', 'iseFleqW4bZzLNEMoAAwCgYIKoZIzj0EAwIDRwAwRAIgR5d');

// ── Admin panel ────────────────────────────────────────────────────────────────
define('ADMIN_ALLOWED_EMAIL', 'tbelghith@gmail.com');
define('ADMIN_LOGIN_URL',     SITE_BASE_URL . '/loginIBBjATBgNVHSUEDDAKBg.php');
define('ADMIN_PANEL_URL',     SITE_BASE_URL . '/adminIBBjATBgNVHSUEDDAKBg.php');

// ── Google OAuth ───────────────────────────────────────────────────────────────
// Credentials live in .secrets (KEY=VALUE, gitignored). Defaults = OAuth disabled.
$_google_client_id     = '';
$_google_client_secret = '';
$_secrets_file = __DIR__ . '/.secrets';
if (is_readable($_secrets_file)) {
    foreach (file($_secrets_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $_sl) {
        if (!str_contains($_sl, '=')) continue;
        [$_sk, $_sv] = explode('=', $_sl, 2);
        if (trim($_sk) === 'GOOGLE_CLIENT_ID')     $_google_client_id     = trim($_sv);
        if (trim($_sk) === 'GOOGLE_CLIENT_SECRET') $_google_client_secret = trim($_sv);
    }
}
define('GOOGLE_CLIENT_ID',     $_google_client_id);
define('GOOGLE_CLIENT_SECRET', $_google_client_secret);
unset($_secrets_file, $_sl, $_sk, $_sv, $_google_client_id, $_google_client_secret);

// ── CT log identities ─────────────────────────────────────────────────────────
// Key = filename stem in PKI_CT_KEYS_DIR (e.g. "kablouti" → kablouti.pem / kablouti.id)
// Value = [description, operator, mmd_seconds]
define('CT_LOG_META', [
    'kablouti'   => ['Meerkat Kablouti CT 2025h1',   'Kablouti Certificate Services',       86400],
    'karkoub'    => ['Meerkat Karkoub CT 2025h2',  'Karkoub Trust Infrastructure',        86400],
    'sal7ouf'    => ['Meerkat Sal7ouf CT 2026h1', 'Sal7ouf Digital Logs',                86400],
    'farhoud'    => ['Meerkat Farhoud CT 2025',    'Farhoud CT Authority',                86400],
    'habhoub'    => ['Meerkat Habhoub CT 2026',   'Habhoub Certificate Logs',            86400],
    'sardouk'    => ['Meerkat Sardouk CT 2025h2',  'Sardouk Log Services',                86400],
    'dhibi'      => ['Meerkat Dhibi CT 2026h1',    'Dhibi Digital Trust',                 86400],
    'bousannoun' => ['Meerkat Bousannoun CT 2025',      'Bousannoun Certificate Transparency',  86400],
]);

// ── Activity logging ───────────────────────────────────────────────────────────
// Included here so every page that loads config.php auto-logs visits + PHP errors.
// Admin pages define ADMIN_NO_LOG before including config.php to opt out.
require_once __DIR__ . '/includes/admin_db.php';
