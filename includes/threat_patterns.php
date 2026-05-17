<?php
/**
 * threat_patterns.php — centralised honeypot / exploit URI dictionary
 *
 * Each entry in HONEYPOT_PATTERNS is a regex fragment designed to be
 * compatible with BOTH:
 *   • MySQL REGEXP (ICU / POSIX ERE) — used in SOC SQL queries
 *   • PHP preg_match() with  #…#i   — used in session_analysis
 *
 * Authoring rules
 *   [.] for literal dot  (avoids ERE "any char" meaning of .)
 *   [+] for literal plus
 *   No /  (conflicts with PHP / delimiter in some callers)
 *   No PCRE extensions (no (?:…), no lookahead)
 *   Prefer anchored suffixes like ($|[?]) over unbounded trailing .*
 */

const HONEYPOT_PATTERNS = [

    // ── Network / VPN appliances ──────────────────────────────────────────────
    '[+]CSCOE[+]',              // Cisco ASA WebVPN  (/+CSCOE+/logon.html)
    'dana-na/auth',             // Pulse Secure / Ivanti Connect Secure VPN
    'dana-cached/page/nc',      // Pulse Secure secondary probe
    'remote/login',             // Fortinet FortiGate SSL-VPN
    'remote/fgt_lang',          // Fortinet FortiOS language probe
    'remote/hostcheck',         // Fortinet host-check endpoint
    'vpn/index[.]html',         // Generic VPN portal fingerprint

    // ── Microsoft Exchange / OWA ──────────────────────────────────────────────
    '/owa/',                    // Outlook Web App
    '/ecp/',                    // Exchange Control Panel (admin)
    '/autodiscover/',           // Exchange Autodiscover
    '/mapi/',                   // Exchange MAPI over HTTP
    '/EWS/',                    // Exchange Web Services
    '/PowerShell/',             // Exchange PowerShell remoting endpoint
    '/rpc/',                    // Exchange RPC over HTTP (legacy)

    // ── WordPress ─────────────────────────────────────────────────────────────
    'wp-login[.]php',
    'wp-admin',
    'wp-config[.]php',
    'xmlrpc[.]php',
    'wp-content/debug[.]log',

    // ── PHP admin / database panels ───────────────────────────────────────────
    'phpmyadmin',
    'adminer',
    '/pma/',
    '/myadmin/',
    '/mypma/',
    '/pgadmin/',
    '/dbadmin/',

    // ── CMS / Java / app servers ──────────────────────────────────────────────
    '/administrator/',          // Joomla admin
    '/manager/html',            // Apache Tomcat manager
    '/manager/text',            // Tomcat text manager
    '/solr/',                   // Apache Solr admin UI
    '/jenkins/',                // Jenkins CI
    '/confluence/',             // Atlassian Confluence

    // ── Sensitive config / credential files ───────────────────────────────────
    '[.]env($|[?/])',           // .env .env.local .env.production …
    '[.]git/',                  // .git/config .git/HEAD …
    '[.]htaccess',
    '[.]htpasswd',
    '[.]ssh/',
    'web[.]config',
    '[.]DS_Store',
    '[.]svn/',
    '[.]idea/',
    'config[.]yml',
    'database[.]yml',
    'secrets[.]yml',

    // ── Backup / dump archives ────────────────────────────────────────────────
    '[.](sql|bak|backup|tar|gz|zip|7z|rar|dump)($|[?])',

    // ── Webshells / exploit PHP files ─────────────────────────────────────────
    'phpinfo',
    '/shell[.]php',
    '/cmd[.]php',
    'c99[.]php',
    'r57[.]php',
    'b374k[.]php',
    'webshell',
    'backdoor[.]php',
    '/setup[.]php',
    '/install[.]php',
    'config[.]php[.]bak',

    // ── OS / path traversal ───────────────────────────────────────────────────
    '/etc/passwd',
    '/etc/shadow',
    '/proc/self',
    '/windows/win[.]ini',
    '/winnt/win[.]ini',

    // ── Framework-specific exploits ───────────────────────────────────────────
    '_ignition/execute-solution',   // Laravel Ignition RCE  (CVE-2021-3129)
    '/telescope/',                  // Laravel Telescope (dev UI on prod)
    '/actuator/',                   // Spring Boot Actuator (sensitive data)
    '/phpunit/',                    // PHPUnit eval-stdin exploit path prefix
    'eval-stdin[.]php',             // PHPUnit RCE vector
    'swagger-ui[.]html',            // API browser (recon / schema exposure)
    '/v2/api-docs',                 // Swagger v2 schema endpoint

];

/**
 * Returns a MySQL REGEXP alternation string for use in:
 *   WHERE uri REGEXP '<?= honeypot_mysql_regexp() ?>'
 */
function honeypot_mysql_regexp(): string {
    return implode('|', HONEYPOT_PATTERNS);
}

/**
 * Returns the raw pattern fragment (no delimiters, no flags) for embedding
 * in a larger PHP regex, e.g.:
 *   $rx = '#' . honeypot_php_fragment() . '|UNION.{1,20}SELECT#i';
 */
function honeypot_php_fragment(): string {
    return implode('|', HONEYPOT_PATTERNS);
}
