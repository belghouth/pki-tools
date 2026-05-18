<?php
// ── Admin DB — connection, schema, session helpers ────────────────────────────
// Loaded from config.php. All functions are fail-safe (return null on error).

if (!defined('ADMIN_DB_NAME') || ADMIN_DB_NAME === '') return;

function admin_pdo(): ?PDO {
    static $pdo  = null;
    static $done = false;
    if ($done) return $pdo;
    $done = true;

    // Circuit breaker: if the last attempt failed, wait 30 s before retrying.
    $flag = sys_get_temp_dir() . '/mkt_admin_db_fail';
    if (file_exists($flag) && time() - filemtime($flag) < 30) return null;

    try {
        $dsn = sprintf(
            'mysql:host=%s;dbname=%s;charset=utf8mb4;connect_timeout=2',
            ADMIN_DB_HOST, ADMIN_DB_NAME
        );
        $pdo = new PDO($dsn, ADMIN_DB_USER, ADMIN_DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        @unlink($flag);
        adminSchema($pdo);
    } catch (Throwable) {
        $pdo = null;
        @touch($flag);
    }
    return $pdo;
}

function schemaMigrate(PDO $pdo, string $sql): void {
    try {
        $pdo->exec($sql);
    } catch (Throwable) {
        // Column/index/value already exists — idempotent, safe to ignore
    }
}

function schemaActivity(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS visits (
        id           BIGINT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
        created_at   DATETIME(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        ip           VARCHAR(45)      NOT NULL DEFAULT '',
        method       VARCHAR(10)      NOT NULL DEFAULT '',
        uri          VARCHAR(2048)    NOT NULL DEFAULT '',
        query_string TEXT,
        user_agent   TEXT,
        referer      VARCHAR(2048),
        host         VARCHAR(255),
        is_https     TINYINT(1)       NOT NULL DEFAULT 0,
        script_name  VARCHAR(128),
        accept_lang  VARCHAR(128),
        server_json  JSON,
        INDEX idx_created_at (created_at),
        INDEX idx_ip         (ip),
        INDEX idx_script     (script_name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS errors (
        id           BIGINT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
        created_at   DATETIME(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        ip           VARCHAR(45)      NOT NULL DEFAULT '',
        uri          VARCHAR(2048)    NOT NULL DEFAULT '',
        error_type   VARCHAR(60),
        error_errno  INT,
        error_msg    TEXT,
        error_file   VARCHAR(512),
        error_line   INT UNSIGNED,
        script_name  VARCHAR(128),
        server_json  JSON,
        INDEX idx_created_at (created_at),
        INDEX idx_type       (error_type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    schemaMigrate($pdo, "ALTER TABLE visits ADD COLUMN status SMALLINT UNSIGNED NOT NULL DEFAULT 200 AFTER accept_lang");
    schemaMigrate($pdo, "ALTER TABLE visits ADD INDEX idx_status (status)");
    schemaMigrate($pdo, "ALTER TABLE errors ADD COLUMN acknowledged_at DATETIME NULL DEFAULT NULL AFTER error_line");
    schemaMigrate($pdo, "ALTER TABLE errors ADD INDEX idx_ack (acknowledged_at)");
}

function schemaInfra(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS geoip_cache (
        ip         VARCHAR(45) PRIMARY KEY,
        country    CHAR(3)     NOT NULL DEFAULT 'XX',
        fetched_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_fetched (fetched_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS admin_sessions (
        token        CHAR(64)     PRIMARY KEY,
        email        VARCHAR(255) NOT NULL,
        created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        ip           VARCHAR(45),
        user_agent   TEXT,
        INDEX idx_last_seen (last_seen)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id            BIGINT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
        email         VARCHAR(255)     NOT NULL UNIQUE,
        name          VARCHAR(255)     NOT NULL DEFAULT '',
        is_root       TINYINT(1)       NOT NULL DEFAULT 0,
        is_disabled   TINYINT(1)       NOT NULL DEFAULT 0,
        attributes    JSON,
        password_hash VARCHAR(255)     DEFAULT NULL,
        mfa_secret    VARCHAR(128)     DEFAULT NULL,
        created_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email    (email),
        INDEX idx_disabled (is_disabled)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // Seed immutable root admin — no-op if already present
    $pdo->prepare("INSERT IGNORE INTO users (email, name, is_root) VALUES (?, 'Thameur Belghith', 1)")
        ->execute([ADMIN_ALLOWED_EMAIL]);

    $pdo->exec("CREATE TABLE IF NOT EXISTS blocked_ips (
        id          BIGINT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
        ip          VARCHAR(45)      NOT NULL UNIQUE,
        reason      VARCHAR(500)     DEFAULT NULL,
        blocked_by  VARCHAR(255)     NOT NULL DEFAULT '',
        blocked_at  DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_ip         (ip),
        INDEX idx_blocked_at (blocked_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS nginx_visits (
        id           BIGINT UNSIGNED   AUTO_INCREMENT PRIMARY KEY,
        created_at   DATETIME(3)       NOT NULL,
        ip           VARCHAR(45)       NOT NULL DEFAULT '',
        method       VARCHAR(10)       NOT NULL DEFAULT '',
        host         VARCHAR(255)      NOT NULL DEFAULT '',
        vhost        VARCHAR(255)      NOT NULL DEFAULT '',
        uri          VARCHAR(2048)     NOT NULL DEFAULT '',
        query_string TEXT,
        status       SMALLINT UNSIGNED NOT NULL DEFAULT 200,
        bytes_sent   INT UNSIGNED      DEFAULT NULL,
        user_agent   TEXT,
        referer      VARCHAR(2048),
        is_https     TINYINT(1)        NOT NULL DEFAULT 0,
        proto        VARCHAR(20),
        request_time DECIMAL(10,3)     DEFAULT NULL,
        country      CHAR(3),
        INDEX idx_created_at (created_at),
        INDEX idx_ip         (ip),
        INDEX idx_status     (status),
        INDEX idx_vhost      (vhost(64)),
        INDEX idx_uri        (uri(64))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS nginx_import_cursor (
        id         INT UNSIGNED PRIMARY KEY DEFAULT 1,
        log_inode  BIGINT UNSIGNED NOT NULL DEFAULT 0,
        log_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}

function schemaIntel(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS ip_intel (
        ip            VARCHAR(45)  PRIMARY KEY,
        asn           VARCHAR(20)  DEFAULT NULL,
        org           VARCHAR(255) DEFAULT NULL,
        isp           VARCHAR(255) DEFAULT NULL,
        provider_type ENUM('residential','mobile','hosting','proxy','unknown') NOT NULL DEFAULT 'unknown',
        is_hosting    TINYINT(1)   NOT NULL DEFAULT 0,
        is_proxy      TINYINT(1)   NOT NULL DEFAULT 0,
        is_mobile     TINYINT(1)   NOT NULL DEFAULT 0,
        rdns          VARCHAR(255) DEFAULT NULL,
        bot_claimed   VARCHAR(60)  DEFAULT NULL,
        bot_verified  TINYINT(1)   DEFAULT NULL,
        fetched_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_fetched  (fetched_at),
        INDEX idx_provider (provider_type),
        INDEX idx_bot      (bot_claimed, bot_verified)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS sessions (
        id             BIGINT UNSIGNED   AUTO_INCREMENT PRIMARY KEY,
        ip             VARCHAR(45)       NOT NULL,
        session_start  DATETIME(3)       NOT NULL,
        session_end    DATETIME(3)       NOT NULL,
        duration_s     INT UNSIGNED      NOT NULL DEFAULT 0,
        req_count      INT UNSIGNED      NOT NULL DEFAULT 0,
        uniq_paths     INT UNSIGNED      NOT NULL DEFAULT 0,
        ua_count       SMALLINT UNSIGNED NOT NULL DEFAULT 1,
        c404           INT UNSIGNED      NOT NULL DEFAULT 0,
        c5xx           INT UNSIGNED      NOT NULL DEFAULT 0,
        exploit_hits   INT UNSIGNED      NOT NULL DEFAULT 0,
        has_scanner    TINYINT(1)        NOT NULL DEFAULT 0,
        replay_pairs   INT UNSIGNED      NOT NULL DEFAULT 0,
        pki_hits       INT UNSIGNED      NOT NULL DEFAULT 0,
        score          SMALLINT UNSIGNED NOT NULL DEFAULT 0,
        classification ENUM('human','researcher','crawler','scanner','attacker','unknown','social_probe') NOT NULL DEFAULT 'unknown',
        signals        JSON,
        analyzed_at    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_session (ip, session_start),
        INDEX idx_ip    (ip),
        INDEX idx_start (session_start),
        INDEX idx_score (score),
        INDEX idx_class (classification)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS session_cursor (
        id            INT UNSIGNED PRIMARY KEY DEFAULT 1,
        last_analyzed DATETIME(3)  NOT NULL DEFAULT '2000-01-01 00:00:00.000',
        updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS my_ips (
        ip         VARCHAR(45)                     PRIMARY KEY,
        label      VARCHAR(60)                     DEFAULT NULL,
        type       ENUM('auto','manual')  NOT NULL DEFAULT 'auto',
        first_seen DATETIME               NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen  DATETIME               NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_type      (type),
        INDEX idx_last_seen (last_seen)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    schemaMigrate($pdo, "ALTER TABLE sessions MODIFY classification ENUM('human','researcher','crawler','scanner','attacker','unknown','social_probe') NOT NULL DEFAULT 'unknown'");

    $pdo->exec("CREATE TABLE IF NOT EXISTS ip_watchlist (
        ip               VARCHAR(45)       NOT NULL PRIMARY KEY,
        added_at         DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
        source           VARCHAR(32)       NOT NULL DEFAULT 'manual',
        reason           TEXT,
        score_at_add     SMALLINT UNSIGNED NOT NULL DEFAULT 0,
        status           ENUM('watching','candidate') NOT NULL DEFAULT 'watching',
        escalated_at     DATETIME          DEFAULT NULL,
        escalated_reason TEXT              DEFAULT NULL,
        INDEX idx_status (status),
        INDEX idx_added  (added_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS alert_cursor (
        id            INT UNSIGNED PRIMARY KEY DEFAULT 1,
        last_run_at   DATETIME     NOT NULL DEFAULT '2000-01-01 00:00:00',
        last_alert_at DATETIME     DEFAULT NULL,
        updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                            ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS contact_messages (
        id          INT UNSIGNED  NOT NULL AUTO_INCREMENT PRIMARY KEY,
        name        VARCHAR(120)  NOT NULL,
        email       VARCHAR(254)  NOT NULL,
        topic       VARCHAR(40)   NOT NULL,
        message     TEXT          NOT NULL,
        ip          VARCHAR(45)   NOT NULL DEFAULT '',
        user_agent  VARCHAR(300)  NOT NULL DEFAULT '',
        read_at     DATETIME      DEFAULT NULL,
        created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX (created_at),
        INDEX (read_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS post_payloads (
        id          BIGINT UNSIGNED   AUTO_INCREMENT PRIMARY KEY,
        created_at  DATETIME(3)       NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        ip          VARCHAR(45)       NOT NULL DEFAULT '',
        uri         VARCHAR(255)      NOT NULL DEFAULT '',
        user_agent  TEXT,
        outcome     VARCHAR(40)       NOT NULL DEFAULT '',
        status_code SMALLINT UNSIGNED NOT NULL DEFAULT 200,
        post_json   JSON,
        INDEX idx_created_at (created_at),
        INDEX idx_ip         (ip),
        INDEX idx_outcome    (outcome),
        INDEX idx_uri        (uri(64))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}

function adminSchema(PDO $pdo): void {
    static $done = false;
    if ($done) return;
    $done = true;

    schemaActivity($pdo);
    schemaInfra($pdo);
    schemaIntel($pdo);
}

// Validate admin cookie; returns email on success or null.
function admin_auth_check(): ?string {
    $token = $_COOKIE['mkt_adm'] ?? '';
    if (strlen($token) !== 64 || !ctype_xdigit($token)) return null;
    $pdo = admin_pdo();
    if (!$pdo) return null;
    try {
        $st = $pdo->prepare(
            "SELECT email FROM admin_sessions WHERE token=? AND last_seen > DATE_SUB(NOW(), INTERVAL 12 HOUR)"
        );
        $st->execute([$token]);
        $row = $st->fetch();
        if (!$row) return null;
        // Verify the user still exists and is not disabled — log out immediately if not
        $us = $pdo->prepare("SELECT id FROM users WHERE email=? AND is_disabled=0 LIMIT 1");
        $us->execute([$row['email']]);
        if (!$us->fetch()) {
            $pdo->prepare("DELETE FROM admin_sessions WHERE token=?")->execute([$token]);
            setcookie('mkt_adm', '', ['expires' => time() - 3600, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
            return null;
        }
        $pdo->prepare("UPDATE admin_sessions SET last_seen=NOW(), ip=?, user_agent=? WHERE token=?")
            ->execute([$_SERVER['REMOTE_ADDR'] ?? '', substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500), $token]);
        return $row['email'];
    } catch (Throwable) { return null; }
}

function admin_create_session(string $email): string {
    $token = bin2hex(random_bytes(32));
    try {
        $pdo = admin_pdo();
        $pdo?->prepare("INSERT INTO admin_sessions (token,email,ip,user_agent) VALUES (?,?,?,?)")
            ->execute([$token, $email, $_SERVER['REMOTE_ADDR'] ?? '', substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500)]);
    } catch (Throwable) {}
    return $token;
}

function admin_destroy_session(string $token): void {
    try {
        admin_pdo()?->prepare("DELETE FROM admin_sessions WHERE token=?")->execute([$token]);
    } catch (Throwable) {}
}

function log_visit(int $status = 200): void {
    $pdo = admin_pdo();
    if (!$pdo) return;
    // Prefer real client IP (Cloudflare > X-Real-IP > REMOTE_ADDR)
    $raw = $_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['HTTP_X_REAL_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR'] ?? '';
    $ip = substr(trim(explode(',', $raw)[0]), 0, 45);
    // Cloudflare provides country for free — cache it while we're here
    $cf_cc = strtoupper(trim($_SERVER['HTTP_CF_IPCOUNTRY'] ?? ''));
    if (strlen($cf_cc) === 2 && ctype_alpha($cf_cc) && $cf_cc !== 'XX') {
        geoip_cache_store($ip, $cf_cc);
    }
    $srv = [];
    foreach (['SERVER_PROTOCOL','HTTP_CF_IPCOUNTRY','HTTP_CF_VISITOR',
              'CONTENT_TYPE','CONTENT_LENGTH','HTTP_ACCEPT_ENCODING'] as $k) {
        if (!empty($_SERVER[$k])) $srv[$k] = $_SERVER[$k];
    }
    try {
        $pdo->prepare(
            "INSERT INTO visits
             (ip,method,uri,query_string,user_agent,referer,host,is_https,script_name,accept_lang,status,server_json)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
        )->execute([
            $ip,
            substr($_SERVER['REQUEST_METHOD'] ?? 'GET', 0, 10),
            substr(strtok($_SERVER['REQUEST_URI'] ?? '/', '?'), 0, 2048),
            substr($_SERVER['QUERY_STRING'] ?? '', 0, 2048),
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
            substr($_SERVER['HTTP_REFERER'] ?? '', 0, 500),
            substr($_SERVER['HTTP_HOST'] ?? '', 0, 255),
            (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 1 : 0,
            substr(basename($_SERVER['SCRIPT_FILENAME'] ?? ''), 0, 128),
            substr($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '', 0, 128),
            $status,
            $srv ? json_encode($srv) : null,
        ]);
    } catch (Throwable) {}
}

function _admin_log_error(string $type, int $errno, string $msg, string $file, int $line): void {
    $pdo = admin_pdo();
    if (!$pdo) return;
    $raw = $_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['HTTP_X_REAL_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR'] ?? '';
    $ip = substr(trim(explode(',', $raw)[0]), 0, 45);
    try {
        $pdo->prepare(
            "INSERT INTO errors (ip,uri,error_type,error_errno,error_msg,error_file,error_line,script_name)
             VALUES (?,?,?,?,?,?,?,?)"
        )->execute([
            $ip,
            substr($_SERVER['REQUEST_URI'] ?? '', 0, 2048),
            $type,
            $errno,
            substr($msg, 0, 4000),
            substr($file, 0, 512),
            $line,
            substr(basename($_SERVER['SCRIPT_FILENAME'] ?? ''), 0, 128),
        ]);
    } catch (Throwable) {}
}

// Returns [ip => 'US'] map for the given IPs. Checks geoip_cache first;
// calls ip-api.com batch (free, no key) for misses and stores results.
function geoip_country(array $ips): array {
    if (!$ips) return [];
    $pdo = admin_pdo();
    if (!$pdo) return [];
    $ips = array_values(array_unique(array_filter($ips, fn($ip) => !_geoip_is_private($ip))));
    if (!$ips) return [];

    $ph = implode(',', array_fill(0, count($ips), '?'));
    $st = $pdo->prepare("SELECT ip, country FROM geoip_cache WHERE ip IN ($ph) AND fetched_at > DATE_SUB(NOW(), INTERVAL 30 DAY)");
    $st->execute($ips);
    $out = [];
    foreach ($st->fetchAll() as $r) $out[$r['ip']] = $r['country'];

    $miss = array_values(array_diff($ips, array_keys($out)));
    foreach (array_chunk($miss, 100) as $chunk) {
        $ch = curl_init('http://ip-api.com/batch?fields=countryCode,query');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_POSTFIELDS     => json_encode(array_map(fn($ip) => ['query' => $ip], $chunk)),
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        ]);
        $body = curl_exec($ch); curl_close($ch);
        if (!$body) continue;
        $data = json_decode($body, true);
        if (!is_array($data)) continue;
        foreach ($data as $item) {
            $ip = $item['query'] ?? '';
            $cc = $item['countryCode'] ?? 'XX';
            if (!$ip) continue;
            $out[$ip] = $cc;
            geoip_cache_store($ip, $cc);
        }
    }
    return $out;
}

function geoip_cache_store(string $ip, string $cc): void {
    if (_geoip_is_private($ip) || !$cc) return;
    try {
        admin_pdo()?->prepare(
            "INSERT INTO geoip_cache (ip,country) VALUES (?,?) ON DUPLICATE KEY UPDATE country=VALUES(country), fetched_at=NOW()"
        )->execute([$ip, $cc]);
    } catch (Throwable) {}
}

function _geoip_is_private(string $ip): bool {
    if ($ip === '' || $ip === '::1') return true;
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
}

// ── CSRF helpers (tied to the admin session cookie) ───────────────────────────
function _admin_csrf_token(): string {
    return substr(hash_hmac('sha256', 'csrf', $_COOKIE['mkt_adm'] ?? ''), 0, 32);
}
function _admin_csrf_ok(): bool {
    return hash_equals(_admin_csrf_token(), (string)($_POST['_csrf'] ?? ''));
}

// ── User management ───────────────────────────────────────────────────────────
function user_by_email(string $email): ?array {
    try {
        $st = admin_pdo()?->prepare("SELECT * FROM users WHERE email=? AND is_disabled=0 LIMIT 1");
        $st?->execute([$email]);
        return $st?->fetch() ?: null;
    } catch (Throwable) { return null; }
}

function user_list(): array {
    try {
        return admin_pdo()?->query(
            "SELECT id,email,name,is_root,is_disabled,attributes,created_at
             FROM users ORDER BY is_root DESC, created_at ASC"
        )?->fetchAll() ?? [];
    } catch (Throwable) { return []; }
}

function user_create(string $email, string $name, ?string $attrs): string {
    try {
        admin_pdo()?->prepare("INSERT INTO users (email,name,attributes) VALUES (?,?,?)")
            ->execute([$email, $name, $attrs]);
        return '';
    } catch (Throwable $e) {
        return str_contains($e->getMessage(), 'Duplicate') ? 'Email already exists.' : 'Failed to create user.';
    }
}

function user_update(int $id, string $email, string $name, ?string $attrs): string {
    try {
        admin_pdo()?->prepare(
            "UPDATE users SET email=?,name=?,attributes=? WHERE id=? AND is_root=0"
        )->execute([$email, $name, $attrs, $id]);
        return '';
    } catch (Throwable $e) {
        return str_contains($e->getMessage(), 'Duplicate') ? 'Email already exists.' : 'Failed to update user.';
    }
}

function user_delete(int $id): string {
    try {
        admin_pdo()?->prepare("DELETE FROM users WHERE id=? AND is_root=0")->execute([$id]);
        return '';
    } catch (Throwable) { return 'Failed to delete user.'; }
}

function user_toggle_disabled(int $id): string {
    try {
        admin_pdo()?->prepare(
            "UPDATE users SET is_disabled = IF(is_disabled,0,1) WHERE id=? AND is_root=0"
        )->execute([$id]);
        return '';
    } catch (Throwable) { return 'Failed to update user.'; }
}

// ── Error acknowledgement ─────────────────────────────────────────────────────
function ack_error(int $id): void {
    try {
        admin_pdo()?->prepare("UPDATE errors SET acknowledged_at=NOW() WHERE id=? AND acknowledged_at IS NULL")
            ->execute([$id]);
    } catch (Throwable) {}
}

function ack_all_errors(): void {
    try {
        admin_pdo()?->exec("UPDATE errors SET acknowledged_at=NOW() WHERE acknowledged_at IS NULL");
    } catch (Throwable) {}
}

// ── IP blocking ───────────────────────────────────────────────────────────────
function is_ip_blocked(string $ip): bool {
    try {
        $st = admin_pdo()?->prepare("SELECT id FROM blocked_ips WHERE ip=? LIMIT 1");
        $st?->execute([$ip]);
        return (bool)$st?->fetchColumn();
    } catch (Throwable) { return false; }
}

function block_ip(string $ip, ?string $reason, string $blocked_by): string {
    try {
        admin_pdo()?->prepare(
            "INSERT INTO blocked_ips (ip, reason, blocked_by) VALUES (?,?,?)
             ON DUPLICATE KEY UPDATE reason=VALUES(reason), blocked_by=VALUES(blocked_by), blocked_at=NOW()"
        )->execute([$ip, $reason, $blocked_by]);
        return '';
    } catch (Throwable) { return 'Failed to block IP.'; }
}

function unblock_ip(string $ip): string {
    try {
        admin_pdo()?->prepare("DELETE FROM blocked_ips WHERE ip=?")->execute([$ip]);
        return '';
    } catch (Throwable) { return 'Failed to unblock IP.'; }
}

// ── Watchlist ─────────────────────────────────────────────────────────────────
function watchlistLoad(): array {
    try {
        $rows = admin_pdo()?->query(
            "SELECT ip, added_at, source, reason, score_at_add, status,
                    escalated_at, escalated_reason
             FROM ip_watchlist ORDER BY FIELD(status,'candidate','watching'), added_at DESC"
        )?->fetchAll() ?? [];
        $out = [];
        foreach ($rows as $r) { $out[$r['ip']] = $r; }
        return $out;
    } catch (Throwable) { return []; }
}

function watchIp(string $ip, string $reason = '', string $source = 'manual', int $score = 0): string {
    try {
        admin_pdo()?->prepare(
            "INSERT INTO ip_watchlist (ip, reason, source, score_at_add)
             VALUES (?,?,?,?)
             ON DUPLICATE KEY UPDATE reason=VALUES(reason), source=VALUES(source),
             score_at_add=VALUES(score_at_add), status='watching',
             added_at=CURRENT_TIMESTAMP, escalated_at=NULL, escalated_reason=NULL"
        )->execute([$ip, $reason, $source, $score]);
        return '';
    } catch (Throwable) { return 'Failed to watch IP.'; }
}

function unwatchIp(string $ip): string {
    try {
        admin_pdo()?->prepare("DELETE FROM ip_watchlist WHERE ip=?")->execute([$ip]);
        return '';
    } catch (Throwable) { return 'Failed to unwatch IP.'; }
}

function watchlistEscalate(string $ip, string $reason): void {
    try {
        admin_pdo()?->prepare(
            "UPDATE ip_watchlist SET status='candidate', escalated_at=NOW(), escalated_reason=?
             WHERE ip=? AND status='watching'"
        )->execute([$reason, $ip]);
    } catch (Throwable) {
        // Escalation is best-effort — ignore if watchlist entry was deleted concurrently
    }
}

function blocked_ip_list(): array {
    try {
        return admin_pdo()?->query(
            "SELECT b.ip, b.reason, b.blocked_by, b.blocked_at,
                    g.country,
                    COUNT(v.id)                                                          AS total_req,
                    MAX(v.created_at)                                                    AS last_seen,
                    COALESCE(ROUND(SUM(IF(v.status>=400,1,0))/NULLIF(COUNT(v.id),0)*100),0) AS err_pct
             FROM blocked_ips b
             LEFT JOIN geoip_cache g ON g.ip = b.ip
             LEFT JOIN visits v      ON v.ip = b.ip
             GROUP BY b.ip, b.reason, b.blocked_by, b.blocked_at, g.country
             ORDER BY b.blocked_at DESC"
        )?->fetchAll() ?? [];
    } catch (Throwable) { return []; }
}

// ── IP threat intelligence ────────────────────────────────────────────────────

// Fetch ASN / org / provider / bot fields for $ips via ip-api.com, cache in ip_intel.
// Also back-fills geoip_cache for country if not already present.
function ip_intel_enrich(array $ips): void {
    if (!$ips) return;
    $pdo = admin_pdo();
    if (!$pdo) return;
    $ips = array_values(array_unique(array_filter($ips, fn($ip) => !_geoip_is_private($ip))));
    if (!$ips) return;

    // Skip IPs enriched in the last 7 days
    $ph  = implode(',', array_fill(0, count($ips), '?'));
    $st  = $pdo->prepare("SELECT ip FROM ip_intel WHERE ip IN ($ph) AND fetched_at > DATE_SUB(NOW(), INTERVAL 7 DAY)");
    $st->execute($ips);
    $cached = $st->fetchAll(PDO::FETCH_COLUMN);
    $miss   = array_values(array_diff($ips, $cached));
    if (!$miss) return;

    foreach (array_chunk($miss, 100) as $chunk) {
        $ch = curl_init('http://ip-api.com/batch?fields=query,countryCode,as,org,isp,hosting,proxy,mobile');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_POSTFIELDS     => json_encode(array_map(fn($ip) => ['query' => $ip], $chunk)),
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        ]);
        $body = curl_exec($ch);
        curl_close($ch);
        if (!$body) continue;
        $data = json_decode($body, true);
        if (!is_array($data)) continue;

        foreach ($data as $item) {
            $ip = $item['query'] ?? '';
            if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;

            // Country → geoip_cache
            $cc = strtoupper(trim($item['countryCode'] ?? ''));
            if (strlen($cc) === 2 && ctype_alpha($cc) && $cc !== 'XX') geoip_cache_store($ip, $cc);

            // ASN: "AS15169 Google LLC" → split at first space
            $as_raw = trim($item['as'] ?? '');
            $asn    = $org = '';
            if (preg_match('/^(AS\d+)\s+(.+)$/i', $as_raw, $m)) { $asn = $m[1]; $org = substr($m[2], 0, 255); }

            $is_hosting  = !empty($item['hosting']) ? 1 : 0;
            $is_proxy    = !empty($item['proxy'])   ? 1 : 0;
            $is_mobile   = !empty($item['mobile'])  ? 1 : 0;
            $ptype       = match(true) {
                (bool)$is_proxy   => 'proxy',
                (bool)$is_hosting => 'hosting',
                (bool)$is_mobile  => 'mobile',
                default           => 'unknown',
            };
            $isp = substr(trim($item['isp'] ?? ''), 0, 255);
            try {
                $pdo->prepare(
                    "INSERT INTO ip_intel (ip,asn,org,isp,provider_type,is_hosting,is_proxy,is_mobile)
                     VALUES (?,?,?,?,?,?,?,?)
                     ON DUPLICATE KEY UPDATE asn=VALUES(asn),org=VALUES(org),isp=VALUES(isp),
                       provider_type=VALUES(provider_type),is_hosting=VALUES(is_hosting),
                       is_proxy=VALUES(is_proxy),is_mobile=VALUES(is_mobile),fetched_at=NOW()"
                )->execute([$ip, $asn ?: null, $org ?: null, $isp ?: null, $ptype, $is_hosting, $is_proxy, $is_mobile]);
            } catch (Throwable) {}
        }
    }
}

// Read ip_intel rows for the given IPs (no API call — reads cache only).
function ip_intel_get(array $ips): array {
    if (!$ips) return [];
    $pdo = admin_pdo();
    if (!$pdo) return [];
    $ph = implode(',', array_fill(0, count($ips), '?'));
    try {
        $st = $pdo->prepare(
            "SELECT ip,asn,org,isp,provider_type,is_hosting,is_proxy,is_mobile,
                    bot_claimed,bot_verified,rdns FROM ip_intel WHERE ip IN ($ph)"
        );
        $st->execute($ips);
        $out = [];
        foreach ($st->fetchAll() as $r) $out[$r['ip']] = $r;
        return $out;
    } catch (Throwable) { return []; }
}

// ── My IPs ────────────────────────────────────────────────────────────────────

// Record admin IP automatically (type=auto); updates last_seen on revisit.
function my_ip_record(string $ip): void {
    if ($ip === '') return;
    try {
        admin_pdo()?->prepare(
            "INSERT INTO my_ips (ip, type) VALUES (?, 'auto')
             ON DUPLICATE KEY UPDATE last_seen=NOW()"
        )->execute([$ip]);
    } catch (Throwable) {}
}

// Return all known admin IPs as an [ip => row] map for fast lookup.
function my_ips_load(): array {
    try {
        $rows = admin_pdo()?->query(
            "SELECT ip, label, type, first_seen, last_seen FROM my_ips ORDER BY last_seen DESC"
        )?->fetchAll() ?? [];
        $out = [];
        foreach ($rows as $r) $out[$r['ip']] = $r;
        return $out;
    } catch (Throwable) { return []; }
}

function my_ips_add(string $ip, string $label): string {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return 'Invalid IP address.';
    try {
        admin_pdo()?->prepare(
            "INSERT INTO my_ips (ip, label, type) VALUES (?, ?, 'manual')
             ON DUPLICATE KEY UPDATE label=VALUES(label), type='manual', last_seen=NOW()"
        )->execute([$ip, $label !== '' ? $label : null]);
        return '';
    } catch (Throwable) { return 'Failed to add IP.'; }
}

function my_ips_update(string $ip, string $label): string {
    try {
        admin_pdo()?->prepare(
            "UPDATE my_ips SET label=? WHERE ip=?"
        )->execute([$label !== '' ? $label : null, $ip]);
        return '';
    } catch (Throwable) { return 'Failed to update.'; }
}

function my_ips_delete(string $ip): string {
    try {
        admin_pdo()?->prepare("DELETE FROM my_ips WHERE ip=?")->execute([$ip]);
        return '';
    } catch (Throwable) { return 'Failed to delete.'; }
}

function logPostPayload(string $uri, array $postData, int $statusCode, string $outcome): void {
    $pdo = admin_pdo();
    if (!$pdo) return;
    $raw = $_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['HTTP_X_REAL_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR'] ?? '';
    $ip = substr(trim(explode(',', $raw)[0]), 0, 45);
    $safe = $postData;
    // Keep reCAPTCHA token as presence indicator only — value is a JWS, not useful to store
    if (array_key_exists('g_recaptcha_token', $safe)) {
        $safe['g_recaptcha_token'] = $safe['g_recaptcha_token'] !== '' ? '[present]' : '[missing]';
    }
    foreach (['password', 'passwd', 'pass', 'secret'] as $k) {
        if (array_key_exists($k, $safe)) $safe[$k] = '[redacted]';
    }
    try {
        $pdo->prepare(
            "INSERT INTO post_payloads (ip, uri, user_agent, outcome, status_code, post_json)
             VALUES (?, ?, ?, ?, ?, ?)"
        )->execute([
            $ip,
            substr($uri, 0, 255),
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
            substr($outcome, 0, 40),
            $statusCode,
            json_encode($safe, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ]);
    } catch (Throwable) {
        // best-effort logging — silently skip on DB unavailability
    }
}

// Auto-register visit logger + PHP error capture (skipped on admin pages)
if (!defined('ADMIN_NO_LOG')) {
    set_error_handler(static function (int $no, string $msg, string $file, int $line): bool {
        if (error_reporting() & $no) _admin_log_error('php_error', $no, $msg, $file, $line);
        return false; // let PHP use its default handling too
    });
    register_shutdown_function(static function (): void {
        $e = error_get_last();
        if ($e && ($e['type'] & (E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR))) {
            _admin_log_error('php_fatal', $e['type'], $e['message'], $e['file'], $e['line']);
        }
        $s = http_response_code();
        log_visit(is_int($s) ? $s : 200);
    });
}
