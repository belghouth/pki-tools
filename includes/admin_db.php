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
        _admin_schema($pdo);
    } catch (Throwable) {
        $pdo = null;
        @touch($flag);
    }
    return $pdo;
}

function _admin_schema(PDO $pdo): void {
    static $done = false;
    if ($done) return;
    $done = true;

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

    // Migrate: add status column if this is an older schema
    try { $pdo->exec("ALTER TABLE visits ADD COLUMN status SMALLINT UNSIGNED NOT NULL DEFAULT 200 AFTER accept_lang"); } catch (Throwable) {}
    try { $pdo->exec("ALTER TABLE visits ADD INDEX idx_status (status)"); } catch (Throwable) {}

    $pdo->exec("CREATE TABLE IF NOT EXISTS admin_sessions (
        token        CHAR(64)     PRIMARY KEY,
        email        VARCHAR(255) NOT NULL,
        created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        ip           VARCHAR(45),
        user_agent   TEXT,
        INDEX idx_last_seen (last_seen)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
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
