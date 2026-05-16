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
