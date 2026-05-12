<?php
if (!defined('ARTIFACT_PARSER')) {
    http_response_code(403);
    exit('Direct access not permitted.');
}

// ── Abstract module interface ──────────────────────────────────────────────────

abstract class ArtifactModule {
    abstract public function label(): string;
    abstract public function recognize(string $bytes, string $ext): bool;
    abstract public function parse(string $bytes): array;
    abstract public function render(array $parsed): string;
    public function subtype(array $parsed): ?string { return null; }
}

// ── Module registry ───────────────────────────────────────────────────────────

final class ArtifactRegistry {
    private static array $modules = [];

    public static function register(ArtifactModule $m): void {
        self::$modules[] = $m;
    }

    public static function all(): array {
        return self::$modules;
    }

    public static function match(string $bytes, string $ext): ?ArtifactModule {
        foreach (self::$modules as $m) {
            if ($m->recognize($bytes, $ext)) return $m;
        }
        return null;
    }
}

// ── Shared byte-level helpers ─────────────────────────────────────────────────

function artifact_has_pem_header(string $bytes, string $label): bool {
    return str_contains($bytes, "-----BEGIN $label-----");
}

function artifact_is_der(string $bytes): bool {
    return strlen($bytes) > 2
        && ord($bytes[0]) === 0x30
        && !str_contains($bytes, '-----BEGIN');
}

function artifact_to_pem(string $bytes, string $label): ?string {
    // Already correct PEM
    if (str_contains($bytes, "-----BEGIN $label-----")) return $bytes;

    // DER → PEM
    if (artifact_is_der($bytes)) {
        return "-----BEGIN $label-----\n"
             . chunk_split(base64_encode($bytes), 64, "\n")
             . "-----END $label-----\n";
    }

    // Bare base64 (no headers)
    $cleaned = preg_replace('/\s+/', '', $bytes);
    if (preg_match('/^[A-Za-z0-9+\/]+=*$/', $cleaned) && strlen($cleaned) > 16) {
        return "-----BEGIN $label-----\n"
             . chunk_split($cleaned, 64, "\n")
             . "-----END $label-----\n";
    }

    return null;
}

// ── Shell helper (openssl CLI) ────────────────────────────────────────────────

function artifact_openssl(string $args, string $bytes, string $ext = 'pem'): ?string {
    if (!function_exists('shell_exec')) return null;

    $tmp = @tempnam(sys_get_temp_dir(), 'mkt_');
    if ($tmp === false) return null;

    $tmpfile = $tmp . '.' . $ext;
    @rename($tmp, $tmpfile);

    if (@file_put_contents($tmpfile, $bytes) === false) {
        @unlink($tmpfile);
        return null;
    }

    $cmd = 'openssl ' . $args . ' -in ' . escapeshellarg($tmpfile) . ' 2>&1';
    $out = @shell_exec($cmd);
    @unlink($tmpfile);

    return $out !== null ? trim((string) $out) : null;
}
