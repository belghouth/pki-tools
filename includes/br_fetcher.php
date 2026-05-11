<?php
/**
 * BRFetcher — fetches, parses, and caches the CAB Forum Baseline Requirements section index.
 */
class BRFetcher
{
    private string $cachePath;
    private int $maxCacheAgeSecs = 604800; // 7 days

    private const BR_RAW_URL     = 'https://raw.githubusercontent.com/cabforum/servercert/main/docs/BR.md';
    private const GH_RELEASE_URL = 'https://api.github.com/repos/cabforum/servercert/releases/latest';


    public function __construct(string $cachePath)
    {
        $this->cachePath = $cachePath;
    }

    public function loadCache(): ?array
    {
        if (!file_exists($this->cachePath)) {
            return null;
        }
        $raw = file_get_contents($this->cachePath);
        if ($raw === false) {
            return null;
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }

    public function isCacheStale(?array $cache): bool
    {
        if ($cache === null) {
            return true;
        }
        $fetchedAt = strtotime($cache['meta']['fetched_at'] ?? '1970-01-01');
        if ($fetchedAt === false) {
            return true;
        }
        return (time() - $fetchedAt) > $this->maxCacheAgeSecs;
    }

    /**
     * Refresh the cache from GitHub.
     * Returns ['ok' => bool, 'message' => string, 'version' => string|null].
     */
    public function refresh(bool $force = false): array
    {
        $cache = $this->loadCache();

        // Fetch latest version tag from GitHub releases API.
        $latestVersion = $this->fetchLatestVersion();
        if ($latestVersion === null) {
            return [
                'ok'      => false,
                'message' => 'Cannot reach GitHub releases API. Network may be unavailable.',
                'version' => $cache['meta']['version'] ?? null,
            ];
        }

        $cachedVersion = $cache['meta']['version'] ?? '';
        $cacheStale    = $this->isCacheStale($cache);

        if (!$force && $cachedVersion === $latestVersion && !$cacheStale) {
            return [
                'ok'      => true,
                'message' => "Cache is current (version {$latestVersion}).",
                'version' => $latestVersion,
            ];
        }

        // Fetch BR.md content.
        $markdown = $this->fetchBRMarkdown();
        if ($markdown === null) {
            return [
                'ok'      => false,
                'message' => 'Cannot fetch BR.md from GitHub. Check network connectivity.',
                'version' => $cachedVersion ?: null,
            ];
        }

        $sections = $this->parseMarkdown($markdown);
        $payload  = [
            'meta' => [
                'version'    => $latestVersion,
                'fetched_at' => gmdate('Y-m-d\TH:i:s\Z'),
                'source'     => self::BR_RAW_URL,
            ],
            'sections' => $sections,
        ];

        $written = $this->writeCache($payload);
        if (!$written) {
            return [
                'ok'      => false,
                'message' => 'Fetched BR successfully but could not write cache file.',
                'version' => $latestVersion,
            ];
        }

        return [
            'ok'      => true,
            'message' => "Cache updated to version {$latestVersion} (" . count($sections) . " sections).",
            'version' => $latestVersion,
        ];
    }

    private function fetchLatestVersion(): ?string
    {
        $ctx = $this->makeStreamContext(10);
        $body = @file_get_contents(self::GH_RELEASE_URL, false, $ctx);
        if ($body === false) {
            return null;
        }
        $data = json_decode($body, true);
        if (!isset($data['tag_name'])) {
            return null;
        }
        return ltrim(trim($data['tag_name']), 'v');
    }

    private function fetchBRMarkdown(): ?string
    {
        $ctx  = $this->makeStreamContext(30);
        $body = @file_get_contents(self::BR_RAW_URL, false, $ctx);
        return $body !== false ? $body : null;
    }

    private function makeStreamContext(int $timeoutSecs): mixed
    {
        return stream_context_create([
            'http' => [
                'method'          => 'GET',
                'timeout'         => $timeoutSecs,
                'follow_location' => 1,
                'max_redirects'   => 3,
                'user_agent'      => 'PKI-Tools/CPS-Assessor (+https://github.com/)',
                'header'          => "Accept: application/json, text/plain, */*\r\n",
            ],
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ],
        ]);
    }

    /**
     * Parse BR.md and extract numbered sections.
     * Targets ## 1., ### 1.1, #### 1.1.1 heading patterns.
     */
    public function parseMarkdown(string $md): array
    {
        $lines    = explode("\n", $md);
        $sections = [];
        $current  = null;
        $bodyBuf  = [];

        foreach ($lines as $line) {
            // Match headings: ##, ###, #### followed by a number
            if (preg_match('/^(#{2,4})\s+(\d+(?:\.\d+)*)\s+(.*?)\s*$/', $line, $m)) {
                if ($current !== null) {
                    $sections[] = $this->finaliseSection($current, implode("\n", $bodyBuf));
                }
                $current = ['id' => $m[2], 'title' => trim($m[3])];
                $bodyBuf = [];
            } elseif ($current !== null) {
                $bodyBuf[] = $line;
            }
        }
        if ($current !== null) {
            $sections[] = $this->finaliseSection($current, implode("\n", $bodyBuf));
        }

        return $sections;
    }

    private function finaliseSection(array $section, string $body): array
    {
        $shallCount = preg_match_all('/\b(SHALL|MUST|REQUIRED)\b/i', $body, $sm);

        return [
            'id'          => $section['id'],
            'title'       => $section['title'],
            'normative'   => $shallCount > 0,
            'shall_count' => (int)$shallCount,
        ];
    }

    private function writeCache(array $payload): bool
    {
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            return false;
        }
        $tmp = $this->cachePath . '.tmp.' . getmypid();
        if (file_put_contents($tmp, $json, LOCK_EX) === false) {
            return false;
        }
        return rename($tmp, $this->cachePath);
    }
}
