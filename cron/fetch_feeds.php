<?php
/**
 * PKI News Feed Aggregator — daily cron script
 *
 * Fetches RSS/Atom feeds from PKI-relevant sources, merges them sorted
 * by date descending, and writes includes/feed_cache.json for feed.php.
 *
 * ─── Recommended cron job (06:00 UTC every day) ──────────────────────────────
 *
 *   0 6 * * * /usr/bin/php /var/www/html/pki-tools/cron/fetch_feeds.php >> /var/log/pki-feeds.log 2>&1
 *
 *   Find PHP binary path : which php
 *   Find script path     : realpath /path/to/pki-tools/cron/fetch_feeds.php
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

if (php_sapi_name() !== 'cli') { http_response_code(403); exit; }

require_once __DIR__ . '/../config.php';

define('CACHE_FILE',    dirname(__DIR__) . '/includes/feed_cache.json');
define('FETCH_TIMEOUT', 20);
define('USER_AGENT',    'PKITools-FeedBot/1.0 (+' . SITE_BASE_URL . '/feed.php)');

// ── Feed sources ──────────────────────────────────────────────────────────────

$FEEDS = [
    [
        'id'    => 'mdsp',
        'label' => 'mozilla.dev.security.policy',
        'color' => '#e57c29',
        // Google Groups Workspace RSS is dead; mail-archive.com mirrors the list
        'url'   => 'https://www.mail-archive.com/dev-security-policy@mozilla.org/maillist.xml',
        'limit' => 20,
    ],
    [
        'id'    => 'cabf-tls',
        'label' => 'CABF TLS BR',
        'color' => '#00d4aa',
        'url'   => 'https://github.com/cabforum/servercert/commits/main.atom',
        'limit' => 15,
    ],
    [
        'id'    => 'cabf-smime',
        'label' => 'CABF S/MIME BR',
        'color' => '#00b89c',
        'url'   => 'https://github.com/cabforum/smime/commits/main.atom',
        'limit' => 15,
    ],
    [
        'id'    => 'cabf-cs',
        'label' => 'CABF Code Signing',
        'color' => '#008f7a',
        'url'   => 'https://github.com/cabforum/code-signing/commits/main.atom',
        'limit' => 10,
    ],
    [
        'id'    => 'lamps',
        'label' => 'IETF LAMPS WG',
        'color' => '#3b82f6',
        // IETF mail archive public mirror of lamps@ietf.org
        'url'   => 'https://www.mail-archive.com/lamps@ietf.org/maillist.xml',
        'limit' => 15,
    ],
    [
        'id'    => 'mozilla-blog',
        'label' => 'Mozilla Security Blog',
        'color' => '#e66000',
        'url'   => 'https://blog.mozilla.org/security/feed/',
        'limit' => 15,
    ],
    [
        'id'    => 'letsencrypt',
        'label' => "Let's Encrypt Blog",
        'color' => '#4b8aff',
        'url'   => 'https://letsencrypt.org/feed.xml',
        'limit' => 15,
    ],
    [
        'id'    => 'bugzilla-ca',
        'label' => 'Mozilla CA Incidents',
        'color' => '#dc2626',
        // title param and %20-encoded order caused Bugzilla to return HTML; use + and drop title
        'url'   => 'https://bugzilla.mozilla.org/buglist.cgi?product=CA+Program&order=changeddate+DESC&ctype=atom',
        'limit' => 20,
    ],
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function log_msg(string $msg): void
{
    echo '[' . date('Y-m-d H:i:s') . ' UTC] ' . $msg . PHP_EOL;
}

function fetch_url(string $url): ?string
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => FETCH_TIMEOUT,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_USERAGENT      => USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_ENCODING       => '',
            CURLOPT_HTTPHEADER     => [
                'Accept: application/atom+xml, application/rss+xml, text/xml, */*',
            ],
        ]);
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);

        if ($err)       { log_msg("  curl error: $err"); return null; }
        if ($code >= 400) { log_msg("  HTTP $code");      return null; }
        return $body ?: null;
    }

    // fallback: file_get_contents (requires allow_url_fopen = On)
    $ctx = stream_context_create(['http' => [
        'timeout'         => FETCH_TIMEOUT,
        'user_agent'      => USER_AGENT,
        'follow_location' => true,
        'max_redirects'   => 5,
        'header'          => "Accept: application/atom+xml, application/rss+xml, text/xml, */*\r\n",
    ]]);
    $r = @file_get_contents($url, false, $ctx);
    return $r !== false ? $r : null;
}

function excerpt(string $html, int $max = 220): string
{
    $text = preg_replace('/\s+/', ' ', trim(strip_tags($html)));
    return mb_strlen($text) <= $max ? $text : mb_substr($text, 0, $max) . '…';
}

function build_item(array $cfg, string $title, string $url, int $ts, string $summary): array
{
    return [
        'source_id'    => $cfg['id'],
        'source_label' => $cfg['label'],
        'source_color' => $cfg['color'],
        'title'        => $title,
        'url'          => $url,
        'date_iso'     => $ts ? gmdate('c', $ts) : '',
        'date_ts'      => $ts,
        'date_fmt'     => $ts ? gmdate('j M Y', $ts) : 'Unknown date',
        'summary'      => $summary,
    ];
}

function parse_feed(string $raw, array $cfg): array
{
    // Strip UTF-8 BOM and leading whitespace that can break XML parsers
    $raw = ltrim($raw, "\xEF\xBB\xBF");

    libxml_use_internal_errors(true);
    // Use integer values directly — LIBXML_RECOVER may not be compiled in on all builds
    $flags = (defined('LIBXML_RECOVER')   ? LIBXML_RECOVER   : 1)
           | (defined('LIBXML_NOCDATA')   ? LIBXML_NOCDATA   : 16384)
           | (defined('LIBXML_NOERROR')   ? LIBXML_NOERROR   : 32)
           | (defined('LIBXML_NOWARNING') ? LIBXML_NOWARNING : 64);
    $xml   = simplexml_load_string($raw, 'SimpleXMLElement', $flags);
    libxml_clear_errors();

    if (!$xml) {
        log_msg("  XML parse failed");
        return [];
    }

    $items = [];
    $root  = $xml->getName();

    if ($root === 'feed') {
        // Atom (GitHub, IETF datatracker, …)
        foreach ($xml->entry as $entry) {
            $title = trim((string) $entry->title);

            // find rel=alternate link (or first link with href)
            $link = '';
            foreach ($entry->link as $l) {
                $rel = (string) ($l['rel'] ?? 'alternate');
                if (in_array($rel, ['alternate', ''], true)) {
                    $link = (string) $l['href'];
                    break;
                }
            }
            if (!$link) {
                $link = (string) ($entry->link[0]['href'] ?? '');
            }

            $date = trim((string) ($entry->updated ?? $entry->published ?? ''));
            $ts   = $date ? (int) strtotime($date) : 0;
            $sum  = excerpt((string) ($entry->summary ?? $entry->content ?? ''));

            if (!$title || !$link) continue;

            $items[] = build_item($cfg, $title, $link, $ts, $sum);
            if (count($items) >= $cfg['limit']) break;
        }
    } elseif ($root === 'rss') {
        // RSS 2.0 (Mozilla mailing list, blogs, Bugzilla, …)
        foreach ($xml->channel->item as $item) {
            $title = trim((string) $item->title);
            $link  = trim((string) $item->link);
            $date  = trim((string) $item->pubDate);
            $ts    = $date ? (int) strtotime($date) : 0;
            $sum   = excerpt((string) $item->description);

            if (!$title || !$link) continue;

            $items[] = build_item($cfg, $title, $link, $ts, $sum);
            if (count($items) >= $cfg['limit']) break;
        }
    } else {
        log_msg("  unknown root element '$root'");
    }

    return $items;
}

// ── Main ──────────────────────────────────────────────────────────────────────

log_msg('=== PKI feed aggregator started ===');

$all_items = [];
$sources   = [];

foreach ($FEEDS as $feed) {
    log_msg("Fetching [{$feed['id']}] {$feed['url']}");
    $raw = fetch_url($feed['url']);

    if ($raw === null) {
        log_msg('  SKIP: fetch failed');
        continue;
    }

    $items = parse_feed($raw, $feed);
    log_msg('  got ' . count($items) . ' items');

    if ($items) {
        $all_items = array_merge($all_items, $items);
        $sources[] = [
            'id'    => $feed['id'],
            'label' => $feed['label'],
            'color' => $feed['color'],
            'count' => count($items),
        ];
    }
}

if (empty($all_items)) {
    log_msg('ERROR: no items fetched — cache NOT updated');
    exit(1);
}

// Sort by date descending; items with unknown date go to the bottom
usort($all_items, fn($a, $b) => ($b['date_ts'] ?: -1) <=> ($a['date_ts'] ?: -1));

$cache = [
    'fetched_at'     => gmdate('c'),
    'fetched_at_fmt' => gmdate('j M Y') . ' at ' . gmdate('H:i') . ' UTC',
    'total'          => count($all_items),
    'sources'        => $sources,
    'items'          => $all_items,
];

$written = file_put_contents(
    CACHE_FILE,
    json_encode($cache, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
);

if ($written === false) {
    log_msg('ERROR: failed to write ' . CACHE_FILE);
    exit(1);
}

log_msg('Done — ' . count($all_items) . ' items from ' . count($sources) . ' sources → ' . CACHE_FILE);
exit(0);
