<?php
/**
 * seo_head(array $opts): void
 *
 * Outputs the SEO meta block for a page. Call this inside <head> after
 * <meta charset> and <meta name="viewport"> — it emits everything else:
 * <title>, description, author, robots, canonical, Open Graph, Twitter Card,
 * and an optional JSON-LD <script> block.
 *
 * Required opts:
 *   title        string  Full page title (used for <title> and OG)
 *   description  string  Meta description (150–160 chars recommended)
 *
 * Optional opts:
 *   url     string  Canonical URL (default: https://thameur.org + REQUEST_URI, no query)
 *   type    string  OG type — 'website' (default) or 'article'
 *   robots  string  Meta robots value (default: 'index, follow')
 *   image   string  OG/Twitter image URL (default: /img/og-social.png)
 *   jsonld  string  Pre-encoded JSON-LD string (omit to skip the <script> block)
 */
function seo_head(array $opts): void {
    $base  = 'https://thameur.org';
    $image = $opts['image'] ?? $base . '/img/og-social.png';

    $title = htmlspecialchars($opts['title']       ?? 'thameur.org',         ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $desc  = htmlspecialchars($opts['description'] ?? '',                    ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $url   = htmlspecialchars(
        $opts['url'] ?? $base . strtok($_SERVER['REQUEST_URI'] ?? '/', '?'),
        ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'
    );
    $img   = htmlspecialchars($image, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $type  = $opts['type']   ?? 'website';
    $bots  = $opts['robots'] ?? 'index, follow';

    echo "  <title>{$title}</title>\n";
    echo "  <meta name=\"description\" content=\"{$desc}\">\n";
    echo "  <meta name=\"author\" content=\"Thameur Belghith\">\n";
    echo "  <meta name=\"robots\" content=\"{$bots}\">\n";
    echo "  <link rel=\"canonical\" href=\"{$url}\">\n";

    // Open Graph
    echo "  <meta property=\"og:type\"        content=\"{$type}\">\n";
    echo "  <meta property=\"og:site_name\"   content=\"thameur.org\">\n";
    echo "  <meta property=\"og:url\"         content=\"{$url}\">\n";
    echo "  <meta property=\"og:title\"       content=\"{$title}\">\n";
    echo "  <meta property=\"og:description\" content=\"{$desc}\">\n";
    echo "  <meta property=\"og:image\"       content=\"{$img}\">\n";
    echo "  <meta property=\"og:image:width\"  content=\"1200\">\n";
    echo "  <meta property=\"og:image:height\" content=\"630\">\n";
    echo "  <meta property=\"og:image:alt\"   content=\"thameur.org — PKI Tools\">\n";

    // Twitter Card
    echo "  <meta name=\"twitter:card\"        content=\"summary_large_image\">\n";
    echo "  <meta name=\"twitter:title\"       content=\"{$title}\">\n";
    echo "  <meta name=\"twitter:description\" content=\"{$desc}\">\n";
    echo "  <meta name=\"twitter:image\"       content=\"{$img}\">\n";

    // JSON-LD
    if (!empty($opts['jsonld'])) {
        echo "  <script type=\"application/ld+json\">\n" . $opts['jsonld'] . "\n  </script>\n";
    }
}
