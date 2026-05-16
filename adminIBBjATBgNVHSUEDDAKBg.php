<?php
define('ADMIN_NO_LOG', true);
require_once __DIR__ . '/config.php';

$email = admin_auth_check();
if (!$email) { header('Location: ' . ADMIN_LOGIN_URL, true, 302); exit; }

$pdo = admin_pdo();

// ── Tab ────────────────────────────────────────────────────────────────────────
$tab = match($_GET['tab'] ?? '') {
    'users'   => 'users',
    'blocked' => 'blocked',
    default   => 'activity',
};

// ── Block / Unblock — global POST, any tab ────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && _admin_csrf_ok()) {
    $__act = $_POST['action'] ?? '';
    if ($__act === 'block_ip') {
        $__ip  = trim($_POST['ip']     ?? '');
        $__rsn = trim($_POST['reason'] ?? '');
        $__err = filter_var($__ip, FILTER_VALIDATE_IP)
            ? block_ip($__ip, $__rsn ?: null, $email)
            : 'Invalid IP address.';
        header('Location: ?tab=blocked' . ($__err ? '&err=' . urlencode($__err) : '&ok=1'));
        exit;
    }
    if ($__act === 'unblock_ip') {
        $__ip  = trim($_POST['ip'] ?? '');
        $__err = $__ip ? unblock_ip($__ip) : 'Invalid IP.';
        header('Location: ?tab=blocked' . ($__err ? '&err=' . urlencode($__err) : '&ok=1'));
        exit;
    }
}

// ── Users CRUD (POST) ─────────────────────────────────────────────────────────
$u_flash = ''; $u_flash_ok = true;
if ($tab === 'users' && $_SERVER['REQUEST_METHOD'] === 'POST' && _admin_csrf_ok()) {
    $act = $_POST['action'] ?? '';
    $err = '';
    if ($act === 'add_user') {
        $u_em = trim($_POST['email'] ?? ''); $u_nm = trim($_POST['name'] ?? '');
        $u_at = trim($_POST['attributes'] ?? '');
        if ($u_at !== '' && json_decode($u_at) === null)       $err = 'Attributes: invalid JSON.';
        elseif (!filter_var($u_em, FILTER_VALIDATE_EMAIL))     $err = 'Invalid email address.';
        else $err = user_create($u_em, $u_nm, $u_at !== '' ? $u_at : null);
    } elseif ($act === 'update_user') {
        $u_id = (int)($_POST['id'] ?? 0); $u_em = trim($_POST['email'] ?? '');
        $u_nm = trim($_POST['name'] ?? ''); $u_at = trim($_POST['attributes'] ?? '');
        if ($u_id < 1)                                         $err = 'Invalid user.';
        elseif ($u_at !== '' && json_decode($u_at) === null)   $err = 'Attributes: invalid JSON.';
        elseif (!filter_var($u_em, FILTER_VALIDATE_EMAIL))     $err = 'Invalid email address.';
        else $err = user_update($u_id, $u_em, $u_nm, $u_at !== '' ? $u_at : null);
    } elseif ($act === 'delete_user') {
        $u_id = (int)($_POST['id'] ?? 0);
        if ($u_id < 1) { $err = 'Invalid user.'; }
        else {
            $tgt = admin_pdo()?->prepare("SELECT email FROM users WHERE id=? LIMIT 1");
            $tgt?->execute([$u_id]);
            $tgt_email = (string)($tgt?->fetchColumn() ?? '');
            if ($tgt_email === $email) $err = 'You cannot delete your own account.';
            else $err = user_delete($u_id);
        }
    } elseif ($act === 'toggle_user') {
        $u_id = (int)($_POST['id'] ?? 0);
        if ($u_id < 1) { $err = 'Invalid user.'; }
        else {
            $tgt = admin_pdo()?->prepare("SELECT email FROM users WHERE id=? LIMIT 1");
            $tgt?->execute([$u_id]);
            $tgt_email = (string)($tgt?->fetchColumn() ?? '');
            if ($tgt_email === $email) $err = 'You cannot disable your own account.';
            else $err = user_toggle_disabled($u_id);
        }
    }
    header('Location: ?tab=users' . ($err ? '&err=' . urlencode($err) : '&ok=1'));
    exit;
}
if ($tab === 'users') {
    if (isset($_GET['ok']))  { $u_flash = 'Done.';                              $u_flash_ok = true; }
    if (isset($_GET['err'])) { $u_flash = htmlspecialchars($_GET['err'] ?? ''); $u_flash_ok = false; }
}
$b_flash = ''; $b_flash_ok = true;
if ($tab === 'blocked') {
    if (isset($_GET['ok']))  { $b_flash = 'Done.';                              $b_flash_ok = true; }
    if (isset($_GET['err'])) { $b_flash = htmlspecialchars($_GET['err'] ?? ''); $b_flash_ok = false; }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
$TOOL_NAMES = [
    'index.php'              => 'Home',
    'x509parse.php'          => 'X.509 Parser',
    'cert_factory.php'       => 'TLS Cert Factory',
    'mpca_factory.php'       => 'MPCA Factory',
    'linters.php'            => 'Multi-Linter',
    'artifact_parser.php'    => 'Artifact Parser',
    'cps_to_br_assessor.php' => 'CPS-to-BR Assessor',
    'csr_generator.php'      => 'CSR Generator',
    'ct_log.php'             => 'CT Log API',
    'ct_log_doc.php'         => 'CT Log Docs',
    'tsa.php'                => 'TSA API',
    'tsa_doc.php'            => 'TSA Docs',
    'timestamp_it.php'       => 'TimeStampIt',
    'eseal.php'              => 'e-Seal API',
    'eseal_doc.php'          => 'e-Seal Docs',
    'eseal_signer.php'       => 'e-Seal Signer',
    'acme-endpoint.php'      => 'ACME Endpoint',
    'acme_tester.php'        => 'ACME Tester',
    'revocation.php'         => 'Revocation',
    'feed.php'               => 'News Feed',
    'community_tools.php'    => 'Community Tools',
    'references.php'         => 'References',
    'privacy.php'            => 'Privacy',
];
$tool_name = fn(string $s) => $TOOL_NAMES[$s] ?? $s;

function status_badge(int $s): string {
    $c = match(true) { $s < 300 => 'ok', $s < 400 => 'redir', $s < 500 => 'warn', default => 'err' };
    return "<span class=\"badge badge--$c\">$s</span>";
}
function method_badge(string $m): string {
    $c = match($m) { 'GET' => 'get', 'POST' => 'post', default => 'oth' };
    return "<span class=\"badge badge--$c\">$m</span>";
}
function ua_label(string $ua): string {
    if ($ua === '') return '<span class="muted">—</span>';
    $t = 'title="' . htmlspecialchars($ua) . '"';

    // ── Named bots (most specific first) ─────────────────────────────────────
    static $BOT_MAP = [
        'GPTBot'               => 'OpenAI / GPTBot',
        'ChatGPT-User'         => 'OpenAI / ChatGPT',
        'OAI-SearchBot'        => 'OpenAI / Search',
        'Googlebot'            => 'Google / Bot',
        'Google-Extended'      => 'Google / AI',
        'AdsBot-Google'        => 'Google / Ads',
        'Bingbot'              => 'Bing / Bot',
        'BingPreview'          => 'Bing / Preview',
        'Applebot'             => 'Apple / Bot',
        'anthropic-ai'         => 'Anthropic / AI',
        'ClaudeBot'            => 'Anthropic / Claude',
        'FacebookExternalHit'  => 'Meta / Facebook',
        'Facebot'              => 'Meta / Facebook',
        'Twitterbot'           => 'X / Twitter',
        'LinkedInBot'          => 'LinkedIn / Bot',
        'Slackbot'             => 'Slack',
        'Discordbot'           => 'Discord',
        'TelegramBot'          => 'Telegram',
        'WhatsApp'             => 'WhatsApp',
        'Amazonbot'            => 'Amazon / Bot',
        'AhrefsBot'            => 'Ahrefs',
        'SemrushBot'           => 'Semrush',
        'DotBot'               => 'Moz',
        'MJ12bot'              => 'Majestic',
        'YandexBot'            => 'Yandex',
        'DuckDuckBot'          => 'DuckDuckGo',
        'Bytespider'           => 'ByteDance',
        'PetalBot'             => 'Huawei',
        'CCBot'                => 'CommonCrawl',
        'ia_archiver'          => 'Wayback',
        'archive.org_bot'      => 'Wayback',
    ];
    foreach ($BOT_MAP as $sig => $label) {
        if (stripos($ua, $sig) !== false)
            return "<span class=\"ua-bot\" $t>$label</span>";
    }

    // ── Generic tools ─────────────────────────────────────────────────────────
    static $TOOL_MAP = [
        'curl'       => 'curl',
        'python'     => 'python',
        'go-http'    => 'Go HTTP',
        'wget'       => 'wget',
        'java'       => 'Java',
        'scrapy'     => 'Scrapy',
        'zgrab'      => 'zgrab',
        'nuclei'     => 'Nuclei',
        'libwww'     => 'libwww',
        'masscan'    => 'masscan',
        'nmap'       => 'nmap',
    ];
    foreach ($TOOL_MAP as $sig => $label) {
        if (stripos($ua, $sig) !== false)
            return "<span class=\"ua-bot\" $t>$label</span>";
    }
    if (preg_match('/bot|crawl|spider|slurp/i', $ua))
        return "<span class=\"ua-bot\" $t>bot</span>";

    // ── Platform ─────────────────────────────────────────────────────────────
    $plat = '';
    if (stripos($ua, 'iPhone') !== false)        $plat = 'iPhone';
    elseif (stripos($ua, 'iPad') !== false)      $plat = 'iPad';
    elseif (stripos($ua, 'Android') !== false)   $plat = 'Android';
    elseif (stripos($ua, 'CrOS') !== false)      $plat = 'ChromeOS';
    elseif (stripos($ua, 'Windows') !== false)   $plat = 'Windows';
    elseif (stripos($ua, 'Macintosh') !== false) $plat = 'Mac';
    elseif (stripos($ua, 'Linux') !== false)     $plat = 'Linux';

    // ── Browser (order matters: Edge/Opera embed Chrome token) ────────────────
    $browser = '';
    if (stripos($ua, 'EdgiOS/') !== false ||
        stripos($ua, 'EdgA/')   !== false ||
        stripos($ua, 'Edg/')    !== false)             $browser = 'Edge';
    elseif (stripos($ua, 'OPR/')           !== false)  $browser = 'Opera';
    elseif (stripos($ua, 'SamsungBrowser/') !== false) $browser = 'Samsung';
    elseif (stripos($ua, 'FxiOS/')         !== false)  $browser = 'Firefox';
    elseif (stripos($ua, 'Firefox/')       !== false)  $browser = 'Firefox';
    elseif (stripos($ua, 'CriOS/')         !== false)  $browser = 'Chrome';  // Chrome on iOS
    elseif (stripos($ua, 'Chrome/')        !== false)  $browser = 'Chrome';
    elseif (stripos($ua, 'Safari/')        !== false)  $browser = 'Safari';

    if ($browser) {
        $label = $plat ? "$browser / $plat" : $browser;
        return "<span class=\"ua-browser\" $t>$label</span>";
    }
    return '<span class="muted" ' . $t . '>' . htmlspecialchars(substr($ua, 0, 22)) . '…</span>';
}
function flag(string $cc): string {
    $cc = strtoupper(trim($cc));
    if (!preg_match('/^[A-Z]{2}$/', $cc) || $cc === 'XX') return '';
    return mb_chr(0x1F1E6 + ord($cc[0]) - 65) . mb_chr(0x1F1E6 + ord($cc[1]) - 65);
}
function geo_label(string $ip, array $geo): string {
    $cc = $geo[$ip] ?? '';
    if (!$cc || $cc === 'XX') return '<span class="muted">—</span>';
    $f = flag($cc);
    return "<span class=\"geo\" title=\"$cc\">$f <span class=\"geo-cc\">$cc</span></span>";
}
function rel_time(string $dt): string {
    $d = time() - strtotime($dt . ' UTC');
    if ($d < 60)    return $d . 's ago';
    if ($d < 3600)  return floor($d/60) . 'm ago';
    if ($d < 86400) return floor($d/3600) . 'h ago';
    return floor($d/86400) . 'd ago';
}
function q(array $over = [], array $drop = []): string {
    $p = array_filter($_GET, fn($v) => $v !== '');
    foreach ($drop as $k) unset($p[$k]);
    unset($p['page']);
    return '?' . http_build_query(array_merge($p, $over));
}
function pg_url(int $p): string {
    return '?' . http_build_query(array_merge(array_filter($_GET, fn($v) => $v !== ''), ['page' => $p]));
}

// ── Filters ───────────────────────────────────────────────────────────────────
$period  = in_array($_GET['period'] ?? '24h', ['24h', '7d', '30d']) ? $_GET['period'] : '24h';
$fip     = preg_replace('/[^\d\.:a-fA-F]/', '', $_GET['ip']     ?? '');
$fstatus = $_GET['status'] ?? '';
$fmethod = strtoupper(preg_replace('/[^A-Za-z]/', '', $_GET['method'] ?? ''));
$page    = max(1, (int)($_GET['page'] ?? 1));
$pp      = 50;

if (!in_array($fmethod, ['', 'GET', 'POST', 'DELETE', 'PUT', 'HEAD', 'OPTIONS'])) $fmethod = '';
if (!preg_match('/^(\d{3}|\dxx)$/', $fstatus)) $fstatus = '';

$pstart = match($period) {
    '7d'  => 'DATE_SUB(NOW(), INTERVAL 7 DAY)',
    '30d' => 'DATE_SUB(NOW(), INTERVAL 30 DAY)',
    default => 'DATE_SUB(NOW(), INTERVAL 24 HOUR)',
};

$w = ["created_at >= $pstart"]; $bp = [];
if ($fip)     { $w[] = 'ip = ?';     $bp[] = $fip; }
if ($fmethod) { $w[] = 'method = ?'; $bp[] = $fmethod; }
if ($fstatus !== '') {
    if (preg_match('/^(\d)xx$/', $fstatus, $m)) {
        $lo = (int)$m[1] * 100; $hi = $lo + 99;
        $w[] = 'status BETWEEN ? AND ?'; $bp[] = $lo; $bp[] = $hi;
    } else { $w[] = 'status = ?'; $bp[] = (int)$fstatus; }
}
$wsql = implode(' AND ', $w);

// ── Data ──────────────────────────────────────────────────────────────────────
$stats      = ['total' => 0, 'uniq' => 0, 'errs' => 0, 'epct' => 0, 'top_tool' => '—', 'top_cnt' => 0];
$rows       = [];
$total_rows = 0;
$tool_usage = [];
$top_ips    = [];
$err_rows   = [];

if ($tab === 'activity' && $pdo) {
    // Stats (always full period, ignore column filters)
    $r = $pdo->query("SELECT COUNT(*) AS t, COUNT(DISTINCT ip) AS u FROM visits WHERE created_at >= $pstart")->fetch();
    $stats['total'] = (int)$r['t']; $stats['uniq'] = (int)$r['u'];

    $r = $pdo->query("SELECT COUNT(*) AS c FROM visits WHERE created_at >= $pstart AND status >= 400")->fetch();
    $stats['errs'] = (int)$r['c'];
    $stats['epct'] = $stats['total'] > 0 ? round($stats['errs'] / $stats['total'] * 100, 1) : 0;

    $r = $pdo->query("SELECT script_name, COUNT(*) AS c FROM visits WHERE created_at >= $pstart AND script_name NOT IN ('','index.php') GROUP BY script_name ORDER BY c DESC LIMIT 1")->fetch();
    if ($r) { $stats['top_tool'] = $r['script_name']; $stats['top_cnt'] = (int)$r['c']; }

    // Activity table
    $st = $pdo->prepare("SELECT COUNT(*) FROM visits WHERE $wsql"); $st->execute($bp);
    $total_rows = (int)$st->fetchColumn();
    $st = $pdo->prepare("SELECT created_at,ip,method,uri,query_string,status,user_agent,referer,script_name FROM visits WHERE $wsql ORDER BY created_at DESC LIMIT $pp OFFSET " . (($page-1)*$pp));
    $st->execute($bp); $rows = $st->fetchAll();

    // Tool usage
    $tool_usage = $pdo->query("SELECT script_name, COUNT(*) AS c FROM visits WHERE created_at >= $pstart AND script_name != '' GROUP BY script_name ORDER BY c DESC LIMIT 15")->fetchAll();

    // Top IPs (blocked IPs excluded so they don't crowd out active ones)
    $top_ips = $pdo->query("SELECT ip, COUNT(*) AS c, MAX(created_at) AS last, ROUND(SUM(status>=400)/COUNT(*)*100) AS epct FROM visits WHERE created_at >= $pstart AND ip NOT IN (SELECT ip FROM blocked_ips) GROUP BY ip ORDER BY c DESC LIMIT 12")->fetchAll();

    // Errors
    $err_rows = $pdo->query("SELECT created_at,ip,uri,error_type,error_msg,error_file,error_line FROM errors ORDER BY created_at DESC LIMIT 25")->fetchAll();
}

$total_pages = max(1, (int)ceil($total_rows / $pp));
$tool_max    = $tool_usage ? (int)$tool_usage[0]['c'] : 1;

// Geo lookup — cache-first, ip-api.com batch for misses
$geo_ips = array_unique(array_merge(array_column($rows, 'ip'), array_column($top_ips, 'ip')));
$geo     = $pdo ? geoip_country($geo_ips) : [];

$users        = $tab === 'users'   ? user_list()        : [];
$blocked_list = $tab === 'blocked' ? blocked_ip_list()  : [];
$blocked_set  = $pdo ? array_flip($pdo->query("SELECT ip FROM blocked_ips")->fetchAll(PDO::FETCH_COLUMN)) : [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= match($tab) { 'users' => 'Users', 'blocked' => 'Blocked IPs', default => 'Activity' } ?> — <?= SITE_DOMAIN ?></title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,600;1,300&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:      #0e1014; --surface: #13171e; --surface2: #181d26;
      --border:  #2a3040; --border2: #3a4458;
      --accent:  #00d4aa; --accent2: #0099ff;
      --text:    #d4dae6; --muted:   #6b7a90;
      --ok:      #22c55e; --redir: #0099ff; --warn: #f59e0b; --err: #ef4444;
      --mono: 'IBM Plex Mono', monospace; --sans: 'IBM Plex Sans', sans-serif;
      --radius: 6px; --tr: 160ms ease;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 14px; overflow-x: hidden; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.6; min-height: 100vh; }
    a { color: var(--accent); text-decoration: none; transition: color var(--tr); }
    a:hover { color: #fff; }

    /* admin bar */
    .admin-bar { background: rgba(18,22,28,.98); border-bottom: 1px solid #1a2030; padding: 0 1.75rem; height: 34px; display: flex; align-items: center; justify-content: space-between; font-family: var(--mono); font-size: .68rem; letter-spacing: .04em; }
    .admin-bar-user { color: #4a5a70; } .admin-bar-user span { color: var(--accent); }
    .admin-bar-logout { color: #4a5a70; transition: color var(--tr); } .admin-bar-logout:hover { color: #fca5a5; }

    /* layout */
    .wrap { max-width: 100%; margin: 0 auto; padding: 2rem 1.75rem; }

    /* page header */
    .page-hd { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: .75rem; margin-bottom: 1.75rem; }
    .page-hd h1 { font-size: 1.15rem; font-weight: 600; color: #fff; }
    .period-tabs { display: flex; gap: .25rem; }
    .period-tabs a { font-family: var(--mono); font-size: .68rem; letter-spacing: .08em; text-transform: uppercase; padding: .3rem .75rem; border-radius: var(--radius); border: 1px solid var(--border2); color: var(--muted); transition: all var(--tr); }
    .period-tabs a:hover { color: var(--text); border-color: var(--accent); }
    .period-tabs a.active { background: rgba(0,212,170,.1); border-color: var(--accent); color: var(--accent); }

    /* stat cards */
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.75rem; }
    @media(max-width:760px) { .stats-grid { grid-template-columns: repeat(2,1fr); } }
    .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.1rem 1.25rem; }
    .stat-val { font-family: var(--mono); font-size: 1.5rem; font-weight: 600; color: #fff; line-height: 1.1; }
    .stat-val.warn { color: var(--warn); } .stat-val.err { color: var(--err); }
    .stat-lbl { font-size: .73rem; color: var(--muted); margin-top: .3rem; }
    .stat-sub { font-family: var(--mono); font-size: .65rem; color: #3d4f68; margin-top: .15rem; }

    /* analytics row (tool usage + top IPs side by side, above full-width table) */
    .side-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; margin-bottom: 0; }
    @media(max-width:760px) { .side-row { grid-template-columns: 1fr; } }

    /* cards */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 1.25rem; }
    .card-hd { padding: .75rem 1.1rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
    .card-hd h2 { font-family: var(--mono); font-size: .7rem; letter-spacing: .1em; text-transform: uppercase; color: var(--accent); }
    .card-hd .card-meta { font-family: var(--mono); font-size: .65rem; color: #3d4f68; }
    .card-body { padding: 1rem; }

    /* filter bar */
    .filter-bar { display: flex; flex-wrap: wrap; gap: .6rem; align-items: flex-end; margin-bottom: 1rem; }
    .flt { display: flex; flex-direction: column; gap: .3rem; }
    .flt label { font-family: var(--mono); font-size: .62rem; letter-spacing: .08em; text-transform: uppercase; color: #3d4f68; }
    .flt input, .flt select { background: var(--surface2); border: 1px solid var(--border2); border-radius: 4px; color: var(--text); font-family: var(--mono); font-size: .75rem; padding: .35rem .6rem; outline: none; transition: border-color var(--tr); }
    .flt input:focus, .flt select:focus { border-color: var(--accent); }
    .flt input { width: 140px; } .flt select { width: 100px; }
    .btn-sm { padding: .35rem .85rem; background: rgba(0,212,170,.12); border: 1px solid rgba(0,212,170,.3); border-radius: 4px; color: var(--accent); font-family: var(--mono); font-size: .72rem; cursor: pointer; transition: all var(--tr); }
    .btn-sm:hover { background: rgba(0,212,170,.2); } .btn-sm.clear { background: transparent; border-color: var(--border2); color: var(--muted); }
    .btn-sm.clear:hover { border-color: var(--border2); color: var(--text); }

    /* result meta */
    .result-meta { font-family: var(--mono); font-size: .68rem; color: #3d4f68; margin-bottom: .6rem; }
    .result-meta span { color: var(--muted); }

    /* table */
    .tbl-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: .78rem; }
    th { font-family: var(--mono); font-size: .62rem; letter-spacing: .08em; text-transform: uppercase; color: #3d4f68; padding: .5rem .75rem; border-bottom: 1px solid var(--border); text-align: left; white-space: nowrap; }
    td { padding: .45rem .75rem; border-bottom: 1px solid rgba(42,48,64,.6); vertical-align: middle; white-space: nowrap; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,.02); }
    .ts { font-family: var(--mono); font-size: .68rem; color: var(--muted); }
    .uri { font-family: var(--mono); font-size: .72rem; color: var(--text); max-width: 420px; overflow: hidden; text-overflow: ellipsis; }
    .ip-link { font-family: var(--mono); font-size: .72rem; color: var(--accent2); }
    .ip-link:hover { color: #fff; }
    .muted { color: var(--muted); font-size: .68rem; }
    .referer { max-width: 220px; overflow: hidden; text-overflow: ellipsis; font-size: .68rem; color: var(--muted); }

    /* badges */
    .badge { font-family: var(--mono); font-size: .63rem; padding: .15rem .45rem; border-radius: 3px; display: inline-block; font-weight: 600; }
    .badge--ok   { background: rgba(34,197,94,.12);  color: var(--ok);   border: 1px solid rgba(34,197,94,.25); }
    .badge--redir{ background: rgba(0,153,255,.12);  color: var(--redir);border: 1px solid rgba(0,153,255,.25); }
    .badge--warn { background: rgba(245,158,11,.12); color: var(--warn); border: 1px solid rgba(245,158,11,.25); }
    .badge--err  { background: rgba(239,68,68,.12);  color: var(--err);  border: 1px solid rgba(239,68,68,.25); }
    .badge--get  { background: rgba(0,153,255,.08);  color: var(--accent2); border: 1px solid rgba(0,153,255,.2); }
    .badge--post { background: rgba(245,158,11,.08); color: var(--warn);    border: 1px solid rgba(245,158,11,.2); }
    .badge--oth  { background: rgba(255,255,255,.04); color: var(--muted);  border: 1px solid var(--border); }
    .ua-bot     { font-family: var(--mono); font-size: .65rem; color: var(--err);  background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.2); border-radius: 3px; padding: .1rem .35rem; }
    .ua-browser { font-family: var(--mono); font-size: .65rem; color: var(--muted); }

    /* pagination */
    .pager { display: flex; gap: .35rem; flex-wrap: wrap; margin-top: .85rem; align-items: center; }
    .pager a, .pager span { font-family: var(--mono); font-size: .68rem; padding: .3rem .6rem; border-radius: 4px; border: 1px solid var(--border); color: var(--muted); transition: all var(--tr); }
    .pager a:hover { border-color: var(--accent); color: var(--accent); }
    .pager span.cur { border-color: var(--accent); color: var(--accent); background: rgba(0,212,170,.08); }
    .pager .ellipsis { border: none; color: #3d4f68; padding: .3rem .2rem; }

    /* tool usage bars */
    .tool-row { display: flex; align-items: center; gap: .6rem; margin-bottom: .5rem; }
    .tool-row:last-child { margin-bottom: 0; }
    .tool-lbl { font-family: var(--mono); font-size: .72rem; color: var(--muted); width: 170px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tool-bar-bg { flex: 1; height: 6px; background: var(--surface2); border-radius: 3px; overflow: hidden; }
    .tool-bar-fill { height: 100%; background: var(--accent); border-radius: 3px; transition: width .4s ease; }
    .tool-cnt { font-family: var(--mono); font-size: .65rem; color: #3d4f68; width: 40px; text-align: right; flex-shrink: 0; }

    /* errors table */
    .err-msg { font-family: var(--mono); font-size: .68rem; color: var(--text); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .err-file { font-family: var(--mono); font-size: .63rem; color: #3d4f68; max-width: 200px; overflow: hidden; text-overflow: ellipsis; }
    .empty-state { padding: 2rem; text-align: center; font-family: var(--mono); font-size: .72rem; color: #3d4f68; }

    /* geo */
    .geo { font-size: 1rem; white-space: nowrap; display: inline-flex; align-items: center; gap: .35rem; }
    .geo-cc { font-family: var(--mono); font-size: .8rem; color: var(--text); font-weight: 600; letter-spacing: .04em; }

    /* IP table side */
    .ip-table td:first-child { font-family: var(--mono); font-size: .72rem; }
    .epct-warn { color: var(--warn); }

    /* tab nav */
    .tab-nav { background: rgba(18,22,28,.98); border-bottom: 1px solid var(--border); padding: 0 1.75rem; display: flex; }
    .tab-nav a { display: inline-flex; align-items: center; padding: .55rem 1.1rem; font-family: var(--mono); font-size: .68rem; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); border-bottom: 2px solid transparent; margin-bottom: -1px; transition: all var(--tr); text-decoration: none; }
    .tab-nav a:hover { color: var(--text); }
    .tab-nav a.active { color: var(--accent); border-bottom-color: var(--accent); }

    /* flash */
    .flash { padding: .65rem 1rem; border-radius: var(--radius); font-size: .8rem; margin-bottom: 1.25rem; }
    .flash--ok  { background: rgba(34,197,94,.08);  border: 1px solid rgba(34,197,94,.25);  color: #86efac; }
    .flash--err { background: rgba(239,68,68,.08);  border: 1px solid rgba(239,68,68,.25);  color: #fca5a5; }

    /* users page header */
    .users-hd { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem; }
    .users-hd h1 { font-size: 1.15rem; font-weight: 600; color: #fff; }

    /* user table action buttons */
    .btn-act { font-family: var(--mono); font-size: .65rem; padding: .2rem .55rem; border-radius: 3px; border: 1px solid var(--border2); background: transparent; color: var(--muted); cursor: pointer; transition: all var(--tr); text-decoration: none; display: inline-block; }
    .btn-act:hover { color: var(--text); border-color: var(--text); }
    .btn-act.primary { border-color: rgba(0,212,170,.35); color: var(--accent); }
    .btn-act.primary:hover { background: rgba(0,212,170,.1); }
    .btn-act.warn-act { border-color: rgba(245,158,11,.3); color: var(--warn); }
    .btn-act.warn-act:hover { background: rgba(245,158,11,.08); }
    .btn-act.danger { border-color: rgba(239,68,68,.3); color: #fca5a5; }
    .btn-act.danger:hover { background: rgba(239,68,68,.1); border-color: var(--err); }

    /* user status/role badges */
    .badge--root     { background: rgba(0,212,170,.08);  border: 1px solid rgba(0,212,170,.2);  color: var(--accent); font-size: .62rem; padding: .1rem .4rem; border-radius: 3px; font-family: var(--mono); }
    .badge--active   { background: rgba(34,197,94,.08);  border: 1px solid rgba(34,197,94,.2);  color: var(--ok);     font-size: .62rem; padding: .1rem .4rem; border-radius: 3px; font-family: var(--mono); }
    .badge--disabled { background: rgba(239,68,68,.08);  border: 1px solid rgba(239,68,68,.2);  color: #fca5a5;       font-size: .62rem; padding: .1rem .4rem; border-radius: 3px; font-family: var(--mono); }

    /* inline block button (activity table IP cell) */
    .btn-block-sm { background: none; border: none; cursor: pointer; color: #2a3040; font-size: .72rem; padding: 0 .2rem; line-height: 1; transition: color var(--tr); vertical-align: middle; }
    .btn-block-sm:hover { color: var(--err); }
    .badge--blocked-sm { font-family: var(--mono); font-size: .65rem; color: rgba(239,68,68,.5); vertical-align: middle; margin-left: .15rem; cursor: default; }

    /* modal — [hidden] must win over display:flex */
    [hidden] { display: none !important; }
    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.72); display: flex; align-items: center; justify-content: center; z-index: 100; padding: 1rem; }
    .modal-card { background: var(--surface); border: 1px solid var(--border2); border-radius: 8px; width: 100%; max-width: 440px; }
    .modal-hd { padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
    .modal-hd h3 { font-family: var(--mono); font-size: .75rem; letter-spacing: .1em; text-transform: uppercase; color: var(--accent); }
    .modal-close { background: none; border: none; color: var(--muted); font-size: 1.3rem; cursor: pointer; line-height: 1; padding: 0 .2rem; transition: color var(--tr); }
    .modal-close:hover { color: var(--text); }
    .modal-body { padding: 1.25rem; display: flex; flex-direction: column; gap: .9rem; }
    .form-row { display: flex; flex-direction: column; gap: .35rem; }
    .form-row label { font-family: var(--mono); font-size: .62rem; letter-spacing: .08em; text-transform: uppercase; color: #3d4f68; }
    .form-row input, .form-row textarea { background: var(--surface2); border: 1px solid var(--border2); border-radius: 4px; color: var(--text); font-family: var(--mono); font-size: .78rem; padding: .45rem .7rem; outline: none; transition: border-color var(--tr); width: 100%; resize: vertical; }
    .form-row input:focus, .form-row textarea:focus { border-color: var(--accent); }
    .form-actions { display: flex; justify-content: flex-end; gap: .5rem; padding: .75rem 1.25rem; border-top: 1px solid var(--border); }
  </style>
</head>
<body>

<?php $navLabel = 'Admin Panel'; require __DIR__ . '/includes/site_nav.php'; ?>
<div class="admin-bar">
  <span class="admin-bar-user">Signed in as <span><?= htmlspecialchars($email) ?></span></span>
  <a href="<?= ADMIN_LOGIN_URL ?>?logout=1" class="admin-bar-logout">Sign out</a>
</div>
<nav class="tab-nav">
  <a href="?" class="<?= $tab === 'activity' ? 'active' : '' ?>">Activity</a>
  <a href="?tab=blocked" class="<?= $tab === 'blocked' ? 'active' : '' ?>">Blocked IPs <?php if ($blocked_set): ?><span style="font-size:.6rem;opacity:.6">(<?= count($blocked_set) ?>)</span><?php endif; ?></a>
  <a href="?tab=users" class="<?= $tab === 'users' ? 'active' : '' ?>">Users</a>
</nav>

<div class="wrap">

  <?php if ($tab === 'activity'): ?>
  <!-- ── Header ──────────────────────────────────────────────────────────────── -->
  <div class="page-hd">
    <h1>Site Activity</h1>
    <div class="period-tabs">
      <?php foreach (['24h' => 'Last 24 h', '7d' => '7 days', '30d' => '30 days'] as $k => $lbl): ?>
      <a href="<?= q(['period' => $k]) ?>" class="<?= $period === $k ? 'active' : '' ?>"><?= $lbl ?></a>
      <?php endforeach; ?>
    </div>
  </div>

  <!-- ── Stats ───────────────────────────────────────────────────────────────── -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-val"><?= number_format($stats['total']) ?></div>
      <div class="stat-lbl">Requests</div>
    </div>
    <div class="stat-card">
      <div class="stat-val"><?= number_format($stats['uniq']) ?></div>
      <div class="stat-lbl">Unique IPs</div>
    </div>
    <div class="stat-card">
      <div class="stat-val <?= $stats['epct'] > 10 ? 'err' : ($stats['epct'] > 3 ? 'warn' : '') ?>">
        <?= $stats['epct'] ?>%
      </div>
      <div class="stat-lbl">Error rate (4xx+5xx)</div>
      <div class="stat-sub"><?= number_format($stats['errs']) ?> requests</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="font-size:1rem;line-height:1.4"><?= htmlspecialchars($tool_name($stats['top_tool'])) ?></div>
      <div class="stat-lbl">Top tool</div>
      <div class="stat-sub"><?= number_format($stats['top_cnt']) ?> requests</div>
    </div>
  </div>

  <!-- ── Analytics row (tool usage + top IPs) ──────────────────────────────── -->
  <div class="side-row">

    <div class="card">
      <div class="card-hd"><h2>Tool Usage</h2></div>
      <div class="card-body">
        <?php if ($tool_usage): ?>
        <?php foreach ($tool_usage as $t): ?>
        <div class="tool-row">
          <span class="tool-lbl" title="<?= htmlspecialchars($t['script_name']) ?>"><?= htmlspecialchars($tool_name($t['script_name'])) ?></span>
          <div class="tool-bar-bg"><div class="tool-bar-fill" style="width:<?= round($t['c']/$tool_max*100) ?>%"></div></div>
          <span class="tool-cnt"><?= number_format($t['c']) ?></span>
        </div>
        <?php endforeach; ?>
        <?php else: ?><div class="empty-state">No data yet.</div><?php endif; ?>
      </div>
    </div>

    <div class="card">
      <div class="card-hd"><h2>Top IPs</h2></div>
      <div class="tbl-wrap">
        <table class="ip-table">
          <thead><tr><th>IP</th><th>Country</th><th>Req</th><th>Err%</th><th>Last seen</th><th></th></tr></thead>
          <tbody>
          <?php if ($top_ips): ?>
          <?php foreach ($top_ips as $row): ?>
          <tr>
            <td><a href="<?= q(['ip' => $row['ip']]) ?>" class="ip-link"><?= htmlspecialchars($row['ip']) ?></a></td>
            <td><?= geo_label($row['ip'], $geo) ?></td>
            <td><?= number_format($row['c']) ?></td>
            <td class="<?= (int)$row['epct'] > 30 ? 'epct-warn' : '' ?> muted"><?= (int)$row['epct'] ?>%</td>
            <td class="muted"><?= rel_time($row['last']) ?></td>
            <td>
              <form method="POST" style="display:inline" onsubmit="return confirm('Block <?= htmlspecialchars(addslashes($row['ip'])) ?>?')">
                <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
                <input type="hidden" name="action" value="block_ip">
                <input type="hidden" name="ip" value="<?= htmlspecialchars($row['ip']) ?>">
                <button type="submit" class="btn-act danger" style="font-size:.6rem;padding:.15rem .45rem">Block</button>
              </form>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php else: ?><tr><td colspan="5" class="empty-state">No data yet.</td></tr><?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

  </div><!-- .side-row -->

  <!-- ── Activity table (full width) ────────────────────────────────────────── -->
  <div class="card">
    <div class="card-hd">
      <h2>Activity Feed</h2>
      <div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">
        <span class="card-meta"><?= number_format($total_rows) ?> rows matched</span>
        <?php if ($fip): ?>
        <?php if (isset($blocked_set[$fip])): ?>
        <form method="POST" style="display:inline">
          <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
          <input type="hidden" name="action" value="unblock_ip">
          <input type="hidden" name="ip" value="<?= htmlspecialchars($fip) ?>">
          <button type="submit" class="btn-sm" style="border-color:rgba(34,197,94,.3);color:#86efac;font-size:.65rem;padding:.25rem .7rem">↩ Unblock <?= htmlspecialchars($fip) ?></button>
        </form>
        <?php else: ?>
        <form method="POST" style="display:inline" onsubmit="return confirm('Block <?= htmlspecialchars(addslashes($fip)) ?>?')">
          <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
          <input type="hidden" name="action" value="block_ip">
          <input type="hidden" name="ip" value="<?= htmlspecialchars($fip) ?>">
          <button type="submit" class="btn-sm" style="border-color:rgba(239,68,68,.3);color:#fca5a5;font-size:.65rem;padding:.25rem .7rem">⊘ Block <?= htmlspecialchars($fip) ?></button>
        </form>
        <?php endif; ?>
        <?php endif; ?>
      </div>
    </div>
    <div class="card-body">

      <!-- Filters -->
      <form method="GET" class="filter-bar">
        <input type="hidden" name="period" value="<?= htmlspecialchars($period) ?>">
        <div class="flt">
          <label>IP</label>
          <input type="text" name="ip" value="<?= htmlspecialchars($fip) ?>" placeholder="1.2.3.4">
        </div>
        <div class="flt">
          <label>Status</label>
          <select name="status">
            <option value="">All</option>
            <?php foreach (['2xx','3xx','4xx','5xx'] as $opt): ?>
            <option value="<?= $opt ?>" <?= $fstatus === $opt ? 'selected' : '' ?>><?= $opt ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="flt">
          <label>Method</label>
          <select name="method">
            <option value="">All</option>
            <?php foreach (['GET','POST','HEAD','OPTIONS','DELETE','PUT'] as $m): ?>
            <option value="<?= $m ?>" <?= $fmethod === $m ? 'selected' : '' ?>><?= $m ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="flt" style="flex-direction:row;gap:.4rem;align-items:flex-end">
          <button type="submit" class="btn-sm">Filter</button>
          <a href="<?= q([], ['ip','status','method','page']) ?>" class="btn-sm clear">Clear</a>
        </div>
      </form>

      <!-- Table -->
      <?php if ($rows): ?>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th><th>IP</th><th>Country</th><th>M</th><th>Path</th>
              <th>Status</th><th>Tool</th><th>UA</th><th>Referer</th>
            </tr>
          </thead>
          <tbody>
          <?php foreach ($rows as $r): ?>
          <tr>
            <td><span class="ts" title="<?= htmlspecialchars($r['created_at']) ?> UTC"><?= rel_time($r['created_at']) ?></span></td>
            <td style="white-space:nowrap">
              <a href="<?= q(['ip' => $r['ip']]) ?>" class="ip-link"><?= htmlspecialchars($r['ip']) ?></a>
              <?php if (isset($blocked_set[$r['ip']])): ?>
              <span class="badge--blocked-sm" title="Blocked">⊘</span>
              <?php else: ?>
              <form method="POST" style="display:inline" onsubmit="return confirm('Block <?= htmlspecialchars(addslashes($r['ip'])) ?>?')"><input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>"><input type="hidden" name="action" value="block_ip"><input type="hidden" name="ip" value="<?= htmlspecialchars($r['ip']) ?>"><button type="submit" class="btn-block-sm" title="Block this IP">⊘</button></form>
              <?php endif; ?>
            </td>
            <td><?= geo_label($r['ip'], $geo) ?></td>
            <td><?= method_badge($r['method']) ?></td>
            <td><span class="uri" title="<?= htmlspecialchars($r['uri'] . ($r['query_string'] ? '?'.$r['query_string'] : '')) ?>">
              <?= htmlspecialchars($r['uri']) ?>
            </span></td>
            <td><?= status_badge((int)$r['status']) ?></td>
            <td><span class="muted"><?= htmlspecialchars($tool_name($r['script_name'])) ?></span></td>
            <td><?= ua_label($r['user_agent']) ?></td>
            <td><span class="referer" title="<?= htmlspecialchars($r['referer']) ?>"><?= $r['referer'] ? htmlspecialchars($r['referer']) : '<span class="muted">—</span>' ?></span></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php else: ?>
      <div class="empty-state">No activity found for this filter.</div>
      <?php endif; ?>

      <!-- Pagination -->
      <?php if ($total_pages > 1): ?>
      <div class="pager">
        <?php if ($page > 1): ?><a href="<?= pg_url($page-1) ?>">← Prev</a><?php endif; ?>
        <?php
          $pages_to_show = [];
          for ($i = 1; $i <= $total_pages; $i++) {
            if ($i === 1 || $i === $total_pages || abs($i - $page) <= 2) $pages_to_show[] = $i;
          }
          $prev = null;
          foreach ($pages_to_show as $pn):
            if ($prev !== null && $pn - $prev > 1): ?><span class="ellipsis">…</span><?php endif;
            $prev = $pn;
        ?>
        <?php if ($pn === $page): ?><span class="cur"><?= $pn ?></span>
        <?php else: ?><a href="<?= pg_url($pn) ?>"><?= $pn ?></a><?php endif; ?>
        <?php endforeach; ?>
        <?php if ($page < $total_pages): ?><a href="<?= pg_url($page+1) ?>">Next →</a><?php endif; ?>
      </div>
      <?php endif; ?>

    </div>
  </div><!-- activity card -->

  <!-- ── Errors ──────────────────────────────────────────────────────────────── -->
  <div class="card">
    <div class="card-hd">
      <h2>PHP Errors</h2>
      <span class="card-meta">latest 25</span>
    </div>
    <?php if ($err_rows): ?>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Time</th><th>IP</th><th>Type</th><th>URI</th><th>Message</th><th>File : line</th></tr></thead>
        <tbody>
        <?php foreach ($err_rows as $e): ?>
        <tr>
          <td><span class="ts" title="<?= htmlspecialchars($e['created_at']) ?> UTC"><?= rel_time($e['created_at']) ?></span></td>
          <td><a href="<?= q(['ip' => $e['ip']]) ?>" class="ip-link"><?= htmlspecialchars($e['ip']) ?></a></td>
          <td><span class="badge badge--warn"><?= htmlspecialchars($e['error_type']) ?></span></td>
          <td><span class="uri"><?= htmlspecialchars($e['uri']) ?></span></td>
          <td><span class="err-msg" title="<?= htmlspecialchars($e['error_msg']) ?>"><?= htmlspecialchars($e['error_msg']) ?></span></td>
          <td><span class="err-file"><?= htmlspecialchars(basename($e['error_file'])) ?> : <?= (int)$e['error_line'] ?></span></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php else: ?>
    <div class="empty-state">No PHP errors logged.</div>
    <?php endif; ?>
  </div>

  <?php endif; /* $tab === 'activity' */ ?>

  <?php if ($tab === 'users'): ?>

  <?php if ($u_flash): ?>
  <div class="flash flash--<?= $u_flash_ok ? 'ok' : 'err' ?>"><?= $u_flash ?></div>
  <?php endif; ?>

  <div class="users-hd">
    <h1>Users</h1>
    <button class="btn-sm" onclick="document.getElementById('modal-add').hidden=false">+ Add User</button>
  </div>

  <div class="card">
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Email</th><th>Status</th><th>Role</th><th>Attributes</th><th>Created</th><th>Actions</th></tr>
        </thead>
        <tbody>
        <?php if ($users): ?>
        <?php foreach ($users as $u): ?>
        <tr>
          <td><?= htmlspecialchars($u['name'] ?: '—') ?></td>
          <td><span class="ip-link" style="color:var(--text)"><?= htmlspecialchars($u['email']) ?></span></td>
          <td><?= $u['is_disabled'] ? '<span class="badge--disabled">Disabled</span>' : '<span class="badge--active">Active</span>' ?></td>
          <td><?= $u['is_root'] ? '<span class="badge--root">Root Admin</span>' : '<span class="muted">User</span>' ?></td>
          <td>
            <?php if ($u['attributes']): ?>
            <span class="muted" style="font-family:var(--mono);font-size:.65rem;cursor:default" title="<?= htmlspecialchars($u['attributes']) ?>">{…}</span>
            <?php else: ?><span class="muted">—</span><?php endif; ?>
          </td>
          <td><span class="ts"><?= htmlspecialchars(substr($u['created_at'], 0, 10)) ?></span></td>
          <td style="white-space:nowrap">
            <?php if ($u['is_root']): ?>
            <span class="muted" style="font-size:.65rem;font-family:var(--mono)">protected</span>
            <?php else: ?>
            <button class="btn-act primary"
              onclick="openEditModal(<?= (int)$u['id'] ?>,<?= json_encode($u['name']) ?>,<?= json_encode($u['email']) ?>,<?= json_encode($u['attributes'] ?? '') ?>)">Edit</button>
            <?php if ($u['email'] !== $email): ?>
            <form method="POST" style="display:inline"
              onsubmit="return confirm('<?= $u['is_disabled'] ? 'Enable' : 'Disable' ?> this user?')">
              <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
              <input type="hidden" name="action" value="toggle_user">
              <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
              <button type="submit" class="btn-act <?= $u['is_disabled'] ? '' : 'warn-act' ?>"><?= $u['is_disabled'] ? 'Enable' : 'Disable' ?></button>
            </form>
            <form method="POST" style="display:inline"
              onsubmit="return confirm('Delete this user? This cannot be undone.')">
              <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
              <input type="hidden" name="action" value="delete_user">
              <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
              <button type="submit" class="btn-act danger">Delete</button>
            </form>
            <?php else: ?>
            <span class="muted" style="font-size:.65rem;font-family:var(--mono)">you</span>
            <?php endif; ?>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
        <?php else: ?>
        <tr><td colspan="7" class="empty-state">No users found.</td></tr>
        <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Add User Modal -->
  <div class="modal-overlay" id="modal-add" hidden onclick="if(event.target===this)this.hidden=true">
    <div class="modal-card">
      <div class="modal-hd">
        <h3>Add User</h3>
        <button class="modal-close" onclick="document.getElementById('modal-add').hidden=true">×</button>
      </div>
      <form method="POST">
        <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
        <input type="hidden" name="action" value="add_user">
        <div class="modal-body">
          <div class="form-row">
            <label>Name</label>
            <input type="text" name="name" placeholder="Full name">
          </div>
          <div class="form-row">
            <label>Email</label>
            <input type="email" name="email" required placeholder="user@example.com">
          </div>
          <div class="form-row">
            <label>Attributes <span style="text-transform:none;color:var(--muted)">(optional JSON)</span></label>
            <textarea name="attributes" rows="3" placeholder='{"department":"engineering"}'></textarea>
          </div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn-sm clear" onclick="document.getElementById('modal-add').hidden=true">Cancel</button>
          <button type="submit" class="btn-sm">Add User</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Edit User Modal -->
  <div class="modal-overlay" id="modal-edit" hidden onclick="if(event.target===this)this.hidden=true">
    <div class="modal-card">
      <div class="modal-hd">
        <h3>Edit User</h3>
        <button class="modal-close" onclick="document.getElementById('modal-edit').hidden=true">×</button>
      </div>
      <form method="POST">
        <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
        <input type="hidden" name="action" value="update_user">
        <input type="hidden" name="id" id="edit-id">
        <div class="modal-body">
          <div class="form-row">
            <label>Name</label>
            <input type="text" name="name" id="edit-name" placeholder="Full name">
          </div>
          <div class="form-row">
            <label>Email</label>
            <input type="email" name="email" id="edit-email" required placeholder="user@example.com">
          </div>
          <div class="form-row">
            <label>Attributes <span style="text-transform:none;color:var(--muted)">(optional JSON)</span></label>
            <textarea name="attributes" id="edit-attrs" rows="3" placeholder='{"department":"engineering"}'></textarea>
          </div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn-sm clear" onclick="document.getElementById('modal-edit').hidden=true">Cancel</button>
          <button type="submit" class="btn-sm">Save</button>
        </div>
      </form>
    </div>
  </div>

  <?php endif; /* $tab === 'users' */ ?>

  <?php if ($tab === 'blocked'): ?>

  <?php if ($b_flash): ?>
  <div class="flash flash--<?= $b_flash_ok ? 'ok' : 'err' ?>"><?= $b_flash ?></div>
  <?php endif; ?>

  <!-- Manual block form -->
  <div class="users-hd" style="align-items:flex-end;flex-wrap:wrap;gap:.75rem">
    <h1>Blocked IPs</h1>
    <form method="POST" style="display:flex;align-items:flex-end;gap:.5rem;flex-wrap:wrap;margin-left:auto">
      <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
      <input type="hidden" name="action" value="block_ip">
      <div class="flt">
        <label>IP Address</label>
        <input type="text" name="ip" placeholder="1.2.3.4" required style="width:150px">
      </div>
      <div class="flt" style="flex:1;min-width:160px">
        <label>Reason <span style="text-transform:none;color:var(--muted)">(optional)</span></label>
        <input type="text" name="reason" placeholder="Abuse, scanning…" style="width:100%">
      </div>
      <button type="submit" class="btn-sm" style="border-color:rgba(239,68,68,.3);color:#fca5a5" onclick="return confirm('Block this IP?')">⊘ Block</button>
    </form>
  </div>

  <div class="card">
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th>IP</th><th>Country</th><th>All-time req</th><th>Last seen</th><th>Err%</th><th>Blocked by</th><th>Blocked at</th><th>Reason</th><th></th></tr>
        </thead>
        <tbody>
        <?php if ($blocked_list): ?>
        <?php foreach ($blocked_list as $b): ?>
        <tr>
          <td>
            <a href="?ip=<?= urlencode($b['ip']) ?>" class="ip-link" title="View activity for this IP"><?= htmlspecialchars($b['ip']) ?></a>
          </td>
          <td>
            <?php if ($b['country'] && $b['country'] !== 'XX'): ?>
            <?= geo_label($b['ip'], [$b['ip'] => $b['country']]) ?>
            <?php else: ?><span class="muted">—</span><?php endif; ?>
          </td>
          <td><?= $b['total_req'] ? number_format((int)$b['total_req']) : '<span class="muted">—</span>' ?></td>
          <td><?= $b['last_seen'] ? rel_time($b['last_seen']) : '<span class="muted">—</span>' ?></td>
          <td class="<?= (int)$b['err_pct'] > 30 ? 'epct-warn' : 'muted' ?>"><?= $b['total_req'] ? (int)$b['err_pct'] . '%' : '<span class="muted">—</span>' ?></td>
          <td><span class="muted" style="font-size:.72rem"><?= htmlspecialchars($b['blocked_by']) ?></span></td>
          <td><span class="ts" title="<?= htmlspecialchars($b['blocked_at']) ?> UTC"><?= rel_time($b['blocked_at']) ?></span></td>
          <td><span class="muted" style="font-family:var(--mono);font-size:.68rem;max-width:180px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?= htmlspecialchars($b['reason'] ?? '') ?>"><?= $b['reason'] ? htmlspecialchars($b['reason']) : '—' ?></span></td>
          <td>
            <form method="POST" style="display:inline" onsubmit="return confirm('Unblock <?= htmlspecialchars(addslashes($b['ip'])) ?>?')">
              <input type="hidden" name="_csrf" value="<?= _admin_csrf_token() ?>">
              <input type="hidden" name="action" value="unblock_ip">
              <input type="hidden" name="ip" value="<?= htmlspecialchars($b['ip']) ?>">
              <button type="submit" class="btn-act">Unblock</button>
            </form>
          </td>
        </tr>
        <?php endforeach; ?>
        <?php else: ?>
        <tr><td colspan="9" class="empty-state">No blocked IPs.</td></tr>
        <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>

  <?php endif; /* $tab === 'blocked' */ ?>

</div><!-- .wrap -->

<script>
// Convert UTC timestamps to local time on hover title
document.querySelectorAll('.ts').forEach(function(el) {
  var utc = el.title;
  if (!utc) return;
  var d = new Date(utc.replace(' ', 'T') + 'Z');
  el.title = d.toLocaleString();
});
// Auto-submit selects
document.querySelectorAll('.filter-bar select').forEach(function(s) {
  s.addEventListener('change', function() { this.closest('form').submit(); });
});
// User edit modal
function openEditModal(id, name, email, attrs) {
  document.getElementById('edit-id').value    = id;
  document.getElementById('edit-name').value  = name;
  document.getElementById('edit-email').value = email;
  document.getElementById('edit-attrs').value = attrs;
  document.getElementById('modal-edit').hidden = false;
}
</script>

</body>
</html>
