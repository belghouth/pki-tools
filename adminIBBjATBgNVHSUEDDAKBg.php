<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/admin_db.php';

$email = admin_auth_check();
if (!$email) {
    header('Location: ' . ADMIN_LOGIN_URL, true, 302);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin — <?= SITE_DOMAIN ?></title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,600;1,300&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:      #0e1014;
      --surface: #13171e;
      --border:  #2a3040;
      --border2: #3a4458;
      --accent:  #00d4aa;
      --text:    #d4dae6;
      --muted:   #6b7a90;
      --mono:    'IBM Plex Mono', monospace;
      --sans:    'IBM Plex Sans', sans-serif;
      --radius:  6px;
      --tr:      160ms ease;
      --max:     1140px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; overflow-x: hidden; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-weight: 300;
      line-height: 1.7;
      min-height: 100vh;
    }
    a { color: var(--accent); text-decoration: none; transition: color var(--tr); }
    a:hover { color: #fff; }

    .admin-bar {
      background: rgba(18,22,28,0.98);
      border-bottom: 1px solid #1a2030;
      padding: 0 1.75rem;
      height: 36px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-family: var(--mono);
      font-size: 0.7rem;
      letter-spacing: 0.04em;
    }
    .admin-bar-user { color: #4a5a70; }
    .admin-bar-user span { color: var(--accent); }
    .admin-bar-logout { color: #4a5a70; transition: color var(--tr); }
    .admin-bar-logout:hover { color: #fca5a5; }

    .admin-main {
      max-width: var(--max);
      margin: 0 auto;
      padding: 3rem 2rem;
    }

    .admin-empty {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 45vh;
      text-align: center;
      gap: 1rem;
    }
    .admin-empty svg { opacity: 0.18; }
    .admin-empty-label {
      font-family: var(--mono);
      font-size: 0.72rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
    }
  </style>
</head>
<body>

<?php $navLabel = 'Admin Panel'; require __DIR__ . '/includes/site_nav.php'; ?>

<div class="admin-bar">
  <span class="admin-bar-user">Signed in as <span><?= htmlspecialchars($email) ?></span></span>
  <a href="<?= ADMIN_LOGIN_URL ?>?logout=1" class="admin-bar-logout">Sign out</a>
</div>

<main class="admin-main">
  <div class="admin-empty">
    <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="#6b7a90" stroke-width="1.2">
      <rect x="3" y="3" width="7" height="7" rx="1"/>
      <rect x="14" y="3" width="7" height="7" rx="1"/>
      <rect x="3" y="14" width="7" height="7" rx="1"/>
      <rect x="14" y="14" width="7" height="7" rx="1"/>
    </svg>
    <p class="admin-empty-label">Content coming soon</p>
  </div>
</main>

</body>
</html>
