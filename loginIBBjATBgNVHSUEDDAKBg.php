<?php
define('ADMIN_NO_LOG', true);
require_once __DIR__ . '/config.php';

// Isolated PHP session for OAuth CSRF state only
session_name('mkt_ao');
session_set_cookie_params([
    'lifetime' => 600,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

// Already authenticated?
if (admin_auth_check()) {
    header('Location: ' . ADMIN_PANEL_URL, true, 302);
    exit;
}

// Logout
if (isset($_GET['logout'])) {
    $t = $_COOKIE['mkt_adm'] ?? '';
    if (strlen($t) === 64 && ctype_xdigit($t)) admin_destroy_session($t);
    setcookie('mkt_adm', '', ['expires' => time() - 3600, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
    session_destroy();
    header('Location: ' . ADMIN_LOGIN_URL, true, 302);
    exit;
}

function _google_token_exchange(string $code): ?array {
    $ch = curl_init('https://oauth2.googleapis.com/token');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_POSTFIELDS     => http_build_query([
            'code'          => $code,
            'client_id'     => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET,
            'redirect_uri'  => ADMIN_LOGIN_URL,
            'grant_type'    => 'authorization_code',
        ]),
    ]);
    $body = curl_exec($ch); curl_close($ch);
    if (!$body) return null;
    $d = json_decode($body, true);
    return (is_array($d) && empty($d['error'])) ? $d : null;
}

function _google_userinfo(string $access_token): ?array {
    $ch = curl_init('https://www.googleapis.com/oauth2/v3/userinfo');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . $access_token],
    ]);
    $body = curl_exec($ch); curl_close($ch);
    if (!$body) return null;
    $d = json_decode($body, true);
    return (is_array($d) && !empty($d['email'])) ? $d : null;
}

$error = null;

// Initiate OAuth redirect
if (isset($_GET['initiate'])) {
    if (GOOGLE_CLIENT_ID === '') {
        $error = 'Google OAuth is not configured yet.';
    } else {
        $state = bin2hex(random_bytes(16));
        $_SESSION['oauth_state'] = $state;
        header('Location: https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
            'client_id'     => GOOGLE_CLIENT_ID,
            'redirect_uri'  => ADMIN_LOGIN_URL,
            'response_type' => 'code',
            'scope'         => 'openid email',
            'state'         => $state,
            'prompt'        => 'select_account',
        ]), true, 302);
        exit;
    }

// OAuth callback from Google
} elseif (isset($_GET['code'])) {
    $code  = (string)($_GET['code']  ?? '');
    $state = (string)($_GET['state'] ?? '');

    if (!$state || !isset($_SESSION['oauth_state']) || !hash_equals($_SESSION['oauth_state'], $state)) {
        $error = 'Authentication failed. Please try again.';
    } else {
        unset($_SESSION['oauth_state']);
        $tokens = _google_token_exchange($code);
        $info   = $tokens ? _google_userinfo($tokens['access_token'] ?? '') : null;

        if (!$info || empty($info['email_verified']) || !user_by_email($info['email'])) {
            $error = 'Access denied.';
        } else {
            $tok = admin_create_session($info['email']);
            setcookie('mkt_adm', $tok, [
                'expires'  => time() + 43200,
                'path'     => '/',
                'secure'   => true,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
            header('Location: ' . ADMIN_PANEL_URL, true, 302);
            exit;
        }
    }

} elseif (isset($_GET['error'])) {
    $error = 'Google sign-in was cancelled or failed.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign In</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; }
    body {
      background: #0e1014;
      color: #d4dae6;
      font-family: 'IBM Plex Sans', sans-serif;
      font-weight: 300;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1.5rem;
    }

    .card {
      width: 100%;
      max-width: 360px;
      background: #13171e;
      border: 1px solid #2a3040;
      border-radius: 8px;
      padding: 2.5rem 2rem;
      text-align: center;
    }

    .card-logo {
      width: 48px; height: 48px;
      filter: drop-shadow(0 0 12px rgba(0,212,170,0.3));
      margin-bottom: 1.4rem;
    }

    .card-eyebrow {
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.68rem;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: #00d4aa;
      margin-bottom: 0.5rem;
    }

    .card-title {
      font-size: 1.2rem;
      font-weight: 600;
      color: #fff;
      margin-bottom: 0.4rem;
    }

    .card-sub {
      font-size: 0.8rem;
      color: #6b7a90;
      margin-bottom: 2rem;
    }

    .error-box {
      background: rgba(239,68,68,0.08);
      border: 1px solid rgba(239,68,68,0.3);
      border-radius: 6px;
      color: #fca5a5;
      font-size: 0.82rem;
      padding: 0.75rem 1rem;
      margin-bottom: 1.5rem;
      text-align: left;
    }

    .btn-google {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.65rem;
      width: 100%;
      padding: 0.75rem 1.25rem;
      background: #fff;
      color: #1f1f1f;
      border: none;
      border-radius: 6px;
      font-family: 'IBM Plex Sans', sans-serif;
      font-size: 0.88rem;
      font-weight: 400;
      cursor: pointer;
      text-decoration: none;
      transition: background 150ms ease, box-shadow 150ms ease;
    }
    .btn-google:hover {
      background: #f8f8f8;
      box-shadow: 0 2px 8px rgba(0,0,0,0.35);
      color: #1f1f1f;
    }

    .not-configured {
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.75rem;
      color: #3d4f68;
    }
  </style>
</head>
<body>
  <div class="card">
    <img src="/img/meerkat_120.png" alt="" class="card-logo">
    <p class="card-eyebrow">thameur.org</p>
    <h1 class="card-title">Admin Access</h1>
    <p class="card-sub">Restricted — authorised personnel only.</p>

    <?php if ($error): ?>
    <div class="error-box"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if (GOOGLE_CLIENT_ID !== ''): ?>
    <a href="?initiate=1" class="btn-google">
      <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
      </svg>
      Continue with Google
    </a>
    <?php else: ?>
    <p class="not-configured">Google OAuth not configured.</p>
    <?php endif; ?>
  </div>
</body>
</html>
