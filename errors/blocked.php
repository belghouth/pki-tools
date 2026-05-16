<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Access Restricted | thameur.org</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:      #0e1014;
      --surface: #13171e;
      --border:  #2a3040;
      --border2: #3a4458;
      --accent:  #ef4444;
      --text:    #d4dae6;
      --muted:   #6b7a90;
      --mono:    'IBM Plex Mono', monospace;
      --sans:    'IBM Plex Sans', sans-serif;
      --radius:  6px;
      --tr:      160ms ease;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; scroll-behavior: smooth; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-weight: 300;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    a { color: #6b7a90; text-decoration: none; transition: color var(--tr); }
    a:hover { color: var(--text); }

    .site-header {
      position: sticky; top: 0; z-index: 20;
      background: rgba(14,16,20,0.88);
      backdrop-filter: blur(10px);
      border-bottom: 1px solid var(--border);
      padding: 0 2rem;
      display: flex; align-items: center; justify-content: space-between;
      height: 54px;
    }
    .header-logo {
      font-family: var(--mono);
      font-size: .9rem; font-weight: 600;
      letter-spacing: .08em; text-transform: uppercase;
      color: #3d4f68;
    }

    .error-stage {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      text-align: center;
      padding: 4rem 2rem;
      position: relative;
      overflow: hidden;
      background:
        radial-gradient(ellipse 700px 500px at 50% 40%, rgba(239,68,68,.04) 0%, transparent 70%),
        var(--bg);
    }

    .error-stage::before {
      content: '';
      position: absolute; inset: 0;
      background-image:
        linear-gradient(var(--border) 1px, transparent 1px),
        linear-gradient(90deg, var(--border) 1px, transparent 1px);
      background-size: 60px 60px;
      opacity: .12;
      pointer-events: none;
    }

    .error-inner {
      position: relative;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: .5rem;
      max-width: 480px;
    }

    .error-meerkat {
      width: 100px;
      object-fit: contain;
      margin-bottom: .8rem;
      filter: drop-shadow(0 0 18px rgba(239,68,68,.2)) grayscale(.4);
    }

    .error-code {
      font-family: var(--mono);
      font-size: clamp(4rem, 16vw, 7rem);
      font-weight: 600;
      line-height: 1;
      color: var(--accent);
      letter-spacing: -.04em;
      opacity: .7;
    }

    .error-title {
      font-size: clamp(1.1rem, 3vw, 1.5rem);
      font-weight: 600;
      color: #fff;
      margin-top: .4rem;
    }

    .error-desc {
      font-size: .9rem;
      color: var(--muted);
      line-height: 1.7;
      margin-top: .6rem;
      max-width: 360px;
    }

    .error-contact {
      font-family: var(--mono);
      font-size: .72rem;
      color: #3d4f68;
      margin-top: 1.5rem;
    }
    .error-contact a { color: #4a5a70; }
    .error-contact a:hover { color: var(--muted); }

    .site-footer {
      border-top: 1px solid var(--border);
      padding: 1.2rem 2rem;
      text-align: center;
      font-family: var(--mono);
      font-size: .72rem;
      color: #3d4f68;
    }

    @media (max-width: 520px) {
      .site-header { padding: 0 1rem; }
      .error-stage  { padding: 3rem 1.25rem; }
    }
  </style>
</head>
<body>

<header class="site-header">
  <span class="header-logo">thameur.org</span>
</header>

<main class="error-stage">
  <div class="error-inner">
    <img src="/img/meerkat_240.png" alt="" class="error-meerkat">
    <div class="error-code">403</div>
    <div class="error-title">Access Restricted</div>
    <p class="error-desc">
      This service is not available at this time.
    </p>
    <p class="error-contact">
      If you believe this is a mistake, contact
      <a href="mailto:me@thameur.org">me@thameur.org</a>
    </p>
  </div>
</main>

<footer class="site-footer">
  &copy; <script>document.write(new Date().getFullYear())</script> Thameur Belghith
</footer>

</body>
</html>
