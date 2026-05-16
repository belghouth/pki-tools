<?php
/**
 * recaptcha.php — Google reCAPTCHA v3 helper
 *
 * Include this file from any page that needs reCAPTCHA v3 protection.
 * It provides:
 *   - Constants for site/secret keys
 *   - recaptcha_verify()  — server-side token verification
 *   - recaptcha_head()    — <script> tag to output in <head>
 *   - recaptcha_bind_js() — inline JS to bind token injection to specific
 *                           submit buttons by name/value
 *
 * Usage in a page:
 *   require_once __DIR__ . '/recaptcha.php';
 *
 *   // In <head>:
 *   <?= recaptcha_head() ?>
 *
 *   // In the form, before </form>:
 *   <input type="hidden" name="g_recaptcha_token" id="g_recaptcha_token">
 *
 *   // Before </body>:
 *   <?= recaptcha_bind_js([
 *       ['name' => 'fetch_domain',   'value' => '1',        'action' => 'fetch_domain'],
 *       ['name' => 'linter_action',  'value' => 'crtsh:*',  'action' => 'crtsh_lint'],
 *   ]) ?>
 *
 *   // Server-side on POST:
 *   if (recaptcha_required()) {
 *       if (!recaptcha_verify($_POST['g_recaptcha_token'] ?? '', 'fetch_domain')) {
 *           $error = 'reCAPTCHA verification failed. Please try again.';
 *       }
 *   }
 *
 * Register your domain and get keys at:
 *   https://www.google.com/recaptcha/admin
 * Select: reCAPTCHA v3
 */

// ── Keys — loaded from .secrets file ─────────────────────────────────────────
// .secrets format (one per line, no quotes):
//   RECAPTCHA_SITE_KEY=your_site_key_here
//   RECAPTCHA_SECRET_KEY=your_secret_key_here
//
// Place .secrets in the site root (same directory as recaptcha.php) and
// ensure it is not web-accessible (deny in nginx/apache config).

$_recaptcha_secrets_file = __DIR__ . '/.secrets';
$_recaptcha_site_key     = 'YOUR_RECAPTCHA_SITE_KEY_HERE';
$_recaptcha_secret_key   = 'YOUR_RECAPTCHA_SECRET_KEY_HERE';
$_recaptcha_bypass_ips   = [];

if (is_readable($_recaptcha_secrets_file)) {
    foreach (file($_recaptcha_secrets_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $_line) {
        $_line = trim($_line);
        if ($_line === '' || $_line[0] === '#') continue;
        [$_k, $_v] = array_pad(explode('=', $_line, 2), 2, '');
        $_k = trim($_k); $_v = trim($_v);
        if ($_k === 'RECAPTCHA_SITE_KEY')   $_recaptcha_site_key   = $_v;
        if ($_k === 'RECAPTCHA_SECRET_KEY') $_recaptcha_secret_key = $_v;
        // Comma-separated list of IPs that skip reCAPTCHA (e.g. your own IP).
        // RECAPTCHA_BYPASS_IPS=1.2.3.4,5.6.7.8
        if ($_k === 'RECAPTCHA_BYPASS_IPS') {
            $_recaptcha_bypass_ips = array_filter(array_map('trim', explode(',', $_v)));
        }
    }
}

define('RECAPTCHA_SITE_KEY',   $_recaptcha_site_key);
define('RECAPTCHA_SECRET_KEY', $_recaptcha_secret_key);
define('RECAPTCHA_BYPASS_IPS', $_recaptcha_bypass_ips);
unset($_recaptcha_secrets_file, $_recaptcha_site_key, $_recaptcha_secret_key, $_recaptcha_bypass_ips, $_line, $_k, $_v);

// Minimum score threshold (0.0–1.0). Google recommends 0.5 as a starting point.
// Lower = more permissive, higher = stricter.
define('RECAPTCHA_MIN_SCORE', 0.3);

// reCAPTCHA v3 verification endpoint.
define('RECAPTCHA_VERIFY_URL', 'https://www.recaptcha.net/recaptcha/api/siteverify');

// ── Server-side verification ──────────────────────────────────────────────────

/**
 * Verifies a reCAPTCHA v3 token server-side.
 *
 * @param string $token   The g-recaptcha-response token from the form POST.
 * @param string $action  The action name used when the token was generated.
 *                        Must match what was passed to grecaptcha.execute().
 * @return bool           True if the token is valid and score meets threshold.
 */
function recaptcha_verify(string $token, string $action): bool {
    // IP bypass — allows the site owner to use the tools without reCAPTCHA friction.
    // Add IPs to RECAPTCHA_BYPASS_IPS in .secrets.
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    if ($remote !== '' && in_array($remote, RECAPTCHA_BYPASS_IPS, true)) {
        return true;
    }

    if ($token === '' || RECAPTCHA_SECRET_KEY === 'YOUR_RECAPTCHA_SECRET_KEY_HERE') {
        return false;
    }

    if (!function_exists('curl_init')) {
        // Fall back to file_get_contents if cURL is unavailable.
        $response = @file_get_contents(
            RECAPTCHA_VERIFY_URL,
            false,
            stream_context_create([
                'http' => [
                    'method'  => 'POST',
                    'header'  => 'Content-Type: application/x-www-form-urlencoded',
                    'content' => http_build_query([
                        'secret'   => RECAPTCHA_SECRET_KEY,
                        'response' => $token,
                    ]),
                    'timeout' => 5,
                ],
            ])
        );
    } else {
        $ch = curl_init(RECAPTCHA_VERIFY_URL);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query([
                'secret'   => RECAPTCHA_SECRET_KEY,
                'response' => $token,
            ]),
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
    }

    if (!$response) return false;

    $data = json_decode($response, true);
    if (!is_array($data))                          return false;
    if (empty($data['success']))                   return false;
    if (($data['score'] ?? 0) < RECAPTCHA_MIN_SCORE) return false;

    // Action name must match — prevents token reuse across different forms.
    if (!empty($data['action']) && $data['action'] !== $action) return false;

    return true;
}

/**
 * Returns true if reCAPTCHA keys are configured (not placeholder values).
 * Use this to conditionally enforce or skip verification during development.
 */
function recaptcha_configured(): bool {
    return RECAPTCHA_SITE_KEY   !== 'YOUR_RECAPTCHA_SITE_KEY_HERE'
        && RECAPTCHA_SECRET_KEY !== 'YOUR_RECAPTCHA_SECRET_KEY_HERE';
}

// ── HTML helpers ──────────────────────────────────────────────────────────────

/**
 * Returns the <script> tag to include in <head>.
 * Must be called once per page.
 */
function recaptcha_head(): string {
    $key = htmlspecialchars(RECAPTCHA_SITE_KEY, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8');
    return '<script src="https://www.google.com/recaptcha/api.js?render=' . $key . '" async defer></script>' . "\n";
}

/**
 * Returns inline JS that intercepts specific submit buttons, executes
 * grecaptcha.execute() with the appropriate action, injects the token
 * into the hidden field, then re-submits the form.
 *
 * $bindings is an array of:
 *   [
 *     'button_name'  => (string) the button's name attribute
 *     'button_value' => (string) the button's value attribute, or '*' for any value
 *     'action'       => (string) reCAPTCHA action name (alphanumeric + /_ only)
 *   ]
 *
 * The hidden field <input type="hidden" name="g_recaptcha_token" id="g_recaptcha_token">
 * must be present inside the form.
 */
function recaptcha_bind_js(array $bindings): string {
    $site_key = json_encode(RECAPTCHA_SITE_KEY);
    $bindings_json = json_encode(array_map(fn($b) => [
        'name'   => $b['button_name'],
        'value'  => $b['button_value'],
        'action' => $b['action'],
    ], $bindings));

    return <<<HTML
<script>
(function() {
  var siteKey  = {$site_key};
  var bindings = {$bindings_json};

  function getAction(btn) {
    for (var i = 0; i < bindings.length; i++) {
      var b = bindings[i];
      if (btn.name === b.name && (b.value === '*' || btn.value === b.value)) {
        return b.action;
      }
    }
    return null;
  }

  document.addEventListener('DOMContentLoaded', function() {
    var form = document.querySelector('form');
    if (!form) return;

    var tokenField = document.getElementById('g_recaptcha_token');
    if (!tokenField) return;

    // This hidden field carries the clicked button's name=value through
    // form.submit(), which does not include button values in the POST body.
    var btnProxy = document.createElement('input');
    btnProxy.type = 'hidden';
    form.appendChild(btnProxy);

    var clickedBtn = null;
    form.addEventListener('click', function(e) {
      var t = e.target.closest('button[type="submit"]');
      if (t) clickedBtn = t;
    }, true);

    form.addEventListener('submit', function(e) {
      var btn    = clickedBtn;
      var action = btn ? getAction(btn) : null;

      if (!action) return; // Not a protected button — let it submit normally.

      e.preventDefault();

      grecaptcha.ready(function() {
        grecaptcha.execute(siteKey, { action: action }).then(function(token) {
          tokenField.value = token;

          // Inject the button's name=value so the server sees it in $_POST.
          btnProxy.name  = btn.name;
          btnProxy.value = btn.value;

          // Disable the button itself so the browser does not try to
          // include it again (it won't, but keeps things clean).
          btn.disabled = true;

          form.submit();
        });
      });
    });
  });
})();
</script>
HTML;
}

