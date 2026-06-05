<?php
/**
 * PoW Captcha - Proof of Work Captcha PHP
 *
 * Usage: require_once __DIR__ . '/pow_captcha.php';
 *
 * Protection automatique par challenge Proof-of-Work sur toute requete entrante.
 * - Cookie signe HMAC (host + fingerprint + expiration)
 * - Bypass des bots legitimes via rDNS + forward DNS
 * - Page captcha auto-contenue (HTML/CSS/JS inline, Web Worker)
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

// !!! IMPORTANT !!! Remplacer cette valeur par une chaine aleatoire secrete.
// Generer par exemple avec : php -r "echo bin2hex(random_bytes(32));"
if (!defined('POW_SECRET')) {
    define('POW_SECRET', 'clésecrete');
}

// --- PoW multi-sous-challenges ---------------------------------------------
// Au lieu d'un unique challenge difficile, on emet N sous-challenges
// independants de difficulte K bits chacun. Travail total moyen =
// N * 2^K hashs. La variance relative est divisee par sqrt(N) par rapport
// a un challenge unique de meme travail total, ce qui stabilise enormement
// le temps de resolution (P99/P50 passe de ~10x a ~2x).
//
// Reglages cibles : ~1-3s sur tous devices.
//   N = 16, K = 16 -> 16 * 65536 = ~1.05M hashs en moyenne (equivalent a
//   l'ancien single-challenge a 20 bits, mais avec variance divisee par 4).
if (!defined('POW_SUBCHALLENGES'))   define('POW_SUBCHALLENGES', 16);   // N
if (!defined('POW_SUB_DIFFICULTY'))  define('POW_SUB_DIFFICULTY', 16);  // K bits / sub

// Garde-fous serveur anti-DoS et anti-downgrade.
if (!defined('POW_MAX_SUBCHALLENGES')) define('POW_MAX_SUBCHALLENGES', 64);
if (!defined('POW_MAX_SUB_DIFFICULTY')) define('POW_MAX_SUB_DIFFICULTY', 30);

// Alias legacy (certains integrateurs pouvaient lire POW_DIFFICULTY).
if (!defined('POW_DIFFICULTY'))    define('POW_DIFFICULTY', POW_SUB_DIFFICULTY);

// Duree de validite d'un challenge emis (secondes).
if (!defined('POW_CHALLENGE_TTL')) define('POW_CHALLENGE_TTL', 30);

// Duree de validite du cookie apres resolution (secondes). 30 minutes par defaut.
if (!defined('POW_COOKIE_TTL'))    define('POW_COOKIE_TTL', 1800);

// Nom du cookie de session captcha.
if (!defined('POW_COOKIE_NAME'))   define('POW_COOKIE_NAME', '__pow_token');

// Liste de bots legitimes : mot-cle dans l'User-Agent (lowercase) => suffixes rDNS autorises.
if (!defined('POW_BOT_KEYWORDS_DEFINED')) {
    define('POW_BOT_KEYWORDS_DEFINED', true);
    $GLOBALS['POW_BOT_KEYWORDS'] = [
        'googlebot'           => ['.googlebot.com', '.google.com'],
        'google-inspectiontool' => ['.googlebot.com', '.google.com'],
        'adsbot-google'       => ['.googlebot.com', '.google.com'],
        'mediapartners-google'=> ['.googlebot.com', '.google.com'],
        'bingbot'             => ['.search.msn.com'],
        'msnbot'              => ['.search.msn.com'],
        'qwantbot'            => ['.qwant.com'],
        'duckduckbot'         => ['.duckduckgo.com', '.duckduckbot.com'],
        'yandexbot'           => ['.yandex.ru', '.yandex.net', '.yandex.com'],
        'yandeximages'        => ['.yandex.ru', '.yandex.net', '.yandex.com'],
        'applebot'            => ['.applebot.apple.com', '.apple.com'],
        'facebookexternalhit' => ['.facebook.com', '.tfbnw.net'],
        'meta-externalagent'  => ['.facebook.com', '.tfbnw.net'],
        'twitterbot'          => ['.twttr.com', '.twitter.com'],
        'linkedinbot'         => ['.linkedin.com'],
        'petalbot'            => ['.petalsearch.com', '.aspiegel.com', '.huawei.com'],
        'baiduspider'         => ['.baidu.com', '.baidu.jp'],
        'sogou'               => ['.sogou.com'],
    ];
}

// Liste de patterns d'URL exclus de la protection (fnmatch style).
// Exemple : '/assets/*', '/favicon.ico', '/api/public/*'
if (!defined('POW_EXCLUDE_PATHS_DEFINED')) {
    define('POW_EXCLUDE_PATHS_DEFINED', true);
    $GLOBALS['POW_EXCLUDE_PATHS'] = [
      
    ];
}

// Whitelist d'IP / CIDR (IPv4 et IPv6). Exemples :
//   '203.0.113.42'         (IPv4 exacte)
//   '198.51.100.0/24'      (CIDR IPv4)
//   '2001:db8::1'          (IPv6 exacte)
//   '2001:db8::/32'        (CIDR IPv6)
if (!defined('POW_IP_WHITELIST_DEFINED')) {
    define('POW_IP_WHITELIST_DEFINED', true);
    $GLOBALS['POW_IP_WHITELIST'] = [
        // '127.0.0.1',
        // '::1',
        // '10.0.0.0/8',
    ];
}

// ============================================================================
// HELPERS
// ============================================================================

/**
 * IP reelle du client (REMOTE_ADDR uniquement, par securite).
 */
function pow_client_ip() {
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

/**
 * User-Agent du client.
 */
function pow_client_ua() {
    return isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
}

/**
 * Host de la requete.
 */
function pow_request_host() {
    return isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
}

/**
 * Empreinte client : hash de IP + UA.
 */
function pow_client_fingerprint() {
    return hash('sha256', pow_client_ip() . '|' . pow_client_ua());
}

/**
 * Signature HMAC-SHA256 du payload.
 */
function pow_sign($payload) {
    return hash_hmac('sha256', $payload, POW_SECRET);
}

/**
 * Verification signature en temps constant.
 */
function pow_verify_sig($payload, $sig) {
    if (!is_string($sig) || strlen($sig) !== 64) return false;
    $expected = pow_sign($payload);
    return hash_equals($expected, $sig);
}

/**
 * Encodage base64url.
 */
function pow_b64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function pow_b64url_decode($data) {
    $pad = strlen($data) % 4;
    if ($pad) $data .= str_repeat('=', 4 - $pad);
    return base64_decode(strtr($data, '-_', '+/'));
}

/**
 * La requete cible-t-elle un chemin exclu ?
 */
function pow_path_excluded() {
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
    $path = parse_url($uri, PHP_URL_PATH);
    if (!$path) $path = '/';
    $patterns = isset($GLOBALS['POW_EXCLUDE_PATHS']) ? $GLOBALS['POW_EXCLUDE_PATHS'] : [];
    foreach ($patterns as $pat) {
        if (fnmatch($pat, $path)) return true;
    }
    return false;
}

/**
 * Verifie si une IP (v4 ou v6) appartient a un CIDR ou correspond a une IP exacte.
 */
function pow_ip_in_range($ip, $range) {
    if (strpos($range, '/') === false) {
        // IP exacte : compare les formes binaires (normalise IPv6)
        $a = @inet_pton($ip);
        $b = @inet_pton($range);
        if ($a === false || $b === false) return false;
        return hash_equals($a, $b);
    }
    list($subnet, $prefix) = explode('/', $range, 2);
    $prefix = intval($prefix);
    $sub = @inet_pton($subnet);
    $cli = @inet_pton($ip);
    if ($sub === false || $cli === false) return false;
    if (strlen($sub) !== strlen($cli)) return false; // v4 vs v6 mismatch

    $bits_total = strlen($sub) * 8;
    if ($prefix < 0 || $prefix > $bits_total) return false;

    $full_bytes = intdiv($prefix, 8);
    $rem_bits   = $prefix % 8;

    if ($full_bytes > 0 && substr($sub, 0, $full_bytes) !== substr($cli, 0, $full_bytes)) {
        return false;
    }
    if ($rem_bits > 0) {
        $mask = 0xFF << (8 - $rem_bits) & 0xFF;
        if ((ord($sub[$full_bytes]) & $mask) !== (ord($cli[$full_bytes]) & $mask)) {
            return false;
        }
    }
    return true;
}

/**
 * L'IP du client est-elle whitelistee ?
 */
function pow_ip_whitelisted() {
    $ip = pow_client_ip();
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    $list = isset($GLOBALS['POW_IP_WHITELIST']) ? $GLOBALS['POW_IP_WHITELIST'] : [];
    foreach ($list as $entry) {
        if (pow_ip_in_range($ip, $entry)) return true;
    }
    return false;
}

/**
 * Detection HTTPS.
 */
function pow_is_https() {
    if (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') return true;
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') return true;
    if (!empty($_SERVER['SERVER_PORT']) && intval($_SERVER['SERVER_PORT']) === 443) return true;
    return false;
}

// ============================================================================
// COOKIE : verification & emission
// ============================================================================

/**
 * Verifie que le client possede un cookie captcha valide.
 */
function pow_check_cookie() {
    if (empty($_COOKIE[POW_COOKIE_NAME])) return false;
    $raw = $_COOKIE[POW_COOKIE_NAME];

    $parts = explode('.', $raw, 2);
    if (count($parts) !== 2) return false;
    list($payload_b64, $sig_b64) = $parts;

    $payload = pow_b64url_decode($payload_b64);
    $sig     = pow_b64url_decode($sig_b64);
    if ($payload === false || $sig === false || $sig === '') return false;

    $expected = hash_hmac('sha256', $payload, POW_SECRET, true);
    if (!hash_equals($expected, $sig)) return false;

    // payload : host|fingerprint|expiration
    $fields = explode('|', $payload);
    if (count($fields) !== 3) return false;
    list($host, $fp, $exp) = $fields;

    if ($host !== pow_request_host()) return false;
    if (!hash_equals(pow_client_fingerprint(), $fp)) return false;
    if (intval($exp) < time()) return false;

    return true;
}

/**
 * Emet le cookie signe apres resolution du captcha.
 */
function pow_issue_cookie() {
    $exp = time() + POW_COOKIE_TTL;
    $payload = pow_request_host() . '|' . pow_client_fingerprint() . '|' . $exp;
    $sig = hash_hmac('sha256', $payload, POW_SECRET, true);
    $value = pow_b64url_encode($payload) . '.' . pow_b64url_encode($sig);

    $params = [
        'expires'  => $exp,
        'path'     => '/',
        'secure'   => pow_is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ];
    if (PHP_VERSION_ID >= 70300) {
        setcookie(POW_COOKIE_NAME, $value, $params);
    } else {
        setcookie(POW_COOKIE_NAME, $value, $exp, '/; SameSite=Lax', '', pow_is_https(), true);
    }
}

// ============================================================================
// BOTS LEGITIMES
// ============================================================================

/**
 * Retourne true si l'UA match un bot legitime ET que rDNS + forward DNS valident.
 */
function pow_is_legitimate_bot() {
    $ua = strtolower(pow_client_ua());
    if ($ua === '') return false;

    $keywords = isset($GLOBALS['POW_BOT_KEYWORDS']) ? $GLOBALS['POW_BOT_KEYWORDS'] : [];
    $allowed_suffixes = null;
    foreach ($keywords as $kw => $suffixes) {
        if (strpos($ua, $kw) !== false) {
            $allowed_suffixes = $suffixes;
            break;
        }
    }
    if ($allowed_suffixes === null) return false;

    $ip = pow_client_ip();
    $rdns = @gethostbyaddr($ip);
    if (!$rdns || $rdns === $ip) return false;

    $rdns_l = strtolower(rtrim($rdns, '.'));
    $suffix_ok = false;
    foreach ($allowed_suffixes as $suf) {
        $suf_l = strtolower($suf);
        // suffixe type ".googlebot.com" -> accepte "foo.googlebot.com" mais pas "evilgooglebot.com"
        $needle = ltrim($suf_l, '.');
        if ($rdns_l === $needle) { $suffix_ok = true; break; }
        if (substr($rdns_l, -strlen('.' . $needle)) === '.' . $needle) { $suffix_ok = true; break; }
    }
    if (!$suffix_ok) return false;

    // Forward DNS : l'IP doit figurer dans les enregistrements A/AAAA du rDNS.
    $ips = @gethostbynamel($rdns);
    if (is_array($ips) && in_array($ip, $ips, true)) return true;

    // Fallback IPv6 / exhaustif via dns_get_record
    $records = @dns_get_record($rdns, DNS_A | DNS_AAAA);
    if (is_array($records)) {
        foreach ($records as $r) {
            if (!empty($r['ip']) && $r['ip'] === $ip)   return true;
            if (!empty($r['ipv6']) && $r['ipv6'] === $ip) return true;
        }
    }

    return false;
}

// ============================================================================
// VERIFICATION SOLUTION POW
// ============================================================================

/**
 * Retourne true si le hash binaire $hash commence par $bits bits a 0.
 */
function pow_has_leading_zero_bits($hash, $bits) {
    $full_bytes = intdiv($bits, 8);
    $rem_bits   = $bits % 8;
    if (strlen($hash) < $full_bytes + ($rem_bits ? 1 : 0)) return false;
    for ($i = 0; $i < $full_bytes; $i++) {
        if (ord($hash[$i]) !== 0) return false;
    }
    if ($rem_bits > 0) {
        $mask = 0xFF << (8 - $rem_bits) & 0xFF;
        if ((ord($hash[$full_bytes]) & $mask) !== 0) return false;
    }
    return true;
}

/**
 * Verifie une solution soumise (POST) et emet le cookie si valide.
 * Retourne true si la solution est acceptee.
 *
 * Protocole multi-sous-challenges :
 *   Le client fournit N nonces resolvant chacun un sous-challenge independant.
 *   Le i-eme sous-challenge est considere resolu si
 *     SHA-256(challenge . ":" . i . ":" . nonce_i)
 *   a K bits de poids fort a zero, ou K = pow_sub_difficulty.
 */
function pow_verify_pow_solution() {
    $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '';
    if ($method !== 'POST') return false;

    if (empty($_POST['pow_challenge']) || empty($_POST['pow_ts']) ||
        empty($_POST['pow_sig']) || !isset($_POST['pow_nonces']) ||
        empty($_POST['pow_sub_count']) || empty($_POST['pow_sub_difficulty'])) {
        return false;
    }

    $challenge       = (string)$_POST['pow_challenge'];
    $ts              = (string)$_POST['pow_ts'];
    $sub_count       = (string)$_POST['pow_sub_count'];
    $sub_difficulty  = (string)$_POST['pow_sub_difficulty'];
    $sig             = (string)$_POST['pow_sig'];
    $nonces_raw      = (string)$_POST['pow_nonces'];

    // Format basique
    if (!ctype_xdigit($challenge) || !ctype_digit($ts) ||
        !ctype_digit($sub_count) || !ctype_digit($sub_difficulty)) return false;
    if (strlen($challenge) < 16 || strlen($challenge) > 128) return false;

    // Signature liee au fingerprint (inclut N et K pour empecher tout tampering).
    $payload = $challenge . '|' . $ts . '|' . $sub_count . '|' . $sub_difficulty . '|' . pow_client_fingerprint();
    if (!pow_verify_sig($payload, $sig)) return false;

    // TTL
    $ts_i = intval($ts);
    if (abs(time() - $ts_i) > POW_CHALLENGE_TTL) return false;

    // Bornes : empeche downgrade (client qui aurait change N ou K malgre la
    // signature, cas theoriquement impossible car signe) et DoS serveur.
    $N = intval($sub_count);
    $K = intval($sub_difficulty);
    if ($N < POW_SUBCHALLENGES || $N > POW_MAX_SUBCHALLENGES) return false;
    if ($K < POW_SUB_DIFFICULTY || $K > POW_MAX_SUB_DIFFICULTY) return false;

    // Travail total minimum : N * 2^K >= config * 2^config (defense de
    // profondeur supplementaire au cas ou N/K seraient tunes).
    $target_work = POW_SUBCHALLENGES * (1 << POW_SUB_DIFFICULTY);
    $given_work  = $N * (1 << $K);
    if ($given_work < $target_work) return false;

    // Parse nonces : "n0,n1,...,n(N-1)"
    $nonces = explode(',', $nonces_raw);
    if (count($nonces) !== $N) return false;

    $seen = [];
    for ($i = 0; $i < $N; $i++) {
        $n = $nonces[$i];
        // Format : entier decimal non signe, longueur raisonnable pour
        // eviter un DoS de hash sur chaine enorme.
        if (!ctype_digit($n) || strlen($n) > 20) return false;

        // Unicite : empeche l'astuce consistant a reutiliser le meme nonce
        // pour tous les sous-challenges (ce qui retomberait sur une loterie
        // unique et annulerait le gain de variance).
        if (isset($seen[$n])) return false;
        $seen[$n] = true;

        $hash = hash('sha256', $challenge . ':' . $i . ':' . $n, true);
        if (!pow_has_leading_zero_bits($hash, $K)) return false;
    }

    return true;
}

// ============================================================================
// PAGE CAPTCHA
// ============================================================================

/**
 * Genere et renvoie la page HTML de challenge PoW, puis exit.
 */
function pow_render_challenge_page() {
    $challenge  = bin2hex(random_bytes(16));
    $ts         = time();
    $N          = POW_SUBCHALLENGES;
    $K          = POW_SUB_DIFFICULTY;
    $payload    = $challenge . '|' . $ts . '|' . $N . '|' . $K . '|' . pow_client_fingerprint();
    $sig        = pow_sign($payload);

    $self = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
    $self_attr = htmlspecialchars($self, ENT_QUOTES, 'UTF-8');

    // Headers anti-cache + securite
    if (!headers_sent()) {
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('X-Robots-Tag: noindex, nofollow');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
    }

    $c_js   = json_encode($challenge);
    $ts_js  = json_encode((string)$ts);
    $sig_js = json_encode($sig);
    $n_js   = json_encode((int)$N);
    $k_js   = json_encode((int)$K);

    ?><!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<link rel="icon" type="image/png" href="https://cdn.thbl.fr/favicon.png">
<title>Vérification de sécurité</title>
<style>
  :root {
    --bg: #0b0b0d;
    --bg-soft: #111114;
    --text: #ececee;
    --muted: #a1a1aa;
    --muted-2: #71717a;
    --border: #1f1f23;
    --border-strong: #2a2a30;
    --accent: #ff7a1a;
    --accent-2: #ffa057;
    --accent-dim: rgba(255, 122, 26, 0.12);
    --accent-ring: rgba(255, 122, 26, 0.28);
    --track: #26262b;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0;
    min-height: 100%;
    background: var(--bg);
    color: var(--text);
    font-family: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
  }
  body {
    min-height: 100vh;
    position: relative;
    overflow-x: hidden;
    background:
      radial-gradient(1100px 700px at 85% -10%, rgba(255,122,26,0.09), transparent 60%),
      radial-gradient(900px 600px at -10% 110%, rgba(255,122,26,0.06), transparent 60%),
      linear-gradient(180deg, var(--bg) 0%, #0d0d10 100%);
  }
  /* Grille fine en fond pour texture */
  body::before {
    content: "";
    position: fixed; inset: 0;
    pointer-events: none;
    background-image:
      linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px);
    background-size: 56px 56px;
    mask-image: radial-gradient(ellipse at 50% 40%, #000 30%, transparent 75%);
    -webkit-mask-image: radial-gradient(ellipse at 50% 40%, #000 30%, transparent 75%);
    z-index: 0;
  }

  .page {
    position: relative;
    z-index: 1;
    min-height: 100vh;
    display: grid;
    grid-template-rows: auto 1fr auto;
  }

  /* Header top */
  .topbar {
    padding: 22px 32px;
    display: flex; align-items: center; gap: 12px;
  }
  .topbar .logo {
    width: 28px; height: 28px;
    border-radius: 6px;
    object-fit: contain;
  }
  .topbar .wordmark {
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.02em;
    color: var(--text);
  }
  .topbar .dot {
    width: 6px; height: 6px; border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 10px var(--accent-ring);
    margin-left: 2px;
  }

  /* Contenu central pleine page */
  .main {
    padding: 24px 32px 48px;
    display: flex; align-items: center; justify-content: center;
  }
  .content {
    width: 100%;
    max-width: 1080px;
    display: grid;
    grid-template-columns: minmax(0, 1.05fr) minmax(0, 1fr);
    gap: 72px;
    align-items: center;
  }

  /* Colonne gauche : texte principal */
  .lead-col .eyebrow {
    display: inline-flex; align-items: center; gap: 8px;
    font-size: 11px; font-weight: 600;
    letter-spacing: 0.22em; text-transform: uppercase;
    color: var(--accent);
    padding: 6px 10px;
    border: 1px solid var(--accent-ring);
    background: var(--accent-dim);
    border-radius: 999px;
    margin-bottom: 24px;
  }
  .lead-col .eyebrow .pulse {
    width: 6px; height: 6px; border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 0 0 var(--accent-ring);
    animation: pow-pulse 1.6s ease-out infinite;
  }
  @keyframes pow-pulse {
    0%   { box-shadow: 0 0 0 0 rgba(255,122,26,0.5); }
    100% { box-shadow: 0 0 0 10px rgba(255,122,26,0); }
  }

  .lead-col h1 {
    font-size: clamp(32px, 4.4vw, 52px);
    line-height: 1.05;
    font-weight: 700;
    letter-spacing: -0.025em;
    margin: 0 0 18px 0;
  }
  .lead-col h1 .accent {
    background: linear-gradient(180deg, var(--accent) 0%, var(--accent-2) 100%);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }
  .lead-col p.lead {
    color: var(--muted);
    font-size: 16px;
    line-height: 1.65;
    margin: 0 0 32px 0;
    max-width: 56ch;
  }

  .features {
    list-style: none;
    padding: 0; margin: 0;
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 18px 28px;
  }
  .features li {
    display: flex; gap: 12px; align-items: flex-start;
  }
  .features .ic {
    flex: 0 0 32px;
    width: 32px; height: 32px;
    border-radius: 9px;
    background: var(--accent-dim);
    color: var(--accent);
    display: flex; align-items: center; justify-content: center;
    border: 1px solid var(--accent-ring);
  }
  .features .ic svg { width: 15px; height: 15px; }
  .features .txt strong {
    display: block;
    font-size: 14px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 3px;
    letter-spacing: -0.005em;
  }
  .features .txt span {
    font-size: 13px;
    color: var(--muted);
    line-height: 1.55;
  }

  /* Colonne droite : spinner + statut */
  .verify-col {
    display: flex; flex-direction: column; align-items: center;
    justify-content: center;
    padding: 24px 0;
  }
  .orb {
    position: relative;
    width: 220px; height: 220px;
    display: flex; align-items: center; justify-content: center;
  }
  .orb::before, .orb::after {
    content: "";
    position: absolute; inset: 0;
    border-radius: 50%;
    border: 1px solid var(--border-strong);
  }
  .orb::before {
    inset: 0;
    background: radial-gradient(circle at 50% 40%, rgba(255,122,26,0.10), transparent 65%);
  }
  .orb::after {
    inset: 22px;
    border-color: var(--border);
  }
  .spinner {
    position: relative;
    width: 110px; height: 110px;
    border: 3px solid var(--track);
    border-top-color: var(--accent);
    border-right-color: var(--accent);
    border-radius: 50%;
    animation: pow-spin 1s linear infinite;
    box-shadow: 0 0 24px rgba(255,122,26,0.22), inset 0 0 0 1px rgba(255,255,255,0.02);
  }
  @keyframes pow-spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) {
    .spinner { animation-duration: 2.6s; }
    .lead-col .eyebrow .pulse { animation: none; }
  }

  .verify-meta {
    margin-top: 28px;
    text-align: center;
  }
  .verify-meta .status {
    font-size: 14px;
    font-weight: 500;
    color: var(--text);
    margin-bottom: 4px;
    min-height: 20px;
  }
  .verify-meta .sub {
    font-size: 12.5px;
    color: var(--muted-2);
  }
  .verify-meta .progress-wrap {
    margin: 14px auto 6px;
    width: 220px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
  }
  .verify-meta .progress-track {
    width: 100%;
    height: 6px;
    background: var(--track);
    border-radius: 999px;
    overflow: hidden;
    position: relative;
  }
  .verify-meta .progress-bar {
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, var(--accent) 0%, var(--accent-2) 100%);
    border-radius: 999px;
    transition: width .35s cubic-bezier(.22,.61,.36,1);
    box-shadow: 0 0 12px rgba(255,122,26,0.35);
  }
  .verify-meta .progress-label {
    font-size: 11.5px;
    color: var(--muted-2);
    font-variant-numeric: tabular-nums;
    letter-spacing: 0.04em;
  }
  .verify-meta .err {
    color: #f87171;
    font-size: 13px;
    margin-top: 8px;
    display: none;
  }

  /* Footer */
  .footer {
    padding: 22px 32px 28px;
    display: flex; align-items: center; justify-content: space-between;
    gap: 16px;
    border-top: 1px solid var(--border);
    color: var(--muted-2);
    font-size: 12px;
  }
  .footer .right { display: flex; align-items: center; gap: 14px; }
  .footer a { color: var(--muted); text-decoration: none; }
  .footer a:hover { color: var(--text); }

  noscript {
    display: block;
    margin-top: 16px;
    padding: 12px 14px;
    border: 1px solid var(--border-strong);
    border-radius: 10px;
    background: var(--bg-soft);
    color: var(--muted);
    font-size: 13px;
    max-width: 360px;
  }

  /* Responsive */
  @media (max-width: 900px) {
    .content {
      grid-template-columns: 1fr;
      gap: 24px;
      min-height: calc(100vh - 180px);
      place-items: center;
    }
    /* On masque completement la colonne d'explications sur mobile */
    .lead-col { display: none; }
    .verify-col { padding: 0; }
    .topbar { padding: 18px 20px; }
    .main   { padding: 16px 20px 24px; }
    .footer {
      padding: 16px 20px;
      flex-direction: column;
      align-items: center;
      text-align: center;
      gap: 6px;
    }
    .footer .right { flex-wrap: wrap; justify-content: center; }
    .orb    { width: 180px; height: 180px; }
    .spinner{ width: 90px; height: 90px; }
    .verify-meta { margin-top: 24px; }
    .verify-meta .status {
      font-size: 18px;
      font-weight: 600;
      letter-spacing: -0.01em;
    }
    .verify-meta .sub {
      font-size: 13px;
      margin-top: 4px;
    }
  }
</style>
</head>
<body>
  <div class="page">
    <header class="topbar">
      <img class="logo" src="https://cdn.thbl.fr/favicon.png" alt="" aria-hidden="true">
      <span class="wordmark">Vérification de sécurité<span class="dot" aria-hidden="true"></span></span>
    </header>

    <main class="main" role="main">
      <div class="content">
        <section class="lead-col">
          <span class="eyebrow"><span class="pulse" aria-hidden="true"></span>Sécurité</span>
          <h1>Un instant, on <span class="accent">vérifie votre navigateur</span>.</h1>
          <p class="lead">
            Ce site utilise un captcha automatique base sur une preuve de travail (Proof of Work).
            Votre navigateur resout un petit defi cryptographique pendant quelques secondes.
            Aucune case à cocher, aucune image à identifier, aucune donnée personnelle collectée.
          </p>

          <ul class="features">
            <li>
              <span class="ic" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"></path></svg>
              </span>
              <span class="txt">
                <strong>Protection anti-abus</strong>
                <span>Bloque bots malveillants, scrapers et attaques automatisées.</span>
              </span>
            </li>
            <li>
              <span class="ic" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path></svg>
              </span>
              <span class="txt">
                <strong>Totalement automatique</strong>
                <span>Quelques secondes de calcul. Aucune interaction requise.</span>
              </span>
            </li>
            <li>
              <span class="ic" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1l3 5 5 1-4 4 1 6-5-3-5 3 1-6-4-4 5-1z"></path></svg>
              </span>
              <span class="txt">
                <strong>Respect de la vie privée</strong>
                <span>Aucun tracking ni service externe. Tout s'execute localement.</span>
              </span>
            </li>
            <li>
              <span class="ic" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"></path></svg>
              </span>
              <span class="txt">
                <strong>Une seule fois</strong>
                <span>Valide pendant 30 minutes sur l'ensemble du site.</span>
              </span>
            </li>
          </ul>
        </section>

        <section class="verify-col">
          <div class="orb" aria-hidden="true">
            <div class="spinner"></div>
          </div>
          <div class="verify-meta">
            <div class="status" id="pow-status">Vérification en cours...</div>
            <div class="progress-wrap" aria-hidden="true">
              <div class="progress-track">
                <div class="progress-bar" id="pow-progress-bar"></div>
              </div>
              <div class="progress-label" id="pow-progress-label">0 / <?php echo (int)$N; ?></div>
            </div>
            <div class="sub">Ne fermez pas cet onglet.</div>
            <div class="err" id="pow-err">Échec de la vérification. Rechargez la page.</div>
            <noscript>JavaScript est requis pour valider cette vérification. Veuillez l'activer puis recharger la page.</noscript>
          </div>

          <form id="pow-form" method="POST" action="<?php echo $self_attr; ?>" style="display:none">
            <input type="hidden" name="pow_challenge"       value="<?php echo htmlspecialchars($challenge, ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="pow_ts"              value="<?php echo (int)$ts; ?>">
            <input type="hidden" name="pow_sub_count"       value="<?php echo (int)$N; ?>">
            <input type="hidden" name="pow_sub_difficulty"  value="<?php echo (int)$K; ?>">
            <input type="hidden" name="pow_sig"             value="<?php echo htmlspecialchars($sig, ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="pow_nonces"          id="pow-nonces" value="">
          </form>
        </section>
      </div>
    </main>

    <footer class="footer">
      <div class="left">Si la vérification ne se termine pas, rechargez la page.</div>
      <div class="right">
        <span>Proof of Work</span>
        <span>&middot;</span>
        <span><?php echo htmlspecialchars(pow_request_host(), ENT_QUOTES, 'UTF-8'); ?></span>
      </div>
    </footer>
  </div>

<script>
(function () {
  var CHALLENGE   = <?php echo $c_js; ?>;
  var TS          = <?php echo $ts_js; ?>;
  var SIG         = <?php echo $sig_js; ?>;
  var SUB_COUNT   = <?php echo $n_js; ?>;
  var DIFFICULTY  = <?php echo $k_js; ?>;

  var statusEl   = document.getElementById('pow-status');
  var errEl      = document.getElementById('pow-err');
  var form       = document.getElementById('pow-form');
  var noncesEl   = document.getElementById('pow-nonces');
  var barEl      = document.getElementById('pow-progress-bar');
  var labelEl    = document.getElementById('pow-progress-label');

  function fail(msg) {
    statusEl.style.display = 'none';
    errEl.textContent = msg || 'Échec de la vérification. Rechargez la page.';
    errEl.style.display = 'block';
  }

  if (!window.Worker || !window.crypto || !crypto.subtle) {
    fail('Votre navigateur ne supporte pas la vérification cryptographique.');
    return;
  }

  // -------------------------------------------------------------------------
  // Worker : resout UN sous-challenge a la fois.
  //   in  : { challenge, subIndex, difficulty, nonceOffset }
  //   out : { type:"done", subIndex, nonce }
  //
  // Chaque worker part d'un offset different pour garantir l'unicite des
  // nonces entre sous-challenges (requis par le serveur pour empecher
  // l'astuce du nonce unique reutilise sur tous les slots).
  // -------------------------------------------------------------------------
  var workerCode = [
    'self.onmessage = async function (e) {',
    '  var challenge  = e.data.challenge;',
    '  var subIndex   = e.data.subIndex;',
    '  var difficulty = e.data.difficulty;',
    '  var nonce      = +e.data.nonceOffset || 0;',
    '  var fullBytes  = (difficulty / 8) | 0;',
    '  var remBits    = difficulty % 8;',
    '  var mask       = remBits ? (0xFF << (8 - remBits)) & 0xFF : 0;',
    '  var enc        = new TextEncoder();',
    '  var prefix     = challenge + ":" + subIndex + ":";',
    '  while (true) {',
    '    for (var i = 0; i < 500; i++) {',
    '      var buf = await crypto.subtle.digest("SHA-256", enc.encode(prefix + nonce));',
    '      var h = new Uint8Array(buf);',
    '      var ok = true;',
    '      for (var b = 0; b < fullBytes; b++) { if (h[b] !== 0) { ok = false; break; } }',
    '      if (ok && remBits > 0) { if ((h[fullBytes] & mask) !== 0) ok = false; }',
    '      if (ok) { self.postMessage({ type: "done", subIndex: subIndex, nonce: String(nonce) }); return; }',
    '      nonce++;',
    '    }',
    '  }',
    '};'
  ].join('\n');

  var blob    = new Blob([workerCode], { type: 'application/javascript' });
  var blobUrl = URL.createObjectURL(blob);

  // Pool de workers : au plus SUB_COUNT, au moins 2, jamais plus que
  // hardwareConcurrency - 1 (laisse un core pour l'UI).
  var hw = navigator.hardwareConcurrency || 4;
  var poolSize = Math.max(2, Math.min(SUB_COUNT, hw - 1));

  // File d'attente des sous-challenges a assigner.
  var pending = [];
  for (var i = 0; i < SUB_COUNT; i++) pending.push(i);

  var nonces    = new Array(SUB_COUNT);
  var done      = 0;
  var finished  = false;
  var workers   = [];

  // Chaque worker demarre sur une plage de nonces disjointe pour garantir
  // l'unicite globale (requise par le serveur). 2^42 espace largement
  // suffisant par sous-challenge a K=17.
  // On espace les offsets de 2^40 entre workers pour qu'il n'y ait aucune
  // chance de collision en pratique.
  var OFFSET_STEP = Math.pow(2, 40);

  function updateProgress() {
    var pct = Math.round((done / SUB_COUNT) * 100);
    barEl.style.width = pct + '%';
    labelEl.textContent = done + ' / ' + SUB_COUNT;
  }

  function assignNext(worker) {
    if (pending.length === 0) {
      // Plus rien a faire pour ce worker : on le termine.
      try { worker.terminate(); } catch (_) {}
      return;
    }
    var subIndex    = pending.shift();
    // Offset unique par sous-challenge pour garantir l'unicite globale des
    // nonces (le serveur refuse les doublons). A K=17, chaque sous-challenge
    // teste ~131k nonces en moyenne, loin des 2^40 reserves par slot.
    var nonceOffset = subIndex * OFFSET_STEP;
    worker.postMessage({
      challenge:   CHALLENGE,
      subIndex:    subIndex,
      difficulty:  DIFFICULTY,
      nonceOffset: nonceOffset
    });
  }

  function onWorkerMessage(worker) {
    return function (ev) {
      if (finished) return;
      var d = ev.data || {};
      if (d.type !== 'done') return;
      if (nonces[d.subIndex] !== undefined) {
        // Slot deja rempli : on reassigne simplement le worker.
        assignNext(worker);
        return;
      }
      nonces[d.subIndex] = d.nonce;
      done++;
      updateProgress();

      if (done >= SUB_COUNT) {
        finished = true;
        // Terminate tous les workers restants.
        for (var j = 0; j < workers.length; j++) {
          try { workers[j].terminate(); } catch (_) {}
        }
        try { URL.revokeObjectURL(blobUrl); } catch (_) {}
        // Verification d'unicite cote client (le serveur refusera sinon).
        var seen = {};
        for (var k = 0; k < SUB_COUNT; k++) {
          if (seen[nonces[k]]) { fail('Collision de nonce, rechargez la page.'); return; }
          seen[nonces[k]] = true;
        }
        noncesEl.value = nonces.join(',');
        statusEl.textContent = 'Vérifié. Chargement...';
        barEl.style.width = '100%';
        form.submit();
        return;
      }
      assignNext(worker);
    };
  }

  function onWorkerError() { fail('Erreur pendant la vérification.'); }

  for (var w = 0; w < poolSize; w++) {
    var worker;
    try { worker = new Worker(blobUrl); }
    catch (ex) { fail('Impossible de démarrer la vérification.'); return; }
    worker.onmessage = onWorkerMessage(worker);
    worker.onerror   = onWorkerError;
    workers.push(worker);
    assignNext(worker);
  }

  updateProgress();
})();
</script>
</body>
</html><?php
    exit;
}

// ============================================================================
// POINT D'ENTREE
// ============================================================================

function pow_captcha_protect() {
    // 1. Chemin exclu ?
    if (pow_path_excluded()) return;

    // 2. IP whitelistee ?
    if (pow_ip_whitelisted()) return;

    // 3. Cookie valide ?
    if (pow_check_cookie()) return;

    // 4. Soumission d'une solution PoW (POST) ?
    $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '';
    if ($method === 'POST' && !empty($_POST['pow_challenge'])) {
        if (pow_verify_pow_solution()) {
            pow_issue_cookie();
            // Redirection GET vers la meme URL pour eviter le repost + nettoyer l'URL.
            $loc = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
            if (!headers_sent()) {
                header('Cache-Control: no-store');
                header('Location: ' . $loc, true, 303);
            }
            exit;
        }
        // solution invalide -> tombe sur l'affichage d'un nouveau challenge
    }

    // 5. Bot legitime ?
    if (pow_is_legitimate_bot()) return;

    // 6. Sinon : challenge.
    pow_render_challenge_page();
}

pow_captcha_protect();
