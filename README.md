# L7 Anti-DDoS PHP

Protection automatique anti-DDoS niveau applicatif (L7) pour PHP, basée sur un **captcha Proof-of-Work**. Un seul fichier à inclure, aucune dépendance, aucun service externe, aucune base de données.

Pensé pour bloquer les bots malveillants, scrapers et floods HTTP tout en laissant passer les vrais utilisateurs **sans interaction** (pas de case à cocher, pas d'image à identifier).

## Sommaire

- [Fonctionnement](#fonctionnement)
- [Caractéristiques](#caractéristiques)
- [Installation](#installation)
- [Configuration](#configuration)
- [Bots légitimes supportés](#bots-légitimes-supportés)
- [Exclusion de chemins](#exclusion-de-chemins)
- [Whitelist d'IP](#whitelist-dip)
- [Détails techniques](#détails-techniques)
- [FAQ](#faq)
- [Licence](#licence)

## Fonctionnement

À chaque requête entrante, le script :

1. **Vérifie le chemin** : si l'URL correspond à un pattern exclu, la requête passe.
2. **Vérifie l'IP** : si l'IP est whitelistée (CIDR IPv4/IPv6 supportés), la requête passe.
3. **Vérifie le cookie** : si le client possède un cookie signé HMAC valide (lié à son `host`, `IP+UA` et durée de vie), la requête passe.
4. **Vérifie une éventuelle soumission PoW** (POST) : si les N nonces fournis résolvent les N sous-challenges, un cookie est émis et le client redirigé vers l'URL d'origine.
5. **Vérifie les bots légitimes** (Googlebot, Bingbot, etc.) via **rDNS + forward DNS** : si l'UA déclare un bot connu *et* que les enregistrements DNS valident l'IP, la requête passe.
6. **Sinon** : une page de vérification est servie. Le navigateur résout en quelques secondes un challenge cryptographique en arrière-plan (Web Workers + SubtleCrypto), puis soumet la solution automatiquement.

Une fois le challenge résolu, le cookie reste valide **30 minutes** par défaut sur l'ensemble du site.

## Caractéristiques

- **Fichier unique** (`pow_captcha.php`) — ~1100 lignes, zéro dépendance.
- **Pas de session, pas de base de données**, pas de Redis. Tout l'état tient dans un cookie signé HMAC-SHA256.
- **Captcha invisible** : page de vérification animée pendant 1–3 secondes, soumission automatique.
- **Multi-sous-challenges** (N=16 × K=16 bits par défaut) : variance de résolution **divisée par √N**, expérience stable sur tous les devices (P99/P50 ≈ 2x au lieu de 10x avec un challenge unique équivalent).
- **Multi-worker** : utilise `navigator.hardwareConcurrency - 1` Web Workers en parallèle.
- **Cookie lié au fingerprint** : `host + SHA-256(IP+UA) + expiration`, signé HMAC. Pas réutilisable cross-IP ni cross-domaine.
- **Validation des bots légitimes** : rDNS + forward DNS (la simple chaîne UA ne suffit pas, conformément aux recommandations Google/Bing).
- **Whitelist IP** avec support **CIDR IPv4 et IPv6**.
- **Exclusion de chemins** via patterns `fnmatch` (`/assets/*`, `/api/public/*`, etc.).
- **Anti-downgrade** : N et K sont signés côté serveur, le client ne peut pas réduire la difficulté.
- **Anti-tampering** : signature HMAC sur `challenge | timestamp | N | K | fingerprint`.
- **TTL court sur les challenges** (30 s par défaut) pour limiter la pré-calcul.
- **Unicité forcée des nonces** entre sous-challenges (empêche l'astuce du nonce unique réutilisé).
- Headers sécurisés : `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`.

## Installation

### 1. Inclure le fichier

Au tout début de vos pages PHP (avant tout `echo`, output ou `header()`) :

```php
<?php
require_once __DIR__ . '/pow_captcha.php';

// Reste de votre application...
```

### 2. Protection globale (recommandé)

Pour protéger l'intégralité du site, ajoutez à votre `.htaccess` (Apache) :

```apache
php_value auto_prepend_file "/chemin/absolu/vers/pow_captcha.php"
```

Ou dans `php.ini` / `php-fpm` :

```ini
auto_prepend_file = "/chemin/absolu/vers/pow_captcha.php"
```

### 3. Définir la clé secrète

**OBLIGATOIRE** avant la mise en production. Ouvrez `pow_captcha.php` et remplacez :

```php
define('POW_SECRET', 'clésecrete');
```

Par une chaîne aléatoire forte. Générez-la avec :

```bash
php -r "echo bin2hex(random_bytes(32));"
```

> **Important** : si vous changez `POW_SECRET`, tous les cookies déjà émis sont invalidés (chaque visiteur devra repasser le captcha une fois).

## Configuration

Toutes les constantes sont définies avec `if (!defined(...))`, ce qui permet de les surcharger **avant** l'inclusion du fichier :

```php
define('POW_SECRET',         'votre_clé_de_64_caractères');
define('POW_SUBCHALLENGES',  16);   // Nombre de sous-challenges (N)
define('POW_SUB_DIFFICULTY', 16);   // Difficulté par sous-challenge en bits (K)
define('POW_CHALLENGE_TTL',  30);   // Durée de validité d'un challenge émis (s)
define('POW_COOKIE_TTL',     1800); // Durée de validité du cookie (s), 30 min
define('POW_COOKIE_NAME',    '__pow_token');

require_once __DIR__ . '/pow_captcha.php';
```

### Réglage de la difficulté

Le travail moyen est de `N × 2^K` hashs SHA-256. Quelques repères :

| N  | K  | Travail moyen | Temps cible (desktop) |
|----|----|---------------|------------------------|
| 16 | 14 | ~262 k hashs  | ~0.5 s                 |
| 16 | 16 | ~1.05 M hashs | **~1–3 s** (défaut)    |
| 16 | 18 | ~4.2 M hashs  | ~5–10 s                |
| 32 | 16 | ~2.1 M hashs  | ~2–5 s, variance plus faible |

**Conseil** : augmentez `N` plutôt que `K` si vous voulez plus de stabilité. Augmentez `K` si vous voulez plus de difficulté.

Bornes de sécurité serveur (modifiables) :

```php
define('POW_MAX_SUBCHALLENGES',   64);
define('POW_MAX_SUB_DIFFICULTY',  30);
```

## Bots légitimes supportés

Détection par mot-clé UA + validation rDNS + forward DNS (les UA seuls ne sont **jamais** suffisants) :

- Googlebot (`googlebot`, `adsbot-google`, `mediapartners-google`, `google-inspectiontool`)
- Bingbot / MSNBot
- Qwantbot
- DuckDuckBot
- YandexBot / YandexImages
- AppleBot
- Facebook / Meta (`facebookexternalhit`, `meta-externalagent`)
- Twitterbot
- LinkedInBot
- PetalBot (Huawei)
- BaiduSpider
- Sogou

Pour ajouter un bot custom, éditez `$GLOBALS['POW_BOT_KEYWORDS']` dans `pow_captcha.php` :

```php
$GLOBALS['POW_BOT_KEYWORDS']['monbot'] = ['.exemple.com'];
```

## Exclusion de chemins

Pour exclure certaines routes (assets statiques, API publique, webhooks, etc.) :

```php
$GLOBALS['POW_EXCLUDE_PATHS'] = [
    '/assets/*',
    '/favicon.ico',
    '/robots.txt',
    '/api/public/*',
    '/webhook/stripe',
];
```

Les patterns utilisent `fnmatch` (`*` = wildcard, `?` = un caractère).

> **Attention** : excluez uniquement ce qui n'a pas besoin de protection. Plus l'exclusion est large, plus la surface d'attaque l'est aussi.

## Whitelist d'IP

Support IPv4 et IPv6, IP exactes ou plages CIDR :

```php
$GLOBALS['POW_IP_WHITELIST'] = [
    '127.0.0.1',
    '::1',
    '203.0.113.42',
    '198.51.100.0/24',
    '2001:db8::/32',
    '10.0.0.0/8',
];
```

## Détails techniques

### Protocole PoW

1. Le serveur émet un **challenge** = `bin2hex(random_bytes(16))` (128 bits aléatoires).
2. Il calcule `payload = challenge | ts | N | K | fingerprint(IP+UA)` et signe `sig = HMAC-SHA256(payload, POW_SECRET)`.
3. Le client doit fournir N nonces tels que pour chaque `i ∈ [0, N)` :
   ```
   SHA-256(challenge + ":" + i + ":" + nonce_i)
   ```
   commence par K bits à zéro, **et** que les N nonces soient tous distincts.
4. Le serveur revérifie `sig`, `ts` (anti-rejeu), les bornes `N/K`, calcule chaque hash et émet le cookie.

### Cookie

Format : `base64url(payload) . base64url(signature_binaire)`

- `payload` = `host | sha256(IP+UA) | expiration_unix`
- `signature` = `HMAC-SHA256(payload, POW_SECRET)` (32 octets bruts)
- Attributs : `HttpOnly`, `SameSite=Lax`, `Secure` si HTTPS détecté, `Path=/`

### Pourquoi multi-sous-challenges ?

Un challenge unique à 20 bits a un temps de résolution dont la variance suit une loi exponentielle (P99/P50 ≈ 6.6x, P99.9/P50 ≈ 10x). Avec N sous-challenges de K bits chacun, le temps total est une somme de N variables exponentielles, donc tend vers une gaussienne (variance relative divisée par √N).

**Résultat** : avec N=16, P99/P50 ≈ 2x au lieu de 10x. Les utilisateurs sur device lent ne sont plus piégés par la queue de distribution.

### Sécurité

- HMAC-SHA256 partout, comparaisons en temps constant (`hash_equals`).
- Pas de PHP session : aucun état serveur, aucun stockage à protéger.
- `REMOTE_ADDR` uniquement pour l'IP (jamais `X-Forwarded-For` côté client, donc impossible à spoofer par le client).
- Signature inclut `N` et `K` : empêche un client de soumettre une solution "facile" avec un challenge "dur".
- Bornes serveur `POW_MAX_*` : empêche un DoS par client soumettant des paramètres énormes.
- TTL court sur le challenge (30 s) : empêche la pré-résolution massive.
- Unicité des nonces : empêche le contournement par nonce constant.

### Limitations

- Requiert **JavaScript** et **`crypto.subtle`** côté client (disponible sur tous les navigateurs modernes, HTTPS requis pour `crypto.subtle` sur la plupart des contextes). Une page d'erreur explicite est affichée sinon.
- Si vous êtes derrière un proxy/CDN qui change `REMOTE_ADDR`, configurez-le pour exposer la vraie IP du client (sinon tous les visiteurs partageront la même IP du proxy).
- Le fingerprint inclut User-Agent : un changement d'UA force à repasser le captcha (rare en pratique).

## FAQ

**Le captcha s'affiche à chaque page, est-ce normal ?**
Non. Si le cookie est correctement émis, il reste valide 30 min. Vérifiez :
- Que `POW_SECRET` est défini et **stable** entre les requêtes.
- Que vous n'avez pas plusieurs serveurs avec des `POW_SECRET` différents derrière un load balancer (ils doivent tous partager la même clé).
- Que le cookie n'est pas bloqué par votre navigateur (mode privé strict, extensions).

**Comment changer le design de la page de vérification ?**
La page est dans la fonction `pow_render_challenge_page()` (CSS inline). Modifiez les variables CSS `--accent`, `--bg`, le logo (`<img src="...">`), le texte, etc.

**Comment réagir au passage du captcha côté serveur (logs, analytics) ?**
Ajoutez votre code dans `pow_verify_pow_solution()` juste avant `return true`, ou dans `pow_issue_cookie()`.

**Cela protège-t-il contre les DDoS volumétriques (L3/L4) ?**
Non. Ce module protège uniquement la **couche applicative (L7)**. Pour du volumétrique, utilisez un CDN/anti-DDoS en amont (Cloudflare, OVH Anti-DDoS, etc.).

**Compatible avec le cache HTTP (Varnish, Cloudflare) ?**
La page de challenge envoie `Cache-Control: no-store`. Les requêtes des visiteurs authentifiés portent le cookie `__pow_token` — configurez votre cache pour bypasser dès qu'il est présent, ou pour ne cacher que les chemins exclus.

## Licence

[MIT](LICENSE) — © 2026 Thibault Lapeyre
