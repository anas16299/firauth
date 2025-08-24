# FirAuth — JWT / Cookie Authentication for Multi‑Service Laravel

FirAuth provides a clean, extensible authentication layer for **multi‑service** Laravel setups:

-  **JWT (RS256 recommended)** — sign on the **main** service, verify on **consumer** services
-  **Cookie or Bearer transport** — HttpOnly cookie across subdomains, or `Authorization: Bearer`
-  **Single‑session via Redis** — `session_id` claim validated across services
-  **Pre / Post checkers** — plug custom gates (integration credentials, password reset, MFA, timezone, …)
-  **Drop‑in routes** — `/firauth/login`, `/firauth/refresh`, `/firauth/logout`
-  **Stateless on consumers** — `request()->user()` is built from JWT claims (no DB hit)

> Package namespace used below: **`cs/auth`** (PSR‑4 root: `Firauth\auth\`).  
> Adjust to your vendor/name if you publish under another vendor on Packagist.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
    - [Environment variables quick reference](#environment-variables-quick-reference)
    - [JWT (RS256 vs HS256)](#jwt-rs256-vs-hs256)
    - [Cookie transport](#cookie-transport)
    - [Redis session binding](#redis-session-binding)
    - [Routes toggles](#routes-toggles)
- [Quick Start](#quick-start)
    - [Main service](#main-service)
    - [Consumer services](#consumer-services)
- [Routes \u0026 Middlewares](#routes--middlewares)
- [Overriding *only* the Login action (best practice)](#overriding-only-the-login-action-best-practice)
- [Pre / Post Checkers](#pre--post-checkers)
- [Refresh Best Practice](#refresh-best-practice)
- [Logout Behavior](#logout-behavior)
- [Testing Recipes](#testing-recipes)
- [Postman Tips](#postman-tips)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
- [Optional Artisan Commands](#optional-artisan-commands)
- [License](#license)

---

## Requirements

- PHP 8.0+ (Laravel 8/9/10/11 supported)
- Redis (recommended for single‑session)
- [tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth) (used internally)
- OpenSSL if using RS256

---

## Installation

```bash
composer require anastosios/firauth

# Publish config
php artisan vendor:publish --tag=firauth-config

# Interactive setup (main vs consumer, cookie/jwt, keys, redis, etc.)
php artisan firauth:install
```

The installer will ask you:

- Is this the **MAIN** service? (issues tokens and exposes /firauth routes)
- Strategy: `cookie` (HttpOnly) or `jwt`
- Redis connection  TTL (seconds) for sessions
- JWT: **RS256** (preferred) or HS256, along with TTLs and key paths

> **Recommendation**: Use **RS256** for multi‑service ,  private key on main only, public key on consumers.

---

## Configuration

### Environment variables quick reference

```env
# Core
FIRAUTH_MAIN_SERVICE=true|false
FIRAUTH_STRATEGY=cookie|jwt

# Cookie
FIRAUTH_COOKIE_NAME=FIRAUTH_token
FIRAUTH_COOKIE_DOMAIN=.your-domain.com
FIRAUTH_COOKIE_SECURE=true
FIRAUTH_COOKIE_HTTP_ONLY=true
FIRAUTH_COOKIE_SAMESITE=Lax   # Lax|Strict|None (use None with HTTPS only)
FIRAUTH_COOKIE_LIFETIME=60    # minutes

# Redis session binding
FIRAUTH_SESSION_REDIS=session
FIRAUTH_SESSION_KEY_PREFIX=session_
FIRAUTH_SESSION_TTL=0         # 0=no expiry at Redis level

# JWT behavior
FIRAUTH_REMEMBER_DAYS=90
FIRAUTH_RENEW_WINDOW=600       # refresh only if <= 10m remaining (or expired)
FIRAUTH_USE_MODEL_CLAIMS=true  # use getJWTCustomClaims() from your User model
FIRAUTH_BIND_SESSION=false     # bind Redis session at login automatically

# Route options
FIRAUTH_ROUTES_PREFIX=firauth
FIRAUTH_ROUTES_EXPOSE_LOGIN=true
FIRAUTH_ROUTES_EXPOSE_REFRESH=true
FIRAUTH_ROUTES_EXPOSE_LOGOUT=true

# JWT (tymon)
JWT_ALGO=RS256              # RS256 recommended (or HS256)
JWT_TTL=60                  # minutes
JWT_REFRESH_TTL=20160       # minutes (14 days)
JWT_BLACKLIST_ENABLED=true
JWT_BLACKLIST_GRACE_PERIOD=30
JWT_PASSPHRASE=             # if your private key is encrypted

# For RS256
JWT_PUBLIC_KEY="file:///absolute/path/to/public.pem"
JWT_PRIVATE_KEY="file:///absolute/path/to/private.pem"

# For HS256 (alternative)
JWT_SECRET=change_me_please
```

> **Tip:** For local dev cookie tests, map a host in `/etc/hosts` (e.g., `127.0.0.1 api.your-domain.test`) and use `FIRAUTH_COOKIE_DOMAIN=.your-domain.test` so the browser/Postman attaches cookies correctly.

### JWT (RS256 vs HS256)

- **RS256** (recommended): sign with **private key** on the main service; verify with **public key** on all consumers. Keys are read via `file://` URIs.
- **HS256**: shared secret across services (simpler but less ideal for multi‑service separation).

### Cookie transport

When `FIRAUTH_STRATEGY=cookie` the package sets an `HttpOnly` cookie named `firauth_token`. Configure domain/samesite/secure flags in config/env. Consumers under subdomains will automatically receive the cookie.

> The middleware prefers the cookie in cookie strategy; otherwise it falls back to the `Authorization: Bearer` header.

### Redis session binding

Single‑session across services is enforced by a `session_id` claim bound to Redis:

- On login, a `session_id` is included in the JWT (either from your `getJWTCustomClaims()` or generated).
- Middleware validates `session_id` against Redis (`FIRAUTH_SESSION_REDIS`  `FIRAUTH_SESSION_KEY_PREFIX`).
- Logout revokes the Redis entry and blacklists the token.

### Routes toggles

You can selectively expose package routes:

```env
FIRAUTH_ROUTES_EXPOSE_LOGIN=true|false
FIRAUTH_ROUTES_EXPOSE_REFRESH=true|false
FIRAUTH_ROUTES_EXPOSE_LOGOUT=true|false
```

Disable only login to override it in your app while keeping refresh/logout from the package.

---

## Quick Start

### Main service

1. Run the installer and choose **Main service = yes**.
2. Set RS256 keys using `file://` paths in `.env` (or use HS256 with `JWT_SECRET`).
3. If using cookies, configure `FIRAUTH_COOKIE_DOMAIN` for your apex/subdomains.
4. Test login:
   ```bash
   curl -i -X POST https://api.your-domain.com/firauth/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"user@example.com","password":"secret"}'
   ```
   You should see a JSON response and a `Set-Cookie: firauth_token=...` header (cookie strategy).

### Consumer services

1. Run the installer and choose **Main service = no**.
2. Configure **only the public key** for RS256 (`JWT_PUBLIC_KEY`).
3. Protect routes with the middleware:
   ```php
   Route::middleware('firauth')->group(function () {
       Route::get('/me', fn() => response()->json(request()->user()));
       // your protected routes…
   });
   ```
The middleware will verify signature/expiry/nbf/blacklist, validate the Redis `session_id`, and expose a dynamic `request()->user()` built from claims (no DB hit).

---

## Routes & Middlewares

**Routes (package):**

- `POST /firauth/login` — issues the JWT (+ `Set-Cookie` in cookie mode)
- `POST /firauth/refresh` — refreshes token; middleware: `firauth.token` (token presence; accepts expired token)
- `POST /firauth/logout` — blacklists current token  revokes Redis session; middleware: `firauth` (full check)

**Middlewares:**

- `firauth` — Full verification (signature, expiry, blacklist)  Redis `session_id` validation; binds `request()->user()` from claims.
- `firauth.token` — Helper that injects cookie token into the `Authorization` header if missing (used for `/refresh`).

---

## Overriding *only* the Login action (best practice)

You can replace only the login endpoint and reuse the package’s services:

1. Disable the package login route in `.env`:
   ```env
   FIRAUTH_ROUTES_EXPOSE_LOGIN=false
   ```

2. Create a **subclass** of the base controller and override `login()`:
   ```php
   // app/Http/Controllers/Auth/CustomAuthController.php
   namespace App\Http\Controllers\Auth;

   use Illuminate\Http\Request;
   use Illuminate\Validation\ValidationException;
   use Firauth\auth\Http\Controllers\AuthController as BaseAuthController;

   class CustomAuthController extends BaseAuthController
   {
       public function login(Request $request)
       {
           $request->validate([
               'email'    => 'required|string',
               'password' => 'required|string',
               'remember' => 'sometimes|boolean',
           ]);

           $rememberDays = $request->boolean('remember')
               ? (int) config('firauth.jwt.remember_me_days')
               : null;

           // Reuse token driver (no direct Tymon calls here)
           $result = $this->tokens->attempt(
               $request->only('email','password'),
               $rememberDays
           );

           if (!$result) {
               throw ValidationException::withMessages(['email' => ['Invalid credentials']])->status(422);
           }

           $claims    = $result['claims'] ?? [];
           $user      = $result['user'];
           $sessionId = $claims['session_id'] ?? null;

           if (config('firauth.jwt.bind_session_in_login', false) && $sessionId) {
               $this->sessions->bind($user['id'], $sessionId);
           }

           // Use the transport to emit JSON + optional Set-Cookie
           return $this->transport->loginResponse($result['token'], $user);
       }
   }
   ```

3. Register only your login route (keep refresh/logout from the package):
   ```php
   // routes/api.php
   use App\Http\Controllers\Auth\CustomAuthController;
   Route::post('firauth/login', [CustomAuthController::class, 'login']);
   ```

---

## Pre / Post Checkers

Use checkers to inject custom logic **without** touching core auth:

- **Pre checkers** (run first) — may short‑circuit or **bypass JWT** by returning user attributes.  
  If a pre checker returns an array, we treat the user as authenticated and **skip everything else** by default.  
  If that case still needs post checks, include `['_run_post' => true]` in the returned array.

- **Post checkers** (run last) — final gate **after** JWT \u002b Redis session validation (or pre opted‑in).  
  Perfect for: password‑reset gates (423), tenant disabled, timezone binding, MFA after JWT, etc.  
  Return a `Response` to block, or `null` to allow; you may mutate the `$userAttrs` array by reference.

**Contracts:**

```php
// Pre — return Response|array|null
interface PreAuthCheckerInterface {
    public function handle(Request $request): \Symfony\Component\HttpFoundation\Response|array|null;
}

// Post — return ?Response; can mutate user attrs by reference
interface PostAuthCheckerInterface {
    public function handle(Request $request, array &$userAttrs): ?\Symfony\Component\HttpFoundation\Response;
}
```

Register your checkers in `config/firauth.php`:

```php
'middleware' => [
  'pre'  => [
    // \App\FirAuth\Checkers\IntegrationCredentialsPreChecker::class,
  ],
  'post' => [
    // \App\FirAuth\Checkers\ForcePasswordResetPostChecker::class,
    // \App\FirAuth\Checkers\TimezoneBinderPostChecker::class,
  ],
],
```

---

## Refresh Best Practice

- Set a window to refresh **only when near expiry** or expired:
  ```env
  FIRAUTH_RENEW_WINDOW=600   # 10 minutes
  ```
- Behavior at `/firauth/refresh`:
    - If token **far from expiry** → `{ "still_valid": true, "expires_in": <seconds> }`
    - If **expired** or **within window** → a **new token** is issued; the old is **blacklisted** immediately.
- To reduce races during refresh (parallel requests):
  ```env
  JWT_BLACKLIST_GRACE_PERIOD=30
  ```

---

## Logout Behavior

- `POST /firauth/logout` (middleware: `firauth` full check):
    - Blacklists the current token.
    - Revokes the Redis session entry → **global single‑session kill**.
    - Returns 200 (cookie cleared if cookie strategy).
    - A second logout with the same token returns **401** (blacklisted \u002b no session).

---

## Testing Recipes

**JWT (header)**
```bash
# Login (get token)
TOKEN=$(curl -s -X POST https://api.your-domain.com/firauth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}' | jq -r '.data.token')

# Protected route
curl -H "Authorization: Bearer $TOKEN" https://api.your-domain.com/protected

# Refresh
curl -X POST -H "Authorization: Bearer $TOKEN" https://api.your-domain.com/firauth/refresh

# Logout
curl -X POST -H "Authorization: Bearer $TOKEN" https://api.your-domain.com/firauth/logout
```

**Cookie**
```bash
# Let curl manage cookies automatically (-c to save, -b to send)
curl -c cookies.txt -b cookies.txt -i -X POST https://api.your-domain.com/firauth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'

# Refresh / protected / logout
curl -c cookies.txt -b cookies.txt -i -X POST https://api.your-domain.com/firauth/refresh
curl -c cookies.txt -b cookies.txt -i https://api.your-domain.com/protected
curl -c cookies.txt -b cookies.txt -i -X POST https://api.your-domain.com/firauth/logout
```

**Feature tests (Laravel)**
- Login returns token (or sets cookie) \u002b payload has `exp`
- Refresh near expiry issues a new token; far from expiry returns `still_valid`
- Logout revokes session and blacklists token; second logout is 401

---

## Postman Tips

- **Do not** paste the full `Set‑Cookie` header as your `Cookie` header; send only `Cookie: firauth_token=<TOKEN>`.
- In cookie mode, prefer using a host that matches `FIRAUTH_COOKIE_DOMAIN` (e.g., `api.your-domain.test`) so Postman attaches cookies automatically.
- If both cookie *and* `Authorization` header are present, cookie is preferred in cookie strategy (package behavior). Keep your `Authorization` header clean to avoid sending stale tokens.

---


# What’s Next (Roadmap)


### 1. Pluggable Session Stores (Not Only Redis)

Make the session binding layer driver-based so teams can choose from:

- Redis (default)
- Database
- File
- In-memory / Array (for testing)
- Custom-defined stores

**Goal:** Decouple session handling from Redis to allow for flexible and testable implementations.

---

### 2. Multi-Device Sessions & Revocation UX

Support **both** `single-session` (default today) and `multi-session` modes.

####  Modes

- `single`: One active `session_id` per user (current behavior).
- `multi`: Track a **set** of session IDs per user.
    - `revoke(user, session_id)` → removes one device
    - `revoke(user, null)` → removes all sessions for the user

####  Claims

Add optional claims:
- `device_id`
- `client metadata` (OS, browser, device info)

####  APIs (optional)

- `GET /firauth/sessions` → List all active devices
- `DELETE /firauth/sessions/{session_id}` → Revoke specific device

#### ⚙ Dev Experience

- Artisan command:
  ```bash
  php artisan firauth:sessions {userId}
---

### 3. Pre-Built SSO Adapters (as Pre-Checkers)

Ship optional pre-auth adapters for popular identity providers:
- OAuth2 / OIDC flows:
  - Microsoft
  - Google
  - GitHub.
