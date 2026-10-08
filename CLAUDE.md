# CLAUDE.md

Cross-service context (workspace layout, per-service repos and branches) lives in `../CLAUDE.md` — read it first.

## What this is

`finchglow/authenticator` is a Laravel package (no app, no `artisan`) that every Finchglow Travels service (user, product, booking, payment) pulls in for request authentication. PSR-4 `Finchglow\Authenticator\` → `src/`. Auto-discovered via `extra.laravel.providers` → `AuthenticatorServiceProvider`, which merges `src/config/authenticator.php` into `authenticator.*` and registers the middleware aliases below. Requires `firebase/php-jwt ^7.0` and `paragonie/ciphersweet ^4`.

There is **no test suite, linter config, or CI** in this repo. Verify changes by pointing a consuming service at your branch (see Release flow) and exercising its routes. `README.md` is outdated (only lists the first four middlewares) and contains a hardcoded DB default — don't copy from it.

All DB reads go through the **`authentication_db`** connection, which each consuming service defines in its own `config/database.php` (it points at the user-service database).

## Middleware aliases

| Alias | Class | Behaviour |
|---|---|---|
| `auth-client-key[:type]` | `AuthenticateClientMiddleware` | Reads `FC-API-KEY` header. Key containing `live` is rejected unless `authenticator.app_env` is in `live_key_environments`. Takes the part after the first `_`, sha256-hashes it, looks it up in `api_keys.{live,test}_hash_api_key`, joins `agencies`/`companies`/`branches` (polymorphic `keyable_type` `App\Models\Agency` or `App\Models\Company`), checks optional `type` arg against `api_keys.type`, then CipherSweet-decrypts `{live,test}_api_key` and compares to the raw key. On success merges `company_details` into the request (`id`, `agency_id`, `company_id`, `name`, `branch_id`, `branch_name`, `agency_type`, `user_type`, …). Failures → 403 `UnAuthorized`, unexpected errors → 500 `Invalid Authentication`. |
| `jwt-auth:{type}` | `JwtAuthMiddleware` | Reads JWT from the `token` header (the `Authorization` read is commented out). Claim `type` must equal the arg. For types other than `super_admin`/`company`, `company_details` must exist and `agent` → `company_id` must match `company_details.id`; `user` → `company_id`/`agency_id` must match. Merges `user` into request and calls `Auth::setUser(GenericUser)`. Returns JSON 401 `{status:false,error}` rather than aborting. |
| `check-permission:{name}` | `CheckPermissionMiddleware` | Decodes `token` header, sets `Auth` user. `role == owner` bypasses. Otherwise queries `PERMISSIONS_TABLE` (default `model_has_permissions`) joined to `permissions` by `model_id` + `model_type` (`App\Models\Admin` for `super_admin`/`company`, `App\Models\Agent` for `agent`, else `App\Models\User`). Missing permission → 401. |
| `get-user` | `GetUserMiddleware` | Optional auth: if `token` header decodes, sets `Auth` user; any failure is swallowed. |
| `third-party` | `IsThirdPartyMiddleware` | Requires `company_details.agency_type === 'third_party'` (run after `auth-client-key`). |
| `third-party-ip-allowlist` | `EnforceThirdPartyIpAllowlist` | See hardening below. |
| `third-party-signature` | `VerifyThirdPartySignature` | See hardening below. |
| `third-party-throttle` | `ThrottleThirdParty` | See hardening below. |

JWT claims are taken from the token's `data` object (`JwtAuthService::decodeToken`, HS512, strips `Bearer `). `JwtAuthService::getAuthUser()` is a static helper that reads the `Authorization` header instead of `token`.

## Third-party hardening

All three must run after `auth-client-key` and key off `company_details.agency_id`; with no agency id they pass through. Per-agency settings come from `ThirdPartySecuritySettingsService::getForAgency()` — a row in `third_party_security_settings` (`keyable_type = App\Models\Agency`), `hmac_secret` CipherSweet-decrypted, `allowed_ips` JSON-decoded. No row → feature off (opt-in per agency).

- **IP allowlist**: when `enforce_ip_allowlist` and `allowed_ips` set, `$request->ip()` must be in the list. Globally disabled by `THIRD_PARTY_IP_ALLOWLIST_MIDDLEWARE_ENABLED=false`.
- **Signature**: when `enforce_signature` and `hmac_secret` set, requires `X-FC-Signature` + `X-FC-Timestamp` (within `THIRD_PARTY_SIGNATURE_TOLERANCE`, default 300s). Expected = `hash_hmac('sha256', METHOD\npath\nbody\ntimestamp, secret)`, compared with `hash_equals`. Replay protection caches `third-party-signature:{agencyId}:{signature}` for the tolerance window (use a shared store via `THIRD_PARTY_SIGNATURE_CACHE_STORE` when running multiple instances). Never put the decrypted secret into `company_details`.
- **Throttle**: Laravel `RateLimiter`, key `third-party:{agencyId|ip}`, limit `rate_limit_per_minute` from settings or `DEFAULT_THIRD_PARTY_RATE_LIMIT` (60), 60s decay, 429 with `Retry-After`. Globally disabled by `THIRD_PARTY_RATE_LIMIT_MIDDLEWARE_ENABLED=false`. Not logged to `error_logs`.

The Fusio API gateway already enforces IP allowlist + rate limit upstream; the enable flags exist so ops can turn off the app-level duplicates without editing routes. Currently `travels-product-service/routes/third_party.php` only applies `auth-client-key:agency` + `third-party` (the full chain is commented out).

## Failure logging

Middlewares using the `Concerns\LogsAuthorizationFailures` trait (`auth-client-key`, `third-party`, IP allowlist, signature) insert into `authentication_db.error_logs` (`service=authenticator`, `type=authorization`, `file=<class>`, `error` JSON with a `checkpoint` such as `missing_api_key_header`, `env_mismatch`, `api_key_not_found`, `signature_replayed`) before aborting via `abortWithLog()`. Unexpected exceptions log checkpoint `unexpected_exception` with trace. New rejection points should use `abortWithLog('<distinct_checkpoint>')`. `jwt-auth`, `check-permission`, `get-user` and throttle do not log.

## Config / env

`API_KEY_TABLE`, `API_KEY_COLUMN`, `API_SECRET_COLUMN`, `JWT_KEY`, `PERMISSIONS_TABLE`, `APP_ENV`, `AUTHENTICATOR_LIVE_ENVIRONMENTS` (default `prod,production,live`, case-insensitive), plus the `THIRD_PARTY_*` / `DEFAULT_THIRD_PARTY_RATE_LIMIT` keys above. Gotchas:
- `JwtAuthService`, `CipherSweetEncryption` and `CheckPermissionMiddleware` call `env()` directly (`JWT_KEY`, `PERMISSIONS_TABLE`), so they return null under `config:cache`. The `api_key_*` and `jwt_key` config keys are not read anywhere.
- `JWT_KEY` is both the HS512 JWT secret and the CipherSweet key; `CipherSweetEncryption` throws unless it is exactly 64 hex chars.
- `register()` uses `mergeConfigFrom`, so new keys work even where a service has published an older `config/authenticator.php` (`vendor:publish --tag=config`).

## Release & consumption

Repo: `github.com/Finchglow-Holdings/authenticator`. Each service lists it under `repositories` (`type: git`, or `vcs` in user-service) and requires `"finchglow/authenticator": "^3.5"`; all four lock files are on `v3.5`. Releases are plain git tags with no `composer.json` version field (`v1.0.0`…`v1.3.2`, then `vX.Y`, latest `v3.5`).

To ship a change: push it, tag the commit (`git tag vX.Y && git push origin vX.Y`), then in **each** service run `composer update finchglow/authenticator` and commit the updated `composer.lock`. A major bump (`v4.0`) also requires editing each service's constraint. Recent tags were cut from feature branches — `origin/master` is well behind the tagged commits, so check which branch holds the latest tag before branching.

## Documentation

Design and feature docs live in `docs/` as Markdown, indexed in `docs/README.md`. When adding or significantly changing a feature, flow, or integration, write or update a doc there and add it to the index.
