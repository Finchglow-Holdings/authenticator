# CLAUDE.md

Cross-service context (workspace layout, per-service repos and branches) lives in `../CLAUDE.md` — read it first.

## What this is

`finchglow/authenticator` is a Laravel package (no app, no `artisan`) that every Finchglow Travels service (user, product, booking, payment) pulls in for request authentication. PSR-4 `Finchglow\Authenticator\` → `src/`. Auto-discovered via `extra.laravel.providers` → `AuthenticatorServiceProvider`, which merges `src/config/authenticator.php` into `authenticator.*` and registers the middleware aliases below. Its `boot()` also prepends the global `StripClientCompanyDetails` middleware to the HTTP kernel, which removes any client-supplied `company_details` from the query, form, file and JSON bags so only `auth-client-key` can set it. Requires PHP `^8.2`, `illuminate/support ^10|^11|^12`, `firebase/php-jwt ^7.0` and `paragonie/ciphersweet ^4`.

Tests: `vendor/bin/phpunit` (Orchestra Testbench 9; `tests/TestCase.php` defines an in-memory SQLite `authentication_db`, creates the user-service tables it reads, and registers test routes). CI runs the suite on PHP 8.2 and 8.3 (`.github/workflows/tests.yml`). There is no linter config. The lock file was resolved on PHP 8.2; if you regenerate it on a newer PHP, CI's `composer install` on 8.2 can fail. For end-to-end checks, point a consuming service at your branch (see Release flow).

All DB reads go through the **`authentication_db`** connection, which each consuming service defines in its own `config/database.php` (it points at the user-service database).

## Middleware aliases

| Alias | Class | Behaviour |
|---|---|---|
| `auth-client-key[:type]` | `AuthenticateClientMiddleware` | Reads `FC-API-KEY` header and parses it strictly as `^(test\|live)_([A-Za-z0-9]+)$` (else `malformed_api_key`). A `live_` key is rejected unless `authenticator.app_env` is in `live_key_environments`. Sha256-hashes the part after the prefix and looks it up in `api_keys.{live,test}_hash_api_key` with `deleted_at IS NULL`, joins `agencies`/`companies` (polymorphic `keyable_type` `App\Models\Agency` or `App\Models\Company`), rejects with `keyable_inactive` an agency key whose agency is soft-deleted or `status = 'inactive'`, or any key whose company is `inactive` (null status is allowed). Checks the optional `type` arg against `api_keys.type`, then CipherSweet-decrypts `{live,test}_api_key` and compares to the raw key. The branch comes from a separate `branches` query: `agency_id = keyable_id` for agency keys, or `company_id = keyable_id AND agency_id IS NULL` for company keys, ordered `name = 'HQ'` first, then active, then oldest. On success merges `company_details` into the request (`id`, `type`, `agency_id`, `company_id`, `agency_name`, `agency_type`, `owner_id`, `company_email`, `company_name`, `company_type`, `branch_name`, `branch_id`, `user_type`, `name`). For company keys `agency_*` and `company_id` are null and `id` is the company id. Failures → 403 `UnAuthorized`, unexpected errors → 500 `Invalid Authentication`. |
| `auth-internal` | `AuthenticateInternalRequest` | Service-to-service auth. If the `authenticator.service_key_header` header (default `X-Service-Key`) is present, it must `hash_equals` a non-empty `authenticator.service_key`. On success it sets request attribute `internal_service = true` and no `company_details`; otherwise `invalid_service_key`, with no fallthrough. Without that header, an `FC-API-KEY` delegates to `AuthenticateClientMiddleware` with no type arg. With neither → `missing_internal_credentials`. |
| `jwt-auth:{type}` | `JwtAuthMiddleware` | Reads JWT from the `token` header (the `Authorization` read is commented out). Claim `type` must equal the arg. For types other than `super_admin`/`company`, `company_details` must exist and `agent` → `company_id` must match `company_details.id`; `user` → `company_id`/`agency_id` must match. Merges `user` into request and calls `Auth::setUser(GenericUser)`. Returns JSON 401 `{status:false,error}` rather than aborting. Decode exceptions return the generic `error: "Unauthorized"`, and the real message goes to `Log::info`. |
| `check-permission:{name}` | `CheckPermissionMiddleware` | Decodes `token` header (missing or undecodable → 401 `Access denied`), sets `Auth` user. `role == owner` bypasses. Otherwise queries `authenticator.permissions_table` (default `model_has_permissions`) joined to `permissions` by `model_id` + `model_type` (`App\Models\Admin` for `super_admin`/`company`, `App\Models\Agent` for `agent`, else `App\Models\User`). Only direct permissions count; roles are ignored. Missing permission → 401. |
| `get-user` | `GetUserMiddleware` | Optional auth: if `token` header decodes, sets `Auth` user; any failure is swallowed. |
| `third-party` | `IsThirdPartyMiddleware` | Requires `company_details.agency_type === 'third_party'` (run after `auth-client-key`). |
| `third-party-ip-allowlist` | `EnforceThirdPartyIpAllowlist` | See hardening below. |
| `third-party-signature` | `VerifyThirdPartySignature` | See hardening below. |
| `third-party-throttle` | `ThrottleThirdParty` | See hardening below. |

JWT claims are taken from the token's `data` object (`JwtAuthService::decodeToken`, HS512, strips `Bearer `). `JwtAuthService::getAuthUser()` is a static helper that reads the `Authorization` header instead of `token`.

## Third-party hardening

All three must run after `auth-client-key` and key off `company_details.agency_id`; with no agency id they pass through. Per-agency settings come from `ThirdPartySecuritySettingsService::getForAgency()` — a row in `third_party_security_settings` (`keyable_type = App\Models\Agency`), `hmac_secret` CipherSweet-decrypted, `allowed_ips` JSON-decoded. The raw row (secret still encrypted) is memoized in `request()->attributes` under `authenticator.third_party_security_settings.{agencyId}`, so a full chain runs one query per request. No row → feature off (opt-in per agency).

- **IP allowlist**: when `enforce_ip_allowlist` and `allowed_ips` set, `$request->ip()` must match via `IpUtils::checkIp` (exact IPs or CIDR, IPv4/IPv6). Behind a load balancer this needs the service's `TrustProxies` configured. Globally disabled by `THIRD_PARTY_IP_ALLOWLIST_MIDDLEWARE_ENABLED=false`.
- **Signature**: when `enforce_signature` and `hmac_secret` set, requires `X-FC-Signature` + `X-FC-Timestamp` (within `THIRD_PARTY_SIGNATURE_TOLERANCE`, default 300s). Expected = `hash_hmac('sha256', METHOD\npath\nbody\ntimestamp, secret)`, compared with `hash_equals`. Replay protection uses an atomic `Cache::add` of `third-party-signature:{agencyId}:{signature}` for the tolerance window (use a shared store via `THIRD_PARTY_SIGNATURE_CACHE_STORE` when running multiple instances). Never put the decrypted secret into `company_details`.
- **Throttle**: Laravel `RateLimiter`, key `third-party:{agencyId|ip}`, limit `rate_limit_per_minute` from settings or `DEFAULT_THIRD_PARTY_RATE_LIMIT` (60), 60s decay, 429 with `Retry-After`. Uses the container's limiter (default store) unless `THIRD_PARTY_RATE_LIMIT_CACHE_STORE` names a shared store. Globally disabled by `THIRD_PARTY_RATE_LIMIT_MIDDLEWARE_ENABLED=false`. Not logged to `error_logs`.

The Fusio API gateway already enforces IP allowlist + rate limit upstream; the enable flags exist so ops can turn off the app-level duplicates without editing routes. Currently `travels-product-service/routes/third_party.php` only applies `auth-client-key:agency` + `third-party` (the full chain is commented out).

## Failure logging

Middlewares using the `Concerns\LogsAuthorizationFailures` trait (`auth-client-key`, `auth-internal`, `third-party`, IP allowlist, signature) call `abortWithLog()` on rejection. It always writes `Log::warning('authenticator: <checkpoint>')` (file, message, IP; no trace). Then, except for `missing_api_key_header`, it inserts into `authentication_db.error_logs` (`service=authenticator`, `type=authorization`, `file=<class>`, `error` JSON with a `checkpoint` such as `malformed_api_key`, `env_mismatch`, `api_key_not_found`, `keyable_inactive`, `invalid_service_key`, `signature_replayed`). Inserts are rate-limited to one per checkpoint per IP per 60s via `Cache::add('authenticator:auth-failure:{checkpoint}:{ip}')` on the default cache store. Any failure in the cache or insert is caught and sent to `Log::error`, so the response stays 403. Unexpected exceptions log checkpoint `unexpected_exception` with the trace truncated to 2000 chars. New rejection points should use `abortWithLog('<distinct_checkpoint>')`. `jwt-auth`, `check-permission`, `get-user` and throttle do not log to `error_logs` (`jwt-auth` logs decode failures at `info`).

## Config / env

`JWT_KEY` (`jwt_key`, no default), `AUTHENTICATOR_ENCRYPTION_KEY` (`encryption_key`, defaults to `JWT_KEY`), `PERMISSIONS_TABLE`, `APP_ENV`, `AUTHENTICATOR_LIVE_ENVIRONMENTS` (default `prod,production,live`, case-insensitive), `INTERNAL_SERVICE_KEY` / `INTERNAL_SERVICE_KEY_HEADER` (default `X-Service-Key`), plus the `THIRD_PARTY_*` / `DEFAULT_THIRD_PARTY_RATE_LIMIT` keys above. Gotchas:
- `src/` reads only `config('authenticator.*')`, never `env()`, so `config:cache` is safe. `JwtAuthService::decodeToken` throws `RuntimeException('JWT key is not configured')` when `jwt_key` is empty.
- `JWT_KEY` is the HS512 JWT secret. `encryption_key` is the CipherSweet key, and `CipherSweetEncryption` throws unless it is exactly 64 chars. User-service still encrypts API keys and HMAC secrets with its own `JWT_KEY`, so only set `AUTHENTICATOR_ENCRYPTION_KEY` once user-service encrypts with that same value.
- `register()` uses `mergeConfigFrom`, so new keys work even where a service has published an older `config/authenticator.php` (`vendor:publish --tag=config`).

## Release & consumption

Repo: `github.com/Finchglow-Holdings/authenticator`. Each service lists it under `repositories` (`type: git`, or `vcs` in user-service) and requires `"finchglow/authenticator": "^3.5"`; all four lock files are on `v3.5`. Releases are plain git tags with no `composer.json` version field (`v1.0.0`…`v1.3.2`, then `vX.Y`, latest `v3.5`).

To ship a change: push it, tag the commit (`git tag vX.Y && git push origin vX.Y`), then in **each** service run `composer update finchglow/authenticator` and commit the updated `composer.lock`. A major bump (`v4.0`) also requires editing each service's constraint. Recent tags were cut from feature branches — `origin/master` is well behind the tagged commits, so check which branch holds the latest tag before branching.

## Documentation

Design and feature docs live in `docs/` as Markdown, indexed in `docs/README.md`. When adding or significantly changing a feature, flow, or integration, write or update a doc there and add it to the index.
