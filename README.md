# Finchglow Authenticator

Laravel package that authenticates requests for the Finchglow Travels services (user, product, payment, booking). It verifies JWTs issued by user-service and API keys, permissions and partner settings stored in the user-service database.

Requires PHP 8.2+ and Laravel 10, 11 or 12. The service provider is auto-discovered.

## Installation

```bash
composer require finchglow/authenticator
```

### Database connection

Every lookup goes through a connection named `authentication_db`, which each consuming service must define in `config/database.php`. It points at the user-service database. Keep credentials in env only, with no defaults:

```php
'authentication_db' => [
    'driver' => 'mysql',
    'host' => env('AUTH_DB_HOST'),
    'port' => env('AUTH_DB_PORT', '3306'),
    'database' => env('AUTH_DB_DATABASE'),
    'username' => env('AUTH_DB_USERNAME'),
    'password' => env('AUTH_DB_PASSWORD'),
    'charset' => 'utf8mb4',
    'collation' => 'utf8mb4_unicode_ci',
    'prefix' => '',
    'strict' => true,
],
```

The package reads `api_keys`, `agencies`, `companies`, `branches`, `model_has_permissions`, `permissions` and `third_party_security_settings`. It also inserts into `error_logs`, so the database user needs INSERT on that table.

## Middleware

| Alias | Headers | What it does |
|---|---|---|
| `auth-client-key[:company\|agency]` | `FC-API-KEY` | Validates a `test_…` or `live_…` key. Live keys only work when `APP_ENV` is a live environment. Rejects soft-deleted keys, inactive or deleted agencies and inactive companies. The optional argument must match the key type. On success it merges `company_details` (`id`, `type`, `agency_id`, `company_id`, `agency_name`, `agency_type`, `owner_id`, `company_email`, `company_name`, `company_type`, `branch_id`, `branch_name`, `user_type`, `name`) into the request. The branch is the HQ branch, falling back to the oldest active one. |
| `auth-internal` | `X-Service-Key` or `FC-API-KEY` | Service-to-service calls. A valid service key sets the `internal_service` request attribute and no `company_details`. A wrong service key returns 403. Without the service-key header it behaves like `auth-client-key`. Neither header returns 403. |
| `jwt-auth:{type}` | `token` | Verifies an HS512 JWT and requires its `type` to match. For types other than `super_admin` and `company` it must run after `auth-client-key`. An `agent` token's `company_id` must equal `company_details.id`, and a `user` token's `company_id`/`agency_id` must match `company_details`. Sets the `user` input and `Auth::user()` (a `GenericUser`). Failures return 401 `{"status":false,"error":"Unauthorized"}`. |
| `check-permission:{name}` | `token` | Owners (`role = owner`) pass. Everyone else needs the permission assigned directly in `model_has_permissions`. A missing or invalid token, or a missing permission, returns 401. |
| `get-user` | `token` | Optional auth: sets `Auth::user()` when the token is valid and ignores it otherwise. |
| `third-party` | — | Requires `company_details.agency_type` to be `third_party`. Run after `auth-client-key`. |
| `third-party-ip-allowlist` | — | When the agency enforces it, the client IP must match `allowed_ips` (single IPs or CIDR ranges, IPv4 or IPv6). |
| `third-party-signature` | `X-FC-Signature`, `X-FC-Timestamp` | When the agency enforces it, checks `hex(hmac_sha256("METHOD\npath\nbody\ntimestamp", secret))` within the tolerance window and rejects replays. |
| `third-party-throttle` | — | Per-agency rate limit per minute, then 429 with `Retry-After`. |

A client-supplied `company_details` value is removed from the query string and body of every request by a global middleware, so only `auth-client-key` can set it.

```php
Route::middleware(['auth-client-key', 'jwt-auth:agent', 'check-permission:create booking'])->group(function () {
    Route::post('/bookings', [BookingController::class, 'store']);
});

Route::middleware('auth-internal')->post('/internal/bookings/sync', [SyncController::class, 'store']);
```

Rejections from `auth-client-key`, `auth-internal`, `third-party`, the IP allowlist and the signature check return 403 `UnAuthorized`. Each one is logged to the application log as `authenticator: <checkpoint>`. It is also written to `error_logs`, except for a missing `FC-API-KEY` header, and at most once per checkpoint per IP per minute.

## Configuration

Settings come from `config('authenticator.*')`, so `php artisan config:cache` is safe. Publish the config with `php artisan vendor:publish --tag=config` only if you need to override it in code.

| Env | Default | Purpose |
|---|---|---|
| `JWT_KEY` | — | HS512 secret used to verify JWTs (64 hex characters). Required. |
| `AUTHENTICATOR_ENCRYPTION_KEY` | `JWT_KEY` | CipherSweet key for stored API keys and HMAC secrets (64 hex characters). Must match the key user-service encrypts with. |
| `PERMISSIONS_TABLE` | `model_has_permissions` | Permission pivot table. |
| `APP_ENV` | `dev` | Compared with `AUTHENTICATOR_LIVE_ENVIRONMENTS`. |
| `AUTHENTICATOR_LIVE_ENVIRONMENTS` | `prod,production,live` | Environments that accept `live_` keys. Case-insensitive. |
| `INTERNAL_SERVICE_KEY` | — | Shared secret for `auth-internal`. If empty, service keys never match. |
| `INTERNAL_SERVICE_KEY_HEADER` | `X-Service-Key` | Header that carries the service key. |
| `THIRD_PARTY_SECURITY_TABLE` | `third_party_security_settings` | Per-agency hardening settings. |
| `THIRD_PARTY_SIGNATURE_HEADER` | `X-FC-Signature` | Signature header. |
| `THIRD_PARTY_TIMESTAMP_HEADER` | `X-FC-Timestamp` | Timestamp header. |
| `THIRD_PARTY_SIGNATURE_TOLERANCE` | `300` | Allowed clock skew and replay window, in seconds. |
| `THIRD_PARTY_SIGNATURE_CACHE_STORE` | default store | Cache store for replay protection. Use a shared store such as `redis` when running more than one instance. |
| `DEFAULT_THIRD_PARTY_RATE_LIMIT` | `60` | Requests per minute when the agency has no limit set. |
| `THIRD_PARTY_RATE_LIMIT_CACHE_STORE` | default store | Cache store for the throttle. Use a shared store when running more than one instance. |
| `THIRD_PARTY_IP_ALLOWLIST_MIDDLEWARE_ENABLED` | `true` | Turns the IP allowlist off everywhere. |
| `THIRD_PARTY_RATE_LIMIT_MIDDLEWARE_ENABLED` | `true` | Turns the throttle off everywhere. |

## Testing

```bash
composer install
vendor/bin/phpunit
```

The suite uses Orchestra Testbench with an in-memory SQLite `authentication_db`.
