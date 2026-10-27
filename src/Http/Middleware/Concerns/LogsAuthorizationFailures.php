<?php

namespace Finchglow\Authenticator\Http\Middleware\Concerns;

use Finchglow\Authenticator\Exceptions\AuthenticationRejected;
use Finchglow\Authenticator\Http\Middleware\AuthenticateClientMiddleware;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Shared 403/authorization logging for middlewares, so every rejection point is traceable
 * in the error_logs table via a distinct checkpoint name.
 */
trait LogsAuthorizationFailures
{
    /**
     * Log the failed checkpoint to error_logs, then reject the request.
     * Production gets a short public message and code; other environments get the checkpoint and an explicit cause.
     */
    protected function abortWithLog(string $checkpoint, array $context = [], int $status = 403): never
    {
        [$code, $check, $public, $explicit] = self::rejection($checkpoint);

        $replace = [];
        foreach ($context + ['ip' => request()->ip()] as $key => $value) {
            $replace['{'.$key.'}'] = (string) $value;
        }
        $explicit = strtr($explicit, $replace);

        $this->logAuthorizationFailure($checkpoint, $explicit);

        if (AuthenticateClientMiddleware::isLiveEnvironment()) {
            throw new AuthenticationRejected($status, strtr($public, $replace), $code, $check);
        }

        throw new AuthenticationRejected($status, $explicit, $checkpoint, $check);
    }

    /**
     * @return array{0: string, 1: string, 2: string, 3: string} public code, check, public message, explicit message
     */
    private static function rejection(string $checkpoint): array
    {
        $tolerance = (int) config('authenticator.third_party_signature_tolerance', 300);
        $serviceKeyHeader = config('authenticator.service_key_header', 'X-Service-Key');

        return match ($checkpoint) {
            'missing_api_key_header' => ['missing_api_key', 'client-key', 'The FC-API-KEY header is missing.',
                'No FC-API-KEY header was sent.'],
            'malformed_api_key' => ['malformed_api_key', 'client-key', 'The FC-API-KEY should look like test_… or live_….',
                'FC-API-KEY must be test_ or live_ followed by letters and digits only. Check for spaces or extra text copied along with the key.'],
            'env_mismatch' => ['live_key_not_allowed', 'client-key', 'Live keys only work in production. Use your test_ key.',
                'A live_ key was sent, but APP_ENV "'.config('authenticator.app_env').'" is not a live environment ('.implode(', ', (array) config('authenticator.live_key_environments')).'). Use the test_ key.'],
            'api_key_not_found' => ['invalid_api_key', 'client-key', 'The FC-API-KEY is not recognised.',
                'No active {kind} key matches this FC-API-KEY in this environment. It may be mistyped, have extra characters, belong to another environment, or have been deleted.'],
            'keyable_not_found' => ['invalid_api_key', 'client-key', 'The FC-API-KEY is not recognised.',
                'The key exists, but the agency or company it belongs to was not found.'],
            'key_decryption_mismatch' => ['invalid_api_key', 'client-key', 'The FC-API-KEY is not recognised.',
                'The key hash matched, but the stored key did not decrypt to the same value. This service\'s encryption key (AUTHENTICATOR_ENCRYPTION_KEY or JWT_KEY) differs from the one user-service used.'],
            'keyable_inactive' => ['account_inactive', 'client-key', 'This account is inactive. Contact support.',
                'The key belongs to an inactive or deleted {who}.'],
            'client_type_mismatch' => ['key_not_allowed_here', 'client-key', 'This key can\'t be used on this endpoint.',
                'This route only accepts {expected} keys, not {actual} keys.'],
            'missing_company_details' => ['invalid_api_key', 'partner', 'The FC-API-KEY is not recognised.',
                'No company_details on the request. auth-client-key must run before this middleware.'],
            'not_third_party_agency' => ['not_partner_key', 'partner', 'This key is not a partner API key.',
                'This key belongs to {who}, not a third_party agency.'],
            'ip_not_allowlisted' => ['ip_not_allowed', 'ip-allowlist', 'Requests from {ip} are not on this account\'s IP allowlist.',
                'Request IP {ip} is not in this agency\'s allowed_ips ({allowed}). Outside production, send X-Bypass-Ip-Check: true to skip the check. If {ip} is a private address (10.x, 172.16-31.x, 192.168.x), TRUSTED_PROXIES is not set and the load balancer\'s IP is being checked instead of the caller\'s.'],
            'invalid_signature_headers' => ['missing_signature', 'signature', "X-FC-Signature and X-FC-Timestamp are required, and the timestamp must be within {$tolerance} seconds of the current time.",
                "Missing X-FC-Signature or X-FC-Timestamp, or the timestamp ({timestamp}) is more than {$tolerance}s from server time ({now})."],
            'signature_mismatch' => ['invalid_signature', 'signature', 'The request signature does not match.',
                'Signature mismatch. Sign METHOD\npath\nbody\ntimestamp with HMAC-SHA256 using the agency\'s secret; this request\'s path was "{path}".'],
            'signature_replayed' => ['signature_replayed', 'signature', 'This signed request has already been used.',
                "This exact signature was already used in the last {$tolerance} seconds."],
            'invalid_service_key' => ['invalid_service_key', 'internal', 'The service key is not valid.',
                "{$serviceKeyHeader} does not match INTERNAL_SERVICE_KEY, or INTERNAL_SERVICE_KEY is not set on this service."],
            'missing_internal_credentials' => ['missing_credentials', 'internal', "Send an {$serviceKeyHeader} or FC-API-KEY header.",
                "Internal route: no {$serviceKeyHeader} or FC-API-KEY header was sent."],
            default => ['unauthorized', 'auth', 'UnAuthorized', $checkpoint],
        };
    }

    /**
     * Log an exception that wasn't raised via abortWithLog() (i.e. a genuine bug, not a rejection).
     */
    protected function logUnexpectedException(\Throwable $exception): void
    {
        $this->logAuthorizationFailure('unexpected_exception', $exception->getMessage(), $exception->getTraceAsString());
    }

    private function logAuthorizationFailure(string $checkpoint, string $message, ?string $trace = null): void
    {
        Log::warning('authenticator: '.$checkpoint, [
            'file' => class_basename(static::class),
            'message' => $message,
            'ip' => request()->ip(),
        ]);

        if ($checkpoint === 'missing_api_key_header') {
            return;
        }

        try {
            if (!Cache::add('authenticator:auth-failure:'.$checkpoint.':'.request()->ip(), true, 60)) {
                return;
            }

            DB::connection('authentication_db')->table('error_logs')->insert([
                'service' => 'authenticator',
                'type' => 'authorization',
                'file' => class_basename(static::class),
                'error' => json_encode(array_filter([
                    'checkpoint' => $checkpoint,
                    'message' => $message,
                    'trace' => $trace !== null ? substr($trace, 0, 2000) : null,
                ])),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        } catch (\Throwable $exception) {
            Log::error('authenticator: failed to write error_logs', [
                'checkpoint' => $checkpoint,
                'error' => $exception->getMessage(),
            ]);
        }
    }
}
