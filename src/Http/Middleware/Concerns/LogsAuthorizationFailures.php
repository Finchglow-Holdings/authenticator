<?php

namespace Finchglow\Authenticator\Http\Middleware\Concerns;

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
     * Log the failed checkpoint to error_logs, then abort the request.
     */
    protected function abortWithLog(string $checkpoint, int $status = 403, string $message = 'UnAuthorized'): never
    {
        $this->logAuthorizationFailure($checkpoint, $message);

        abort($status, $message);
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
