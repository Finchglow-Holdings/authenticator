<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Middleware\Concerns\LogsAuthorizationFailures;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateInternalRequest
{
    use LogsAuthorizationFailures;

    public function handle(Request $request, Closure $next): Response
    {
        $header = config('authenticator.service_key_header', 'X-Service-Key');

        if ($request->headers->has($header)) {
            $serviceKey = (string) config('authenticator.service_key');

            if ($serviceKey === '' || !hash_equals($serviceKey, (string) $request->header($header))) {
                $this->abortWithLog('invalid_service_key');
            }

            $request->attributes->set('internal_service', true);

            return $next($request);
        }

        if ($request->header('FC-API-KEY')) {
            return (new AuthenticateClientMiddleware())->handle($request, $next);
        }

        $this->abortWithLog('missing_internal_credentials');
    }
}
