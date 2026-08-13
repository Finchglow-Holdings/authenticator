<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Middleware\Concerns\LogsAuthorizationFailures;
use Finchglow\Authenticator\Http\Services\JwtAuthService;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

class IsThirdPartyMiddleware
{
    use LogsAuthorizationFailures;

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $agency = request()->company_details ?? null;
            if (empty($agency)) {
                $this->abortWithLog('missing_company_details');
            }

            if ($agency['agency_type'] !== "third_party") {
                $this->abortWithLog('not_third_party_agency');
            }

            return $next($request);
        } catch (HttpException $exception) {
            // Already logged with its checkpoint in abortWithLog(), just rethrow.
            throw $exception;
        } catch (\Exception $exception) {
            $this->logUnexpectedException($exception);

            abort(500, "Invalid Authentication");
        }
    }
}
