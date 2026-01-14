<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Services\JwtAuthService;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

class IsThirdPartyMiddleware
{
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
                abort(403, "UnAuthorized");
            }

            if ($agency['agency_type'] !== "third_party") {
                abort(403, "UnAuthorized");
            }

            return $next($request);
        } catch (\Exception $exception) {
            DB::connection('authentication_db')->table('error_logs')->insert([
                'service' => 'authenticator',
                'type' => 'authorization',
                'file' => 'IsThirdPartyMiddleware',
                'error' => json_encode([
                    'message' => $exception->getMessage(),
                    'trace' => $exception->getTraceAsString(),
                ]),
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            if ($exception->getMessage() != "UnAuthorized") {
                abort(500, "Invalid Authentication");
            }
            abort(403, "UnAuthorized");
        }
    }
}
