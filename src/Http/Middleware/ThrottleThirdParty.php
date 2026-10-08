<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Services\ThirdPartySecuritySettingsService;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

/**
 * Self-contained per-agency rate limit (falls back to IP when unauthenticated). Always on with
 * a sane default, so consuming apps don't need any RouteServiceProvider wiring.
 */
class ThrottleThirdParty
{
    public function __construct(protected RateLimiter $limiter)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        if (!config('authenticator.third_party_rate_limit_middleware_enabled', true)) {
            return $next($request);
        }

        $agencyId = $request->company_details['agency_id'] ?? null;
        $key = 'third-party:'.($agencyId ?? $request->ip());

        $settings = $agencyId ? (new ThirdPartySecuritySettingsService())->getForAgency($agencyId) : null;
        $maxAttempts = $settings['rate_limit_per_minute'] ?? config('authenticator.default_third_party_rate_limit', 60);

        $cacheStore = config('authenticator.third_party_rate_limit_cache_store');
        $limiter = $cacheStore ? new RateLimiter(Cache::store($cacheStore)) : $this->limiter;

        if ($limiter->tooManyAttempts($key, $maxAttempts)) {
            abort(429, 'Too Many Requests', ['Retry-After' => (string) $limiter->availableIn($key)]);
        }

        $limiter->hit($key, 60);

        return $next($request);
    }
}
