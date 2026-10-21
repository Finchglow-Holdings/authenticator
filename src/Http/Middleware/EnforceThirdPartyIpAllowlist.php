<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Middleware\Concerns\LogsAuthorizationFailures;
use Finchglow\Authenticator\Http\Services\ThirdPartySecuritySettingsService;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Response;

/**
 * Must run after 'auth-client-key' (relies on request()->company_details). Opt-in per agency:
 * passes through when no settings row exists or enforce_ip_allowlist is off.
 * Outside production the check only runs when the caller sends X-Bypass-Ip-Check: false.
 */
class EnforceThirdPartyIpAllowlist
{
    use LogsAuthorizationFailures;

    public function handle(Request $request, Closure $next): Response
    {
        if (!config('authenticator.third_party_ip_allowlist_middleware_enabled', true)) {
            return $next($request);
        }

        if (!AuthenticateClientMiddleware::isLiveEnvironment() && $this->bypassRequested($request)) {
            return $next($request);
        }

        $agencyId = $request->company_details['agency_id'] ?? null;

        if (!$agencyId) {
            return $next($request);
        }

        $settings = (new ThirdPartySecuritySettingsService())->getForAgency($agencyId);

        if (!$settings || !$settings['enforce_ip_allowlist'] || empty($settings['allowed_ips'])) {
            return $next($request);
        }

        if (!IpUtils::checkIp((string) $request->ip(), $settings['allowed_ips'])) {
            $this->abortWithLog('ip_not_allowlisted');
        }

        return $next($request);
    }

    private function bypassRequested(Request $request): bool
    {
        // Not sent, empty or unrecognised all mean bypass; only an explicit false runs the check
        $value = trim((string) $request->header('X-Bypass-Ip-Check'));

        return $value === '' || filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) !== false;
    }
}
