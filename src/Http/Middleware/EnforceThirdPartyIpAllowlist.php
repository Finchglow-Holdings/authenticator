<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Services\ThirdPartySecuritySettingsService;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Must run after 'auth-client-key' (relies on request()->company_details). Opt-in per agency:
 * passes through when no settings row exists or enforce_ip_allowlist is off.
 */
class EnforceThirdPartyIpAllowlist
{
    public function handle(Request $request, Closure $next): Response
    {
        if (!config('authenticator.third_party_ip_allowlist_middleware_enabled', true)) {
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

        if (!in_array($request->ip(), $settings['allowed_ips'], true)) {
            abort(403, 'UnAuthorized');
        }

        return $next($request);
    }
}
