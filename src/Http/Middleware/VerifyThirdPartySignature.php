<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Middleware\Concerns\LogsAuthorizationFailures;
use Finchglow\Authenticator\Http\Services\ThirdPartySecuritySettingsService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

/**
 * Must run after 'auth-client-key'. Opt-in per agency via enforce_signature. The decrypted
 * hmac_secret is only ever kept in a local variable here - never merged into
 * request()->company_details, since that array is merged into request input and could end up
 * in logs/error tracking.
 */
class VerifyThirdPartySignature
{
    use LogsAuthorizationFailures;

    public function handle(Request $request, Closure $next): Response
    {
        $agencyId = $request->company_details['agency_id'] ?? null;

        if (!$agencyId) {
            return $next($request);
        }

        $settings = (new ThirdPartySecuritySettingsService())->getForAgency($agencyId);

        if (!$settings || !$settings['enforce_signature'] || empty($settings['hmac_secret'])) {
            return $next($request);
        }

        $signatureHeader = config('authenticator.third_party_signature_header', 'X-FC-Signature');
        $timestampHeader = config('authenticator.third_party_timestamp_header', 'X-FC-Timestamp');
        $tolerance = (int) config('authenticator.third_party_signature_tolerance', 300);

        $signature = $request->header($signatureHeader);
        $timestamp = $request->header($timestampHeader);

        if (!$signature || !$timestamp || abs(time() - (int) $timestamp) > $tolerance) {
            $this->abortWithLog('invalid_signature_headers');
        }

        $payload = $request->method()."\n".$request->path()."\n".$request->getContent()."\n".$timestamp;
        $expected = hash_hmac('sha256', $payload, $settings['hmac_secret']);

        if (!hash_equals($expected, $signature)) {
            $this->abortWithLog('signature_mismatch');
        }

        $cacheStore = config('authenticator.third_party_signature_cache_store');
        $cache = $cacheStore ? Cache::store($cacheStore) : Cache::store();
        $replayKey = "third-party-signature:{$agencyId}:{$signature}";

        if (!$cache->add($replayKey, true, $tolerance)) {
            $this->abortWithLog('signature_replayed');
        }

        return $next($request);
    }
}
