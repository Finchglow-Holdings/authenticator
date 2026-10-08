<?php

namespace Finchglow\Authenticator\Http\Services;

use Illuminate\Support\Facades\DB;

class ThirdPartySecuritySettingsService
{
    /**
     * Fetch third-party hardening settings for an agency, decrypting the hmac secret if present.
     * Returns null when the agency has no settings row configured (fully backward compatible).
     */
    public function getForAgency(string $agencyId): ?array
    {
        $table = config('authenticator.third_party_security_table', 'third_party_security_settings');
        $attributeKey = "authenticator.third_party_security_settings.{$agencyId}";

        // Memoize the still-encrypted row so the decrypted secret never sits on the request.
        if (!request()->attributes->has($attributeKey)) {
            request()->attributes->set($attributeKey, DB::connection('authentication_db')
                ->table($table)
                ->where('keyable_id', $agencyId)
                ->where('keyable_type', 'App\\Models\\Agency')
                ->first());
        }

        $settings = request()->attributes->get($attributeKey);

        if (!$settings) {
            return null;
        }

        $result = (array) $settings;

        if (!empty($result['hmac_secret'])) {
            $encryptService = new CipherSweetEncryption();
            $result['hmac_secret'] = $encryptService->decryptValue($table, 'hmac_secret', $result['hmac_secret']);
        }

        $result['allowed_ips'] = !empty($result['allowed_ips']) ? json_decode($result['allowed_ips'], true) : [];
        $result['enforce_signature'] = (bool) ($result['enforce_signature'] ?? false);
        $result['enforce_ip_allowlist'] = (bool) ($result['enforce_ip_allowlist'] ?? false);

        return $result;
    }
}
