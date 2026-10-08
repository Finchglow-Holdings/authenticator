<?php

namespace Finchglow\Authenticator\Tests;

use Finchglow\Authenticator\Http\Services\CipherSweetEncryption;
use Illuminate\Support\Facades\DB;

class ThirdPartyHardeningTest extends TestCase
{
    private string $agencyId;

    private string $key;

    protected function setUp(): void
    {
        parent::setUp();

        $this->agencyId = $this->createAgency($this->createCompany());
        $this->key = $this->createApiKey($this->agencyId, 'agency');
    }

    public function test_valid_signature_passes_and_a_replay_is_rejected(): void
    {
        $secret = 'partner-hmac-secret';
        $this->createSecuritySettings($this->agencyId, [
            'enforce_signature' => true,
            'hmac_secret' => (new CipherSweetEncryption())->encryptKey('third_party_security_settings', 'hmac_secret', $secret),
        ]);
        $body = '{"origin":"LOS","destination":"ABV"}';
        $timestamp = (string) time();
        $signature = hash_hmac('sha256', "POST\nsigned\n{$body}\n{$timestamp}", $secret);

        $this->signedRequest($body, $timestamp, $signature)->assertOk();
        $this->signedRequest($body, $timestamp, $signature)->assertForbidden();

        $this->assertSame(['signature_replayed'], $this->errorLogCheckpoints());
    }

    public function test_invalid_signature_is_rejected(): void
    {
        $this->createSecuritySettings($this->agencyId, [
            'enforce_signature' => true,
            'hmac_secret' => (new CipherSweetEncryption())->encryptKey('third_party_security_settings', 'hmac_secret', 'partner-hmac-secret'),
        ]);
        $timestamp = (string) time();

        $this->signedRequest('{}', $timestamp, hash_hmac('sha256', "POST\nsigned\n{}\n{$timestamp}", 'wrong-secret'))
            ->assertForbidden();

        $this->assertSame(['signature_mismatch'], $this->errorLogCheckpoints());
    }

    public function test_ip_allowlist_supports_cidr_and_ipv6(): void
    {
        $this->createSecuritySettings($this->agencyId, [
            'enforce_ip_allowlist' => true,
            'allowed_ips' => json_encode(['10.0.0.0/8', '2001:db8::/32', '203.0.113.7']),
        ]);

        foreach (['10.20.30.40', '203.0.113.7', '2001:db8::1'] as $ip) {
            $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->getJson('/allowlisted', ['FC-API-KEY' => $this->key])
                ->assertOk();
        }

        $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.10'])
            ->getJson('/allowlisted', ['FC-API-KEY' => $this->key])
            ->assertForbidden();
    }

    public function test_throttle_returns_429_with_retry_after(): void
    {
        config(['authenticator.third_party_rate_limit_cache_store' => 'array']);
        $this->createSecuritySettings($this->agencyId, ['rate_limit_per_minute' => 2]);

        $this->getJson('/throttled', ['FC-API-KEY' => $this->key])->assertOk();
        $this->getJson('/throttled', ['FC-API-KEY' => $this->key])->assertOk();
        $this->getJson('/throttled', ['FC-API-KEY' => $this->key])
            ->assertStatus(429)
            ->assertHeader('Retry-After');
    }

    public function test_settings_are_queried_once_per_request(): void
    {
        $this->createSecuritySettings($this->agencyId, ['rate_limit_per_minute' => 10]);
        $queries = 0;
        DB::listen(function ($query) use (&$queries) {
            if (str_contains($query->sql, 'third_party_security_settings')) {
                $queries++;
            }
        });

        $this->getJson('/hardened', ['FC-API-KEY' => $this->key])->assertOk();

        $this->assertSame(1, $queries);
    }

    private function signedRequest(string $body, string $timestamp, string $signature)
    {
        return $this->call('POST', '/signed', [], [], [], [
            'HTTP_FC_API_KEY' => $this->key,
            'HTTP_X_FC_TIMESTAMP' => $timestamp,
            'HTTP_X_FC_SIGNATURE' => $signature,
            'HTTP_ACCEPT' => 'application/json',
            'CONTENT_TYPE' => 'application/json',
        ], $body);
    }
}
