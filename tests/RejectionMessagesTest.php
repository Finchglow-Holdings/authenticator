<?php

namespace Finchglow\Authenticator\Tests;

class RejectionMessagesTest extends TestCase
{
    private string $key;

    private string $companyKey;

    protected function setUp(): void
    {
        parent::setUp();

        $companyId = $this->createCompany();
        $agencyId = $this->createAgency($companyId);
        $this->key = $this->createApiKey($agencyId, 'agency');
        $this->companyKey = $this->createApiKey($companyId, 'company');
        $this->createSecuritySettings($agencyId, [
            'enforce_ip_allowlist' => true,
            'allowed_ips' => json_encode(['203.0.113.7']),
        ]);
    }

    public function test_outside_production_rejections_name_the_check_and_the_cause(): void
    {
        $response = $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.10'])
            ->getJson('/allowlisted', ['FC-API-KEY' => $this->key])
            ->assertForbidden()
            ->assertJsonPath('status', false)
            ->assertJsonPath('error.code', 'ip_not_allowlisted')
            ->assertJsonPath('error.check', 'ip-allowlist')
            ->assertJsonMissingPath('exception');
        $this->assertStringStartsWith('Request IP 192.168.1.10 is not in this agency\'s allowed_ips (203.0.113.7).', $response->json('message'));

        $response = $this->getJson('/client', ['FC-API-KEY' => 'test_doesnotexist'])
            ->assertForbidden()
            ->assertJsonPath('error.code', 'api_key_not_found')
            ->assertJsonPath('error.check', 'client-key');
        $this->assertStringStartsWith('No active test key matches this FC-API-KEY', $response->json('message'));

        $this->getJson('/client/agency', ['FC-API-KEY' => $this->companyKey])
            ->assertForbidden()
            ->assertJsonPath('error.code', 'client_type_mismatch')
            ->assertJsonPath('message', 'This route only accepts agency keys, not company keys.');
    }

    public function test_production_rejections_use_public_codes_and_messages(): void
    {
        config(['authenticator.app_env' => 'production']);

        $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.10'])
            ->getJson('/allowlisted', ['FC-API-KEY' => $this->key])
            ->assertForbidden()
            ->assertExactJson([
                'status' => false,
                'message' => 'Requests from 192.168.1.10 are not on this account\'s IP allowlist.',
                'error' => ['source' => 'api', 'code' => 'ip_not_allowed', 'check' => 'ip-allowlist'],
            ]);

        $this->getJson('/client', ['FC-API-KEY' => 'test_doesnotexist'])
            ->assertForbidden()
            ->assertExactJson([
                'status' => false,
                'message' => 'The FC-API-KEY is not recognised.',
                'error' => ['source' => 'api', 'code' => 'invalid_api_key', 'check' => 'client-key'],
            ]);
    }

    public function test_rate_limit_rejection_says_when_to_retry(): void
    {
        config(['authenticator.third_party_rate_limit_cache_store' => 'array']);
        $agencyId = $this->createAgency($this->createCompany());
        $this->createSecuritySettings($agencyId, ['rate_limit_per_minute' => 1]);
        $key = $this->createApiKey($agencyId, 'agency');

        $this->getJson('/throttled', ['FC-API-KEY' => $key])->assertOk();
        $response = $this->getJson('/throttled', ['FC-API-KEY' => $key])
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertJsonPath('error.code', 'rate_limited')
            ->assertJsonPath('error.check', 'rate-limit');
        $this->assertStringStartsWith('Rate limit of 1 requests per minute reached', $response->json('message'));
    }
}
