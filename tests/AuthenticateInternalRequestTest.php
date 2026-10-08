<?php

namespace Finchglow\Authenticator\Tests;

class AuthenticateInternalRequestTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['authenticator.service_key' => 'internal-service-key-123']);
    }

    public function test_valid_service_key_passes_without_company_details(): void
    {
        $this->getJson('/internal', ['X-Service-Key' => 'internal-service-key-123'])
            ->assertOk()
            ->assertExactJson(['internal_service' => true, 'company_details' => null]);
    }

    public function test_service_key_header_name_is_configurable(): void
    {
        config(['authenticator.service_key_header' => 'X-Internal-Key']);

        $this->getJson('/internal', ['X-Internal-Key' => 'internal-service-key-123'])
            ->assertOk()
            ->assertJson(['internal_service' => true]);
    }

    public function test_wrong_service_key_is_rejected_even_with_a_valid_client_key(): void
    {
        $key = $this->createApiKey($this->createCompany(), 'company');

        $this->getJson('/internal', ['X-Service-Key' => 'wrong', 'FC-API-KEY' => $key])->assertForbidden();

        $this->assertSame(['invalid_service_key'], $this->errorLogCheckpoints());
    }

    public function test_empty_configured_service_key_never_matches(): void
    {
        foreach (['', null] as $configured) {
            config(['authenticator.service_key' => $configured]);

            $this->getJson('/internal', ['X-Service-Key' => ''])->assertForbidden();
            $this->getJson('/internal', ['X-Service-Key' => 'anything'])->assertForbidden();
        }
    }

    public function test_falls_back_to_a_valid_client_key(): void
    {
        $companyId = $this->createCompany();
        $key = $this->createApiKey($companyId, 'company');

        $this->getJson('/internal', ['FC-API-KEY' => $key])
            ->assertOk()
            ->assertJson(['internal_service' => false, 'company_details' => ['id' => $companyId]]);
    }

    public function test_invalid_client_key_fallback_is_rejected(): void
    {
        $this->getJson('/internal', ['FC-API-KEY' => 'test_doesnotexist'])->assertForbidden();

        $this->assertSame(['api_key_not_found'], $this->errorLogCheckpoints());
    }

    public function test_missing_credentials_are_rejected(): void
    {
        $this->getJson('/internal')->assertForbidden();

        $this->assertSame(['missing_internal_credentials'], $this->errorLogCheckpoints());
    }
}
