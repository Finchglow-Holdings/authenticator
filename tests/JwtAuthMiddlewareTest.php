<?php

namespace Finchglow\Authenticator\Tests;

use Illuminate\Support\Str;

class JwtAuthMiddlewareTest extends TestCase
{
    public function test_agent_bound_to_the_client_key_company_is_authenticated(): void
    {
        $companyId = $this->createCompany();
        $key = $this->createApiKey($companyId, 'company');
        $agentId = (string) Str::ulid();
        $token = $this->token(['id' => $agentId, 'type' => 'agent', 'company_id' => $companyId]);

        $this->getJson('/agent', ['FC-API-KEY' => $key, 'token' => $token])
            ->assertOk()
            ->assertJson(['id' => $agentId]);
    }

    public function test_agent_from_another_company_is_rejected(): void
    {
        $key = $this->createApiKey($this->createCompany(), 'company');
        $token = $this->token(['id' => (string) Str::ulid(), 'type' => 'agent', 'company_id' => (string) Str::ulid()]);

        $this->getJson('/agent', ['FC-API-KEY' => $key, 'token' => $token])
            ->assertUnauthorized()
            ->assertExactJson(['status' => false, 'error' => 'Unauthorized to access this resource']);
    }

    public function test_invalid_token_returns_a_generic_401(): void
    {
        $companyId = $this->createCompany();
        $key = $this->createApiKey($companyId, 'company');
        $claims = ['id' => (string) Str::ulid(), 'type' => 'agent', 'company_id' => $companyId];
        $badTokens = ['not-a-jwt', $this->token($claims, 3600, str_repeat('f', 64)), $this->token($claims, -120)];

        foreach ($badTokens as $badToken) {
            $this->getJson('/agent', ['FC-API-KEY' => $key, 'token' => $badToken])
                ->assertUnauthorized()
                ->assertExactJson(['status' => false, 'error' => 'Unauthorized']);
        }
    }

    public function test_missing_jwt_key_returns_a_generic_401(): void
    {
        $companyId = $this->createCompany();
        $key = $this->createApiKey($companyId, 'company');
        $token = $this->token(['id' => (string) Str::ulid(), 'type' => 'agent', 'company_id' => $companyId]);
        config(['authenticator.jwt_key' => null]);

        $this->getJson('/agent', ['FC-API-KEY' => $key, 'token' => $token])
            ->assertUnauthorized()
            ->assertExactJson(['status' => false, 'error' => 'Unauthorized']);
    }
}
