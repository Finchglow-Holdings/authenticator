<?php

namespace Finchglow\Authenticator\Tests;

use Illuminate\Support\Facades\Schema;

class AuthenticateClientMiddlewareTest extends TestCase
{
    public function test_valid_company_key_sets_company_details(): void
    {
        $companyId = $this->createCompany();
        $branchId = $this->createBranch($companyId, null, 'Head Office', '2024-01-01 00:00:00');
        $key = $this->createApiKey($companyId, 'company');

        $response = $this->getJson('/client', ['FC-API-KEY' => $key])->assertOk();

        $this->assertSame([
            'id', 'type', 'agency_id', 'company_id', 'agency_name', 'agency_type', 'owner_id',
            'company_email', 'company_name', 'company_type', 'branch_name', 'branch_id', 'user_type', 'name',
        ], array_keys($response->json()));
        $response->assertJson([
            'id' => $companyId,
            'type' => 'company',
            'agency_id' => null,
            'company_id' => null,
            'company_email' => 'ops@acme.test',
            'company_name' => 'Acme Travels',
            'company_type' => 'travel_agency',
            'branch_name' => 'Head Office',
            'branch_id' => $branchId,
            'user_type' => 'company',
            'name' => 'Acme Travels',
        ]);
    }

    public function test_valid_agency_key_sets_agency_details(): void
    {
        $companyId = $this->createCompany();
        $agencyId = $this->createAgency($companyId);
        $key = $this->createApiKey($agencyId, 'agency');

        $response = $this->getJson('/client/agency', ['FC-API-KEY' => $key])->assertOk();

        $this->assertSame([
            'id', 'type', 'agency_id', 'company_id', 'agency_name', 'agency_type', 'owner_id',
            'company_email', 'company_name', 'company_type', 'branch_name', 'branch_id', 'user_type', 'name',
        ], array_keys($response->json()));
        $response->assertJson([
            'id' => $agencyId,
            'type' => 'agency',
            'agency_id' => $agencyId,
            'company_id' => $companyId,
            'agency_name' => 'Skyline Partner',
            'agency_type' => 'third_party',
            'company_name' => 'Acme Travels',
            'branch_name' => null,
            'branch_id' => null,
            'user_type' => 'agency',
            'name' => 'Skyline Partner',
        ]);
    }

    public function test_agency_key_resolves_the_hq_branch(): void
    {
        $companyId = $this->createCompany();
        $agencyId = $this->createAgency($companyId);
        $this->createBranch($companyId, $agencyId, 'Ikeja', '2024-01-01 00:00:00');
        $hqId = $this->createBranch($companyId, $agencyId, 'HQ', '2024-06-01 00:00:00');
        $this->createBranch($companyId, null, 'Company HQ', '2023-01-01 00:00:00');
        $key = $this->createApiKey($agencyId, 'agency');

        $this->getJson('/client', ['FC-API-KEY' => $key])
            ->assertOk()
            ->assertJson(['branch_id' => $hqId, 'branch_name' => 'HQ']);
    }

    public function test_company_key_ignores_agency_branches(): void
    {
        $companyId = $this->createCompany();
        $agencyId = $this->createAgency($companyId);
        $this->createBranch($companyId, $agencyId, 'HQ', '2023-01-01 00:00:00');
        $this->createBranch($companyId, null, 'Closed', '2023-06-01 00:00:00', ['status' => 0]);
        $mainId = $this->createBranch($companyId, null, 'Main', '2024-01-01 00:00:00');
        $key = $this->createApiKey($companyId, 'company');

        $this->getJson('/client', ['FC-API-KEY' => $key])
            ->assertOk()
            ->assertJson(['branch_id' => $mainId, 'branch_name' => 'Main']);
    }

    public function test_missing_header_is_rejected_without_writing_error_logs(): void
    {
        $this->getJson('/client')->assertForbidden();

        $this->assertSame(0, $this->db()->table('error_logs')->count());
    }

    public function test_malformed_keys_are_rejected(): void
    {
        foreach (['abc', 'test-abc', 'test_abc_def', 'prod_abc', 'test_', 'live_ab$c'] as $key) {
            $this->getJson('/client', ['FC-API-KEY' => $key])->assertForbidden();
        }

        $this->assertSame(['malformed_api_key'], $this->errorLogCheckpoints());
    }

    public function test_live_key_is_rejected_outside_live_environments(): void
    {
        $companyId = $this->createCompany();
        $key = $this->createApiKey($companyId, 'company', 'live');

        $this->getJson('/client', ['FC-API-KEY' => $key])->assertForbidden();

        $this->assertSame(['env_mismatch'], $this->errorLogCheckpoints());
    }

    public function test_live_key_is_accepted_in_a_live_environment(): void
    {
        config(['authenticator.app_env' => 'production']);
        $companyId = $this->createCompany();
        $key = $this->createApiKey($companyId, 'company', 'live');

        $this->getJson('/client', ['FC-API-KEY' => $key])->assertOk()->assertJson(['id' => $companyId]);
    }

    public function test_test_key_containing_live_is_not_treated_as_live(): void
    {
        $companyId = $this->createCompany();
        $key = $this->createApiKey($companyId, 'company', 'test', [], 'liveAb12cd34live56ef78live');

        $this->getJson('/client', ['FC-API-KEY' => $key])->assertOk();
    }

    public function test_soft_deleted_key_is_rejected(): void
    {
        $companyId = $this->createCompany();
        $key = $this->createApiKey($companyId, 'company', 'test', ['deleted_at' => now()]);

        $this->getJson('/client', ['FC-API-KEY' => $key])->assertForbidden();

        $this->assertSame(['api_key_not_found'], $this->errorLogCheckpoints());
    }

    public function test_inactive_agency_is_rejected(): void
    {
        $agencyId = $this->createAgency($this->createCompany(), ['status' => 'inactive']);
        $key = $this->createApiKey($agencyId, 'agency');

        $this->getJson('/client', ['FC-API-KEY' => $key])->assertForbidden();

        $this->assertSame(['keyable_inactive'], $this->errorLogCheckpoints());
    }

    public function test_soft_deleted_agency_is_rejected(): void
    {
        $agencyId = $this->createAgency($this->createCompany(), ['deleted_at' => now()]);
        $key = $this->createApiKey($agencyId, 'agency');

        $this->getJson('/client', ['FC-API-KEY' => $key])->assertForbidden();
    }

    public function test_agency_of_inactive_company_is_rejected(): void
    {
        $agencyId = $this->createAgency($this->createCompany(['status' => 'inactive']));
        $key = $this->createApiKey($agencyId, 'agency');

        $this->getJson('/client', ['FC-API-KEY' => $key])->assertForbidden();
    }

    public function test_inactive_company_is_rejected(): void
    {
        $companyId = $this->createCompany(['status' => 'inactive']);
        $key = $this->createApiKey($companyId, 'company');

        $this->getJson('/client', ['FC-API-KEY' => $key])->assertForbidden();
    }

    public function test_null_status_is_allowed(): void
    {
        $agencyId = $this->createAgency($this->createCompany(['status' => null]), ['status' => null]);
        $key = $this->createApiKey($agencyId, 'agency');

        $this->getJson('/client', ['FC-API-KEY' => $key])->assertOk();
    }

    public function test_client_type_mismatch_is_rejected(): void
    {
        $companyId = $this->createCompany();
        $key = $this->createApiKey($companyId, 'company');

        $this->getJson('/client/agency', ['FC-API-KEY' => $key])->assertForbidden();

        $this->assertSame(['client_type_mismatch'], $this->errorLogCheckpoints());
    }

    public function test_repeated_failures_from_one_ip_write_a_single_error_log(): void
    {
        $this->getJson('/client', ['FC-API-KEY' => 'test_doesnotexist'])->assertForbidden();
        $this->getJson('/client', ['FC-API-KEY' => 'test_stillmissing'])->assertForbidden();

        $this->assertSame(['api_key_not_found'], $this->errorLogCheckpoints());
    }

    public function test_error_log_failure_does_not_turn_403_into_500(): void
    {
        Schema::connection('authentication_db')->drop('error_logs');

        $this->getJson('/client', ['FC-API-KEY' => 'test_doesnotexist'])->assertForbidden();
    }
}
