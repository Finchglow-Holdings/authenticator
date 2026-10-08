<?php

namespace Finchglow\Authenticator\Tests;

class StripClientCompanyDetailsTest extends TestCase
{
    public function test_json_body_and_query_company_details_are_stripped(): void
    {
        $this->postJson('/echo?company_details[id]=spoofed', ['company_details' => ['id' => 'spoofed', 'agency_id' => 'spoofed']])
            ->assertOk()
            ->assertExactJson(['company_details' => null]);
    }

    public function test_form_body_company_details_are_stripped(): void
    {
        $this->post('/echo', ['company_details' => ['id' => 'spoofed']], ['Accept' => 'application/json'])
            ->assertOk()
            ->assertExactJson(['company_details' => null]);
    }

    public function test_client_key_still_sets_company_details_after_stripping(): void
    {
        $companyId = $this->createCompany();
        $key = $this->createApiKey($companyId, 'company');

        $this->getJson('/client?company_details[id]=spoofed', ['FC-API-KEY' => $key])
            ->assertOk()
            ->assertJson(['id' => $companyId]);
    }
}
