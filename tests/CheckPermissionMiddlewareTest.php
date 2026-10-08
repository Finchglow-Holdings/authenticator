<?php

namespace Finchglow\Authenticator\Tests;

use Illuminate\Support\Str;

class CheckPermissionMiddlewareTest extends TestCase
{
    public function test_owner_bypasses_the_permission_check(): void
    {
        $token = $this->token(['id' => (string) Str::ulid(), 'type' => 'company', 'role' => 'owner']);

        $this->getJson('/permission', ['token' => $token])->assertOk();
    }

    public function test_direct_permission_is_allowed(): void
    {
        $adminId = (string) Str::ulid();
        $permissionId = $this->db()->table('permissions')->insertGetId(['name' => 'view bookings']);
        $this->db()->table('model_has_permissions')->insert([
            'permission_id' => $permissionId,
            'model_type' => 'App\\Models\\Admin',
            'model_id' => $adminId,
        ]);
        $token = $this->token(['id' => $adminId, 'type' => 'company', 'role' => 'admin']);

        $this->getJson('/permission', ['token' => $token])->assertOk()->assertJson(['id' => $adminId]);
    }

    public function test_missing_permission_returns_401(): void
    {
        $token = $this->token(['id' => (string) Str::ulid(), 'type' => 'agent', 'role' => 'agent']);

        $this->getJson('/permission', ['token' => $token])->assertUnauthorized();
    }

    public function test_invalid_token_returns_401_not_500(): void
    {
        $this->getJson('/permission', ['token' => 'not-a-jwt'])
            ->assertUnauthorized()
            ->assertJson(['message' => 'Access denied']);
    }

    public function test_missing_token_returns_401(): void
    {
        $this->getJson('/permission')->assertUnauthorized();
    }
}
