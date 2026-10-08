<?php

namespace Finchglow\Authenticator\Tests;

use Finchglow\Authenticator\AuthenticatorServiceProvider;
use Finchglow\Authenticator\Http\Services\CipherSweetEncryption;
use Firebase\JWT\JWT;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app)
    {
        return [AuthenticatorServiceProvider::class];
    }

    protected function defineEnvironment($app)
    {
        $app['config']->set('database.connections.authentication_db', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
            'foreign_key_constraints' => false,
        ]);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('authenticator.app_env', 'local');
    }

    protected function defineRoutes($router)
    {
        $companyDetails = fn () => response()->json(request()->company_details);

        $router->get('client', $companyDetails)->middleware('auth-client-key');
        $router->get('client/agency', $companyDetails)->middleware('auth-client-key:agency');
        $router->get('internal', fn () => response()->json([
            'internal_service' => request()->attributes->get('internal_service', false),
            'company_details' => request()->company_details,
        ]))->middleware('auth-internal');
        $router->post('echo', fn () => response()->json(['company_details' => request()->company_details]));
        $router->get('agent', fn () => response()->json(['id' => Auth::user()->id]))->middleware(['auth-client-key', 'jwt-auth:agent']);
        $router->get('permission', fn () => response()->json(['id' => Auth::user()->id]))->middleware('check-permission:view bookings');
        $router->post('signed', fn () => 'ok')->middleware(['auth-client-key', 'third-party-signature']);
        $router->get('allowlisted', fn () => 'ok')->middleware(['auth-client-key', 'third-party-ip-allowlist']);
        $router->get('throttled', fn () => 'ok')->middleware(['auth-client-key', 'third-party-throttle']);
        $router->get('hardened', fn () => 'ok')->middleware(['auth-client-key', 'third-party-ip-allowlist', 'third-party-signature', 'third-party-throttle']);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $schema = Schema::connection('authentication_db');

        $schema->create('companies', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->string('email');
            $table->string('name');
            $table->string('company_type');
            $table->string('status')->nullable();
            $table->timestamps();
        });

        $schema->create('agencies', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->ulid('company_id');
            $table->string('name');
            $table->string('agency_type');
            $table->ulid('owner_id')->nullable();
            $table->string('status')->nullable();
            $table->timestamps();
            $table->softDeletes();
        });

        $schema->create('branches', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->ulid('company_id');
            $table->string('agency_id')->nullable();
            $table->string('name');
            $table->boolean('status')->default(1);
            $table->timestamps();
        });

        $schema->create('api_keys', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->ulid('keyable_id');
            $table->string('keyable_type');
            $table->string('type');
            $table->longText('test_hash_api_key')->nullable();
            $table->longText('live_hash_api_key')->nullable();
            $table->longText('test_api_key')->nullable();
            $table->longText('live_api_key')->nullable();
            $table->timestamps();
            $table->softDeletes();
        });

        $schema->create('permissions', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('guard_name')->default('api');
        });

        $schema->create('model_has_permissions', function (Blueprint $table) {
            $table->unsignedBigInteger('permission_id');
            $table->string('model_type');
            $table->string('model_id');
        });

        $schema->create('third_party_security_settings', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->ulid('keyable_id');
            $table->string('keyable_type');
            $table->longText('hmac_secret')->nullable();
            $table->json('allowed_ips')->nullable();
            $table->unsignedInteger('rate_limit_per_minute')->nullable();
            $table->boolean('enforce_signature')->default(false);
            $table->boolean('enforce_ip_allowlist')->default(false);
            $table->timestamps();
        });

        $schema->create('error_logs', function (Blueprint $table) {
            $table->id();
            $table->string('service');
            $table->string('type');
            $table->string('file');
            $table->json('error');
            $table->timestamps();
        });
    }

    protected function db()
    {
        return DB::connection('authentication_db');
    }

    protected function createCompany(array $attributes = []): string
    {
        $id = (string) Str::ulid();

        $this->db()->table('companies')->insert(array_merge([
            'id' => $id,
            'email' => 'ops@acme.test',
            'name' => 'Acme Travels',
            'company_type' => 'travel_agency',
            'status' => 'active',
        ], $attributes));

        return $id;
    }

    protected function createAgency(string $companyId, array $attributes = []): string
    {
        $id = (string) Str::ulid();

        $this->db()->table('agencies')->insert(array_merge([
            'id' => $id,
            'company_id' => $companyId,
            'name' => 'Skyline Partner',
            'agency_type' => 'third_party',
            'owner_id' => (string) Str::ulid(),
            'status' => 'active',
        ], $attributes));

        return $id;
    }

    protected function createBranch(string $companyId, ?string $agencyId, string $name, string $createdAt, array $attributes = []): string
    {
        $id = (string) Str::ulid();

        $this->db()->table('branches')->insert(array_merge([
            'id' => $id,
            'company_id' => $companyId,
            'agency_id' => $agencyId,
            'name' => $name,
            'status' => 1,
            'created_at' => $createdAt,
        ], $attributes));

        return $id;
    }

    protected function createApiKey(string $keyableId, string $type, string $mode = 'test', array $attributes = [], ?string $secret = null): string
    {
        $secret ??= Str::random($mode === 'live' ? 32 : 24);

        $this->db()->table('api_keys')->insert(array_merge([
            'id' => (string) Str::ulid(),
            'keyable_id' => $keyableId,
            'keyable_type' => $type === 'agency' ? 'App\\Models\\Agency' : 'App\\Models\\Company',
            'type' => $type,
            "{$mode}_hash_api_key" => hash('sha256', $secret),
            "{$mode}_api_key" => (new CipherSweetEncryption())->encryptKey('api_keys', "{$mode}_api_key", $secret),
        ], $attributes));

        return "{$mode}_{$secret}";
    }

    protected function createSecuritySettings(string $agencyId, array $attributes = []): void
    {
        $this->db()->table('third_party_security_settings')->insert(array_merge([
            'id' => (string) Str::ulid(),
            'keyable_id' => $agencyId,
            'keyable_type' => 'App\\Models\\Agency',
        ], $attributes));
    }

    protected function token(array $data, int $expiresIn = 3600, ?string $key = null): string
    {
        $now = time();

        return JWT::encode([
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $expiresIn,
            'data' => $data,
        ], $key ?? config('authenticator.jwt_key'), 'HS512');
    }

    protected function errorLogCheckpoints(): array
    {
        return $this->db()->table('error_logs')->pluck('error')
            ->map(fn ($error) => json_decode($error, true)['checkpoint'])
            ->all();
    }
}
