<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Middleware\Concerns\LogsAuthorizationFailures;
use Finchglow\Authenticator\Http\Services\CipherSweetEncryption;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Illuminate\Support\Facades\DB;

class AuthenticateClientMiddleware
{
    use LogsAuthorizationFailures;

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, $clientType = ""): Response
    {
        try {
            $apiKey = $request->header('FC-API-KEY');
            if (!$apiKey) {
                $this->abortWithLog('missing_api_key_header');
            }

            if (!preg_match('/^(test|live)_([A-Za-z0-9]+)$/', $apiKey, $matches)) {
                $this->abortWithLog('malformed_api_key');
            }

            $isLive = $matches[1] === 'live';

            if ($isLive && !$this->isLiveEnvironment()) {
                $this->abortWithLog('env_mismatch');
            }

            if ($isLive) {
                $column = "live_hash_api_key";
                $hashColumn = "live_api_key";
            } else {
                $column = "test_hash_api_key";
                $hashColumn = "test_api_key";
            }

            $key = $matches[2];
            $hashedKey = hash('sha256', $key);

            $keyFound = DB::connection('authentication_db')
                ->table('api_keys')
                ->where($column, $hashedKey)
                ->whereNull('api_keys.deleted_at')
                ->first();

            if (!$keyFound) {
                $this->abortWithLog('api_key_not_found');
            }

            $keyFound = DB::connection('authentication_db')
                ->table('api_keys')
                ->leftJoin('agencies', function ($join) {
                    $join->on('agencies.id', '=', 'api_keys.keyable_id')
                        ->where('api_keys.keyable_type', '=', 'App\\Models\\Agency');
                })
                ->leftJoin('companies', function ($join) {
                    $join->on('companies.id', '=', 'agencies.company_id')
                        ->orOn(function ($join) {
                            $join->on('companies.id', '=', 'api_keys.keyable_id')
                                ->where('api_keys.keyable_type', '=', 'App\\Models\\Company');
                        });
                })
                ->where($column, $hashedKey)
                ->whereNull('api_keys.deleted_at')
                ->select(
                    'api_keys.keyable_id as id',
                    'api_keys.test_api_key',
                    'api_keys.live_api_key',
                    'api_keys.type',
                    'agencies.id as agency_id',
                    'agencies.company_id as company_id',
                    'agencies.name as agency_name',
                    'agencies.agency_type',
                    'agencies.owner_id',
                    'companies.email as company_email',
                    'companies.name as company_name',
                    'companies.company_type',
                    'agencies.status as agency_status',
                    'agencies.deleted_at as agency_deleted_at',
                    'companies.status as company_status'
                )
                ->first();

            if (!$keyFound) {
                $this->abortWithLog('keyable_not_found');
            }

            $agencyInactive = $keyFound->type == 'agency'
                && ($keyFound->agency_deleted_at !== null || $keyFound->agency_status === 'inactive');

            if ($agencyInactive || $keyFound->company_status === 'inactive') {
                $this->abortWithLog('keyable_inactive');
            }

            if ($clientType !== "" && $clientType !== $keyFound->type) {
                $this->abortWithLog('client_type_mismatch');
            }

            $encryptService = new CipherSweetEncryption();
            $encryptedKey = $encryptService->decryptValue('api_keys', $hashColumn, $keyFound->$hashColumn);

            if ($encryptedKey != $key) {
                $this->abortWithLog('key_decryption_mismatch');
            }

            unset($keyFound->test_api_key);
            unset($keyFound->live_api_key);
            unset($keyFound->agency_status);
            unset($keyFound->agency_deleted_at);
            unset($keyFound->company_status);

            $branch = DB::connection('authentication_db')
                ->table('branches')
                ->when(
                    $keyFound->type == 'agency',
                    fn ($query) => $query->where('agency_id', $keyFound->id),
                    fn ($query) => $query->where('company_id', $keyFound->id)->whereNull('agency_id')
                )
                ->orderByRaw("name = 'HQ' desc")
                ->orderByDesc('status')
                ->orderBy('created_at')
                ->first(['id', 'name']);

            $keyableArray = json_decode(json_encode($keyFound), true);
            $keyableArray['branch_name'] = $branch->name ?? null;
            $keyableArray['branch_id'] = $branch->id ?? null;
            $keyableArray['user_type'] = $keyFound->type;

            if ($keyFound->type == 'agency') {
                $keyableArray['name'] = $keyableArray['agency_name'];
            } else {
                $keyableArray['name'] = $keyableArray['company_name'];
            }
            $request->merge(['company_details' => $keyableArray]);

            return $next($request);
        } catch (HttpException $exception) {
            // Already logged with its checkpoint in abortWithLog(), just rethrow.
            throw $exception;
        } catch (\Exception $exception) {
            $this->logUnexpectedException($exception);

            abort(500, "Invalid Authentication");
        }
    }

    private function isLiveEnvironment(): bool
    {
        $appEnv = strtolower(trim((string) config('authenticator.app_env')));

        $liveEnvironments = array_map(
            fn ($environment) => strtolower(trim((string) $environment)),
            (array) config('authenticator.live_key_environments', ['prod'])
        );

        return in_array($appEnv, $liveEnvironments, true);
    }
}
