<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Services\CipherSweetEncryption;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\DB;

class AuthenticateClientMiddleware
{
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
                abort(403, "UnAuthorized");
            }

            $isLive = str_contains($apiKey, "live");

            if ($isLive) {
                $column = "live_hash_api_key";
                $hashColumn = "live_api_key";
            } else {
                $column = "test_hash_api_key";
                $hashColumn = "test_api_key";
            }

            $key = explode("_", $apiKey)[1];
            $hashedKey = hash('sha256', $key);

            $keyFound = DB::connection('authentication_db')
                ->table('api_keys')
                ->where($column, $hashedKey)
                ->first();

            if (!$keyFound) {
                abort(403, "UnAuthorized");
            }

            $table = 'companies';
            if ($keyFound->type == 'agency') {
                $table = 'agencies';
            }

            if ($clientType != "" && $clientType != $keyFound->type) {
                abort(403, "UnAuthorized");
            }


            $keyFound = DB::connection('authentication_db')
                ->table('api_keys')
                ->leftJoin('agencies', function ($join) {
                    $join->on('agencies.id', '=', 'api_keys.keyable_id')
                        ->where('api_keys.keyable_type', '=', 'App\\Models\\Agency');
                })
                ->leftJoin('companies', function ($join) {
                    $join->on('companies.id', '=', 'api_keys.keyable_id')
                        ->where('api_keys.keyable_type', '=', 'App\\Models\\Company');
                })
                ->leftJoin('branches as agency_branches', 'agency_branches.agency_id', '=', 'agencies.id')
                ->leftJoin('branches as company_branches', 'company_branches.company_id', '=', 'companies.id')
                ->where($column, $hashedKey)
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
                    'agency_branches.name as agency_branch_name',
                    'agency_branches.id as agency_branch_id',
                    'company_branches.name as branch_name',
                    'company_branches.id as branch_id'
                )
                ->first();

            if (!$keyFound) {
                abort(403, "UnAuthorized");
            }

            $encryptService = new CipherSweetEncryption();
            $encryptedKey = $encryptService->decryptValue('api_keys', $hashColumn, $keyFound->$hashColumn);

            if ($encryptedKey != $key) {
                abort(403, "UnAuthorized");
            }

            unset($keyFound->test_api_key);
            unset($keyFound->live_api_key);

            $keyableArray = json_decode(json_encode($keyFound), true);
            $keyableArray['user_type'] = $keyFound->type;

            if ($keyFound->type == 'agency') {
                $keyableArray['name'] = $keyableArray['agency_name'];
                $keyableArray['branch_name'] = $keyableArray['agency_branch_name'];
                $keyableArray['branch_id'] = $keyableArray['agency_branch_id'];
                unset($keyableArray['agency_branch_id']);
                unset($keyableArray['agency_branch_name']);
            } else {
                $keyableArray['name'] = $keyableArray['company_name'];
            }
            $request->merge(['company_details' => $keyableArray]);

            return $next($request);
        } catch (\Exception $exception) {
            DB::connection('authentication_db')->table('error_logs')->insert([
                'service' => 'authenticator',
                'type' => 'authorization',
                'file' => 'AuthenticateClientMiddleware.php',
                'error' => json_encode([
                    'message' => $exception->getMessage(),
                    'trace' => $exception->getTraceAsString(),
                ]),
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            if ($exception->getMessage() != "UnAuthorized") {
                abort(403, $exception->getMessage());
            }
            abort(403, "UnAuthorized");
        }
    }
}
