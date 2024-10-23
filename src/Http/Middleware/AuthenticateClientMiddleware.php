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
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $apiKey = $request->header('FC-API-KEY');
            if (!$apiKey) {
                abort(401, "UnAuthorized");
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
                abort(401, "UnAuthorized");
            }

            $table = 'companies';
            if ($keyFound->type == 'agency') {
                $table = 'agencies';
            }

            $keyable = DB::connection('authentication_db')
                ->table($table)
                ->where('id', $keyFound->keyable_id)
                ->first();

            if (!$keyFound) {
                abort(401, "UnAuthorized");
            }

            $encryptService = new CipherSweetEncryption();
            $encryptedKey = $encryptService->decryptValue('api_keys', $hashColumn, $keyFound->$hashColumn);


            if ($encryptedKey != $key) {
                abort(401, "UnAuthorized");
            }

            $keyableArray = json_decode(json_encode($keyable), true);
            $request->merge(['company_details' => $keyableArray]);


            return $next($request);
        } catch (\Exception $exception) {
            abort(401, "An error occurred contact admin.");
        }
    }
}
