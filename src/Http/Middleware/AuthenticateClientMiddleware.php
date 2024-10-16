<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
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
    public function handle(Request $request, Closure $next, $tableName): Response
    {
        if (!$request->header('FC-API-KEY')) {
            return response()->json(['error' => 'API key missing'], 401);
        }

        $apiKey = $request->header('FC-API-KEY');

        $apiKeyColumn = env('API_KEY_COLUMN', 'api_key');
        $apiSecretColumn = env('API_SECRET_COLUMN', 'api_secret');

         // Check if the API key exists in the specified table
         $client = DB::table($tableName)
            ->where($apiKeyColumn, $apiKey)
            ->first();

        if (!$client) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
