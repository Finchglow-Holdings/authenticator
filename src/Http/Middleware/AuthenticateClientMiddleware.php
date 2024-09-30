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
    public function handle(Request $request, Closure $next): Response
    {
        if (!$request->header('X-API-KEY')) {
            return response()->json(['error' => 'API key missing'], 401);
        }


            // Get environment variables for the table and column names
        $table = env('API_KEY_TABLE', 'users'); // Default to 'users' if not set
        $apiKeyColumn = env('API_KEY_COLUMN', 'api_key');
        $apiSecretColumn = env('API_SECRET_COLUMN', 'api_secret');

         // Check if the API key exists in the specified table
         $client = DB::table($table)
            ->where($apiKeyColumn, $apiKeyColumn)
            ->first();

        if (!$client) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
