<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Services\JwtAuthService;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class GetUserMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->header('token');
        if ($token) {
            try {
                $jwtAuthService = new JwtAuthService();
                $decodedToken = $jwtAuthService->decodeToken($token);
                $user = new GenericUser((array) $decodedToken);
                Auth::setUser($user);
            } catch (\Throwable $th) {
                return $next($request);
            }
        }
        
        return $next($request);
    }
}
