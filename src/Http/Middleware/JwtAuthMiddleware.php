<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Services\JwtAuthService;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;

class JwtAuthMiddleware {
    public function handle($request, Closure $next, $type)
    {
        $jwtAuthService = new JwtAuthService();
//       $token = $request->header('Authorization');
        $token = null;

        if(!$token) {
            $token = $request->header('token');
        }

        if (!$token) {
            return response()->json(['status' => false, 'error' => 'Unauthorized'], Response::HTTP_UNAUTHORIZED);
        }

        try {
            $loggedInUser =  $jwtAuthService->decodeToken($token);

            if ($loggedInUser->type != $type) {
                return response()->json(['status' => false, 'error' => 'Unauthorized to access this resource'], Response::HTTP_UNAUTHORIZED);
            }

            $request->merge(['user' => (array) $loggedInUser]);

            // set Auth user;
            $user = new GenericUser((array) $loggedInUser);
            Auth::setUser($user);

            return $next($request);

        } catch (\Exception $e) {
            return response()->json(['status' => false, 'error' => $e->getMessage()], Response::HTTP_UNAUTHORIZED);
        }
    }
}
