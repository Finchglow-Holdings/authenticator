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
            $companyDetails = request()->company_details;

            // if it is an agent or user, it checks if they are using the right company of agency details
            if (!in_array($type, ["super_admin", "company"])) {
                if (empty($companyDetails)) {
                    return response()->json(['status' => false, 'error' => 'Unauthorized to access this resource'], Response::HTTP_UNAUTHORIZED);
                }
                if ($loggedInUser->type == 'agent') {
                    if ($loggedInUser->company_id !== $companyDetails['id'] ?? "") {
                        return response()->json(['status' => false, 'error' => 'Unauthorized to access this resource'], Response::HTTP_UNAUTHORIZED);
                    }
                }

                if ($loggedInUser->type == 'customer') {
                    if ($loggedInUser->company_id !== $companyDetails['company_id'] ?? "") {
                        return response()->json(['status' => false, 'error' => 'Unauthorized to access this resource'], Response::HTTP_UNAUTHORIZED);
                    }

                    if ($loggedInUser->agency_id !== $companyDetails['agency_id'] ?? "") {
                        return response()->json(['status' => false, 'error' => 'Unauthorized to access this resource'], Response::HTTP_UNAUTHORIZED);
                    }
                }
            }

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
