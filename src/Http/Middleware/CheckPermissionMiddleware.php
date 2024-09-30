<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Finchglow\Authenticator\Http\Services\JwtAuthService;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

class CheckPermissionMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {

        $jwtAuthService = new JwtAuthService();

        $token = $request->header('token');
        if(!$token) {
            $token = $request->header('token');
        }

        if (!$token) {
            abort(Response::HTTP_UNAUTHORIZED, 'Access denied');
        }

        $decodedToken = $jwtAuthService->decodeToken($token);
        // set Auth user;
        $user = new GenericUser((array) $decodedToken);
        Auth::setUser($user);

        $permissionsTable = env('PERMISSIONS_TABLE', default: 'model_has_permissions');
        $modelType = 'App\Models\User';

        if ($user->type == 'admin') {
            $modelType = 'App\Models\Admin';
        } else if ($user->type == 'agent') {
            $modelType = 'App\Models\Agent';
        }

        $permissions = DB::connection('authentication_db')
            ->table($permissionsTable)
            ->join('permissions', "$permissionsTable.permission_id", '=', 'permissions.id')
            ->where("$permissionsTable.model_id", $user->id)
            ->where("$permissionsTable.model_type", $modelType)
            ->select('permissions.name')
            ->pluck('name');

        if (!in_array($permissions, explode(", ", $permissions))) {
            abort(Response::HTTP_UNAUTHORIZED, 'You do not have permission to perform this action.');
        }


        return $next($request);
    }
}
