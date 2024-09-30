<?php

namespace Finchglow\Authenticator\Http\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Response;

class JwtAuthService
{
    public function decodeToken(string $token){
        $token = str_replace("Bearer ", "", $token);
        $secretKey = env('JWT_KEY', 'secret');
        $decodedToken = JWT::decode($token, new Key($secretKey, 'HS512'));
        return $decodedToken->data;
    }

    public static function getAuthUser() {
        $token = request()->header('Authorization');
        if (!$token) {
            abort(Response::HTTP_UNAUTHORIZED, 'Unauthorized');
        }

        $service = new self();

        try {
            return $service->decodeToken($token);
        } catch (\Exception $e) {
            abort(Response::HTTP_UNAUTHORIZED, $e->getMessage());
        }
    }
}
