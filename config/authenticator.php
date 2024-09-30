<?php

return [
    'api_key_table' => env('API_KEY_TABLE', 'users'), // Default table
    'api_key_column' => env('API_KEY_COLUMN', 'api_key'), // Default column for API key
    'api_secret_column' => env('API_SECRET_COLUMN', 'api_secret'), // Default column for API secret
    'jwt_key' => env('JWT_KEY', 'secret'), // Default key for JWT
    'permissions_table' => env('PERMISSIONS_TABLE', 'model_has_permissions'),
];
