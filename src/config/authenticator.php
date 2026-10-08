<?php

return [
    'api_key_table' => env('API_KEY_TABLE', 'users'), // Default table
    'api_key_column' => env('API_KEY_COLUMN', 'api_key'), // Default column for API key
    'api_secret_column' => env('API_SECRET_COLUMN', 'api_secret'), // Default column for API secret
    'jwt_key' => env('JWT_KEY', 'secret'), // Default key for JWT
    'permissions_table' => env('PERMISSIONS_TABLE', 'model_has_permissions'),
    'app_env' => env('APP_ENV', 'dev'),

    // Which app_env values are treated as production, and so may use live_ API keys.
    // Compared case-insensitively. Services name their prod environment differently
    // ("prod" vs "production"), so this accepts a comma-separated list.
    'live_key_environments' => array_values(array_filter(array_map(
        'trim',
        explode(',', (string) env('AUTHENTICATOR_LIVE_ENVIRONMENTS', 'prod,production,live'))
    ))),

    // Third-party hardening: signature verification, IP allowlist, per-agency rate limit.
    'third_party_security_table' => env('THIRD_PARTY_SECURITY_TABLE', 'third_party_security_settings'),
    'third_party_signature_header' => env('THIRD_PARTY_SIGNATURE_HEADER', 'X-FC-Signature'),
    'third_party_timestamp_header' => env('THIRD_PARTY_TIMESTAMP_HEADER', 'X-FC-Timestamp'),
    'third_party_signature_tolerance' => env('THIRD_PARTY_SIGNATURE_TOLERANCE', 300),
    // Null = use the app's default cache store. Set to a shared store (e.g. "redis") for
    // correct replay protection when the app runs multiple instances.
    'third_party_signature_cache_store' => env('THIRD_PARTY_SIGNATURE_CACHE_STORE'),
    'default_third_party_rate_limit' => env('DEFAULT_THIRD_PARTY_RATE_LIMIT', 60),

    // The upstream API gateway (Fusio) already enforces per-client IP allowlist + rate limit
    // for third-party traffic (see ApiGatewayService::registerClient in travels-user-service).
    // These two flags let ops disable the app-level duplicates in one place, across every
    // consuming service, once the gateway is confirmed as the sole enforcement point - without
    // having to edit route middleware arrays in each service.
    'third_party_ip_allowlist_middleware_enabled' => env('THIRD_PARTY_IP_ALLOWLIST_MIDDLEWARE_ENABLED', true),
    'third_party_rate_limit_middleware_enabled' => env('THIRD_PARTY_RATE_LIMIT_MIDDLEWARE_ENABLED', true),
];
