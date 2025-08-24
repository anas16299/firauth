<?php

/*
|--------------------------------------------------------------------------
| Firauth Authentication Configuration
|--------------------------------------------------------------------------
|
| This file contains the configuration options for the Firauth authentication
| package. These settings control various aspects of authentication including
| token management, session handling, and middleware configuration.
|
*/

return [
    /*
    |--------------------------------------------------------------------------
    | Authentication Service Configuration
    |--------------------------------------------------------------------------
    |
    | These settings determine the core behavior of the authentication service.
    |
    */

    // Whether this instance is the main authentication service or consumer
    'main_service' => env('FIRAUTH_MAIN_SERVICE', false),

    // The authentication driver to use (currently supports 'tymon_jwt')
    'driver' => env('FIRAUTH_DRIVER', 'tymon_jwt'),

    // The token transport strategy ('jwt' for body transport, 'cookie' for cookie transport)
    'strategy' => env('FIRAUTH_STRATEGY', 'jwt'),

    /*
    |--------------------------------------------------------------------------
    | Cookie Settings
    |--------------------------------------------------------------------------
    |
    | Configure how the authentication token is stored and transmitted via cookies.
    |
    */

    'cookie' => [
        // The name of the cookie that will store the token
        'name' => env('FIRAUTH_COOKIE_NAME', 'FIRAUTH_token'),
        // The domain scope for the cookie
        'domain' => env('FIRAUTH_COOKIE_DOMAIN', null),
        // Cookie lifetime in minutes
        'lifetime' => (int)env('FIRAUTH_COOKIE_LIFETIME', 60),
        // Whether the cookie should only be transmitted over HTTPS
        'secure' => (bool)env('FIRAUTH_COOKIE_SECURE', true),
        // Whether the cookie is accessible only through HTTP(S) protocol
        'http_only' => (bool)env('FIRAUTH_COOKIE_HTTP_ONLY', true),
        // SameSite cookie attribute ('Lax', 'Strict', or 'None')
        'same_site' => env('FIRAUTH_COOKIE_SAMESITE', 'None'),
        // Cookie path
        'path'      => '/',
    ],

    /*
    |--------------------------------------------------------------------------
    | Session Management
    |--------------------------------------------------------------------------
    |
    | Configure the session storage and behavior for maintaining user sessions.
    |
    */

    'session' => [
        // Redis connection name for session storage
        'redis_connection' => env('FIRAUTH_SESSION_REDIS', null),
        // Prefix for session keys in storage
        'key_prefix' => env('FIRAUTH_SESSION_PREFIX', 'session_'),
        // Session time-to-live in seconds (null for unlimited)
        'ttl_seconds'      => env('FIRAUTH_SESSION_TTL', null),
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for JWT token generation, validation, and renewal behavior.
    |
    */

    'jwt' => [
        // Number of days to remember the user when "remember me" is used
        'remember_me_days' => (int)env('FIRAUTH_REMEMBER_DAYS', 90),
        // Whether to include model claims in the JWT payload
        'use_model_claims' => (bool)env('FIRAUTH_USE_MODEL_CLAIMS', true),
        // Whether to bind the session during login
        'bind_session_in_login' => (bool)env('FIRAUTH_BIND_SESSION_IN_LOGIN', false),
        // Time window in seconds before token expiry to trigger renewal
        'renew_if_less_than_seconds' => (int)env('FIRAUTH_RENEW_WINDOW', 600),
    ],

    /*
    |--------------------------------------------------------------------------
    | Middleware Configuration
    |--------------------------------------------------------------------------
    |
    | Configure authentication middleware checkers that run before and after
    | the main authentication process.
    |
    */

    'middleware' => [
        // Pre-auth checkers (run before JWT). Each item is a class name.
        'pre' => [

        ],

        // Post-auth checkers (run after JWT+session). Each item is a class name.
        'post' => [

        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Routes Configuration
    |--------------------------------------------------------------------------
    |
    | Configure the routing settings for authentication endpoints including
    | the route prefix and which routes should be exposed.
    |
    */

    'routes' => [
        // The prefix for all authentication routes
        'prefix' => env('FIRAUTH_ROUTES_PREFIX', 'firauth'),
        // Which authentication routes should be exposed
        'expose' => [
            'login' => (bool)env('FIRAUTH_ROUTES_EXPOSE_LOGIN', true),
            'refresh' => (bool)env('FIRAUTH_ROUTES_EXPOSE_REFRESH', true),
            'logout' => (bool)env('FIRAUTH_ROUTES_EXPOSE_LOGOUT', true),
        ],
    ],

    'local_keys'=>['testing','test','stg','staging','local','dev','development']



];
