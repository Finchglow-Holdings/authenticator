<?php

namespace Finchglow\Authenticator;

use Finchglow\Authenticator\Http\Middleware\AuthenticateClientMiddleware;
use Finchglow\Authenticator\Http\Middleware\CheckPermissionMiddleware;
use Finchglow\Authenticator\Http\Middleware\GetUserMiddleware;
use Finchglow\Authenticator\Http\Middleware\JwtAuthMiddleware;
use Illuminate\Support\ServiceProvider;

class AuthenticatorServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $this->app['router']->aliasMiddleware('auth-client-key', AuthenticateClientMiddleware::class);
        $this->app['router']->aliasMiddleware('check-permission', CheckPermissionMiddleware::class);
        $this->app['router']->aliasMiddleware('get-user', GetUserMiddleware::class);
        $this->app['router']->aliasMiddleware('jwt-auth', JwtAuthMiddleware::class);

        $this->publishes([
            __DIR__ . '/Http/Middleware/AuthenticateClientMiddleware.php' => app_path('Http/Middleware/AuthenticateClientMiddleware.php'),
        ], 'middleware');

        $this->publishes([
            __DIR__ . '/config/authenticator.php' => config_path('authenticator.php'),
        ], 'config');
    }
}
