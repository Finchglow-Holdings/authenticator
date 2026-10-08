<?php

namespace Finchglow\Authenticator;

use Finchglow\Authenticator\Http\Middleware\AuthenticateClientMiddleware;
use Finchglow\Authenticator\Http\Middleware\AuthenticateInternalRequest;
use Finchglow\Authenticator\Http\Middleware\CheckPermissionMiddleware;
use Finchglow\Authenticator\Http\Middleware\EnforceThirdPartyIpAllowlist;
use Finchglow\Authenticator\Http\Middleware\GetUserMiddleware;
use Finchglow\Authenticator\Http\Middleware\IsThirdPartyMiddleware;
use Finchglow\Authenticator\Http\Middleware\JwtAuthMiddleware;
use Finchglow\Authenticator\Http\Middleware\StripClientCompanyDetails;
use Finchglow\Authenticator\Http\Middleware\ThrottleThirdParty;
use Finchglow\Authenticator\Http\Middleware\VerifyThirdPartySignature;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Support\ServiceProvider;

class AuthenticatorServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Merge package defaults so new config keys work even for apps that already
        // published their own config/authenticator.php before these keys existed.
        $this->mergeConfigFrom(__DIR__ . '/config/authenticator.php', 'authenticator');
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $this->app['router']->aliasMiddleware('auth-client-key', AuthenticateClientMiddleware::class);
        $this->app['router']->aliasMiddleware('auth-internal', AuthenticateInternalRequest::class);
        $this->app['router']->aliasMiddleware('check-permission', CheckPermissionMiddleware::class);
        $this->app['router']->aliasMiddleware('get-user', GetUserMiddleware::class);
        $this->app['router']->aliasMiddleware('jwt-auth', JwtAuthMiddleware::class);
        $this->app['router']->aliasMiddleware('third-party', IsThirdPartyMiddleware::class);
        $this->app['router']->aliasMiddleware('third-party-ip-allowlist', EnforceThirdPartyIpAllowlist::class);
        $this->app['router']->aliasMiddleware('third-party-signature', VerifyThirdPartySignature::class);
        $this->app['router']->aliasMiddleware('third-party-throttle', ThrottleThirdParty::class);

        if ($this->app->bound(HttpKernel::class)) {
            $kernel = $this->app->make(HttpKernel::class);

            if (method_exists($kernel, 'prependMiddleware')) {
                $kernel->prependMiddleware(StripClientCompanyDetails::class);
            }
        }

        $this->publishes([
            __DIR__ . '/Http/Middleware/AuthenticateClientMiddleware.php' => app_path('Http/Middleware/AuthenticateClientMiddleware.php'),
        ], 'middleware');

        $this->publishes([
            __DIR__ . '/config/authenticator.php' => config_path('authenticator.php'),
        ], 'config');
    }
}
