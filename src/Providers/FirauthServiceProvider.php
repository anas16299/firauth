<?php

namespace Firauth\Providers;

use Firauth\Drivers\JwtTymonDriver;
use Firauth\Drivers\PublicKeyJwtDriver;
use Firauth\Transport\BodyTransport;
use Firauth\Session\NullSessionStore;
use Firauth\Session\RedisSessionStore;
use Firauth\Transport\CookieTransport;
use Illuminate\Support\ServiceProvider;
use Firauth\Contracts\TransportInterface;
use Firauth\Contracts\TokenDriverInterface;
use Firauth\Contracts\SessionStoreInterface;
use Firauth\Http\Middleware\EnsureTokenPresent;
use Firauth\Http\Middleware\EnsureAuthenticated;
use Firauth\Console\Commands\InstallFirAuthCommand;

class FirauthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Merge package config (available even if not published)
        $this->mergeConfigFrom(__DIR__ . '/../Config/firauth.php', 'firauth');

        // Token driver (open for extension)
        $this->app->bind(TokenDriverInterface::class, function ($app) {
            $driver = config('firauth.driver', 'tymon_jwt');
            switch ($driver) {
                case 'tymon_jwt':
                    return new JwtTymonDriver();
                case 'public':
                    return new PublicKeyJwtDriver();
                default:
                    throw new \RuntimeException('Unsupported firauth driver: ' . $driver);
            }
        });

        // Session store
        $this->app->bind(SessionStoreInterface::class, function ($app) {
            $conn = config('firauth.session.redis_connection');
            $prefix = config('firauth.session.key_prefix', 'session_');
            if ($conn) {
                return new RedisSessionStore($conn, $prefix);
            }
            return new NullSessionStore();
        });

        // Transport
        $this->app->bind(TransportInterface::class, function ($app) {
            $strategy = config('firauth.strategy', 'jwt'); // jwt=body, cookie=cookie
            if ($strategy === 'cookie') {
                return new CookieTransport(config('firauth.cookie', []));
            }
            return new BodyTransport();
        });


    }

    public function boot(): void
    {
        // Publish config so apps can customize
        $this->publishes([
            __DIR__ . '/../Config/firauth.php' => config_path('firauth.php'),
        ], 'firauth-config');

        // Conditionally load routes only if this app is the main auth service
        if (config('firauth.main_service', false)) {
            app('router')
                ->middleware('api')
                ->prefix('api')
                ->group(function () {
                    require __DIR__ . '/../Routes/api.php';
                });
        }

        app('router')->aliasMiddleware('firauth', EnsureAuthenticated::class);
        app('router')->aliasMiddleware('firauth.token', EnsureTokenPresent::class);

        if ($this->app->runningInConsole()) {
            $this->commands([
                InstallFirAuthCommand::class,
            ]);
        }
    }
}
