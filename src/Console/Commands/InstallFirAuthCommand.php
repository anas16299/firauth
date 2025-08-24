<?php

namespace Firauth\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Str;

/**
 * -----------------------------------------------------
 * | FirAuth Package Installer                          |
 * -----------------------------------------------------
 *
 * This command provides an interactive installer for the FirAuth package.
 * It guides users through the configuration setup and environment variable
 * configuration for authentication settings.
 *
 * Installation Steps:
 * -----------------
 * | 1. Publishes configuration files to config/firauth.php
 * | 2. Configures environment variables in .env
 * | 3. Sets up authentication strategy (JWT/Cookie based)
 * | 4. Configures session storage settings
 * | 5. Sets up cookie configuration (if using cookie auth)
 * | 6. Configures JWT settings (if using JWT auth)
 * | 7. Clears application caches
 *
 * Configuration Options:
 * -------------------
 * | - Main service flag
 * | - Auth strategy (JWT/Cookie)
 * | - Cookie settings (domain, lifetime, security)
 * | - Session storage (Redis connection, TTL)
 * | - JWT configuration (algorithm, keys, TTLs)
 * | - Remember me duration
 *
 * @package firauth
 */
class InstallFirAuthCommand extends Command
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'firauth:install
        {--force : Overwrite existing published files}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and configure FIRAUTH (interactive)';

    /**
     * Execute the console command.
     *
     * Runs the interactive installation process:
     * 1. Publishes configuration files
     * 2. Configures environment variables
     * 3. Sets up authentication strategy (JWT/Cookie)
     * 4. Configures session storage
     * 5. Clears application caches
     *
     * @return int
     */
    public function handle(): int
    {
        $this->info(' FIRAUTH Installer (interactive)');
        $this->line('Step 1/3) Publishing config file: config/firauth.php');

        // 1) Publish config
        $this->call('vendor:publish', [
            '--tag'   => 'firauth-config',
            '--force' => (bool) $this->option('force'),
        ]);
        $this->info(' Config published.');

        // 2) Ask interactive questions and write .env
        $this->newLine();
        $this->line('Step 2/3) Configure .env');

        // MAIN SERVICE?
        $isMain = $this->confirm('Is this the MAIN auth service (exposes /FIRAUTH routes)?', (bool) env('FIRAUTH_MAIN_SERVICE', false));
        $this->setEnv('FIRAUTH_MAIN_SERVICE', $isMain ? 'true' : 'false');
        $this->setEnv('FIRAUTH_DRIVER', $isMain ? 'tymon_jwt' : 'public');

        // STRATEGY
        $strategy = $this->choice('Auth strategy', ['cookie', 'jwt'], env('FIRAUTH_STRATEGY', 'jwt') === 'cookie' ? 0 : 1);
        $this->setEnv('FIRAUTH_STRATEGY', $strategy);

        // COOKIE (if cookie strategy)
        if ($strategy === 'cookie') {
            $cookieDomain = $this->ask('Cookie domain for subdomains (e.g. .example.com)', env('FIRAUTH_COOKIE_DOMAIN'));
            $sameSite     = $this->choice('Cookie SameSite', ['Lax','Strict','None'], env('FIRAUTH_COOKIE_SAMESITE', 'Lax') === 'Strict' ? 1 : (env('FIRAUTH_COOKIE_SAMESITE','Lax')==='None'?2:0));
            $cookieLifetime = (int) $this->ask('Cookie lifetime (minutes)', env('FIRAUTH_COOKIE_LIFETIME', 60));
            $cookieSecure  = $this->confirm('Cookie Secure (HTTPS only)?', filter_var(env('FIRAUTH_COOKIE_SECURE', true), FILTER_VALIDATE_BOOLEAN));
            $cookieHttp    = $this->confirm('Cookie HttpOnly?', filter_var(env('FIRAUTH_COOKIE_HTTP_ONLY', true), FILTER_VALIDATE_BOOLEAN));

            $this->setEnv('FIRAUTH_COOKIE_DOMAIN', $cookieDomain ?: '');
            $this->setEnv('FIRAUTH_COOKIE_SAMESITE', $sameSite);
            $this->setEnv('FIRAUTH_COOKIE_LIFETIME', (string)$cookieLifetime);
            $this->setEnv('FIRAUTH_COOKIE_SECURE', $cookieSecure ? 'true' : 'false');
            $this->setEnv('FIRAUTH_COOKIE_HTTP_ONLY', $cookieHttp ? 'true' : 'false');
        }

        // SESSION (Redis)
        $redisConn = $this->ask('Redis connection name for session binding (press Enter to skip)', env('FIRAUTH_SESSION_REDIS'));
        $this->setEnv('FIRAUTH_SESSION_REDIS', $redisConn ?: '');
        $sessionTTL = $this->ask('Session TTL in seconds (e.g. 1209600 for 14 days). Press Enter to skip', env('FIRAUTH_SESSION_TTL'));
        if ($sessionTTL !== null && $sessionTTL !== '') {
            $this->setEnv('FIRAUTH_SESSION_TTL', (string) ((int) $sessionTTL));
        }

        // Remember-me days
        $rememberDays = (int) $this->ask('Remember-me days (longer exp when remember=true)', env('FIRAUTH_REMEMBER_DAYS', 90));
        $this->setEnv('FIRAUTH_REMEMBER_DAYS', (string)$rememberDays);

        // JWT TTLs
        $ttl = (int) $this->ask('JWT_TTL (minutes, access token)', env('JWT_TTL', 60));
        $refreshTtl = (int) $this->ask('JWT_REFRESH_TTL (minutes, refresh window)', env('JWT_REFRESH_TTL', 20160));
        $this->setEnv('JWT_TTL', (string)$ttl);
        $this->setEnv('JWT_REFRESH_TTL', (string)$refreshTtl);

        // JWT ALGO
        $algo = $this->choice('JWT_ALGO', ['RS256','HS256'], strtoupper(env('JWT_ALGO','RS256')) === 'HS256' ? 1 : 0);
        $this->setEnv('JWT_ALGO', $algo);

        if ($algo === 'RS256') {
            // Keys
            $pub = $this->ask('JWT_PUBLIC_KEY (absolute path or file:// URI)', env('JWT_PUBLIC_KEY'));
            $priv = $this->ask('JWT_PRIVATE_KEY (absolute path or file:// URI)', env('JWT_PRIVATE_KEY'));

            $pub = $this->normalizeKeyPath($pub);
            $priv = $this->normalizeKeyPath($priv);

            $this->setEnv('JWT_PUBLIC_KEY', $pub);
            $this->setEnv('JWT_PRIVATE_KEY', $priv);

            // optional passphrase
            $pass = $this->ask('JWT_PASSPHRASE (press Enter if none)', env('JWT_PASSPHRASE',''));
            $this->setEnv('JWT_PASSPHRASE', $pass ?? '');

            $this->validateKeyFile('public', $pub);
            $this->validateKeyFile('private', $priv);

            // HS secret not needed here; clear to avoid confusion
            if (env('JWT_SECRET')) {
                $this->warn('Note: HS secret is not used with RS256. Keeping it does not affect RS256.');
            }
        } else {
            // HS256
            $secret = $this->ask('JWT_SECRET (HS256 signing key)', env('JWT_SECRET'));
            $this->setEnv('JWT_SECRET', $secret ?? '');
            $this->info('Using HS256. RS256 key settings will be ignored.');
        }

        // 3) Clear caches
        $this->newLine();
        $this->line('Step 3/3) Clearing caches');
        $this->callSilent('config:clear');
        $this->callSilent('route:clear');

        $this->newLine();
        $this->info(' FIRAUTH install finished.');
        $this->line('• You can re-run this anytime: php artisan firauth:install');
        $this->line('• Verify routes with:       php artisan route:list | grep firauth');
        $this->line('• Verify config via:        php artisan tinker and run config("firauth")');

        return self::SUCCESS;
    }

    /* -------------------- helpers -------------------- */

    /**
     * Normalize the JWT key file path.
     *
     * @param string|null $value The raw key path
     * @return string The normalized file path
     */
    protected function normalizeKeyPath(?string $value): string
    {
        if (!$value) return '';
        $v = trim($value, " \t\n\r\0\x0B\"'");
        if (Str::startsWith($v, 'file://')) return $v;
        if (Str::startsWith($v, ['/'])) {
            return 'file://' . $v;
        }
        // leave as-is (maybe env var or relative path)
        return $v;
    }

    /**
     * Validate that the JWT key file exists.
     *
     * @param string $type The key type (public/private)
     * @param string|null $uri The file URI to validate
     * @return void
     */
    protected function validateKeyFile(string $type, ?string $uri): void
    {
        if (!$uri) {
            $this->warn("JWT_".strtoupper($type)."_KEY not set.");
            return;
        }
        $path = preg_replace('#^file://#', '', $uri);
        if (!@file_exists($path)) {
            $this->warn("⚠ {$type} key file not found at: {$path}");
        } else {
            $this->info("✓ {$type} key found: {$path}");
        }
    }

    /**
     * Set an environment variable in the .env file.
     *
     * @param string $key The environment variable name
     * @param string|null $value The value to set
     * @return void
     */
    protected function setEnv(string $key, ?string $value): void
    {
        $envPath = base_path('.env');
        if (!is_file($envPath)) {
            $this->error('.env file not found.');
            return;
        }
        $content = file_get_contents($envPath) ?: '';
        $line = $key . '=' . $this->quoteEnv($value ?? '');

        if (preg_match("/^{$this->pregKey($key)}=.*/m", $content)) {
            $content = preg_replace("/^{$this->pregKey($key)}=.*/m", $line, $content);
        } else {
            $content .= PHP_EOL . $line;
        }
        file_put_contents($envPath, $content);
        $this->line("• set {$key}");
    }

    /**
     * Escape a key for use in regular expressions.
     *
     * @param string $key The key to escape
     * @return string The escaped key
     */
    protected function pregKey(string $key): string
    {
        return preg_quote($key, '/');
    }

    /**
     * Quote a value for use in .env file if needed.
     *
     * @param string|null $value The value to quote
     * @return string The quoted value
     */
    protected function quoteEnv(?string $value): string
    {
        if ($value === null) return '""';
        $v = (string) $value;

        // booleans should be bare words
        $lower = strtolower($v);
        if (in_array($lower, ['true','false'], true)) {
            return $lower;
        }

        // empty string
        if ($v === '') return '""';

        // quote if contains spaces or special chars
        if (preg_match('/\s|[#=:"\']/', $v)) {
            $v = str_replace('"', '\"', $v);
            return "\"{$v}\"";
        }

        return $v;
    }
}
