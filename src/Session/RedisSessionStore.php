<?php

namespace Firauth\Session;

use Firauth\Contracts\SessionStoreInterface;
use Illuminate\Support\Facades\Redis;

/**
 * Redis implementation of the session store interface.
 *
 * This class provides Redis-based storage for user sessions, allowing for
 * session binding, validation, and revocation operations.
 */
class RedisSessionStore implements SessionStoreInterface
{
    protected $connection;
    protected $prefix;

    /**
     * Create a new Redis session store instance.
     *
     * @param string $connection The Redis connection name
     * @param string $prefix The key prefix for session storage
     */
    public function __construct(string $connection, string $prefix)
    {
        $this->connection = $connection;
        $this->prefix = $prefix;
    }

    /**
     * Generate the Redis key for a user's session.
     *
     * @param string|int $userId The user ID
     * @return string The generated Redis key
     */
    protected function key($userId): string
    {
        return $this->prefix . $userId;
    }

    /**
     * Bind a session ID to a user ID in Redis storage.
     *
     * @param string|int $userId The user ID
     * @param string $sessionId The session ID to bind
     * @return void
     */
    public function bind($userId, $sessionId): void
    {
        $redis = Redis::connection($this->connection);
        $key = $this->key($userId);
        $ttl = config('firauth.session.ttl_seconds');

        if ($ttl) {
            $redis->setex($key, (int)$ttl, $sessionId);
        } else {
            $redis->set($key, $sessionId);
        }
    }

    /**
     * Validate a session ID against the stored session for a user.
     *
     * @param string|int $userId The user ID
     * @param string $sessionId The session ID to validate
     * @return bool True if the session is valid, false otherwise
     */
    public function validate($userId, $sessionId): bool
    {
        $redis = Redis::connection($this->connection);
        $expected = $redis->get($this->key($userId));

        if (is_null($expected)) {
            return false;
        }

        if (!empty($expected) && $expected !== $sessionId) {
            return false;
        }
        return true;
    }

    /**
     * Revoke a user's session from Redis storage.
     *
     * @param string|int $userId The user ID
     * @param string|null $sessionId Optional session ID to validate before revoking
     * @return void
     */
    public function revoke($userId, ?string $sessionId = null): void
    {
        $redis = Redis::connection($this->connection);
        $key   = $this->key($userId);

        if ($sessionId === null) {
            $redis->del($key);
            return;
        }

        $current = $redis->get($key);
        if ($current && hash_equals((string)$current, (string)$sessionId)) {
            $redis->del($key);
        }
    }
}
