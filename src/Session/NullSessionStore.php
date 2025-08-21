<?php

namespace Firauth\Session;

use Firauth\Contracts\SessionStoreInterface;

/**
 * A null implementation of SessionStoreInterface that performs no actual session storage.
 *
 * This implementation is useful for testing or when session management is not required.
 */
class NullSessionStore implements SessionStoreInterface
{
    /**
     * Bind a user ID to a session ID (no-op implementation).
     *
     * @param mixed $userId The user identifier
     * @param mixed $sessionId The session identifier
     * @return void
     */
    public function bind($userId, $sessionId)
    { /* no-op */
    }

    /**
     * Validate if a session ID belongs to a user ID.
     * Always returns true in this null implementation.
     *
     * @param mixed $userId The user identifier
     * @param mixed $sessionId The session identifier
     * @return bool Always returns true
     */
    public function validate($userId, $sessionId)
    {
        return true;
    }

    /**
     * Revoke a user's session or all sessions (no-op implementation).
     *
     * @param mixed $userId The user identifier
     * @param string|null $sessionId The session identifier (null to revoke all sessions)
     * @return void
     */
    public function revoke($userId, ?string $sessionId = null): void
    {
        /* no-op */
    }
}
