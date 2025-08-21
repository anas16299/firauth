<?php

namespace Firauth\Contracts;

interface SessionStoreInterface
{

    /**
     * Bind a user's ID to a session identifier.
     *
     * @param mixed $userId The ID of the user to bind
     * @param mixed $sessionId The session identifier to bind
     * @return void
     */
    public function bind($userId, $sessionId);


    /**
     * Validate if a user's session is still valid.
     *
     * @param mixed $userId The ID of the user to validate
     * @param mixed $sessionId The session identifier to validate
     * @return bool Returns true if the session is valid, false otherwise
     */
    public function validate($userId, $sessionId);


    /**
     * Revoke a user's session(s).
     *
     * @param mixed $userId The ID of the user whose session(s) to revoke
     * @param string|null $sessionId Optional specific session ID to revoke, if null all user sessions will be revoked
     * @return void
     */
    public function revoke($userId, ?string $sessionId = null): void;

}
