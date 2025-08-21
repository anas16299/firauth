<?php

namespace Firauth\Contracts;

interface TokenDriverInterface
{

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param array $credentials
     * @param int|null $rememberDays
     * @param array|null $additionalClaims
     * @return mixed
     */
    public function attempt(array $credentials, $rememberDays = null, array $additionalClaims = null);


    /**
     * Refresh the current authentication token.
     *
     * @return mixed
     */
    public function refresh();


    /**
     * Invalidate the current authentication token.
     *
     * @return mixed
     */
    public function invalidate();


    /**
     * Get the authenticated user's payload.
     *
     * @return mixed
     */
    public function userPayload();


    /**
     * Get the token payload.
     *
     * @return array|null
     */
    public function payload(): ?array;
}
