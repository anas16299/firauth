<?php

namespace Firauth\Contracts;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Post-Authentication Checker Interface
 *
 * Implementations of this interface are used as the final gate
 * in the authentication process to perform additional checks
 * or modify user attributes after successful JWT authentication.
 */
interface PostAuthCheckerInterface
{
    /**
     * Handle post-authentication checks and user attribute modifications.
     *
     * @param Request $request
     * @param array  &$userAttrs User attributes that reference can modify
     * @return Response|null|bool Returns Response to block authentication, null to proceed
     */

    public function handle(Request $request, array &$userAttrs);
}
