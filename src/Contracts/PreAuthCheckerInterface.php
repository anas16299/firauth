<?php

namespace Firauth\Contracts;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface PreAuthCheckerInterface
{

    /**
     * Handle pre-authentication checks for incoming requests.
     *
     * This method runs before the main JWT authentication flow and can:
     * - Return a Response to immediately stop the request
     * - Return true to bypass JWT authentication entirely
     * - Return null to continue with normal JWT flow
     *
     * @param Request $request
     * @return Response|bool|null
     */
    public function handle(Request $request);
}
