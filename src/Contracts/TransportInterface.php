<?php

namespace Firauth\Contracts;

use Illuminate\Http\JsonResponse;

interface TransportInterface
{

    /**
     * Generate response for successful login.
     *
     * @param string $token
     * @param array $userPayload
     * @return JsonResponse
     */
    public function loginResponse($token, array $userPayload,bool $forceResend=false);


    /**
     * Generate response for token refresh.
     *
     * @param string $token
     * @param array $claims
     * @return JsonResponse
     */
    public function refreshResponse($token, array $claims);


    /**
     * Generate response for logout.
     *
     * @return JsonResponse
     */
    public function logoutResponse();
}
