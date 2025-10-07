<?php

namespace Firauth\Transport;

use Firauth\Contracts\TransportInterface;
use Firauth\Support\ResponseHandler;
use Illuminate\Http\JsonResponse;

/**
 * Class BodyTransport
 *
 * Handles API responses by returning JSON responses with tokens in the response body.
 * This transport is suitable for API-only applications that don't require cookie-based authentication.
 *
 * @package firauth\Transport
 */
class BodyTransport implements TransportInterface
{
    /**
     * Generate a successful login response with the token in the response body.
     *
     * @param string $token The JWT token
     * @param array $userPayload Additional user information
     * @return JsonResponse
     */
    public function loginResponse($token, array $userPayload,bool $forceResend=false): JsonResponse
    {
        return ResponseHandler::success(['token' => $token]);
    }

    /**
     * Generate a successful token refresh response with the new token in the response body.
     *
     * @param string $token The new JWT token
     * @param array $claims The JWT claims
     * @return JsonResponse
     */
    public function refreshResponse($token, $claims): JsonResponse
    {
        return ResponseHandler::success(['token' => $token]);
    }

    /**
     * Generate a successful logout response.
     *
     * @return JsonResponse
     */
    public function logoutResponse(): JsonResponse
    {
        return ResponseHandler::success();
    }
}
