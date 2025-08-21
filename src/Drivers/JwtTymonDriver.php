<?php

namespace Firauth\Drivers;

/**
 * JWT Authentication driver using Tymon JWT-Auth package.
 *
 * @link https://github.com/tymondesigns/jwt-auth
 * @package firauth\Drivers
 */

use JWTAuth;
use Carbon\Carbon;
use Tymon\JWTAuth\Exceptions\JWTException;
use Firauth\Contracts\TokenDriverInterface;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;

class JwtTymonDriver implements TokenDriverInterface
{
    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param array $credentials
     * @param int|null $rememberDays
     * @param array|null $additionalClaims
     * @return array|null Returns an array with token, claims and user data if successful, null otherwise
     */
    public function attempt(array $credentials, $rememberDays = null, array $additionalClaims = null)
    {
        $claims = [];

        if (!is_null($rememberDays) && $rememberDays > 0) {
            $claims['exp'] = Carbon::now()->addDays((int)$rememberDays)->timestamp;
        }

        if (!config('firauth.jwt.use_model_claims', true) && is_array($additionalClaims)) {
            $claims = array_merge($claims, $additionalClaims);
        }

        $token = !empty($claims)
            ? JWTAuth::customClaims($claims)->attempt($credentials)
            : JWTAuth::attempt($credentials);

        if (!$token) {
            return null;
        }
        $fullClaims = JWTAuth::setToken($token)->getPayload()->toArray();

        $u = auth()->user();

        return [
            'token' => $token,
            'claims' => $fullClaims,
            'user' => $u->toArray(),
        ];
    }

    /**
     * Refresh a token.
     *
     * @return array Returns an array with new token and claims
     */
    public function refresh()
    {
        $new = JWTAuth::refresh(JWTAuth::getToken());
        $claims = JWTAuth::setToken($new)->getPayload()->toArray();
        return ['token' => $new, 'claims' => $claims];
    }

    /**
     * Invalidate a token.
     *
     * @return void
     */
    public function invalidate()
    {
        JWTAuth::invalidate(JWTAuth::getToken());
    }

    /**
     * Get an authenticated user payload with claims.
     *
     * @return array|null Returns array with user data, session ID and claims if successful, null otherwise
     */
    public function userPayload(): ?array
    {
        try {
            $u = JWTAuth::parseToken()->authenticate();
            if (!$u) return null;

            $claims = \JWTAuth::getPayload()->toArray();

            return [
                'user' => $u->toArray(),
                'session_id' => $claims['session_id'] ?? null,
                'claims' => $claims,
            ];
        } catch (TokenBlacklistedException|TokenExpiredException|TokenInvalidException|JWTException $e) {
            return null;
        }
    }

    /**
     * Get token payload.
     *
     * @return array|null Returns token payload array if successful, null otherwise
     */
    public function payload(): ?array
    {
        try {
            return JWTAuth::parseToken()->getPayload()->toArray();
        } catch (TokenBlacklistedException|TokenExpiredException|TokenInvalidException|JWTException $e) {
            return null;
        }
    }
}
