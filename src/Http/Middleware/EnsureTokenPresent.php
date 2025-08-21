<?php

namespace Firauth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firauth\Support\ResponseHandler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware to ensure the JWT token is present in the request.
 *
 * This middleware checks for the presence of a JWT token either in the Authorization
 * header as a Bearer token or in a cookie. If found in a cookie, it will be
 * injected into the Authorization header.
 */
class EnsureTokenPresent
{
    /**
     * Handle an incoming request.
     *
     * Checks for token presence and injects cookie token into the Authorization header if needed.
     *
     * @param Request $request
     * @param Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            $token = $this->getTokenFromCookie($request);
        }

        if (!$token) {
            return ResponseHandler::error(401, 'Token missing');
        }

        return $next($request);
    }

    /**
     * Attempt to retrieve token from cookie and inject it into the Authorization header.
     *
     * @param Request $request
     * @return string|null
     */
    protected function getTokenFromCookie(Request $request): ?string
    {
        $cookieName = config('firauth.cookie.name', 'firauth_token');
        $cookieToken = $request->cookie($cookieName);

        if ($cookieToken) {
            $request->headers->set('Authorization', 'Bearer ' . $cookieToken);
            return $cookieToken;
        }

        return null;
    }
}
