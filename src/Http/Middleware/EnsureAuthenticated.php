<?php

namespace Firauth\Http\Middleware;

/**
 * Laravel middleware to ensure requests are authenticated.
 *
 * This middleware handles authentication through JWT tokens, supporting both cookie and bearer token methods.
 * It implements pre- and post-authentication checks and manages user session validation.
 *
 */

use Closure;
use Illuminate\Http\Request;
use Illuminate\Auth\GenericUser;
use Firauth\Support\UserBuilder;
use Illuminate\Support\Facades\Auth;
use Firauth\Support\ResponseHandler;
use Firauth\Contracts\TokenDriverInterface;
use Firauth\Contracts\SessionStoreInterface;
use Symfony\Component\HttpFoundation\Response;
use Firauth\Contracts\PreAuthCheckerInterface;
use Firauth\Contracts\PostAuthCheckerInterface;

class EnsureAuthenticated
{
    /**
     * The token driver instance.
     *
     * @var TokenDriverInterface
     */
    protected $tokens;

    /**
     * The session store instance.
     *
     * @var SessionStoreInterface
     */
    protected $sessions;


    /**
     * Create a new middleware instance.
     *
     * @param TokenDriverInterface $tokens
     * @param SessionStoreInterface $sessions
     * @return void
     */
    public function __construct(
        TokenDriverInterface  $tokens,
        SessionStoreInterface $sessions
    )
    {
        $this->tokens = $tokens;
        $this->sessions = $sessions;
    }


    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // 1) If a cookie holds the token and Authorization is missing, inject it
        $cookieName = config('firauth.cookie.name', 'firauth_token');
        if ($request->cookie($cookieName) && !$request->bearerToken()) {
            $request->headers->set('Authorization', 'Bearer ' . $request->cookie($cookieName));
        }

        // 2) PRE CHECKERS — may stop or bypass entirely
        $preOutcome = $this->runPreCheckers($request);
        if ($preOutcome instanceof Response) {
            return $preOutcome;
        }
        if ($preOutcome === true) {
            return $next($request);
        }
        // 3) NORMAL JWT FLOW
        $isMain = (bool)config('firauth.main_service', false);
        $claims = $isMain
            ? ($this->tokens->userPayload()['claims'] ?? null)
            : $this->tokens->payload();

        if (!$claims) {
            return ResponseHandler::error(401, 'Unauthorized');
        }

        // Build dynamic user attributes from claims
        $user = UserBuilder::fromClaims($claims);

        // Validate Redis session (single-session)
        $userId = $user['id'] ?? null;
        $sessionId = $user['session_id'] ?? null;
        if (!$userId || !$this->sessions->validate($userId, $sessionId)) {
            return ResponseHandler::error(401, 'Unauthorized');
        }

        // 4) POST CHECKERS — final gate for normal JWT flow
        $postResp = $this->runPostCheckers($request, $user);
        if ($postResp instanceof Response) {
            return $postResp;
        }

        // 5) Bind the resolved user and hand off
        $request->setUserResolver(function () use ($user) {
            return (object)$user;
        });

        if (config('firauth.generic_user', false)){
            $generic = new GenericUser($user);
            Auth::setUser($generic);
        }
        return $next($request);
    }


    /**
     * Run pre-authentication checkers.
     *
     * @param Request $request
     * @return mixed
     */
    protected function runPreCheckers(Request $request)
    {
        $classes = (array)config('firauth.middleware.pre', []);
        foreach ($classes as $class) {
            /** @var PreAuthCheckerInterface $checker */
            $checker = app($class);
            $result = $checker->handle($request);

            if ($result instanceof Response) {
                return $result;
            }

            if ($result === true) {
                return $result;
            }
        }
        return null;
    }


    /**
     * Run post-authentication checkers.
     *
     * @param Request $request
     * @param array $user
     * @return Response|null
     */
    protected function runPostCheckers(Request $request, array &$user): ?Response
    {
        $classes = (array)config('firauth.middleware.post', []);
        foreach ($classes as $class) {
            /** @var PostAuthCheckerInterface $checker */
            $checker = app($class);
            $resp = $checker->handle($request, $user); // return Response or null
            if ($resp instanceof Response) {
                return $resp;
            }
        }
        return null;
    }
}
