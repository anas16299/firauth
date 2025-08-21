<?php

namespace Firauth\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;
use Firauth\Support\ResponseHandler;
use Firauth\Contracts\TransportInterface;
use Firauth\Contracts\TokenDriverInterface;
use Firauth\Contracts\SessionStoreInterface;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    protected $tokens;
    protected $sessions;
    protected $transport;

    /**
     * Create a new AuthController instance.
     *
     * @param TokenDriverInterface $tokens
     *        The token driver implementation for JWT operations
     * @param SessionStoreInterface $sessions
     *        The session store implementation for managing user sessions
     * @param TransportInterface $transport
     *        The transport implementation for handling auth responses
     * @return void
     */
    public function __construct(
        TokenDriverInterface  $tokens,
        SessionStoreInterface $sessions,
        TransportInterface    $transport
    )
    {
        $this->tokens = $tokens;
        $this->sessions = $sessions;
        $this->transport = $transport;
    }


    /**
     * Authenticate a user and create a new JWT token.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
            'remember' => 'sometimes|boolean',
        ]);

        $rememberDays = $request->boolean('remember') ? (int)config('firauth.jwt.remember_me_days') : null;

        $additional = null;
        if (!config('firauth.jwt.use_model_claims', true)) {
            $sessionId = bin2hex(random_bytes(16));
            $additional = ['session_id' => $sessionId];
        }

        $result = $this->tokens->attempt(
            $request->only('email', 'password'),
            $rememberDays,
            $additional
        );

        if (!$result) {
            throw ValidationException::withMessages(['email' => ['Invalid credentials']])->status(422);
        }
        $claims = $result['claims'] ?? [];

        $user = $result['user'];

        if (config('firauth.jwt.bind_session_in_login', false)) {
            $sessionIdToBind = $claims['session_id'] ?? ($additional['session_id'] ?? null);
            if ($sessionIdToBind) {
                $this->sessions->bind($user['id'], $sessionIdToBind);
            }
        }

        $user['session_id'] = $claims['session_id'] ?? ($additional['session_id'] ?? null);


        return $this->transport->loginResponse($result['token'], $user);
    }


    /**
     * Refresh the JWT token.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function refresh(Request $request)
    {
        try {
            $result = $this->tokens->refresh();
            if (!$result) {
                return ResponseHandler::error(401, 'Cannot refresh');
            }

            $claims = $result['claims'];
            $userId = $claims['sub'] ?? null;
            $sessionId = $claims['session_id'] ?? null;

            if ($userId && !$this->sessions->validate($userId, $sessionId)) {
                $this->tokens->invalidate();
                return ResponseHandler::error(401, 'Session invalid');
            }

            return $this->transport->refreshResponse($result['token'], $claims);
        } catch (\Throwable $e) {
            return ResponseHandler::error(401, 'Refresh failed');
        }
    }


    /**
     * Log out the user and invalidate the token.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function logout(Request $request)
    {
        try {
            $payload = $this->tokens->userPayload();
            if ($payload && isset($payload['user']['id'])) {
                $this->sessions->revoke($payload['user']['id'], $payload['session_id'] ?? null);
            }
            $this->tokens->invalidate();
            return $this->transport->logoutResponse();
        } catch (\Throwable $e) {
            return $this->transport->logoutResponse()->setStatusCode(401);
        }
    }
}
