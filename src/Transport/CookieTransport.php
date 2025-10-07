<?php

namespace Firauth\Transport;

use Illuminate\Http\Response;
use Firauth\Support\ResponseHandler;
use Firauth\Contracts\TransportInterface;

/**
 * Class CookieTransport
 *
 * Handles authentication token transport using HTTP cookies.
 * Implements response handling for login, refresh, and logout operations
 * with customizable cookie parameters.
 *
 * @package firauth\Transport
 */
class CookieTransport implements TransportInterface
{
    /**
     * Cookie configuration parameters
     *
     * @var array
     */
    protected $cfg;

    /**
     * Create a new CookieTransport instance.
     *
     * @param array $cookieConfig Configuration array for cookie parameters
     */
    public function __construct(array $cookieConfig)
    {
        $this->cfg = $cookieConfig;
    }

    /**
     * Generate response for successful login.
     *
     * @param string $token Authentication token
     * @param array $userPayload User data payload
     * @return Response
     */
    public function loginResponse($token, array $userPayload,bool $forceResend=false)
    {
        $data = [];
        if ($forceResend){
            $data = $userPayload;
        }elseif (config('firauth.cookie.return_user_info', false)) {
            $data['user'] = $userPayload;
        }
        $response = ResponseHandler::success($data);
        return $this->withCookie($response, $token);
    }

    /**
     * Generate response for token refresh.
     *
     * @param string $token New authentication token
     * @param array $claims Token claims
     * @return Response
     */
    public function refreshResponse($token, array $claims)
    {
        $response = ResponseHandler::success();
        return $this->withCookie($response, $token);
    }

    /**
     * Generate response for logout.
     *
     */
    public function logoutResponse()
    {
        $response = ResponseHandler::success();
        return $response->withoutCookie(
            $this->cfg['name'] ?? 'firauth_token',
            $this->cfg['path'] ?? '/',
            $this->cfg['domain'] ?? null
        );
    }

    /**
     * Add an authentication cookie to the response.
     *
     * @param  $response
     * @param string $token Authentication token
     * @return Response
     */
    protected function withCookie($response, $token)
    {
        $name = $this->cfg['name'] ?? 'firauth_token';
        $minutes = isset($this->cfg['lifetime']) ? (int)$this->cfg['lifetime'] : 60;
        $path = $this->cfg['path'] ?? '/';

        $domain = $this->cfg['domain'] ?? null;
        $secure = !isset($this->cfg['secure']) || (bool)$this->cfg['secure'];
        $httpOnly = !isset($this->cfg['http_only']) || (bool)$this->cfg['http_only'];
        $sameSite = $this->cfg['same_site'] ?? 'None';


        return $response->cookie(
            $name,
            $token,
            $minutes,
            $path,
            $domain,
            $secure,
            $httpOnly,
            false,
            $sameSite
        );
    }
}
