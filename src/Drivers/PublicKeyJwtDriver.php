<?php
namespace Firauth\Drivers;

use Carbon\Carbon;
use Firauth\Contracts\TokenDriverInterface;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class PublicKeyJwtDriver implements TokenDriverInterface
{
    protected $request;
    public function __construct( ) {
        $this->request = app(Request::class);
    }

    // Consumers never call these; keep them as no-ops or throw.
    public function attempt(array $credentials, $rememberDays = null, array $additionalClaims = null) { return null; }
    public function refresh() { throw new \BadMethodCallException('Not supported on consumer'); }
    public function invalidate() { throw new \BadMethodCallException('Not supported on consumer'); }
    public function userPayload(): ?array { return null; } // main-only

    public function payload(): ?array
    {
        $token = $this->request->bearerToken();
        if (!$token) return null;

        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;

        [$h64, $p64, $s64] = $parts;
        $header  = $this->json($this->b64($h64));  if (!is_array($header))  return null;
        $claims  = $this->json($this->b64($p64));  if (!is_array($claims))  return null;
        $sig     = $this->b64($s64);
        $signed  = $h64.'.'.$p64;

        // Enforce expected algorithm
        $algo = strtoupper((string)($header['alg'] ?? ''));
        $expected = strtoupper((string) config('jwt.algo', 'RS256'));
        if ($algo !== $expected || $algo !== 'RS256') return null;

        // Check time-based claims (iat/nbf/exp)
        $now = time();
        if (isset($claims['iat']) && $claims['iat'] > $now + 60) return null; // skew protection
        if (isset($claims['nbf']) && $claims['nbf'] > $now)    return null;
        if (isset($claims['exp']) && $now >= $claims['exp'])   return null;

        // Load public key
        $pubPath = (string) config('jwt.keys.public', env('JWT_PUBLIC_KEY'));
        $pem = str_starts_with($pubPath, 'file://') ? @file_get_contents(substr($pubPath, 7)) : $pubPath;
        if (!$pem) return null;

        $pub = openssl_pkey_get_public($pem);
        if (!$pub) return null;

        $ok = openssl_verify($signed, $sig, $pub, OPENSSL_ALGO_SHA256);
        openssl_free_key($pub);
        if ($ok !== 1) return null;

        return $claims;
    }

    private function b64(string $s): string
    {
        $r = strlen($s) % 4;
        if ($r) $s .= str_repeat('=', 4 - $r);
        return base64_decode(strtr($s, '-_', '+/')) ?: '';
    }

    private function json(string $s)
    {
        $d = json_decode($s, true);
        return (json_last_error() === JSON_ERROR_NONE) ? $d : null;
    }
}
