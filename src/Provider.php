<?php

declare(strict_types=1);

namespace SocialiteProviders\TelegramOidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Laravel\Socialite\Two\InvalidStateException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'TELEGRAM_OIDC';

    private const AUTHORIZATION_ENDPOINT = 'https://oauth.telegram.org/auth';

    private const TOKEN_ENDPOINT = 'https://oauth.telegram.org/token';

    private const JWKS_ENDPOINT = 'https://oauth.telegram.org/.well-known/jwks.json';

    private const ISSUER = 'https://oauth.telegram.org';

    private const JWKS_CACHE_KEY = 'socialite.telegram_oidc.jwks';

    /**
     * Always requested: `profile` carries the numeric Telegram user id, and `sub` is a different, opaque value.
     */
    private const REQUIRED_SCOPES = ['openid', 'profile'];

    protected $usesPKCE = true;

    protected $scopeSeparator = ' ';

    protected $encodingType = PHP_QUERY_RFC3986;

    protected $scopes = self::REQUIRED_SCOPES;

    public static function additionalConfigKeys(): array
    {
        return ['scopes', 'token_url', 'jwks_url'];
    }

    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->request->filled('error')) {
            throw new \RuntimeException((string) ($this->request->input('error_description') ?: $this->request->input('error')));
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException();
        }

        $response = $this->getAccessTokenResponse($this->getCode());
        $this->credentialsResponseBody = $response;

        $this->user = $this->mapUserToObject($this->validateIdToken((string) Arr::get($response, 'id_token', '')));
        $this->user->setAccessTokenResponseBody($this->credentialsResponseBody);

        return $this->user->setToken($this->parseAccessToken($response))
            ->setRefreshToken($this->parseRefreshToken($response))
            ->setExpiresIn($this->parseExpiresIn($response))
            ->setApprovedScopes($this->parseApprovedScopes($response));
    }

    public function getScopes()
    {
        $configured = $this->config['scopes'] ?? [];

        if (is_string($configured)) {
            $configured = preg_split('/\s+/', trim($configured)) ?: [];
        }

        // Required scopes first, then the configured ones, then any added at runtime via scopes().
        return array_values(array_unique(array_filter(
            array_merge(self::REQUIRED_SCOPES, (array) $configured, $this->scopes),
            static fn ($scope) => is_string($scope) && '' !== $scope
        )));
    }

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(self::AUTHORIZATION_ENDPOINT, $state);
    }

    protected function getTokenUrl()
    {
        $url = $this->getConfig('token_url');

        return is_string($url) && '' !== $url ? $url : self::TOKEN_ENDPOINT;
    }

    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS => $this->getTokenHeaders($code),
            RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
            RequestOptions::HTTP_ERRORS => false,
        ]);

        $body = json_decode((string) $response->getBody(), true);

        if (!is_array($body)) {
            throw new \UnexpectedValueException(sprintf('Telegram OIDC token endpoint returned a non-JSON response (HTTP %d).', $response->getStatusCode()));
        }

        // HTTP errors are not thrown above, so an OAuth error body ({"error": "invalid_grant", ...}) lands here.
        if (isset($body['error'])) {
            $reason = $body['error_description'] ?? $body['error'];

            throw new \RuntimeException('Telegram OIDC token endpoint returned an error: '.(is_string($reason) ? $reason : json_encode($reason)));
        }

        return $body;
    }

    /**
     * Telegram OIDC does not expose a UserInfo endpoint; all claims come from id_token.
     * user() is fully overridden and never calls this method.
     *
     * @param string $token
     *
     * @return array<string, mixed>
     */
    protected function getUserByToken($token): array
    {
        return [];
    }

    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id' => (string) $user['id'],
            'nickname' => Arr::get($user, 'preferred_username'),
            'name' => Arr::get($user, 'name'),
            'email' => null,
            'avatar' => Arr::get($user, 'picture'),
        ]);
    }

    protected function getTokenHeaders($code)
    {
        return [
            'Accept' => 'application/json',
            'Authorization' => 'Basic '.base64_encode($this->clientId.':'.$this->clientSecret),
        ];
    }

    protected function getTokenFields($code)
    {
        $codeVerifier = $this->request->session()->pull('code_verifier');

        if (!is_string($codeVerifier) || '' === $codeVerifier) {
            throw new InvalidStateException();
        }

        return [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUrl,
            'client_id' => $this->clientId,
            'code_verifier' => $codeVerifier,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function validateIdToken(string $idToken): array
    {
        if ('' === $idToken) {
            throw new \UnexpectedValueException('Telegram OIDC token response does not contain id_token.');
        }

        $previousLeeway = JWT::$leeway;
        // 60 s allows clock skew but also extends the replay window by the same amount.
        // JWT::$leeway is a global static — unsafe for concurrent runtimes (Swoole / Octane).
        JWT::$leeway = 60;

        try {
            $jwks = $this->jwks();
            $kid = $this->keyId($idToken);

            // Refetch only for an unknown kid (the signing key rotated since the last fetch),
            // not for every invalid token: expired or badly signed ones fail the same either way.
            if (null !== $kid && !in_array($kid, array_column($jwks['keys'], 'kid'), true)) {
                $jwks = $this->jwks(bustCache: true);
            }

            $payload = JWT::decode($idToken, JWK::parseKeySet($jwks, 'RS256'));
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        $claims = $this->objectToArray($payload);

        if (($claims['iss'] ?? null) !== self::ISSUER) {
            throw new \UnexpectedValueException('Telegram OIDC issuer mismatch.');
        }

        if (!$this->audienceMatches($claims['aud'] ?? null)) {
            throw new \UnexpectedValueException('Telegram OIDC audience mismatch.');
        }

        if (empty($claims['exp']) || !is_numeric($claims['exp'])) {
            throw new \UnexpectedValueException('Telegram OIDC token does not contain exp.');
        }

        // Only `id` matches the user id seen by bots and Mini Apps; never fall back to the opaque `sub`.
        $id = $claims['id'] ?? null;

        if (!is_int($id) && !(is_string($id) && 1 === preg_match('/^\d+$/', $id))) {
            throw new \UnexpectedValueException('Telegram OIDC token does not contain the numeric user id; the "profile" scope must be granted.');
        }

        return $claims;
    }

    /**
     * @return array<string, mixed>
     */
    private function jwks(bool $bustCache = false): array
    {
        if ($bustCache) {
            Cache::forget(self::JWKS_CACHE_KEY);
        }

        return Cache::remember(self::JWKS_CACHE_KEY, now()->addHours(6), function () {
            $response = $this->getHttpClient()->get($this->getJwksUrl(), [
                RequestOptions::HEADERS => ['Accept' => 'application/json'],
                RequestOptions::HTTP_ERRORS => false,
            ]);

            $jwks = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

            if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) {
                throw new \UnexpectedValueException('Telegram OIDC JWKS response is invalid.');
            }

            return $jwks;
        });
    }

    /**
     * The `kid` from the JWT header, or null when the header is unreadable — JWT::decode() reports that itself.
     */
    private function keyId(string $jwt): ?string
    {
        $header = json_decode((string) base64_decode(strtr(explode('.', $jwt)[0], '-_', '+/')), true);
        $kid = is_array($header) ? ($header['kid'] ?? null) : null;

        return is_string($kid) ? $kid : null;
    }

    private function getJwksUrl(): string
    {
        $url = $this->getConfig('jwks_url');

        return is_string($url) && '' !== $url ? $url : self::JWKS_ENDPOINT;
    }

    private function audienceMatches($audience): bool
    {
        if (is_string($audience)) {
            return hash_equals((string) $this->clientId, $audience);
        }

        if (!is_array($audience)) {
            return false;
        }

        foreach ($audience as $value) {
            if (is_string($value) && hash_equals((string) $this->clientId, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, mixed>
     */
    private function objectToArray(\stdClass $payload): array
    {
        try {
            $claims = json_decode(json_encode($payload, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \UnexpectedValueException('Telegram OIDC token claims are invalid.', previous: $e);
        }

        if (!is_array($claims)) {
            throw new \UnexpectedValueException('Telegram OIDC token claims are invalid.');
        }

        return $claims;
    }
}
