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

    /**
     * SocialiteManager::buildProvider() passes the configured `scopes` to scopes() as-is,
     * so "openid profile" may arrive as one element: split every entry.
     */
    public function getScopes()
    {
        $scopes = array_merge(...array_map(
            static fn ($scope) => preg_split('/\s+/', trim((string) $scope)) ?: [],
            $this->scopes
        ));

        return array_values(array_unique(array_filter(
            array_merge(self::REQUIRED_SCOPES, $scopes),
            static fn (string $scope) => '' !== $scope
        )));
    }

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(self::AUTHORIZATION_ENDPOINT, $state);
    }

    protected function getTokenUrl()
    {
        return $this->getConfig('token_url') ?: self::TOKEN_ENDPOINT;
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

    /**
     * The client authenticates with Basic auth (see getTokenHeaders()); OAuth 2.0 forbids sending the secret twice.
     */
    protected function getTokenFields($code)
    {
        return Arr::except(parent::getTokenFields($code), 'client_secret');
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

        $claims = json_decode(json_encode($payload, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);

        if (($claims['iss'] ?? null) !== self::ISSUER) {
            throw new \UnexpectedValueException('Telegram OIDC issuer mismatch.');
        }

        if (!in_array((string) $this->clientId, (array) ($claims['aud'] ?? []), true)) {
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
            $response = $this->getHttpClient()->get($this->getConfig('jwks_url') ?: self::JWKS_ENDPOINT, [
                RequestOptions::HEADERS => ['Accept' => 'application/json'],
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

}
