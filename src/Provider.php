<?php

declare(strict_types=1);

namespace SocialiteProviders\TelegramOidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use JsonException;
use Laravel\Socialite\Two\InvalidStateException;
use RuntimeException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use stdClass;
use UnexpectedValueException;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'TELEGRAM_OIDC';

    private const AUTHORIZATION_ENDPOINT = 'https://oauth.telegram.org/auth';

    private const TOKEN_ENDPOINT = 'https://oauth.telegram.org/token';

    private const JWKS_ENDPOINT = 'https://oauth.telegram.org/.well-known/jwks.json';

    private const ISSUER = 'https://oauth.telegram.org';

    private const JWKS_CACHE_KEY = 'socialite.telegram_oidc.jwks';

    protected $usesPKCE = true;

    protected $scopeSeparator = ' ';

    protected $encodingType = PHP_QUERY_RFC3986;

    protected $scopes = ['openid', 'profile'];

    /**
     * {@inheritdoc}
     */
    public static function additionalConfigKeys(): array
    {
        return ['scopes'];
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->request->filled('error')) {
            throw new RuntimeException((string) ($this->request->input('error_description') ?: $this->request->input('error')));
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
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
     * {@inheritdoc}
     */
    public function getScopes()
    {
        $configured = $this->config['scopes'] ?? null;

        if (is_string($configured)) {
            $scopes = preg_split('/\s+/', trim($configured)) ?: [];
        } elseif (is_array($configured)) {
            $scopes = $configured;
        } else {
            $scopes = $this->scopes;
        }

        $scopes = array_values(array_unique(array_filter(
            $scopes,
            static fn ($scope) => is_string($scope) && $scope !== ''
        )));

        if (! in_array('openid', $scopes, true)) {
            array_unshift($scopes, 'openid');
        }

        return $scopes;
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(self::AUTHORIZATION_ENDPOINT, $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return self::TOKEN_ENDPOINT;
    }

    /**
     * Telegram OIDC returns user claims in id_token and does not expose a UserInfo endpoint.
     *
     * @param  string  $token
     * @return array<string, mixed>
     */
    protected function getUserByToken($token): array
    {
        throw new RuntimeException('Telegram OIDC does not provide a UserInfo endpoint.');
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        $providerId = Arr::get($user, 'id', Arr::get($user, 'sub'));

        if (! is_int($providerId) && ! is_string($providerId)) {
            throw new UnexpectedValueException('Telegram OIDC token does not contain a valid user identifier.');
        }

        return (new User)->setRaw($user)->map([
            'id' => (string) $providerId,
            'nickname' => Arr::get($user, 'preferred_username'),
            'name' => Arr::get($user, 'name'),
            'email' => null,
            'avatar' => Arr::get($user, 'picture'),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenHeaders($code)
    {
        return [
            'Accept' => 'application/json',
            'Authorization' => 'Basic '.base64_encode($this->clientId.':'.$this->clientSecret),
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        $codeVerifier = $this->request->session()->pull('code_verifier');

        if (! is_string($codeVerifier) || $codeVerifier === '') {
            throw new InvalidStateException;
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
        if ($idToken === '') {
            throw new UnexpectedValueException('Telegram OIDC token response does not contain id_token.');
        }

        $headers = new stdClass;
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = 60;

        try {
            $payload = JWT::decode($idToken, JWK::parseKeySet($this->jwks(), 'RS256'), $headers);
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        if (($headers->alg ?? null) !== 'RS256') {
            throw new UnexpectedValueException('Telegram OIDC token uses an unsupported signing algorithm.');
        }

        $claims = $this->objectToArray($payload);

        if (($claims['iss'] ?? null) !== self::ISSUER) {
            throw new UnexpectedValueException('Telegram OIDC issuer mismatch.');
        }

        if (! $this->audienceMatches($claims['aud'] ?? null)) {
            throw new UnexpectedValueException('Telegram OIDC audience mismatch.');
        }

        if (empty($claims['exp']) || ! is_numeric($claims['exp'])) {
            throw new UnexpectedValueException('Telegram OIDC token does not contain exp.');
        }

        if (empty($claims['sub']) && empty($claims['id'])) {
            throw new UnexpectedValueException('Telegram OIDC token does not contain a user identifier.');
        }

        return $claims;
    }

    /**
     * @return array<string, mixed>
     */
    private function jwks(): array
    {
        return Cache::remember(self::JWKS_CACHE_KEY, now()->addHours(6), function () {
            $response = $this->getHttpClient()->get(self::JWKS_ENDPOINT, [
                RequestOptions::HEADERS => ['Accept' => 'application/json'],
            ]);

            $jwks = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

            if (! is_array($jwks) || ! isset($jwks['keys']) || ! is_array($jwks['keys'])) {
                throw new UnexpectedValueException('Telegram OIDC JWKS response is invalid.');
            }

            return $jwks;
        });
    }

    /**
     * @param  mixed  $audience
     */
    private function audienceMatches($audience): bool
    {
        if (is_string($audience)) {
            return hash_equals((string) $this->clientId, $audience);
        }

        if (! is_array($audience)) {
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
    private function objectToArray(stdClass $payload): array
    {
        try {
            $claims = json_decode(json_encode($payload, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new UnexpectedValueException('Telegram OIDC token claims are invalid.', previous: $e);
        }

        if (! is_array($claims)) {
            throw new UnexpectedValueException('Telegram OIDC token claims are invalid.');
        }

        return $claims;
    }
}
