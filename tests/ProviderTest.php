<?php

declare(strict_types=1);

namespace SocialiteProviders\TelegramOidc\Tests;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Orchestra\Testbench\TestCase;
use SocialiteProviders\Manager\Config;
use SocialiteProviders\TelegramOidc\Provider;

class ProviderTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
    }

    public function testRedirectUsesTelegramOidcAuthorizeEndpointWithPkce(): void
    {
        $provider = $this->provider($this->requestWithSession(), scopes: 'profile telegram:bot_access');

        $target = $provider->redirect()->getTargetUrl();

        $this->assertStringStartsWith('https://oauth.telegram.org/auth?', $target);
        $this->assertStringContainsString('code_challenge=', $target);
        $this->assertStringContainsString('code_challenge_method=S256', $target);

        parse_str((string) parse_url($target, PHP_URL_QUERY), $query);

        $this->assertSame('123456', $query['client_id']);
        $this->assertSame('https://example.com/auth/telegram/callback', $query['redirect_uri']);
        $this->assertSame('code', $query['response_type']);
        $this->assertSame('openid profile telegram:bot_access', $query['scope']);
    }

    public function testRedirectAlwaysRequestsProfileScopeAndKeepsRuntimeScopes(): void
    {
        $provider = $this->provider($this->requestWithSession(), scopes: 'openid phone');
        $provider->scopes(['telegram:bot_access']);

        parse_str((string) parse_url($provider->redirect()->getTargetUrl(), PHP_URL_QUERY), $query);

        $this->assertSame('openid profile phone telegram:bot_access', $query['scope']);
    }

    public function testProviderValidatesIdTokenAndMapsNumericTelegramId(): void
    {
        [$privateKey, $jwk] = $this->rsaJwk();
        $idToken = $this->idToken($privateKey, [
            'sub' => 'opaque-telegram-subject',
            'id' => 123456789,
            'name' => 'John Doe',
            'preferred_username' => 'johndoe',
            'picture' => 'https://example.com/avatar.jpg',
        ]);

        $history = [];
        $provider = $this->provider($this->callbackRequest());
        $provider->setHttpClient($this->httpClient([
            $this->tokenResponse($idToken),
            $this->jwksResponse($jwk),
        ], $history));

        $user = $provider->user();

        $this->assertSame('123456789', $user->getId());
        $this->assertSame('johndoe', $user->getNickname());
        $this->assertSame('John Doe', $user->getName());
        $this->assertSame('https://example.com/avatar.jpg', $user->getAvatar());
        $this->assertSame('opaque-telegram-subject', $user->getRaw()['sub']);

        $this->assertCount(2, $history);
        $tokenRequest = $history[0]['request'];
        $this->assertSame(
            'Basic '.base64_encode('123456:client-secret'),
            $tokenRequest->getHeaderLine('Authorization')
        );

        parse_str((string) $tokenRequest->getBody(), $tokenFields);

        $this->assertSame('authorization_code', $tokenFields['grant_type']);
        $this->assertSame('authorization-code', $tokenFields['code']);
        $this->assertSame('123456', $tokenFields['client_id']);
        $this->assertSame('plain-code-verifier', $tokenFields['code_verifier']);
        $this->assertArrayNotHasKey('client_secret', $tokenFields);
    }

    public function testRejectsTokenWithoutNumericTelegramId(): void
    {
        [$privateKey, $jwk] = $this->rsaJwk();
        // Without the "profile" scope Telegram returns only the opaque sub.
        $idToken = $this->idToken($privateKey, ['sub' => 'opaque-telegram-subject']);

        $history = [];
        $provider = $this->provider($this->callbackRequest());
        $provider->setHttpClient($this->httpClient([
            $this->tokenResponse($idToken),
            $this->jwksResponse($jwk),
        ], $history));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('numeric user id');

        $provider->user();
    }

    public function testThrowsOnOAuthError(): void
    {
        $request = $this->requestWithSession([
            'error' => 'access_denied',
            'error_description' => 'The user denied access.',
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The user denied access.');

        $this->provider($request)->user();
    }

    public function testThrowsTokenEndpointError(): void
    {
        $history = [];
        $provider = $this->provider($this->callbackRequest());
        $provider->setHttpClient($this->httpClient([
            new Response(400, ['Content-Type' => 'application/json'], json_encode([
                'error' => 'invalid_grant',
                'error_description' => 'Authorization code expired.',
            ], JSON_THROW_ON_ERROR)),
        ], $history));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Authorization code expired.');

        $provider->user();
    }

    public function testRetriesToFetchJwksOnKeyRotation(): void
    {
        [$privateKey, $jwk] = $this->rsaJwk();
        $idToken = $this->idToken($privateKey, ['sub' => 'opaque-subject', 'id' => 999]);

        // Stale JWKS: same key material but wrong kid — JWT::decode will not find 'test-key'.
        $staleJwk = array_merge($jwk, ['kid' => 'old-key']);

        $history = [];
        $provider = $this->provider($this->callbackRequest());
        $provider->setHttpClient($this->httpClient([
            $this->tokenResponse($idToken),
            $this->jwksResponse($staleJwk),
            $this->jwksResponse($jwk),
        ], $history));

        $this->assertSame('999', $provider->user()->getId());
        $this->assertCount(3, $history);
    }

    public function testDoesNotRefetchJwksForExpiredToken(): void
    {
        [$privateKey, $jwk] = $this->rsaJwk();
        $idToken = $this->idToken($privateKey, [
            'sub' => 'opaque-subject',
            'id' => 999,
            'iat' => time() - 7200,
            'exp' => time() - 3600,
        ]);

        $history = [];
        $provider = $this->provider($this->callbackRequest());
        $provider->setHttpClient($this->httpClient([
            $this->tokenResponse($idToken),
            $this->jwksResponse($jwk),
            $this->jwksResponse($jwk),
        ], $history));

        try {
            $provider->user();
            $this->fail('An expired id_token must be rejected.');
        } catch (ExpiredException) {
        }

        // Token exchange + one JWKS fetch: the signing key is known, so the cache stays.
        $this->assertCount(2, $history);
    }

    /**
     * @param array<string, string> $query
     */
    private function requestWithSession(array $query = []): Request
    {
        $request = Request::create('/auth/telegram/callback', 'GET', $query);
        $request->setLaravelSession(new Store('testing', new ArraySessionHandler(120)));

        return $request;
    }

    private function callbackRequest(): Request
    {
        $request = $this->requestWithSession([
            'code' => 'authorization-code',
            'state' => 'oidc-state',
        ]);
        $request->session()->put('state', 'oidc-state');
        $request->session()->put('code_verifier', 'plain-code-verifier');

        return $request;
    }

    private function provider(Request $request, string $scopes = 'openid profile'): Provider
    {
        $provider = new Provider(
            $request,
            '123456',
            'client-secret',
            'https://example.com/auth/telegram/callback'
        );

        $provider->setConfig(new Config(
            '123456',
            'client-secret',
            'https://example.com/auth/telegram/callback',
            ['scopes' => $scopes]
        ));

        return $provider;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function idToken(string $privateKey, array $claims): string
    {
        return JWT::encode(array_merge([
            'iss' => 'https://oauth.telegram.org',
            'aud' => '123456',
            'iat' => time(),
            'exp' => time() + 3600,
        ], $claims), $privateKey, 'RS256', 'test-key');
    }

    private function tokenResponse(string $idToken): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'telegram-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'id_token' => $idToken,
            'scope' => 'openid profile',
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * @param array<string, string> $jwk
     */
    private function jwksResponse(array $jwk): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'keys' => [$jwk],
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * @param list<Response>                   $responses
     * @param array<int, array<string, mixed>> $history
     */
    private function httpClient(array $responses, array &$history): Client
    {
        $handlerStack = HandlerStack::create(new MockHandler($responses));
        $handlerStack->push(Middleware::history($history));

        return new Client(['handler' => $handlerStack]);
    }

    /**
     * @return array{0: string, 1: array<string, string>}
     */
    private function rsaJwk(): array
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        $this->assertNotFalse($key);
        $this->assertTrue(openssl_pkey_export($key, $privateKey));

        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);

        return [
            $privateKey,
            [
                'kty' => 'RSA',
                'kid' => 'test-key',
                'use' => 'sig',
                'alg' => 'RS256',
                'n' => $this->base64Url($details['rsa']['n']),
                'e' => $this->base64Url($details['rsa']['e']),
            ],
        ];
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
