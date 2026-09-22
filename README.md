# Telegram OIDC

```bash
composer require socialiteproviders/telegram-oidc
```

## Installation & Basic Usage

Please see the [Base Installation Guide](https://socialiteproviders.com/usage/), then follow the provider specific instructions below.

### Add configuration to `config/services.php`

```php
'telegram-oidc' => [
    'client_id'     => env('TELEGRAM_OIDC_CLIENT_ID'),
    'client_secret' => env('TELEGRAM_OIDC_CLIENT_SECRET'),
    'redirect'      => env('TELEGRAM_OIDC_REDIRECT_URI'),
    'scopes'        => env('TELEGRAM_OIDC_SCOPES', 'openid profile'),
],
```

> **Note:** `client_id` is your bot's numeric ID and `client_secret` is the Web Login Client Secret shown by BotFather — not the bot token.

### Add provider event listener

#### Laravel 11+

In Laravel 11, the default `EventServiceProvider` was removed. Instead, add the listener using the `listen` method on the `Event` facade in your `AppServiceProvider` `boot` method.

```php
Event::listen(function (\SocialiteProviders\Manager\SocialiteWasCalled $event) {
    $event->extendSocialite('telegram-oidc', \SocialiteProviders\TelegramOidc\Provider::class);
});
```

<details>
<summary>Laravel 10 or below</summary>

Configure the package's listener to listen for `SocialiteWasCalled` events.

Add the event to your `listen[]` array in `app/Providers/EventServiceProvider`. See the [Base Installation Guide](https://socialiteproviders.com/usage/) for detailed instructions.

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        // ... other providers
        \SocialiteProviders\TelegramOidc\TelegramOidcExtendSocialite::class.'@handle',
    ],
];
```

</details>

### Usage

You should now be able to use the provider like you would regularly use Socialite (assuming you have the facade installed):

```php
return Socialite::driver('telegram-oidc')->redirect();
```

```php
$user = Socialite::driver('telegram-oidc')->user();

$telegramId = $user->getId();       // Telegram numeric user ID
$username   = $user->getNickname(); // @username
$name       = $user->getName();     // Display name
$avatar     = $user->getAvatar();   // Profile photo URL
$claims     = $user->getRaw();      // Full id_token claims
```

### Returned User fields

- `id` — Telegram numeric user ID (from the `id` claim), the same ID bots and Mini Apps see. The opaque OIDC `sub` is a different value; it stays in `getRaw()` and is never used as the ID
- `nickname` — Telegram username (from `preferred_username`)
- `name` — Display name (from `name`)
- `avatar` — Profile photo URL (from `picture`)
- `email` — always `null` (Telegram does not provide email)

## BotFather Setup

This provider uses Telegram's OpenID Connect login flow through `https://oauth.telegram.org`, **not** the legacy Telegram Login Widget.

In BotFather, open your bot settings, go to **Bot Settings → Web Login**, and add the origins and callback URLs your app uses:

```text
https://example.com
https://example.com/auth/telegram/callback
```

Telegram only redirects to URLs registered in BotFather.

## Scopes

The `openid` and `profile` scopes are always included: only `profile` returns the numeric user ID. Configure additional scopes via the `scopes` key in `config/services.php` or the environment variable; scopes added in code with `->scopes([...])` are appended to them:

```env
TELEGRAM_OIDC_SCOPES="openid profile"
```

| Scope | Description |
| --- | --- |
| `profile` | User ID, name, username, avatar (always requested) |
| `phone` | Verified phone number |
| `telegram:bot_access` | Bot access permission |

Keep the bot's ID token signing algorithm (BotFather → Login Widget → Advanced) at RS256 or ES256: with EdDSA or ES256K Telegram rejects the `profile` scope, so no user ID can be obtained.

## Custom endpoints

If your server reaches Telegram through a relay, override the server-to-server URLs. The authorization URL is opened by the user's browser and is not configurable.

```php
'telegram-oidc' => [
    // ...
    'token_url' => env('TELEGRAM_OIDC_TOKEN_URL'), // default https://oauth.telegram.org/token
    'jwks_url'  => env('TELEGRAM_OIDC_JWKS_URL'),  // default https://oauth.telegram.org/.well-known/jwks.json
],
```

## Security

This provider implements Authorization Code Flow and:

- requires PKCE (S256) on every request;
- validates the `id_token` signature against Telegram's published JWKS;
- validates `iss`, `aud` and `exp` claims;
- refetches the JWKS once when the token's `kid` is not in the cached set, to handle key rotation transparently;
- requires Telegram's numeric `id` claim and maps the Socialite user `id` from it.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
