# Telegram OIDC Provider for Laravel Socialite

Telegram OpenID Connect provider for [Laravel Socialite](https://laravel.com/docs/socialite), built on top of [SocialiteProviders Manager](https://socialiteproviders.com/).

This package implements Telegram's current OpenID Connect login flow through `https://oauth.telegram.org`, not the legacy Telegram Login Widget.

## Installation

```bash
composer require barzhahub/socialiteproviders-telegram-oidc
```

## Configuration

Add the Telegram OIDC credentials from BotFather Web Login to `config/services.php`:

```php
'telegram-oidc' => [
    'client_id' => env('TELEGRAM_OIDC_CLIENT_ID'),
    'client_secret' => env('TELEGRAM_OIDC_CLIENT_SECRET'),
    'redirect' => env('TELEGRAM_OIDC_REDIRECT_URI'),
    'scopes' => env('TELEGRAM_OIDC_SCOPES', 'openid profile'),
],
```

Then register the provider in your `EventServiceProvider` or another service provider:

```php
use SocialiteProviders\Manager\SocialiteWasCalled;
use SocialiteProviders\TelegramOidc\TelegramOidcExtendSocialite;

Event::listen(function (SocialiteWasCalled $event) {
    (new TelegramOidcExtendSocialite())->handle($event);
});
```

You can also register it under a custom driver key:

```php
$event->extendSocialite('telegram', \SocialiteProviders\TelegramOidc\Provider::class);
```

## Environment

```env
TELEGRAM_OIDC_CLIENT_ID=
TELEGRAM_OIDC_CLIENT_SECRET=
TELEGRAM_OIDC_REDIRECT_URI="https://example.com/auth/telegram/callback"
TELEGRAM_OIDC_SCOPES="openid profile"
```

The `client_secret` is the Web Login Client Secret shown by BotFather. It is not the bot token.

## BotFather Setup

In BotFather, open your bot settings and configure Web Login. Add the origins and callback URLs that your app uses, for example:

```text
https://example.com
https://example.com/auth/telegram/callback
```

Telegram only redirects to URLs registered in BotFather.

## Usage

```php
return Socialite::driver('telegram-oidc')->redirect();
```

```php
$user = Socialite::driver('telegram-oidc')->user();

$telegramId = $user->getId();
$username = $user->getNickname();
$name = $user->getName();
$avatar = $user->getAvatar();
$claims = $user->getRaw();
```

## Scopes

The `openid` scope is always included. Common scopes:

```env
TELEGRAM_OIDC_SCOPES="openid profile"
```

To request bot access permission:

```env
TELEGRAM_OIDC_SCOPES="openid profile telegram:bot_access"
```

To request the user's verified phone number:

```env
TELEGRAM_OIDC_SCOPES="openid profile phone"
```

## Security

The provider:

- uses Authorization Code Flow with PKCE S256;
- exchanges the authorization code server-side;
- sends client credentials with HTTP Basic authentication;
- validates the `id_token` signature with Telegram JWKS;
- validates the `iss`, `aud`, and `exp` claims;
- maps the Socialite user id from Telegram's numeric `id` claim when present.

Telegram currently returns user claims in `id_token` and does not expose a separate UserInfo endpoint.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
