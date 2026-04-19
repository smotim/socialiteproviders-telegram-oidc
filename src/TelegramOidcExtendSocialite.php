<?php

declare(strict_types=1);

namespace SocialiteProviders\TelegramOidc;

use SocialiteProviders\Manager\SocialiteWasCalled;

class TelegramOidcExtendSocialite
{
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('telegram-oidc', Provider::class);
    }
}
