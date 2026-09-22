# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.4.2] - 2026-09-22

### Changed

- Scopes have a single source: `SocialiteManager` already passes the configured ones to `scopes()`, so the provider only splits them and adds `openid` and `profile`.
- HTTP errors from the token and JWKS endpoints are raised by Guzzle again, with the status and response body in the message, instead of being switched off and parsed by hand. This replaces the token error handling added in 0.4.0.
- The token request reuses Socialite's fields minus `client_secret`; a lost PKCE verifier is already caught by the state check.

### Fixed

- Scopes were sent twice when configured as a string (`openid profile openid profile`): `SocialiteManager::buildProvider()` passes the raw config value to `scopes()`, and 0.4.0 merged it with the parsed config.

## [0.4.0] - 2026-09-22

### Changed

- The `profile` scope is always requested, like `openid`, and a token without Telegram's numeric `id` claim is rejected. Previously the user ID silently fell back to the opaque `sub`, a different value for the same user.
- Scopes added in code with `->scopes([...])` are appended to the configured ones instead of being ignored.
- The JWKS is refetched only when the token's `kid` is unknown, not on every failed validation (expired or badly signed tokens).

### Fixed

- An OAuth error from the token endpoint (`{"error": "invalid_grant", ...}`) is reported with its description instead of "does not contain id_token".
- README no longer claims `nonce` validation, which was removed in 0.3.0.

### Removed

- The `ext-json` requirement: JSON is always available in PHP 8.
