# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.4.1] - 2026-09-22

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
