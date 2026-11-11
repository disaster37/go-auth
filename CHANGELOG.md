# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial `github.com/disaster37/go-auth` library.
- `domain`, `crypto`, `store`, `password`, `jwt`, `apitoken`, `oauth`,
  `httpcookie`, `observ`, `config`, `nethttp`, and `testutil` packages plus the
  root `goauth.Service` facade.
- HS256 JWT access/refresh/OAuth-state pairs and compact HMAC session tokens
  with HKDF-SHA256 key derivation, `TokenVersion`, and `AuthEpoch` revocation.
- OIDC and GitHub OAuth2 providers with PKCE `S256`, OIDC `nonce`, multi-audience
  `azp` verification, `email_verified` enforcement, userinfo merge, 1 MiB
  response cap, cross-origin redirect refusal, and `allowed_endpoints`.
- Single-flight `oauth.Revalidator` with jitter, offline grace, fail-open/fail-closed
  policy, `SessionMaxAge`, and leader-only refresh.
- Configurable-prefix API tokens with SHA-256 hashing, constant-time comparison,
  at-rest encryption, `Reveal`, and `ImportRaw`.
- Exponential lockout, credential-stuffing ban tracking, sliding-window rate
  limiting, trusted-proxy real IP extraction, security headers, and CSRF origin
  validation via `github.com/disaster37/go-secguard`.
- `config.(*Config).ToSecguardConfig()` to map the flat go-auth security and
  CORS configuration onto the go-secguard configuration structs.
- `net/http` middleware/handlers, a mock OIDC server, Dagger CI pipeline,
  GitHub Actions workflow, documentation, and ADRs.

### Changed

- Now depends on `github.com/disaster37/go-secguard v1.0.0` for lockout, rate
  limiting, ban tracking, real IP resolution, security headers, and CSRF origin
  validation. The local `secguard` package is removed.
- Symbol mapping: `LockoutConfig` → `lockout.Config`, `LockoutLimiter` →
  `lockout.Limiter`, `NewLockoutLimiter` → `lockout.New`, `BanTracker` →
  `bantracker.BanTracker`, `NewBanTracker` → `bantracker.New`, and the
  `RateLimiter`/`LoginThrottle` types keep their names under `ratelimit`.
  `ParseTrustedProxyCIDRs`/`ExtractRealIP`/`GetRealIPFromRequest` move to
  `realip`; `DefaultSecurityHeaders`/`ExtractRequestOrigin`/
  `CheckMutationOrigin` move to `headers`.
- **Breaking:** `LoginLimitKey` now returns
  `login|<sha256(lower(trim(username)))|<trim(ip)>` and
  `PasswordChangeLimitKey` returns `chpw|<sha256(trim(userID))|<trim(ip)>`.
  Previously they returned `login:<username>:<ip>` and
  `password:<userID>:<ip>`.
- **Breaking:** `FingerprintLogin` now lowercases and trims the username before
  hashing, so mixed-case or padded usernames produce different digests.
- `nethttp.StatusCodeForError` now also maps the go-secguard sentinels
  (`ErrValidation`, `ErrInvalidIP`, `ErrInvalidCIDR`, `ErrOriginNotAllowed`,
  `ErrIPBanned`, `ErrRateLimited`, `ErrAccountLocked`) to 400/403/429.
- `config.Validate` now wraps both `domain.ErrValidation` and the go-secguard
  CIDR/IP sentinels for invalid `security.trusted_proxy_cidrs` entries.
- `DefaultSecurityHeaders` now sets `Cache-Control: no-store` for the exact
  `/api` path as well as `/api/` prefixes.
- `CheckMutationOrigin` now treats lowercase mutating methods as mutating and
  trims allowlist entries.
- `RateLimiter.Allow` and `LoginThrottle.Allow` now substitute safe defaults for
  non-positive limits/windows instead of denying all requests.
- `BanTracker.Unban` now also clears the IP's failure history, and the `banned`
  map is bounded.

### Removed

- The local `secguard` package and all 16 exported symbols (`LockoutConfig`,
  `LockoutLimiter`, `NewLockoutLimiter`, `RateLimiter`, `NewRateLimiter`,
  `LoginThrottle`, `NewLoginThrottle`, `BanInfo`, `BanTracker`, `NewBanTracker`,
  `ParseTrustedProxyCIDRs`, `ExtractRealIP`, `GetRealIPFromRequest`,
  `DefaultSecurityHeaders`, `ExtractRequestOrigin`, `CheckMutationOrigin`) plus
  the `LoginLimitKey`, `PasswordChangeLimitKey`, `FingerprintLogin`,
  `FingerprintToken`, and `FingerprintSignature` helpers and the six exported
  default constants.
