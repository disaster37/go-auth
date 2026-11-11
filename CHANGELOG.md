# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial `github.com/disaster37/go-auth` library.
- `domain`, `crypto`, `store`, `password`, `jwt`, `apitoken`, `oauth`,
  `httpcookie`, `secguard`, `observ`, `config`, `nethttp`, and `testutil`
  packages plus the root `goauth.Service` facade.
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
  validation.
- `net/http` middleware/handlers, a mock OIDC server, Dagger CI pipeline,
  GitHub Actions workflow, documentation, and ADRs.
