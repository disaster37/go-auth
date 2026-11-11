# ADR-005: Externalize security guardrails to go-secguard

## Status

Accepted.

## Context

The lockout, rate limiting, ban tracking, real IP resolution, security header,
and CSRF origin primitives were implemented inside the local `secguard` package.
A dedicated, zero-dependency library, `github.com/disaster37/go-secguard`, now
provides the same functionality as a strict functional superset. Maintaining a
duplicate implementation in this repository adds review and test burden without
adding capabilities.

## Decision

- Depend on `github.com/disaster37/go-secguard v1.0.0`.
- Delete the local `secguard` package and its tests.
- Translate go-secguard sentinel errors to the `go-auth/domain` vocabulary at
  the `nethttp` boundary, so consumers keep matching `goauth.ErrOriginNotAllowed`
  and friends. `nethttp.StatusCodeForError` additionally accepts the
  go-secguard sentinels for callers that use the library directly.
- Keep the flat `config.SecurityConfig` schema and provide
  `config.(*Config).ToSecguardConfig()` so consumers can build a
  `secguard.Guard` without hand-mapping fields.
- Keep `go-auth/domain` stdlib-only; it must not import `go-secguard/domain`.

## Consequences

- One less package to maintain, test, and document in this repository.
- Consumers gain access to `secguard.Guard`, `go-secguard/observ`, and the extra
  `go-secguard/nethttp` middleware and ban admin handlers.
- Two sentinel-error vocabularies now exist. Translation at the boundary keeps
  the public `go-auth` contract stable, but direct go-secguard callers must use
  the go-secguard sentinels.
- Lockout key formats (`LoginLimitKey`, `PasswordChangeLimitKey`) and
  `FingerprintLogin` normalization change. In-memory limiter state is not
  comparable across the upgrade; a process restart clears it.
