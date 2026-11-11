# ADR-002: Token, session, and revocation model

## Status

Accepted.

## Context

The two source projects used different token formats: `dagger-kubernetes`
issued HS256 JWT access/refresh pairs, while `gohookbridge` used compact
HMAC-SHA256 session tokens. Both needed a way to revoke sessions quickly.

## Decision

- Support both formats in `jwt`:
  - HS256 JWT pairs with explicit `typ` claims (`access`, `refresh`,
    `oauth_state`).
  - Compact `base64url(payload).base64url(hmac)` session tokens.
- Derive signing keys with RFC 5869 HKDF-SHA256 and domain-separated info
  strings (`go-auth.jwt.signing.v1`, `go-auth.session.signing.v1`).
- Enforce two independent revocation counters:
  - `TokenVersion` per user, bumped on logout, password change, and reset.
  - `AuthEpoch` cluster-wide, bumped on global security events.
- Pin HS256 via `jwt.WithValidMethods` and reject tokens whose `typ` does not
  match the requested operation.

## Consequences

- Consumers can migrate incrementally from either format.
- Revocation is cheap (counter comparison) and works across replicas when the
  `EpochStore` is shared.
- Tokens remain stateless; no server-side session table is required.
- Key rotation requires a new secret and invalidates outstanding tokens.
