# ADR-003: OAuth/OIDC security and revalidation

## Status

Accepted.

## Context

OAuth2/OIDC login is a common source of vulnerabilities: login CSRF, open
redirects, audience confusion, unverified email addresses, oversized provider
responses, and stale group membership after an IdP change.

## Decision

- Bind the signed `oauth_state` JWT to a constant-time cookie nonce and use
  PKCE `S256` plus an OIDC `nonce`.
- Verify multi-audience ID tokens with `azp == client_id` (OIDC Core §3.1.3.7).
- Enforce `email_verified` when configured.
- Merge missing claims from UserInfo, with signed ID-token claims taking
  precedence.
- Cap provider responses at 1 MiB and refuse cross-origin redirects.
- Validate discovered token/userinfo endpoints against `allowed_endpoints`.
- Revalidate IdP membership through a single-flight cache with:
  - crypto-seeded ±10% TTL jitter,
  - an offline grace window,
  - fail-open/fail-closed policy,
  - `SessionMaxAge`,
  - leader-only refresh (`isLeader func() bool`).
- Distinguish ambiguous credential expiry (`ErrOAuthCredentialExpired`,
  non-destructive) from definitive revocation (`ErrSessionRevoked`/`ErrForbidden`,
  which deactivates the user and revokes API tokens).

## Consequences

- Login is resistant to CSRF, fixation, audience confusion, and open redirects.
- Followers never rotate single-use refresh tokens they cannot persist.
- Transient IdP outages degrade gracefully according to policy.
- Revalidation adds one cache lookup per authenticated request.
