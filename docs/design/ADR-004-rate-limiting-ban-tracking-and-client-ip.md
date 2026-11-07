# ADR-004: Rate limiting, ban tracking, and client IP resolution

## Status

Accepted.

## Context

Credential stuffing and brute-force attacks need layered defenses. Naive
per-IP counters either ban legitimate clients that repeat one bad credential or
let attackers rotate usernames. Client IP extraction behind proxies is also
easy to spoof if forwarded headers are trusted unconditionally.

## Decision

- `LockoutLimiter`: per-account+IP exponential backoff (30s to 15m, capped
  shift, bounded map with oldest-entry eviction).
- `LoginThrottle`: per-account sliding window for repeated login attempts.
- `RateLimiter`: bounded sliding-window limiter with throttled sweeps.
- `BanTracker`: counts unique SHA-256 credential fingerprints per IP within a
  sliding window, so a single misconfigured client is not banned as an attacker.
- `ExtractRealIP`: honors `X-Forwarded-For`/`X-Real-IP` only when the direct
  peer is in `TrustedProxyCIDRs`, walking XFF right-to-left and skipping trusted
  proxies.
- All maps are bounded (default 4096) and sweeps are throttled to avoid
  per-failure full-map scans.

## Consequences

- Attackers face escalating delays and IP bans without a shared database.
- Legitimate clients repeating one credential are tolerated.
- Correct proxy configuration is required; an overly broad
  `trusted_proxy_cidrs` weakens spoofing resistance.
- State is per-process; multi-replica deployments rely on the shared
  `AuthEpoch`/`TokenVersion` for global revocation, not on limiter state.
