# Security Policy

## Supported versions

Security fixes are applied to the latest minor release on the `main` branch.
Older releases may receive fixes at the maintainers' discretion.

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Report them
privately to the maintainers through GitHub's private vulnerability reporting
(Security → Advisories → Report a vulnerability) or by contacting the repository
owner directly. Include:

- A description of the issue and its impact.
- Reproduction steps or a proof of concept.
- Affected versions and any suggested remediation.

We aim to acknowledge reports within 72 hours and to publish a coordinated fix
and advisory once a patch is available.

## Threat model

| CWE | Threat | Mitigation |
|---|---|---|
| CWE-208 | Observable timing discrepancy | Precomputed bcrypt dummy hash on unknown/passwordless users; `subtle.ConstantTimeCompare`/`hmac.Equal` on tokens, hashes, and nonces. |
| CWE-287 | Improper authentication | Multi-audience OIDC `azp` verification; `email_verified` check; strict JWT `typ` separation; HS256 algorithm pinning. |
| CWE-307 | Excessive authentication attempts | `secguard.LockoutLimiter`, `secguard.LoginThrottle`, and `secguard.BanTracker`. |
| CWE-311 / CWE-319 | Missing encryption of sensitive data | `crypto.Sealer` (AES-256-GCM with HKDF-SHA256 and AAD) for API tokens and upstream OAuth credentials; HTTPS enforcement on OIDC issuers. |
| CWE-326 / CWE-798 | Weak or hardcoded keys | `config` enforces minimum secret lengths; HKDF domain separation; no hardcoded secrets. |
| CWE-352 | CSRF / login CSRF | OAuth state JWT bound to an `HttpOnly; SameSite=Lax` nonce cookie, PKCE `S256`, OIDC `nonce`, and `secguard.CheckMutationOrigin`. |
| CWE-384 | Session fixation | Fresh JWT pair/session ID on every login and callback; state/nonce cookies cleared immediately. |
| CWE-400 | Uncontrolled resource consumption | Bounded maps (4096 entries), throttled sweeps, 1 MiB provider response cap, 15s discovery timeout, 64 KiB login body cap. |
| CWE-532 | Sensitive information in logs | Passwords, hashes, JWTs, API tokens, client secrets, and keys are never logged; sensitive fields use `json:"-"`. |
| CWE-601 | Open redirect | `httpcookie.SafeRedirectPath` rejects `//`, `\`, `/\`, CR/LF, control characters, and non-relative URLs; OIDC HTTP clients refuse cross-origin redirects. |
| CWE-613 | Insufficient session expiration | Short-lived access tokens, rotatable refresh tokens, `TokenVersion`, `AuthEpoch`, `SessionMaxAge`, and IdP revalidation. |
| CWE-916 | Insufficient password hashing effort | bcrypt with configurable cost (default 10, min 10, max 31) and strict 8–72 byte length enforcement. |

## Operational guidance

- Always terminate TLS in front of the service and set `cookie.secure: true`.
- Configure `security.trusted_proxy_cidrs` only with proxies you control, and
  enable `security.behind_reverse_proxy` only when running behind them.
- Use secrets of at least 32 characters for `jwt.secret` and `session.secret`.
- Rotate API tokens and OAuth client secrets regularly.
- Keep `oauth.allowed_groups`/`oauth.allowed_orgs` narrow and review
  `oauth.admin_groups` carefully.
- Run the CI pipeline (`dagger call -m ./dagger --src . ci export --path out`)
  before deploying changes.
