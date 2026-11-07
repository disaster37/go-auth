# Configuration reference

`config.Config` is a plain struct with `mapstructure`, `json`, and `yaml` tags.
`config.DefaultConfig()` returns safe defaults and `(*Config).Validate()`
enforces the rules below. Durations use Go duration strings (for example
`15m`, `168h`).

## Top-level structure

```yaml
internal:
  tokens_file: ""
jwt:
  secret: ""
  access_ttl: 15m
  refresh_ttl: 168h
  oauth_state_ttl: 10m
  use_hkdf: true
session:
  secret: ""
  ttl: 24h
  cookie_name: auth_session
token:
  prefix: dct_
  key_file: ""
  raw_key: ""
  hkdf_info: ""
oauth:
  provider_id: ""
  client_id: ""
  client_secret: ""
  redirect_url: ""
  issuer_url: ""
  allow_insecure_issuer: false
  allowed_endpoints: []
  scopes: [openid, profile, email, groups, offline_access]
  username_claim: preferred_username
  groups_claim: groups
  allowed_groups: []
  allowed_orgs: []
  admin_groups: []
  default_group: ""
  ca_cert_path: ""
  require_nonce: true
  enable_pkce: true
  require_email_verified: false
  auto_create_user: false
  github_orgs: []
  github_teams: []
  group_mappings: []
cookie:
  access_name: auth_access
  refresh_name: auth_refresh
  session_name: auth_session
  state_name: oauth_state
  nonce_name: oauth_nonce
  path: /
  secure: false
  same_site: lax
cors:
  allowed_origins: []
security:
  max_failed_attempts: 5
  base_lockout: 30s
  max_lockout: 15m
  entry_ttl: 30m
  max_entries: 4096
  ban_max_unique_failures: 10
  ban_duration: 15m
  ban_window: 5m
  rate_limit_max: 60
  rate_limit_window: 1m
  login_throttle_attempts: 10
  login_throttle_window: 5m
  trusted_proxy_cidrs: []
  behind_reverse_proxy: false
bootstrap_admin:
  username: admin
  password: ""
```

## `internal`

| Key | Type | Default | Description |
|---|---|---|---|
| `tokens_file` | string | `""` | Path to a legacy flat-file token list used by the legacy fallback validator. |

## `jwt`

| Key | Type | Default | Validation |
|---|---|---|---|
| `secret` | string | `""` | When set, must be at least 32 characters. |
| `access_ttl` | duration | `15m` | Must be positive. |
| `refresh_ttl` | duration | `168h` | Must be greater than `access_ttl`. |
| `oauth_state_ttl` | duration | `10m` | Must be positive. |
| `use_hkdf` | bool | `true` | Derive the signing key with HKDF-SHA256. |

## `session`

| Key | Type | Default | Validation |
|---|---|---|---|
| `secret` | string | `""` | When set, must be at least 32 characters. |
| `ttl` | duration | `24h` | Must be positive. |
| `cookie_name` | string | `auth_session` | Cookie name for compact session tokens. |

## `token`

| Key | Type | Default | Validation |
|---|---|---|---|
| `prefix` | string | `dct_` | Must not be empty. |
| `key_file` | string | `""` | File containing the at-rest encryption key. |
| `raw_key` | string | `""` | Raw at-rest encryption key (prefer `key_file`). |
| `hkdf_info` | string | `""` | Optional HKDF domain-separation info for at-rest keys. |

## `oauth`

| Key | Type | Default | Description |
|---|---|---|---|
| `provider_id` | string | `""` | Enables OAuth when non-empty (for example `oidc` or `github`). |
| `client_id` | string | `""` | Required when `provider_id` is set. |
| `client_secret` | string | `""` | Required when `provider_id` is set. |
| `redirect_url` | string | `""` | Required when `provider_id` is set. |
| `issuer_url` | string | `""` | Required for the `oidc` provider; must be HTTPS unless loopback or `allow_insecure_issuer`. |
| `allow_insecure_issuer` | bool | `false` | Permit an HTTP issuer (trusted development providers only). |
| `allowed_endpoints` | []string | `[]` | Allowlist of discovered token/userinfo endpoints (host + path prefix). |
| `scopes` | []string | `[openid, profile, email, groups, offline_access]` | OIDC scopes; `openid` and `offline_access` are added automatically. |
| `username_claim` | string | `preferred_username` | Claim used for the local username. |
| `groups_claim` | string | `groups` | Claim used for upstream groups. |
| `allowed_groups` | []string | `[]` | Require membership in at least one group. |
| `allowed_orgs` | []string | `[]` | Deprecated alias merged with `allowed_groups`. |
| `admin_groups` | []string | `[]` | Upstream groups that promote the user to admin. |
| `default_group` | string | `""` | Group joined when the user has no memberships (defaults to `default`). |
| `ca_cert_path` | string | `""` | Extra CA certificate for the OIDC HTTP client. |
| `require_nonce` | bool | `true` | Require and verify the OIDC `nonce`. |
| `enable_pkce` | bool | `true` | Send a PKCE `S256` challenge/verifier. |
| `require_email_verified` | bool | `false` | Reject `email_verified: false`. |
| `auto_create_user` | bool | `false` | Create users on first login; when false, require a pre-linked external identity. |
| `github_orgs` | []string | `[]` | GitHub organizations allowed to log in. |
| `github_teams` | []string | `[]` | GitHub teams allowed to log in (`org/team`). |
| `group_mappings` | []object | `[]` | Ordered `{pattern, replacement}` RE2 rules mapping upstream groups to local groups. |

## `cookie`

| Key | Type | Default | Description |
|---|---|---|---|
| `access_name` | string | `auth_access` | Access-token cookie name. |
| `refresh_name` | string | `auth_refresh` | Refresh-token cookie name. |
| `session_name` | string | `auth_session` | Session cookie name. |
| `state_name` | string | `oauth_state` | OAuth state cookie name. |
| `nonce_name` | string | `oauth_nonce` | OIDC nonce cookie name. |
| `path` | string | `/` | Cookie path. |
| `secure` | bool | `false` | Force the `Secure` attribute (also set automatically over TLS). |
| `same_site` | string | `lax` | `lax`, `strict`, or `none`. |

## `cors`

| Key | Type | Default | Description |
|---|---|---|---|
| `allowed_origins` | []string | `[]` | Origins allowed for mutating browser requests. Empty or `*` allows any origin. |

## `security`

| Key | Type | Default | Description |
|---|---|---|---|
| `max_failed_attempts` | int | `5` | Failures before exponential lockout starts. |
| `base_lockout` | duration | `30s` | First lockout duration. |
| `max_lockout` | duration | `15m` | Lockout cap. |
| `entry_ttl` | duration | `30m` | Idle failure-record lifetime. |
| `max_entries` | int | `4096` | Bound on limiter/tracker maps. |
| `ban_max_unique_failures` | int | `10` | Unique credential failures before an IP ban. |
| `ban_duration` | duration | `15m` | Ban duration. |
| `ban_window` | duration | `5m` | Sliding window for unique failures. |
| `rate_limit_max` | int | `60` | Requests allowed per window. |
| `rate_limit_window` | duration | `1m` | Rate-limit window. |
| `login_throttle_attempts` | int | `10` | Login attempts allowed per window. |
| `login_throttle_window` | duration | `5m` | Login-throttle window. |
| `trusted_proxy_cidrs` | []string | `[]` | CIDRs/IPs whose forwarded headers are trusted. Invalid entries fail validation. |
| `behind_reverse_proxy` | bool | `false` | Honor `X-Forwarded-For`/`X-Real-IP` from trusted peers. |

## `bootstrap_admin`

| Key | Type | Default | Validation |
|---|---|---|---|
| `username` | string | `admin` | Development bootstrap username. |
| `password` | string | `""` | When set, must be at least 8 characters. |

## Validation summary

`Validate()` returns an error wrapping `domain.ErrValidation` when:

- `jwt.secret` or `session.secret` is non-empty and shorter than 32 characters.
- `jwt.access_ttl`, `jwt.oauth_state_ttl`, or `session.ttl` is not positive.
- `jwt.refresh_ttl` is not greater than `jwt.access_ttl`.
- `token.prefix` is empty.
- `oauth.provider_id` is set but `client_id`, `client_secret`, or `redirect_url`
  is empty, or the `oidc` provider has no `issuer_url`.
- `oauth.group_mappings` contains an empty or invalid RE2 pattern.
- `security.trusted_proxy_cidrs` contains an invalid CIDR/IP.
- `bootstrap_admin.password` is non-empty and shorter than 8 characters.
