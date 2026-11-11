// Package config defines the go-auth configuration structs with
// mapstructure/json/yaml tags, defaults, and strict validation rules.
package config

import (
	"fmt"
	"time"

	sgconfig "github.com/disaster37/go-secguard/config"
	sgrealip "github.com/disaster37/go-secguard/realip"

	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/oauth"
)

// Config is the top-level go-auth configuration.
type Config struct {
	Internal       InternalConfig       `mapstructure:"internal" json:"internal" yaml:"internal"`
	JWT            JWTConfig            `mapstructure:"jwt" json:"jwt" yaml:"jwt"`
	Session        SessionConfig        `mapstructure:"session" json:"session" yaml:"session"`
	Token          TokenConfig          `mapstructure:"token" json:"token" yaml:"token"`
	OAuth          OAuthConfig          `mapstructure:"oauth" json:"oauth" yaml:"oauth"`
	Cookie         CookieConfig         `mapstructure:"cookie" json:"cookie" yaml:"cookie"`
	CORS           CORSConfig           `mapstructure:"cors" json:"cors" yaml:"cors"`
	Security       SecurityConfig       `mapstructure:"security" json:"security" yaml:"security"`
	BootstrapAdmin BootstrapAdminConfig `mapstructure:"bootstrap_admin" json:"bootstrap_admin" yaml:"bootstrap_admin"`
}

// InternalConfig configures the legacy flat-file token fallback.
type InternalConfig struct {
	TokensFile string `mapstructure:"tokens_file" json:"tokens_file" yaml:"tokens_file"`
}

// JWTConfig configures HS256 JWT issuance.
type JWTConfig struct {
	Secret        string        `mapstructure:"secret" json:"secret" yaml:"secret"`
	AccessTTL     time.Duration `mapstructure:"access_ttl" json:"access_ttl" yaml:"access_ttl"`
	RefreshTTL    time.Duration `mapstructure:"refresh_ttl" json:"refresh_ttl" yaml:"refresh_ttl"`
	OAuthStateTTL time.Duration `mapstructure:"oauth_state_ttl" json:"oauth_state_ttl" yaml:"oauth_state_ttl"`
	UseHKDF       bool          `mapstructure:"use_hkdf" json:"use_hkdf" yaml:"use_hkdf"`
}

// SessionConfig configures compact HMAC session tokens.
type SessionConfig struct {
	Secret     string        `mapstructure:"secret" json:"secret" yaml:"secret"`
	TTL        time.Duration `mapstructure:"ttl" json:"ttl" yaml:"ttl"`
	CookieName string        `mapstructure:"cookie_name" json:"cookie_name" yaml:"cookie_name"`
}

// TokenConfig configures API tokens and at-rest encryption.
type TokenConfig struct {
	Prefix   string `mapstructure:"prefix" json:"prefix" yaml:"prefix"`
	KeyFile  string `mapstructure:"key_file" json:"key_file" yaml:"key_file"`
	RawKey   string `mapstructure:"raw_key" json:"raw_key" yaml:"raw_key"`
	HKDFInfo string `mapstructure:"hkdf_info" json:"hkdf_info" yaml:"hkdf_info"`
}

// OAuthConfig configures the OAuth2/OIDC provider.
type OAuthConfig struct {
	ProviderID           string                   `mapstructure:"provider_id" json:"provider_id" yaml:"provider_id"`
	ClientID             string                   `mapstructure:"client_id" json:"client_id" yaml:"client_id"`
	ClientSecret         string                   `mapstructure:"client_secret" json:"client_secret" yaml:"client_secret"`
	RedirectURL          string                   `mapstructure:"redirect_url" json:"redirect_url" yaml:"redirect_url"`
	IssuerURL            string                   `mapstructure:"issuer_url" json:"issuer_url" yaml:"issuer_url"`
	AllowInsecureIssuer  bool                     `mapstructure:"allow_insecure_issuer" json:"allow_insecure_issuer" yaml:"allow_insecure_issuer"`
	AllowedEndpoints     []string                 `mapstructure:"allowed_endpoints" json:"allowed_endpoints" yaml:"allowed_endpoints"`
	Scopes               []string                 `mapstructure:"scopes" json:"scopes" yaml:"scopes"`
	UsernameClaim        string                   `mapstructure:"username_claim" json:"username_claim" yaml:"username_claim"`
	GroupsClaim          string                   `mapstructure:"groups_claim" json:"groups_claim" yaml:"groups_claim"`
	AllowedGroups        []string                 `mapstructure:"allowed_groups" json:"allowed_groups" yaml:"allowed_groups"`
	AllowedOrgs          []string                 `mapstructure:"allowed_orgs" json:"allowed_orgs" yaml:"allowed_orgs"`
	AdminGroups          []string                 `mapstructure:"admin_groups" json:"admin_groups" yaml:"admin_groups"`
	DefaultGroup         string                   `mapstructure:"default_group" json:"default_group" yaml:"default_group"`
	CACertPath           string                   `mapstructure:"ca_cert_path" json:"ca_cert_path" yaml:"ca_cert_path"`
	RequireNonce         bool                     `mapstructure:"require_nonce" json:"require_nonce" yaml:"require_nonce"`
	EnablePKCE           bool                     `mapstructure:"enable_pkce" json:"enable_pkce" yaml:"enable_pkce"`
	RequireEmailVerified bool                     `mapstructure:"require_email_verified" json:"require_email_verified" yaml:"require_email_verified"`
	AutoCreateUser       bool                     `mapstructure:"auto_create_user" json:"auto_create_user" yaml:"auto_create_user"`
	GitHubOrgs           []string                 `mapstructure:"github_orgs" json:"github_orgs" yaml:"github_orgs"`
	GitHubTeams          []string                 `mapstructure:"github_teams" json:"github_teams" yaml:"github_teams"`
	GroupMappings        []oauth.GroupMappingRule `mapstructure:"group_mappings" json:"group_mappings" yaml:"group_mappings"`
}

// CookieConfig configures cookie names and flags.
type CookieConfig struct {
	AccessName  string `mapstructure:"access_name" json:"access_name" yaml:"access_name"`
	RefreshName string `mapstructure:"refresh_name" json:"refresh_name" yaml:"refresh_name"`
	SessionName string `mapstructure:"session_name" json:"session_name" yaml:"session_name"`
	StateName   string `mapstructure:"state_name" json:"state_name" yaml:"state_name"`
	NonceName   string `mapstructure:"nonce_name" json:"nonce_name" yaml:"nonce_name"`
	Path        string `mapstructure:"path" json:"path" yaml:"path"`
	Secure      bool   `mapstructure:"secure" json:"secure" yaml:"secure"`
	SameSite    string `mapstructure:"same_site" json:"same_site" yaml:"same_site"`
}

// CORSConfig configures allowed browser origins.
type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins" json:"allowed_origins" yaml:"allowed_origins"`
}

// SecurityConfig configures the defense-in-depth guardrails.
type SecurityConfig struct {
	MaxFailedAttempts     int           `mapstructure:"max_failed_attempts" json:"max_failed_attempts" yaml:"max_failed_attempts"`
	BaseLockout           time.Duration `mapstructure:"base_lockout" json:"base_lockout" yaml:"base_lockout"`
	MaxLockout            time.Duration `mapstructure:"max_lockout" json:"max_lockout" yaml:"max_lockout"`
	EntryTTL              time.Duration `mapstructure:"entry_ttl" json:"entry_ttl" yaml:"entry_ttl"`
	MaxEntries            int           `mapstructure:"max_entries" json:"max_entries" yaml:"max_entries"`
	BanMaxUniqueFailures  int           `mapstructure:"ban_max_unique_failures" json:"ban_max_unique_failures" yaml:"ban_max_unique_failures"`
	BanDuration           time.Duration `mapstructure:"ban_duration" json:"ban_duration" yaml:"ban_duration"`
	BanWindow             time.Duration `mapstructure:"ban_window" json:"ban_window" yaml:"ban_window"`
	RateLimitMax          int           `mapstructure:"rate_limit_max" json:"rate_limit_max" yaml:"rate_limit_max"`
	RateLimitWindow       time.Duration `mapstructure:"rate_limit_window" json:"rate_limit_window" yaml:"rate_limit_window"`
	LoginThrottleAttempts int           `mapstructure:"login_throttle_attempts" json:"login_throttle_attempts" yaml:"login_throttle_attempts"`
	LoginThrottleWindow   time.Duration `mapstructure:"login_throttle_window" json:"login_throttle_window" yaml:"login_throttle_window"`
	TrustedProxyCIDRs     []string      `mapstructure:"trusted_proxy_cidrs" json:"trusted_proxy_cidrs" yaml:"trusted_proxy_cidrs"`
	BehindReverseProxy    bool          `mapstructure:"behind_reverse_proxy" json:"behind_reverse_proxy" yaml:"behind_reverse_proxy"`
}

// BootstrapAdminConfig configures the dev bootstrap admin.
type BootstrapAdminConfig struct {
	Username string `mapstructure:"username" json:"username" yaml:"username"`
	Password string `mapstructure:"password" json:"password" yaml:"password"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		JWT: JWTConfig{
			AccessTTL:     15 * time.Minute,
			RefreshTTL:    7 * 24 * time.Hour,
			OAuthStateTTL: 10 * time.Minute,
			UseHKDF:       true,
		},
		Session: SessionConfig{
			TTL:        24 * time.Hour,
			CookieName: "auth_session",
		},
		Token: TokenConfig{
			Prefix: "dct_",
		},
		OAuth: OAuthConfig{
			Scopes:        []string{"openid", "profile", "email", "groups", "offline_access"},
			UsernameClaim: "preferred_username",
			GroupsClaim:   "groups",
			EnablePKCE:    true,
			RequireNonce:  true,
		},
		Cookie: CookieConfig{
			AccessName:  "auth_access",
			RefreshName: "auth_refresh",
			SessionName: "auth_session",
			StateName:   "oauth_state",
			NonceName:   "oauth_nonce",
			Path:        "/",
			SameSite:    "lax",
		},
		Security: SecurityConfig{
			MaxFailedAttempts:     5,
			BaseLockout:           30 * time.Second,
			MaxLockout:            15 * time.Minute,
			EntryTTL:              30 * time.Minute,
			MaxEntries:            4096,
			BanMaxUniqueFailures:  10,
			BanDuration:           15 * time.Minute,
			BanWindow:             5 * time.Minute,
			RateLimitMax:          60,
			RateLimitWindow:       time.Minute,
			LoginThrottleAttempts: 10,
			LoginThrottleWindow:   5 * time.Minute,
		},
		BootstrapAdmin: BootstrapAdminConfig{Username: "admin"},
	}
}

// Validate enforces the minimum secret lengths, TTL sanity, and provider
// completeness rules.
func (c *Config) Validate() error {
	if c.JWT.Secret != "" && len(c.JWT.Secret) < 32 {
		return fmt.Errorf("jwt.secret must be at least 32 characters: %w", domain.ErrValidation)
	}
	if c.Session.Secret != "" && len(c.Session.Secret) < 32 {
		return fmt.Errorf("session.secret must be at least 32 characters: %w", domain.ErrValidation)
	}
	if c.JWT.AccessTTL <= 0 {
		return fmt.Errorf("jwt.access_ttl must be positive: %w", domain.ErrValidation)
	}
	if c.JWT.RefreshTTL <= c.JWT.AccessTTL {
		return fmt.Errorf("jwt.refresh_ttl must exceed jwt.access_ttl: %w", domain.ErrValidation)
	}
	if c.JWT.OAuthStateTTL <= 0 {
		return fmt.Errorf("jwt.oauth_state_ttl must be positive: %w", domain.ErrValidation)
	}
	if c.Session.TTL <= 0 {
		return fmt.Errorf("session.ttl must be positive: %w", domain.ErrValidation)
	}
	if c.Token.Prefix == "" {
		return fmt.Errorf("token.prefix must not be empty: %w", domain.ErrValidation)
	}
	if err := c.validateOAuth(); err != nil {
		return err
	}
	if _, err := sgrealip.ParseTrustedProxyCIDRs(c.Security.TrustedProxyCIDRs); err != nil {
		return fmt.Errorf("security.trusted_proxy_cidrs: %w: %w", domain.ErrValidation, err)
	}
	if c.BootstrapAdmin.Password != "" && len(c.BootstrapAdmin.Password) < 8 {
		return fmt.Errorf("bootstrap_admin.password must be at least 8 characters: %w", domain.ErrValidation)
	}
	return nil
}

func (c *Config) validateOAuth() error {
	if c.OAuth.ProviderID == "" {
		return nil
	}
	if c.OAuth.ClientID == "" {
		return fmt.Errorf("oauth.client_id is required when oauth.provider_id is set: %w", domain.ErrValidation)
	}
	if c.OAuth.ClientSecret == "" {
		return fmt.Errorf("oauth.client_secret is required when oauth.provider_id is set: %w", domain.ErrValidation)
	}
	if c.OAuth.RedirectURL == "" {
		return fmt.Errorf("oauth.redirect_url is required when oauth.provider_id is set: %w", domain.ErrValidation)
	}
	if c.OAuth.ProviderID == "oidc" && c.OAuth.IssuerURL == "" {
		return fmt.Errorf("oauth.issuer_url is required for the oidc provider: %w", domain.ErrValidation)
	}
	if _, err := oauth.NewGroupMapper(c.OAuth.GroupMappings); err != nil {
		return fmt.Errorf("oauth.group_mappings: %w", err)
	}
	return nil
}

// ToSecguardConfig maps the go-auth security and CORS configuration onto the
// github.com/disaster37/go-secguard configuration structs. The flat go-auth
// schema has no per-component enable flag, so every component is enabled.
func (c *Config) ToSecguardConfig() sgconfig.Config {
	return sgconfig.Config{
		Lockout: sgconfig.LockoutConfig{
			Enabled:           true,
			MaxFailedAttempts: c.Security.MaxFailedAttempts,
			BaseLockout:       c.Security.BaseLockout,
			MaxLockout:        c.Security.MaxLockout,
			EntryTTL:          c.Security.EntryTTL,
			MaxEntries:        c.Security.MaxEntries,
		},
		RateLimit: sgconfig.RateLimitConfig{
			Enabled:               true,
			MaxRequests:           c.Security.RateLimitMax,
			Window:                c.Security.RateLimitWindow,
			LoginThrottleAttempts: c.Security.LoginThrottleAttempts,
			LoginThrottleWindow:   c.Security.LoginThrottleWindow,
			MaxEntries:            c.Security.MaxEntries,
		},
		Ban: sgconfig.BanConfig{
			Enabled:           true,
			MaxUniqueFailures: c.Security.BanMaxUniqueFailures,
			BanDuration:       c.Security.BanDuration,
			Window:            c.Security.BanWindow,
			MaxEntries:        c.Security.MaxEntries,
		},
		Proxy: sgconfig.ProxyConfig{
			BehindReverseProxy: c.Security.BehindReverseProxy,
			TrustedProxyCIDRs:  c.Security.TrustedProxyCIDRs,
		},
		CORS: sgconfig.CORSConfig{AllowedOrigins: c.CORS.AllowedOrigins},
	}
}
