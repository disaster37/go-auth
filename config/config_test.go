package config

import (
	"errors"
	"testing"
	"time"

	sgdomain "github.com/disaster37/go-secguard/domain"

	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/oauth"
)

func TestDefaultConfigValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config must validate: %v", err)
	}
}

func TestValidateSecrets(t *testing.T) {
	cfg := DefaultConfig()
	cfg.JWT.Secret = "short"
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short jwt secret: %v", err)
	}
	cfg = DefaultConfig()
	cfg.Session.Secret = "short"
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short session secret: %v", err)
	}
	cfg = DefaultConfig()
	cfg.JWT.Secret = "0123456789abcdef0123456789abcdef"
	cfg.Session.Secret = "0123456789abcdef0123456789abcdef"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid secrets: %v", err)
	}
}

func TestValidateTTLs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.JWT.AccessTTL = 0
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("zero access ttl: %v", err)
	}
	cfg = DefaultConfig()
	cfg.JWT.RefreshTTL = time.Minute
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("refresh <= access: %v", err)
	}
	cfg = DefaultConfig()
	cfg.JWT.OAuthStateTTL = 0
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("zero state ttl: %v", err)
	}
	cfg = DefaultConfig()
	cfg.Session.TTL = 0
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("zero session ttl: %v", err)
	}
}

func TestValidateTokenPrefix(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token.Prefix = ""
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("empty prefix: %v", err)
	}
}

func TestValidateOAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OAuth.ProviderID = "oidc"
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("missing client id: %v", err)
	}
	cfg.OAuth.ClientID = "id"
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("missing client secret: %v", err)
	}
	cfg.OAuth.ClientSecret = "secret"
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("missing redirect url: %v", err)
	}
	cfg.OAuth.RedirectURL = "https://app/cb"
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("missing issuer for oidc: %v", err)
	}
	cfg.OAuth.IssuerURL = "https://issuer"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid oauth: %v", err)
	}
	// GitHub provider does not require an issuer.
	cfg = DefaultConfig()
	cfg.OAuth.ProviderID = "github"
	cfg.OAuth.ClientID = "id"
	cfg.OAuth.ClientSecret = "secret"
	cfg.OAuth.RedirectURL = "https://app/cb"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid github oauth: %v", err)
	}
	// Invalid group mapping.
	cfg.OAuth.GroupMappings = []oauth.GroupMappingRule{{Pattern: "("}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid group mapping must error")
	}
}

func TestValidateSecurityAndBootstrap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.TrustedProxyCIDRs = []string{"not-a-cidr/24"}
	err := cfg.Validate()
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invalid CIDR must wrap domain.ErrValidation: %v", err)
	}
	if !errors.Is(err, sgdomain.ErrInvalidCIDR) {
		t.Fatalf("invalid CIDR must wrap sgdomain.ErrInvalidCIDR: %v", err)
	}

	cfg = DefaultConfig()
	cfg.Security.TrustedProxyCIDRs = []string{"not-an-ip"}
	err = cfg.Validate()
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invalid IP must wrap domain.ErrValidation: %v", err)
	}
	if !errors.Is(err, sgdomain.ErrInvalidIP) {
		t.Fatalf("invalid IP must wrap sgdomain.ErrInvalidIP: %v", err)
	}

	cfg = DefaultConfig()
	cfg.BootstrapAdmin.Password = "short"
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short bootstrap password: %v", err)
	}
}

func TestToSecguardConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS.AllowedOrigins = []string{"https://app.example.com"}
	cfg.Security.TrustedProxyCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16"}

	got := cfg.ToSecguardConfig()

	if !got.Lockout.Enabled || !got.RateLimit.Enabled || !got.Ban.Enabled {
		t.Fatal("all components must be enabled")
	}
	if got.Lockout.MaxFailedAttempts != cfg.Security.MaxFailedAttempts {
		t.Fatalf("lockout max failed attempts=%d", got.Lockout.MaxFailedAttempts)
	}
	if got.Lockout.BaseLockout != cfg.Security.BaseLockout {
		t.Fatalf("lockout base=%v", got.Lockout.BaseLockout)
	}
	if got.Lockout.MaxLockout != cfg.Security.MaxLockout {
		t.Fatalf("lockout max=%v", got.Lockout.MaxLockout)
	}
	if got.Lockout.EntryTTL != cfg.Security.EntryTTL {
		t.Fatalf("lockout entry ttl=%v", got.Lockout.EntryTTL)
	}
	if got.Lockout.MaxEntries != cfg.Security.MaxEntries {
		t.Fatalf("lockout max entries=%d", got.Lockout.MaxEntries)
	}
	if got.RateLimit.MaxRequests != cfg.Security.RateLimitMax {
		t.Fatalf("rate limit max=%d", got.RateLimit.MaxRequests)
	}
	if got.RateLimit.Window != cfg.Security.RateLimitWindow {
		t.Fatalf("rate limit window=%v", got.RateLimit.Window)
	}
	if got.RateLimit.LoginThrottleAttempts != cfg.Security.LoginThrottleAttempts {
		t.Fatalf("login throttle attempts=%d", got.RateLimit.LoginThrottleAttempts)
	}
	if got.RateLimit.LoginThrottleWindow != cfg.Security.LoginThrottleWindow {
		t.Fatalf("login throttle window=%v", got.RateLimit.LoginThrottleWindow)
	}
	if got.RateLimit.MaxEntries != cfg.Security.MaxEntries {
		t.Fatalf("rate limit max entries=%d", got.RateLimit.MaxEntries)
	}
	if got.Ban.MaxUniqueFailures != cfg.Security.BanMaxUniqueFailures {
		t.Fatalf("ban max unique failures=%d", got.Ban.MaxUniqueFailures)
	}
	if got.Ban.BanDuration != cfg.Security.BanDuration {
		t.Fatalf("ban duration=%v", got.Ban.BanDuration)
	}
	if got.Ban.Window != cfg.Security.BanWindow {
		t.Fatalf("ban window=%v", got.Ban.Window)
	}
	if got.Ban.MaxEntries != cfg.Security.MaxEntries {
		t.Fatalf("ban max entries=%d", got.Ban.MaxEntries)
	}
	if got.Proxy.BehindReverseProxy != cfg.Security.BehindReverseProxy {
		t.Fatalf("behind reverse proxy=%v", got.Proxy.BehindReverseProxy)
	}
	if len(got.Proxy.TrustedProxyCIDRs) != len(cfg.Security.TrustedProxyCIDRs) {
		t.Fatalf("trusted proxy cidrs=%v", got.Proxy.TrustedProxyCIDRs)
	}
	for i, cidr := range cfg.Security.TrustedProxyCIDRs {
		if got.Proxy.TrustedProxyCIDRs[i] != cidr {
			t.Fatalf("trusted proxy cidrs[%d]=%q want %q", i, got.Proxy.TrustedProxyCIDRs[i], cidr)
		}
	}
	if len(got.CORS.AllowedOrigins) != 1 || got.CORS.AllowedOrigins[0] != cfg.CORS.AllowedOrigins[0] {
		t.Fatalf("cors allowed origins=%v", got.CORS.AllowedOrigins)
	}
}
