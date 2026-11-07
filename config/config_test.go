package config

import (
	"errors"
	"testing"
	"time"

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
	cfg.Security.TrustedProxyCIDRs = []string{"not-a-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid CIDR must error")
	}
	cfg = DefaultConfig()
	cfg.BootstrapAdmin.Password = "short"
	if err := cfg.Validate(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short bootstrap password: %v", err)
	}
}
