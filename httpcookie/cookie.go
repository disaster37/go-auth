// Package httpcookie provides framework-agnostic cookie specifications and
// open-redirect defense (SafeRedirectPath).
package httpcookie

import "net/http"

const (
	// DefaultAccessCookieName is the default access-token cookie name.
	DefaultAccessCookieName = "auth_access"
	// DefaultRefreshCookieName is the default refresh-token cookie name.
	DefaultRefreshCookieName = "auth_refresh"
	// DefaultSessionCookieName is the default session cookie name.
	DefaultSessionCookieName = "auth_session"
	// DefaultStateCookieName is the default OAuth state cookie name.
	DefaultStateCookieName = "oauth_state"
	// DefaultNonceCookieName is the default OIDC nonce cookie name.
	DefaultNonceCookieName = "oauth_nonce"
	// DefaultOAuthCookiePath is the default path scoping the OAuth state cookie.
	DefaultOAuthCookiePath = "/api/v1/auth/oauth"
	// DefaultStateMaxAge is the default OAuth state cookie max age in seconds.
	DefaultStateMaxAge = 600
)

// Spec is a framework-agnostic HTTP cookie specification that can be written to
// a net/http.ResponseWriter or a CloudWeGo Hertz *app.RequestContext.
type Spec struct {
	Name     string
	Value    string
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// ToStdlib converts the Spec to a *http.Cookie.
func (s Spec) ToStdlib() *http.Cookie {
	return &http.Cookie{ // #nosec G124

		Name:     s.Name,
		Value:    s.Value,
		Path:     s.Path,
		Domain:   s.Domain,
		MaxAge:   s.MaxAge,
		Secure:   s.Secure,
		HttpOnly: s.HttpOnly,
		SameSite: s.SameSite,
	}
}

// Config configures cookie issuance.
type Config struct {
	AccessName     string
	RefreshName    string
	SessionName    string
	StateName      string
	NonceName      string
	Path           string
	OAuthStatePath string
	Secure         bool
	SameSite       http.SameSite
}

// DefaultConfig returns the default cookie configuration.
func DefaultConfig() Config {
	return Config{
		AccessName:     DefaultAccessCookieName,
		RefreshName:    DefaultRefreshCookieName,
		SessionName:    DefaultSessionCookieName,
		StateName:      DefaultStateCookieName,
		NonceName:      DefaultNonceCookieName,
		Path:           "/",
		OAuthStatePath: DefaultOAuthCookiePath,
		Secure:         false,
		SameSite:       http.SameSiteLaxMode,
	}
}

func (c Config) secure(isTLS bool) bool { return c.Secure || isTLS }

// IssuePairSpecs returns the access and refresh cookie specs for a fresh login.
func IssuePairSpecs(cfg Config, isTLS bool, access, refresh string, accessTTLSeconds, refreshTTLSeconds int) (accessSpec, refreshSpec Spec) {
	accessSpec = Spec{
		Name:     cfg.AccessName,
		Value:    access,
		Path:     cfg.Path,
		MaxAge:   accessTTLSeconds,
		Secure:   cfg.secure(isTLS),
		HttpOnly: true,
		SameSite: cfg.SameSite,
	}
	refreshSpec = Spec{
		Name:     cfg.RefreshName,
		Value:    refresh,
		Path:     cfg.Path,
		MaxAge:   refreshTTLSeconds,
		Secure:   cfg.secure(isTLS),
		HttpOnly: true,
		SameSite: cfg.SameSite,
	}
	return accessSpec, refreshSpec
}

// ClearPairSpecs returns the access and refresh cookie specs that clear them.
func ClearPairSpecs(cfg Config, isTLS bool) (accessSpec, refreshSpec Spec) {
	accessSpec = Spec{
		Name:     cfg.AccessName,
		Path:     cfg.Path,
		MaxAge:   -1,
		Secure:   cfg.secure(isTLS),
		HttpOnly: true,
		SameSite: cfg.SameSite,
	}
	refreshSpec = Spec{
		Name:     cfg.RefreshName,
		Path:     cfg.Path,
		MaxAge:   -1,
		Secure:   cfg.secure(isTLS),
		HttpOnly: true,
		SameSite: cfg.SameSite,
	}
	return accessSpec, refreshSpec
}

// IssueSessionSpec returns the session cookie spec.
func IssueSessionSpec(cfg Config, isTLS bool, sessionToken string, maxAgeSeconds int) Spec {
	return Spec{
		Name:     cfg.SessionName,
		Value:    sessionToken,
		Path:     cfg.Path,
		MaxAge:   maxAgeSeconds,
		Secure:   cfg.secure(isTLS),
		HttpOnly: true,
		SameSite: cfg.SameSite,
	}
}

// ClearSessionSpec returns the session cookie spec that clears it.
func ClearSessionSpec(cfg Config, isTLS bool) Spec {
	return Spec{
		Name:     cfg.SessionName,
		Path:     cfg.Path,
		MaxAge:   -1,
		Secure:   cfg.secure(isTLS),
		HttpOnly: true,
		SameSite: cfg.SameSite,
	}
}

// IssueOAuthStateSpec returns the OAuth state cookie spec.
func IssueOAuthStateSpec(cfg Config, isTLS bool, nonce string, maxAgeSeconds int) Spec {
	return Spec{
		Name:     cfg.StateName,
		Value:    nonce,
		Path:     cfg.OAuthStatePath,
		MaxAge:   maxAgeSeconds,
		Secure:   cfg.secure(isTLS),
		HttpOnly: true,
		SameSite: cfg.SameSite,
	}
}

// ClearOAuthStateSpec returns the OAuth state cookie spec that clears it.
func ClearOAuthStateSpec(cfg Config, isTLS bool) Spec {
	return Spec{
		Name:     cfg.StateName,
		Path:     cfg.OAuthStatePath,
		MaxAge:   -1,
		Secure:   cfg.secure(isTLS),
		HttpOnly: true,
		SameSite: cfg.SameSite,
	}
}
