package httpcookie

import (
	"net/http"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AccessName != DefaultAccessCookieName || cfg.RefreshName != DefaultRefreshCookieName ||
		cfg.SessionName != DefaultSessionCookieName || cfg.StateName != DefaultStateCookieName ||
		cfg.NonceName != DefaultNonceCookieName || cfg.Path != "/" ||
		cfg.OAuthStatePath != DefaultOAuthCookiePath || cfg.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected default config: %+v", cfg)
	}
}

func TestIssuePairSpecs(t *testing.T) {
	cfg := DefaultConfig()
	access, refresh := IssuePairSpecs(cfg, true, "a", "r", 900, 604800)
	if access.Name != cfg.AccessName || access.Value != "a" || access.MaxAge != 900 || !access.Secure || !access.HttpOnly {
		t.Fatalf("access spec: %+v", access)
	}
	if refresh.Name != cfg.RefreshName || refresh.Value != "r" || refresh.MaxAge != 604800 || !refresh.Secure {
		t.Fatalf("refresh spec: %+v", refresh)
	}
	// Secure is forced by config even without TLS.
	cfg.Secure = true
	access, _ = IssuePairSpecs(cfg, false, "a", "r", 1, 1)
	if !access.Secure {
		t.Fatal("config Secure must force the flag")
	}
}

func TestClearSpecs(t *testing.T) {
	cfg := DefaultConfig()
	access, refresh := ClearPairSpecs(cfg, false)
	if access.MaxAge != -1 || access.Value != "" || refresh.MaxAge != -1 {
		t.Fatalf("clear pair: %+v %+v", access, refresh)
	}
	session := ClearSessionSpec(cfg, false)
	if session.Name != cfg.SessionName || session.MaxAge != -1 {
		t.Fatalf("clear session: %+v", session)
	}
	state := ClearOAuthStateSpec(cfg, false)
	if state.Name != cfg.StateName || state.Path != cfg.OAuthStatePath || state.MaxAge != -1 {
		t.Fatalf("clear state: %+v", state)
	}
}

func TestIssueSessionAndStateSpecs(t *testing.T) {
	cfg := DefaultConfig()
	session := IssueSessionSpec(cfg, true, "tok", 3600)
	if session.Name != cfg.SessionName || session.Value != "tok" || session.MaxAge != 3600 || !session.Secure {
		t.Fatalf("session spec: %+v", session)
	}
	state := IssueOAuthStateSpec(cfg, false, "nonce", DefaultStateMaxAge)
	if state.Name != cfg.StateName || state.Value != "nonce" || state.Path != cfg.OAuthStatePath || state.MaxAge != DefaultStateMaxAge {
		t.Fatalf("state spec: %+v", state)
	}
}

func TestSpecToStdlib(t *testing.T) {
	spec := Spec{Name: "n", Value: "v", Path: "/p", Domain: "example.com", MaxAge: 10, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	c := spec.ToStdlib()
	if c.Name != "n" || c.Value != "v" || c.Path != "/p" || c.Domain != "example.com" || c.MaxAge != 10 || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", c)
	}
}
