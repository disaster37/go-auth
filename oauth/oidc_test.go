package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/password"
	"github.com/disaster37/go-auth/store"
	"github.com/disaster37/go-auth/testutil"
)

func newOIDCService(t *testing.T, m *testutil.MockOIDCServer, cfg OIDCConfig) (*OIDCOAuthService, *store.MemoryUserStore, *store.MemoryGroupStore) {
	t.Helper()
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	_ = groups.Create(context.Background(), &domain.Group{ID: "g-default", Name: "default"})
	jwtSvc, err := jwt.NewService(jwt.Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatalf("jwt: %v", err)
	}
	cfg.IssuerURL = m.Issuer()
	cfg.ClientID = m.ClientID
	cfg.ClientSecret = "secret"
	cfg.RedirectURL = "http://localhost/callback"
	cfg.AutoCreateUser = true
	svc, err := NewOIDCOAuthService(cfg, nil, password.NewService(users), users, groups, jwtSvc, testSealer(t), nil, nil, observ.NewNoopLogger())
	if err != nil {
		t.Fatalf("new oidc service: %v", err)
	}
	return svc, users, groups
}

func TestNewOIDCOAuthServiceIssuerValidation(t *testing.T) {
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	jwtSvc, _ := jwt.NewService(jwt.Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	_, err := NewOIDCOAuthService(OIDCConfig{IssuerURL: "http://example.com"}, nil, password.NewService(users), users, groups, jwtSvc, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("non-loopback http issuer must be rejected")
	}
	_, err = NewOIDCOAuthService(OIDCConfig{IssuerURL: "http://example.com", AllowInsecureIssuer: true}, nil, password.NewService(users), users, groups, jwtSvc, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("allow_insecure_issuer must permit http: %v", err)
	}
}

func TestOIDCLoginURL(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	svc, _, _ := newOIDCService(t, m, OIDCConfig{})
	url := svc.LoginURL(AuthorizeParams{State: "state-1", Nonce: "nonce-1", CodeChallenge: "challenge-1"})
	for _, want := range []string{"state-1", "nonce-1", "challenge-1", "code_challenge_method=S256"} {
		if !strings.Contains(url, want) {
			t.Fatalf("login url missing %q: %s", want, url)
		}
	}
	if svc.Name() != "" {
		t.Fatalf("provider id=%q", svc.Name())
	}
}

func TestOIDCCompleteSuccess(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.Nonce = "n1"
	svc, users, _ := newOIDCService(t, m, OIDCConfig{RequireNonce: true, EnablePKCE: true, AdminGroups: []string{"admins"}})
	m.Groups = []string{"admins"}

	access, refresh, u, err := svc.Complete(context.Background(), CompleteParams{Code: "code", ExpectedNonce: "n1", CodeVerifier: "verifier"})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if access == "" || refresh == "" || u == nil {
		t.Fatal("expected token pair and user")
	}
	if u.Role != domain.RoleAdmin {
		t.Fatalf("expected admin, got %s", u.Role)
	}
	stored, _ := users.Get(context.Background(), u.ID)
	if stored.OAuthTokenCiphertext == "" {
		t.Fatal("expected sealed credential")
	}
}

func TestOIDCCompleteNonceMismatch(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.Nonce = "n1"
	svc, _, _ := newOIDCService(t, m, OIDCConfig{RequireNonce: true})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code", ExpectedNonce: "wrong"}); err == nil {
		t.Fatal("nonce mismatch must fail")
	}
}

func TestOIDCCompleteAZP(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.Audience = []string{"test-client", "other-client"}
	m.AZP = "other-client"
	svc, _, _ := newOIDCService(t, m, OIDCConfig{})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err == nil {
		t.Fatal("azp mismatch must fail")
	}
	m.AZP = "test-client"
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err != nil {
		t.Fatalf("matching azp must succeed: %v", err)
	}
}

func TestOIDCCompleteEmailVerified(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.EmailVerified = false
	svc, _, _ := newOIDCService(t, m, OIDCConfig{RequireEmailVerified: true})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("unverified email: %v", err)
	}
}

func TestOIDCCompleteEmailVerifiedFromUserinfo(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	// The ID token omits email_verified; userinfo supplies false. The check must
	// run after the userinfo merge so this is not bypassed.
	m.OmitEmailVerified = true
	m.EmailVerified = false
	svc, _, _ := newOIDCService(t, m, OIDCConfig{RequireEmailVerified: true, UsernameClaim: "nickname"})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("unverified email from userinfo: %v", err)
	}
}

func TestOIDCCompleteAuthEpoch(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	svc, _, _ := newOIDCService(t, m, OIDCConfig{AuthEpoch: func() int64 { return 7 }})
	access, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	claims, err := svc.lc.jwt.ParseAccess(access)
	if err != nil {
		t.Fatalf("parse access: %v", err)
	}
	if claims.AuthEpoch != 7 {
		t.Fatalf("auth epoch=%d want 7", claims.AuthEpoch)
	}
}

func TestRefuseCrossOriginRedirectSchemeDowngrade(t *testing.T) {
	orig, _ := http.NewRequest(http.MethodGet, "https://idp.example.com/token", nil)
	next, _ := http.NewRequest(http.MethodGet, "http://idp.example.com/token", nil)
	if err := refuseCrossOriginRedirect(next, []*http.Request{orig}); err == nil {
		t.Fatal("scheme downgrade redirect must be refused")
	}
	same, _ := http.NewRequest(http.MethodGet, "https://idp.example.com/other", nil)
	if err := refuseCrossOriginRedirect(same, []*http.Request{orig}); err != nil {
		t.Fatalf("same-origin redirect must be allowed: %v", err)
	}
}

func TestOIDCCompleteAllowedGroups(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.Groups = []string{"dev"}
	svc, _, _ := newOIDCService(t, m, OIDCConfig{AllowedGroups: []string{"admins"}})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("allowed groups miss: %v", err)
	}
}

func TestOIDCCompleteUserinfoMerge(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.ExtraUserinfoClaims = map[string]any{"nickname": "alice-nick"}
	svc, _, _ := newOIDCService(t, m, OIDCConfig{UsernameClaim: "nickname"})
	_, _, u, err := svc.Complete(context.Background(), CompleteParams{Code: "code"})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if u.Username != "alice-nick" {
		t.Fatalf("expected merged username, got %q", u.Username)
	}
}

func TestOIDCCompleteNoIDToken(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	svc, _, _ := newOIDCService(t, m, OIDCConfig{})
	// Force the token endpoint to fail so no id_token is returned.
	m.TokenStatus = 400
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err == nil {
		t.Fatal("token exchange failure must error")
	}
}

func TestOIDCRevalidate(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockOIDCServer(t)
	m.Groups = []string{"dev"}
	svc, users, _ := newOIDCService(t, m, OIDCConfig{AllowedGroups: []string{"dev"}})

	cred, _ := SealCredential(svc.sealer, &Credential{Provider: "oidc", AccessToken: "at"})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)

	groups, err := svc.Revalidate(ctx, u)
	if err != nil || len(groups) != 1 || groups[0] != "dev" {
		t.Fatalf("revalidate: %v %v", groups, err)
	}

	// Allowlist miss -> forbidden.
	svc.cfg.AllowedGroups = []string{"admins"}
	if _, err := svc.Revalidate(ctx, u); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("allowlist miss: %v", err)
	}
}

func TestOIDCRevalidateNoCredential(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	svc, _, _ := newOIDCService(t, m, OIDCConfig{})
	if _, err := svc.Revalidate(context.Background(), &domain.User{ID: "u1"}); !errors.Is(err, domain.ErrOAuthNoCredential) {
		t.Fatalf("no credential: %v", err)
	}
}

func TestOIDCRevalidateNotLeader(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockOIDCServer(t)
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	jwtSvc, _ := jwt.NewService(jwt.Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	svc, err := NewOIDCOAuthService(OIDCConfig{IssuerURL: m.Issuer(), ClientID: m.ClientID, ClientSecret: "s", RedirectURL: "http://localhost/cb"},
		nil, password.NewService(users), users, groups, jwtSvc, testSealer(t), nil, func() bool { return false }, observ.NewNoopLogger())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	cred, _ := SealCredential(svc.sealer, &Credential{Provider: "oidc", AccessToken: "at"})
	u := &domain.User{ID: "u1", OAuthTokenCiphertext: cred}
	if _, err := svc.Revalidate(ctx, u); !errors.Is(err, domain.ErrOAuthNotLeaderRefresh) {
		t.Fatalf("not leader: %v", err)
	}
}

func TestOIDCRevalidateCredentialExpired(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockOIDCServer(t)
	m.UserinfoStatus = 401
	svc, users, _ := newOIDCService(t, m, OIDCConfig{})
	cred, _ := SealCredential(svc.sealer, &Credential{Provider: "oidc", AccessToken: "at"})
	u := &domain.User{ID: "u1", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)
	if _, err := svc.Revalidate(ctx, u); !errors.Is(err, domain.ErrOAuthCredentialExpired) {
		t.Fatalf("expired credential: %v", err)
	}
}

func TestOIDCRevalidateOversizedBody(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockOIDCServer(t)
	m.OversizedBody = true
	svc, users, _ := newOIDCService(t, m, OIDCConfig{})
	cred, _ := SealCredential(svc.sealer, &Credential{Provider: "oidc", AccessToken: "at"})
	u := &domain.User{ID: "u1", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)
	if _, err := svc.Revalidate(ctx, u); err == nil {
		t.Fatal("oversized body must error")
	}
}

func TestOIDCRevalidateBadCredential(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	svc, _, _ := newOIDCService(t, m, OIDCConfig{})
	u := &domain.User{ID: "u1", OAuthTokenCiphertext: "not-valid-ciphertext"}
	if _, err := svc.Revalidate(context.Background(), u); !errors.Is(err, domain.ErrOAuthCredentialExpired) {
		t.Fatalf("bad credential: %v", err)
	}
}
