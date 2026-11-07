package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/password"
	"github.com/disaster37/go-auth/store"
	"github.com/disaster37/go-auth/testutil"
)

func TestEndpointAllowed(t *testing.T) {
	allowed := []string{"https://idp.example.com/token"}
	if !endpointAllowed(allowed, "https://idp.example.com/token") {
		t.Fatal("exact endpoint must be allowed")
	}
	if !endpointAllowed(allowed, "https://idp.example.com/token/extra") {
		t.Fatal("path prefix must be allowed")
	}
	if endpointAllowed(allowed, "https://evil.example.com/token") {
		t.Fatal("different host must be rejected")
	}
	if endpointAllowed(allowed, "https://idp.example.com/other") {
		t.Fatal("different path must be rejected")
	}
	if endpointAllowed([]string{"::bad"}, "https://idp.example.com/token") {
		t.Fatal("invalid allowlist entry must be skipped")
	}
	if endpointAllowed(allowed, "::bad") {
		t.Fatal("invalid endpoint must be rejected")
	}
}

func TestValidateEndpoints(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	svc, _, _ := newOIDCService(t, m, OIDCConfig{AllowedEndpoints: []string{m.Issuer()}})
	if url := svc.LoginURL(AuthorizeParams{State: "s"}); url == "" {
		t.Fatal("allowed endpoints must permit discovery")
	}

	svc, _, _ = newOIDCService(t, m, OIDCConfig{AllowedEndpoints: []string{"https://other.example.com"}})
	if url := svc.LoginURL(AuthorizeParams{State: "s"}); url != "" {
		t.Fatalf("disallowed endpoints must fail discovery, got %q", url)
	}
}

func TestNewOAuthHTTPClient(t *testing.T) {
	client, err := NewOAuthHTTPClient("", time.Second)
	if err != nil || client == nil {
		t.Fatalf("default client: %v %v", client, err)
	}
	if _, err := NewOAuthHTTPClient(filepath.Join(t.TempDir(), "missing.pem"), time.Second); err == nil {
		t.Fatal("missing CA file must error")
	}

	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write bad pem: %v", err)
	}
	if _, err := NewOAuthHTTPClient(bad, time.Second); err == nil {
		t.Fatal("invalid PEM must error")
	}

	good := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(good, selfSignedPEM(t), 0o600); err != nil {
		t.Fatalf("write ca pem: %v", err)
	}
	if _, err := NewOAuthHTTPClient(good, time.Second); err != nil {
		t.Fatalf("valid CA: %v", err)
	}
}

func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestRefuseCrossOriginRedirect(t *testing.T) {
	via := []*http.Request{httptest.NewRequest(http.MethodGet, "https://idp.example.com/a", nil)}
	req := httptest.NewRequest(http.MethodGet, "https://evil.example.com/b", nil)
	if err := refuseCrossOriginRedirect(req, via); err == nil {
		t.Fatal("cross-origin redirect must be refused")
	}
	req = httptest.NewRequest(http.MethodGet, "https://idp.example.com/b", nil)
	if err := refuseCrossOriginRedirect(req, via); err != nil {
		t.Fatalf("same-origin redirect: %v", err)
	}
	if err := refuseCrossOriginRedirect(req, nil); err != nil {
		t.Fatalf("no via: %v", err)
	}
}

func TestCappedTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", MaxResponseBodyBytes+1)))
	}))
	defer srv.Close()

	client := &http.Client{Transport: &cappedTransport{base: http.DefaultTransport}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("oversized body must error")
	}
}

func TestResolveUsernameAndGroups(t *testing.T) {
	svc := &OIDCOAuthService{usernameClaim: "preferred_username", groupsClaim: "groups"}
	name, err := svc.resolveUsername(map[string]any{"email": "a@example.com"})
	if err != nil || name != "a@example.com" {
		t.Fatalf("email fallback: %q %v", name, err)
	}
	if _, err := svc.resolveUsername(map[string]any{}); err == nil {
		t.Fatal("missing username must error")
	}

	cases := []struct {
		raw  any
		want []string
	}{
		{"dev", []string{"dev"}},
		{"", nil},
		{[]string{"a", "b"}, []string{"a", "b"}},
		{[]any{"a", 1}, []string{"a", "1"}},
		{42, nil},
	}
	for _, tc := range cases {
		got := svc.resolveGroups(map[string]any{"groups": tc.raw})
		if len(got) != len(tc.want) {
			t.Fatalf("groups(%v)=%v want %v", tc.raw, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("groups(%v)=%v want %v", tc.raw, got, tc.want)
			}
		}
	}
	if got := svc.resolveGroups(map[string]any{}); got != nil {
		t.Fatalf("missing groups=%v", got)
	}
}

func TestOAuthTokenRevoked(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&oauth2.RetrieveError{ErrorCode: "invalid_grant"}, true},
		{&oauth2.RetrieveError{ErrorCode: "invalid_token"}, true},
		{&oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusUnauthorized}}, true},
		{&oauth2.RetrieveError{ErrorCode: "server_error"}, false},
		{errors.New("invalid_grant"), true},
		{errors.New("invalid_token"), true},
		{errors.New("401 Unauthorized"), true},
		{errors.New("boom"), false},
	}
	for _, tc := range cases {
		if got := oauthTokenRevoked(tc.err); got != tc.want {
			t.Fatalf("oauthTokenRevoked(%v)=%v want %v", tc.err, got, tc.want)
		}
	}
}

func TestNormalizeScopesExisting(t *testing.T) {
	got := normalizeScopes([]string{"openid", "offline_access", "profile"})
	if len(got) != 3 {
		t.Fatalf("scopes=%v", got)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if !isLoopbackHost(host) {
			t.Fatalf("%q must be loopback", host)
		}
	}
	if isLoopbackHost("example.com") {
		t.Fatal("example.com must not be loopback")
	}
}

func TestValidateIssuerURLInvalid(t *testing.T) {
	if err := validateIssuerURL("://bad", false); err == nil {
		t.Fatal("invalid URL must error")
	}
}

func TestOIDCDiscoverFailure(t *testing.T) {
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	svc, err := NewOIDCOAuthService(OIDCConfig{IssuerURL: "http://127.0.0.1:1", ClientID: "c", ClientSecret: "s", RedirectURL: "http://localhost/cb"},
		nil, nil, users, groups, nil, nil, nil, nil, observ.NewNoopLogger())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if url := svc.LoginURL(AuthorizeParams{State: "s"}); url != "" {
		t.Fatalf("discovery failure must yield empty URL, got %q", url)
	}
}

func TestOIDCCompleteOmitIDToken(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.OmitIDToken = true
	svc, _, _ := newOIDCService(t, m, OIDCConfig{})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err == nil {
		t.Fatal("missing id_token must error")
	}
}

func TestOIDCCompleteMissingSub(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.Subject = ""
	svc, _, _ := newOIDCService(t, m, OIDCConfig{})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err == nil {
		t.Fatal("missing sub must error")
	}
}

func TestOIDCCompleteAZPMissing(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.Audience = []string{"test-client", "other-client"}
	m.AZP = ""
	svc, _, _ := newOIDCService(t, m, OIDCConfig{})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err == nil {
		t.Fatal("multi-audience token without azp must error")
	}
}

func TestOIDCCompleteUsernameMissing(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.Username = ""
	m.Email = ""
	svc, _, _ := newOIDCService(t, m, OIDCConfig{})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err == nil {
		t.Fatal("missing username must error")
	}
}

func TestOIDCCompleteAllowedOrgs(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.Groups = []string{"dev"}
	svc, _, _ := newOIDCService(t, m, OIDCConfig{AllowedOrgs: []string{"dev"}})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err != nil {
		t.Fatalf("allowed orgs: %v", err)
	}
}

func TestOIDCCompleteUserinfoMergeFailure(t *testing.T) {
	m := testutil.NewMockOIDCServer(t)
	m.UserinfoStatus = http.StatusInternalServerError
	svc, _, _ := newOIDCService(t, m, OIDCConfig{UsernameClaim: "nickname"})
	_, _, u, err := svc.Complete(context.Background(), CompleteParams{Code: "code"})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if u.Username != m.Email {
		t.Fatalf("expected email fallback, got %q", u.Username)
	}
}

func TestOIDCRevalidateRefreshSuccess(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockOIDCServer(t)
	m.UserinfoFailOnce = true
	svc, users, _ := newOIDCService(t, m, OIDCConfig{})
	cred, _ := SealCredential(svc.sealer, &Credential{Provider: "oidc", AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now().Add(-time.Hour)})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)

	groups, err := svc.Revalidate(ctx, u)
	if err != nil || len(groups) == 0 {
		t.Fatalf("refresh revalidate: %v %v", groups, err)
	}
	stored, _ := users.Get(ctx, u.ID)
	if stored.OAuthTokenCiphertext == cred {
		t.Fatal("refreshed credential must be persisted")
	}
}

func TestOIDCRevalidateRefreshExpired(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockOIDCServer(t)
	m.UserinfoStatus = http.StatusUnauthorized
	m.TokenStatus = http.StatusBadRequest
	svc, users, _ := newOIDCService(t, m, OIDCConfig{})
	cred, _ := SealCredential(svc.sealer, &Credential{Provider: "oidc", AccessToken: "at", RefreshToken: "rt"})
	u := &domain.User{ID: "u1", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)
	if _, err := svc.Revalidate(ctx, u); !errors.Is(err, domain.ErrOAuthCredentialExpired) {
		t.Fatalf("refresh expired: %v", err)
	}
}

func TestOIDCRevalidateUserinfoError(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockOIDCServer(t)
	m.UserinfoStatus = http.StatusInternalServerError
	svc, users, _ := newOIDCService(t, m, OIDCConfig{})
	cred, _ := SealCredential(svc.sealer, &Credential{Provider: "oidc", AccessToken: "at"})
	u := &domain.User{ID: "u1", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)
	if _, err := svc.Revalidate(ctx, u); err == nil {
		t.Fatal("userinfo error must propagate")
	}
}

func TestOIDCRevalidateDiscoverError(t *testing.T) {
	ctx := context.Background()
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	svc, err := NewOIDCOAuthService(OIDCConfig{IssuerURL: "http://127.0.0.1:1", ClientID: "c", ClientSecret: "s", RedirectURL: "http://localhost/cb"},
		nil, nil, users, groups, nil, testSealer(t), nil, nil, observ.NewNoopLogger())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	cred, _ := SealCredential(svc.sealer, &Credential{Provider: "oidc", AccessToken: "at"})
	u := &domain.User{ID: "u1", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)
	if _, err := svc.Revalidate(ctx, u); err == nil {
		t.Fatal("discovery error must propagate")
	}
}

func TestRevalidatorDefaults(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{groups: []string{"dev"}}
	r, _, _, _ := newRevalidator(t, p, clk, RevalidatorConfig{})
	if r.cfg.Interval != defaultRevalidateInterval || r.cfg.Grace != defaultRevalidateGrace {
		t.Fatalf("defaults not applied: %+v", r.cfg)
	}
	r.Close()
	r.Close()
}

func TestRevalidatorExpiredCredentialChanged(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{err: domain.ErrOAuthCredentialExpired}
	r, users, _, _ := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Hour})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc", OAuthTokenCiphertext: "a"}
	_ = users.Create(ctx, u)

	if _, err := r.Check(ctx, u); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("expired without last-good: %v", err)
	}
	// A re-login changes the credential, forcing an immediate re-check.
	p.err = nil
	p.groups = []string{"dev"}
	u.OAuthTokenCiphertext = "b"
	if _, err := r.Check(ctx, u); err != nil {
		t.Fatalf("recheck after re-login: %v", err)
	}
}

func TestRevalidatorUnavailableFailClosed(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{err: errors.New("network down")}
	r, users, _, _ := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Minute})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc"}
	_ = users.Create(ctx, u)
	if _, err := r.Check(ctx, u); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("fail-closed: %v", err)
	}
}

func TestRevalidatorFailOpenWithoutGroups(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{err: errors.New("network down")}
	r, users, _, _ := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Minute, FailOpen: true})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc"}
	_ = users.Create(ctx, u)
	if _, err := r.Check(ctx, u); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("fail-open without groups: %v", err)
	}
}

func TestGitHubTeamsError(t *testing.T) {
	m := newGitHubMock(t)
	m.teamsStatus = http.StatusInternalServerError
	svc, _, _ := newGitHubService(t, m, GitHubConfig{AllowedTeams: []string{"acme/devs"}})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err == nil {
		t.Fatal("teams error with allowlist must fail")
	}
}

func TestGitHubTeamsErrorWithMapper(t *testing.T) {
	m := newGitHubMock(t)
	m.teamsStatus = http.StatusInternalServerError
	mapper, _ := NewGroupMapper([]GroupMappingRule{{Pattern: `^acme/(.*)$`, Replacement: "eng-$1"}})
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	_ = groups.Create(context.Background(), &domain.Group{ID: "g-default", Name: "default"})
	jwtSvc, _ := jwt.NewService(jwt.Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	svc := NewGitHubOAuthService(GitHubConfig{
		ClientID: "client", ClientSecret: "secret", RedirectURL: "http://localhost/callback",
		TokenURL: m.server.URL + "/login/oauth/access_token", APIBaseURL: m.server.URL,
	}, mapper, password.NewService(users), users, groups, jwtSvc, testSealer(t), nil, observ.NewNoopLogger())
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err != nil {
		t.Fatalf("teams error with mapper must be tolerated: %v", err)
	}
}

func TestGitHubDecodeCappedOversized(t *testing.T) {
	var out map[string]any
	if err := decodeCapped(strings.NewReader(strings.Repeat("a", MaxResponseBodyBytes+1)), &out); err == nil {
		t.Fatal("oversized body must error")
	}
}

func TestGitHubExchangeEmptyToken(t *testing.T) {
	m := newGitHubMock(t)
	m.accessToken = ""
	svc, _, _ := newGitHubService(t, m, GitHubConfig{})
	if _, _, _, err := svc.Complete(context.Background(), CompleteParams{Code: "code"}); err == nil {
		t.Fatal("empty access token must error")
	}
}

func TestGitHubLoginURLPKCE(t *testing.T) {
	m := newGitHubMock(t)
	svc, _, _ := newGitHubService(t, m, GitHubConfig{EnablePKCE: true})
	url := svc.LoginURL(AuthorizeParams{State: "s", CodeChallenge: "challenge"})
	if !strings.Contains(url, "code_challenge=challenge") || !strings.Contains(url, "code_challenge_method=S256") {
		t.Fatalf("pkce url: %s", url)
	}
}

func TestGitHubServiceDefaults(t *testing.T) {
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	jwtSvc, _ := jwt.NewService(jwt.Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	svc := NewGitHubOAuthService(GitHubConfig{}, nil, password.NewService(users), users, groups, jwtSvc, nil, nil, nil)
	if svc.cfg.TokenURL == "" || svc.cfg.APIBaseURL == "" || svc.http == nil {
		t.Fatalf("defaults not applied: %+v", svc.cfg)
	}
}

func TestGitHubRevalidateTeamsError(t *testing.T) {
	ctx := context.Background()
	m := newGitHubMock(t)
	m.teamsStatus = http.StatusInternalServerError
	svc, users, _ := newGitHubService(t, m, GitHubConfig{AllowedTeams: []string{"acme/devs"}})
	cred, _ := SealCredential(svc.lc.sealer, &Credential{Provider: "github", AccessToken: "gh-token"})
	u := &domain.User{ID: "u1", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)
	if _, err := svc.Revalidate(ctx, u); err == nil {
		t.Fatal("teams error must propagate")
	}
}

func TestMapGroups(t *testing.T) {
	inactive, _ := NewGroupMapper(nil)
	if got := mapGroups(inactive, []string{"a"}); len(got) != 1 || got[0] != "a" {
		t.Fatalf("inactive mapGroups=%v", got)
	}
	active, _ := NewGroupMapper([]GroupMappingRule{{Pattern: `^a$`, Replacement: "b"}})
	if got := mapGroups(active, []string{"a"}); len(got) != 1 || got[0] != "b" {
		t.Fatalf("active mapGroups=%v", got)
	}
}

func TestCompleteOAuthLoginNilGroups(t *testing.T) {
	ctx := context.Background()
	lc, _, _, _ := newLoginContext(t, true)
	lc.groups = nil
	access, refresh, u, err := completeOAuthLogin(ctx, lc, "oidc", "sub-1", "https://iss", "alice",
		[]string{"dev"}, []string{"dev"}, &Credential{Provider: "oidc", AccessToken: "at"})
	if err != nil || access == "" || refresh == "" || u == nil {
		t.Fatalf("nil groups: %v %v", u, err)
	}
}

func TestRevalidatorNilGroups(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{err: domain.ErrOAuthNoCredential}
	users := store.NewMemoryUserStore()
	r := NewRevalidator(p, nil, nil, users, nil, nil, observ.NewNoopLogger(), RevalidatorConfig{Clock: clk.Now})
	t.Cleanup(r.Close)
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc"}
	_ = users.Create(ctx, u)
	gids, err := r.Check(ctx, u)
	if err != nil || gids != nil {
		t.Fatalf("nil groups: %v %v", gids, err)
	}
}

func TestGitHubRevalidateTransientError(t *testing.T) {
	ctx := context.Background()
	m := newGitHubMock(t)
	m.userStatus = http.StatusInternalServerError
	svc, users, _ := newGitHubService(t, m, GitHubConfig{})
	cred, _ := SealCredential(svc.lc.sealer, &Credential{Provider: "github", AccessToken: "gh-token"})
	u := &domain.User{ID: "u1", OAuthTokenCiphertext: cred}
	_ = users.Create(ctx, u)
	_, err := svc.Revalidate(ctx, u)
	if err == nil || errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("transient error must not revoke: %v", err)
	}
}
