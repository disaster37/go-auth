package nethttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sgbantracker "github.com/disaster37/go-secguard/bantracker"

	goauth "github.com/disaster37/go-auth"
	"github.com/disaster37/go-auth/apitoken"
	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/httpcookie"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/oauth"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/password"
	"github.com/disaster37/go-auth/store"
)

type env struct {
	svc     *goauth.Service
	jwtSvc  *jwt.Service
	users   *store.MemoryUserStore
	passSvc *password.Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	_ = groups.Create(context.Background(), &domain.Group{ID: "g1", Name: "dev"})
	jwtSvc, err := jwt.NewService(jwt.Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatalf("jwt: %v", err)
	}
	passSvc := password.NewService(users)
	svc := goauth.NewService(goauth.ServiceConfig{
		Users:     passSvc,
		UserStore: users,
		Groups:    groups,
		Epochs:    store.NewMemoryEpochStore(),
		Tokens:    apitoken.NewService(store.NewMemoryAPITokenStore(), apitoken.Config{}),
		JWT:       jwtSvc,
		Logger:    observ.NewNoopLogger(),
	})
	return &env{svc: svc, jwtSvc: jwtSvc, users: users, passSvc: passSvc}
}

func TestExtractBearer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer header-token")
	if got := ExtractBearer(r, "auth_access", false); got != "header-token" {
		t.Fatalf("header: %q", got)
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "auth_access", Value: "cookie-token"})
	if got := ExtractBearer(r, "auth_access", false); got != "cookie-token" {
		t.Fatalf("cookie: %q", got)
	}
	r = httptest.NewRequest(http.MethodGet, "/?token=query-token", nil)
	if got := ExtractBearer(r, "auth_access", true); got != "query-token" {
		t.Fatalf("query: %q", got)
	}
	if got := ExtractBearer(r, "auth_access", false); got != "" {
		t.Fatalf("query disabled: %q", got)
	}
}

func TestContextIdentity(t *testing.T) {
	id := &domain.Identity{UserID: "u1"}
	ctx := ContextWithIdentity(context.Background(), id)
	if got := IdentityFromContext(ctx); got != id {
		t.Fatalf("identity: %v", got)
	}
	if IdentityFromContext(context.Background()) != nil {
		t.Fatal("expected nil identity")
	}
}

func TestRequireAuth(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	u, _ := e.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	access, _, _, _ := e.svc.Login(ctx, "alice", "password123")

	handler := RequireAuth(e.svc, httpcookie.DefaultConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := IdentityFromContext(r.Context())
		if id == nil || id.UserID != u.ID {
			t.Fatal("identity not propagated")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", rec.Code)
	}
}

func TestRequireAdmin(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, _ = e.passSvc.CreateUser(ctx, "admin", "password123", domain.RoleAdmin)
	_, _ = e.passSvc.CreateUser(ctx, "user", "password123", domain.RoleUser)
	adminAccess, _, _, _ := e.svc.Login(ctx, "admin", "password123")
	userAccess, _, _, _ := e.svc.Login(ctx, "user", "password123")

	handler := RequireAdmin(e.svc, httpcookie.DefaultConfig())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+adminAccess)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin status=%d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+userAccess)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin status=%d", rec.Code)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/x", nil))
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing security headers")
	}
}

func TestMutationOriginMiddleware(t *testing.T) {
	handler := MutationOriginMiddleware([]string{"https://app.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestBanCheckMiddleware(t *testing.T) {
	tracker := sgbantracker.New(10, nil)
	tracker.RecordAndBan("203.0.113.5", "fp", 1, time.Minute, time.Minute)
	handler := BanCheckMiddleware(tracker, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned status=%d", rec.Code)
	}
}

func TestStatusCodeForError(t *testing.T) {
	tests := []struct {
		err    error
		status int
	}{
		{domain.ErrValidation, http.StatusBadRequest},
		{domain.ErrUnauthenticated, http.StatusUnauthorized},
		{domain.ErrInvalidCredential, http.StatusUnauthorized},
		{domain.ErrSessionRevoked, http.StatusUnauthorized},
		{domain.ErrOAuthCredentialExpired, http.StatusUnauthorized},
		{domain.ErrForbidden, http.StatusForbidden},
		{domain.ErrOriginNotAllowed, http.StatusForbidden},
		{domain.ErrIPBanned, http.StatusForbidden},
		{domain.ErrNotFound, http.StatusNotFound},
		{domain.ErrTokenNotRecoverable, http.StatusNotFound},
		{domain.ErrConflict, http.StatusConflict},
		{domain.ErrTokenExists, http.StatusConflict},
		{domain.ErrRateLimited, http.StatusTooManyRequests},
		{domain.ErrNotLeader, http.StatusServiceUnavailable},
		{errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		status, _ := StatusCodeForError(tt.err)
		if status != tt.status {
			t.Fatalf("StatusCodeForError(%v)=%d want %d", tt.err, status, tt.status)
		}
	}
	rec := httptest.NewRecorder()
	WriteError(rec, domain.ErrForbidden)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("WriteError status=%d", rec.Code)
	}
}

func TestLoginHandler(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, _ = e.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	cfg := httpcookie.DefaultConfig()
	handler := LoginHandler(e.svc, e.jwtSvc, cfg, false)

	body := `{"username":"alice","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) < 2 {
		t.Fatalf("expected cookie pair, got %d", len(cookies))
	}

	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"alice","password":"wrong"}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login status=%d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("not-json"))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body status=%d", rec.Code)
	}
}

func TestRefreshHandler(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, _ = e.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	_, refresh, _, _ := e.svc.Login(ctx, "alice", "password123")
	cfg := httpcookie.DefaultConfig()
	handler := RefreshHandler(e.svc, e.jwtSvc, cfg, false)

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.RefreshName, Value: refresh})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status=%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/refresh", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no cookie status=%d", rec.Code)
	}
}

func TestLogoutHandler(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, _ = e.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	access, _, _, _ := e.svc.Login(ctx, "alice", "password123")
	cfg := httpcookie.DefaultConfig()
	handler := LogoutHandler(e.svc, cfg, false)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status=%d", rec.Code)
	}
	if _, err := e.svc.Resolve(ctx, access); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("token after logout: %v", err)
	}
}

type fakeOAuthProvider struct {
	access, refresh string
	user            *domain.User
	err             error
}

func (p *fakeOAuthProvider) Name() string { return "fake" }
func (p *fakeOAuthProvider) LoginURL(params oauth.AuthorizeParams) string {
	return "https://idp.example.com/authorize?state=" + params.State
}
func (p *fakeOAuthProvider) Complete(context.Context, oauth.CompleteParams) (string, string, *domain.User, error) {
	return p.access, p.refresh, p.user, p.err
}
func (p *fakeOAuthProvider) Revalidate(context.Context, *domain.User) ([]string, error) {
	return nil, nil
}

func TestOAuthLoginHandler(t *testing.T) {
	e := newEnv(t)
	cfg := httpcookie.DefaultConfig()
	provider := &fakeOAuthProvider{}
	handler := OAuthLoginHandler(provider, e.jwtSvc, cfg, false, "/")

	req := httptest.NewRequest(http.MethodGet, "/oauth/login?redirect=/dashboard", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "state=") {
		t.Fatalf("location=%s", loc)
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("expected state cookie")
	}
}

func TestOAuthCallbackHandler(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	u, _ := e.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	cfg := httpcookie.DefaultConfig()
	provider := &fakeOAuthProvider{access: "a", refresh: "r", user: u}
	handler := OAuthCallbackHandler(provider, e.jwtSvc, cfg, false)

	nonce := "nonce-1"
	state, _ := e.jwtSvc.IssueOAuthState("/dashboard", nonce, "verifier", "fake")

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=code&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: cfg.StateName, Value: nonce})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status=%d body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("redirect=%s", loc)
	}

	// Missing code/state.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/callback", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing params status=%d", rec.Code)
	}

	// Missing state cookie.
	req = httptest.NewRequest(http.MethodGet, "/oauth/callback?code=code&state="+state, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing cookie status=%d", rec.Code)
	}

	// Nonce mismatch.
	req = httptest.NewRequest(http.MethodGet, "/oauth/callback?code=code&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: cfg.StateName, Value: "wrong"})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("nonce mismatch status=%d", rec.Code)
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, map[string]bool{"ok": true})
	var out map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !out["ok"] {
		t.Fatalf("writeJSON: %v %v", out, err)
	}
}

func TestRequireAuthCookie(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	u, _ := e.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	access, _, _, _ := e.svc.Login(ctx, "alice", "password123")
	cfg := httpcookie.DefaultConfig()
	handler := RequireAuth(e.svc, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := IdentityFromContext(r.Context()); id == nil || id.UserID != u.ID {
			t.Fatal("identity not propagated")
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cfg.AccessName, Value: access})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie auth status=%d", rec.Code)
	}
}

func TestRequireAdminUnauthenticated(t *testing.T) {
	e := newEnv(t)
	handler := RequireAdmin(e.svc, httpcookie.DefaultConfig())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestSecurityHeadersTLS(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("TLS request must set HSTS")
	}
}

func TestMutationOriginAllowed(t *testing.T) {
	handler := MutationOriginMiddleware([]string{"https://app.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestBanCheckMiddlewareError(t *testing.T) {
	tracker := sgbantracker.New(10, nil)
	handler := BanCheckMiddleware(tracker, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "bad:addr:extra"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestLogoutHandlerError(t *testing.T) {
	e := newEnv(t)
	handler := LogoutHandler(e.svc, httpcookie.DefaultConfig(), false)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestOAuthCallbackProviderError(t *testing.T) {
	e := newEnv(t)
	cfg := httpcookie.DefaultConfig()
	provider := &fakeOAuthProvider{err: domain.ErrForbidden}
	handler := OAuthCallbackHandler(provider, e.jwtSvc, cfg, false)
	nonce := "nonce-1"
	state, _ := e.jwtSvc.IssueOAuthState("/dashboard", nonce, "verifier", "fake")
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=code&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: cfg.StateName, Value: nonce})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestOAuthCallbackInvalidState(t *testing.T) {
	e := newEnv(t)
	cfg := httpcookie.DefaultConfig()
	handler := OAuthCallbackHandler(&fakeOAuthProvider{}, e.jwtSvc, cfg, false)
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=code&state=garbage", nil)
	req.AddCookie(&http.Cookie{Name: cfg.StateName, Value: "nonce"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestRefreshHandlerInvalidToken(t *testing.T) {
	e := newEnv(t)
	cfg := httpcookie.DefaultConfig()
	handler := RefreshHandler(e.svc, e.jwtSvc, cfg, false)
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.RefreshName, Value: "garbage"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestLoginHandlerOversizedBody(t *testing.T) {
	e := newEnv(t)
	handler := LoginHandler(e.svc, e.jwtSvc, httpcookie.DefaultConfig(), false)
	body := strings.Repeat("a", maxLoginBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}
