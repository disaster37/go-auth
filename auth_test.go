package goauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/disaster37/go-auth/apitoken"
	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/oauth"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/password"
	"github.com/disaster37/go-auth/store"
)

type fakeLegacy struct{ token string }

func (f fakeLegacy) ValidateToken(_ context.Context, token string) (string, error) {
	if token == f.token {
		return "legacy-user", nil
	}
	return "", domain.ErrUnauthenticated
}

type testEnv struct {
	svc     *Service
	users   *store.MemoryUserStore
	groups  *store.MemoryGroupStore
	epochs  *store.MemoryEpochStore
	tokens  *store.MemoryAPITokenStore
	jwtSvc  *jwt.Service
	passSvc *password.Service
}

func newTestEnv(t *testing.T, legacy domain.LegacyTokenValidator) *testEnv {
	t.Helper()
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	epochs := store.NewMemoryEpochStore()
	tokens := store.NewMemoryAPITokenStore()
	_ = groups.Create(context.Background(), &domain.Group{ID: "g1", Name: "dev"})
	jwtSvc, err := jwt.NewService(jwt.Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatalf("jwt: %v", err)
	}
	passSvc := password.NewService(users)
	svc := NewService(ServiceConfig{
		Users:     passSvc,
		UserStore: users,
		Groups:    groups,
		Epochs:    epochs,
		Tokens:    apitoken.NewService(tokens, apitoken.Config{}),
		JWT:       jwtSvc,
		Legacy:    legacy,
		Logger:    observ.NewNoopLogger(),
	})
	return &testEnv{svc: svc, users: users, groups: groups, epochs: epochs, tokens: tokens, jwtSvc: jwtSvc, passSvc: passSvc}
}

func TestResolveEmpty(t *testing.T) {
	env := newTestEnv(t, nil)
	if _, err := env.svc.Resolve(context.Background(), ""); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("empty: %v", err)
	}
}

func TestResolveAPIToken(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	plaintext, _, err := env.svc.tokens.Generate(ctx, u.ID)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	id, err := env.svc.Resolve(ctx, plaintext)
	if err != nil || id.UserID != u.ID || id.Method != domain.AuthMethodAPIToken {
		t.Fatalf("resolve api token: %+v %v", id, err)
	}
	if _, err := env.svc.Resolve(ctx, "dct_invalid"); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("invalid api token: %v", err)
	}
}

func TestResolveJWT(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	access, _, _, err := env.svc.Login(ctx, "alice", "password123")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	id, err := env.svc.Resolve(ctx, access)
	if err != nil || id.UserID != u.ID || id.Method != domain.AuthMethodJWT {
		t.Fatalf("resolve jwt: %+v %v", id, err)
	}
}

func TestResolveStaleTokenVersion(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	access, _, _, _ := env.svc.Login(ctx, "alice", "password123")
	if err := env.passSvc.IncrementTokenVersion(ctx, u.ID); err != nil {
		t.Fatalf("increment: %v", err)
	}
	if _, err := env.svc.Resolve(ctx, access); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("stale version: %v", err)
	}
}

func TestResolveStaleEpoch(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	_, _ = env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	access, _, _, _ := env.svc.Login(ctx, "alice", "password123")
	if _, err := env.epochs.BumpAuthEpoch(ctx); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if _, err := env.svc.Resolve(ctx, access); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("stale epoch: %v", err)
	}
}

func TestResolveLegacy(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, fakeLegacy{token: "legacy-token"})
	id, err := env.svc.Resolve(ctx, "legacy-token")
	if err != nil || id.Method != domain.AuthMethodLegacyToken || id.Role != domain.RoleAdmin {
		t.Fatalf("legacy: %+v %v", id, err)
	}
	if _, err := env.svc.Resolve(ctx, "other"); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestResolveSession(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	key, _ := jwt.DeriveSigningKey("secret", "")
	tok := &jwt.SessionToken{UserID: u.ID, Username: "alice", Method: "internal", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	encoded, _ := jwt.EncodeSession(tok, key)

	id, err := env.svc.ResolveSession(ctx, encoded, key)
	if err != nil || id.UserID != u.ID || id.Method != domain.AuthMethodSession {
		t.Fatalf("resolve session: %+v %v", id, err)
	}
	if _, err := env.svc.ResolveSession(ctx, "", key); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("empty session: %v", err)
	}
	if _, err := env.svc.ResolveSession(ctx, "garbage", key); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("bad session: %v", err)
	}
}

func TestLoginRefreshLogout(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)

	if _, _, _, err := env.svc.Login(ctx, "alice", "wrong"); !errors.Is(err, domain.ErrInvalidCredential) {
		t.Fatalf("bad login: %v", err)
	}
	access, refresh, got, err := env.svc.Login(ctx, "alice", "password123")
	if err != nil || got.ID != u.ID {
		t.Fatalf("login: %v", err)
	}

	newAccess, newRefresh, err := env.svc.Refresh(ctx, refresh)
	if err != nil || newAccess == "" || newRefresh == "" {
		t.Fatalf("refresh: %v", err)
	}
	if _, _, err := env.svc.Refresh(ctx, "garbage"); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("bad refresh: %v", err)
	}

	if err := env.svc.Logout(ctx, access); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := env.svc.Resolve(ctx, access); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("token after logout: %v", err)
	}
	if err := env.svc.Logout(ctx, ""); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("logout empty: %v", err)
	}
}

func TestSetRevalidator(t *testing.T) {
	env := newTestEnv(t, nil)
	env.svc.SetRevalidator(nil)
	if env.svc.revalidator != nil {
		t.Fatal("expected nil revalidator")
	}
}

type fakeOAuthProvider struct {
	groups []string
	err    error
}

func (p *fakeOAuthProvider) Name() string                          { return "fake" }
func (p *fakeOAuthProvider) LoginURL(oauth.AuthorizeParams) string { return "" }
func (p *fakeOAuthProvider) Complete(context.Context, oauth.CompleteParams) (string, string, *domain.User, error) {
	return "", "", nil, nil
}
func (p *fakeOAuthProvider) Revalidate(context.Context, *domain.User) ([]string, error) {
	return p.groups, p.err
}

type failingEpochStore struct{}

func (failingEpochStore) GetAuthEpoch(context.Context) (int64, error) {
	return 0, errors.New("epoch unavailable")
}
func (failingEpochStore) BumpAuthEpoch(context.Context) (int64, error) {
	return 0, errors.New("epoch unavailable")
}

func TestNewServiceNilLogger(t *testing.T) {
	svc := NewService(ServiceConfig{})
	if svc.logger == nil {
		t.Fatal("logger must default to noop")
	}
}

func TestResolveAPITokenUserMissing(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	plaintext, _, _ := env.svc.tokens.Generate(ctx, u.ID)
	if err := env.users.Delete(ctx, u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := env.svc.Resolve(ctx, plaintext); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("missing user: %v", err)
	}
}

func TestResolveJWTUserMissing(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	access, _, _, _ := env.svc.Login(ctx, "alice", "password123")
	if err := env.users.Delete(ctx, u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := env.svc.Resolve(ctx, access); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("missing user: %v", err)
	}
}

func TestResolveDeactivated(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	access, _, _, _ := env.svc.Login(ctx, "alice", "password123")
	now := time.Now()
	u.DeactivatedAt = &now
	if err := env.users.Update(ctx, u); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, err := env.svc.Resolve(ctx, access); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("deactivated: %v", err)
	}
}

func TestResolveGroups(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	if err := env.groups.AddMember(ctx, "g1", u.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	access, _, _, _ := env.svc.Login(ctx, "alice", "password123")
	id, err := env.svc.Resolve(ctx, access)
	if err != nil || len(id.GroupIDs) != 1 || id.GroupIDs[0] != "g1" {
		t.Fatalf("groups: %+v %v", id, err)
	}
}

func TestResolveOAuthRevalidator(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	u.OAuthProvider = "oidc"
	if err := env.users.Update(ctx, u); err != nil {
		t.Fatalf("update: %v", err)
	}
	provider := &fakeOAuthProvider{groups: []string{"dev"}}
	env.svc.SetRevalidator(oauth.NewRevalidator(provider, nil, nil, env.users, env.groups, nil, observ.NewNoopLogger(), oauth.RevalidatorConfig{}))
	access, _, _, _ := env.svc.Login(ctx, "alice", "password123")
	id, err := env.svc.Resolve(ctx, access)
	if err != nil || len(id.GroupIDs) != 1 {
		t.Fatalf("oauth revalidation: %+v %v", id, err)
	}
}

func TestResolveOAuthRevalidatorDenied(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	u.OAuthProvider = "oidc"
	if err := env.users.Update(ctx, u); err != nil {
		t.Fatalf("update: %v", err)
	}
	provider := &fakeOAuthProvider{err: domain.ErrForbidden}
	env.svc.SetRevalidator(oauth.NewRevalidator(provider, nil, nil, env.users, env.groups, nil, observ.NewNoopLogger(), oauth.RevalidatorConfig{}))
	access, _, _, _ := env.svc.Login(ctx, "alice", "password123")
	if _, err := env.svc.Resolve(ctx, access); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("denied: %v", err)
	}
}

func TestRefreshErrorPaths(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	_, refresh, _, _ := env.svc.Login(ctx, "alice", "password123")

	// Missing user.
	if err := env.users.Delete(ctx, u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := env.svc.Refresh(ctx, refresh); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("missing user: %v", err)
	}

	// Stale token version.
	env = newTestEnv(t, nil)
	u, _ = env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	_, refresh, _, _ = env.svc.Login(ctx, "alice", "password123")
	if err := env.passSvc.IncrementTokenVersion(ctx, u.ID); err != nil {
		t.Fatalf("increment: %v", err)
	}
	if _, _, err := env.svc.Refresh(ctx, refresh); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("stale version: %v", err)
	}
}

func TestRefreshSessionMaxAge(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	u.OAuthProvider = "oidc"
	if err := env.users.Update(ctx, u); err != nil {
		t.Fatalf("update: %v", err)
	}
	provider := &fakeOAuthProvider{groups: []string{"dev"}}
	env.svc.SetRevalidator(oauth.NewRevalidator(provider, nil, nil, env.users, env.groups, nil, observ.NewNoopLogger(), oauth.RevalidatorConfig{SessionMaxAge: time.Nanosecond}))
	_, refresh, _, _ := env.svc.Login(ctx, "alice", "password123")
	if _, _, err := env.svc.Refresh(ctx, refresh); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("max age: %v", err)
	}
}

func TestRefreshRevalidatorDenied(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	u.OAuthProvider = "oidc"
	if err := env.users.Update(ctx, u); err != nil {
		t.Fatalf("update: %v", err)
	}
	provider := &fakeOAuthProvider{err: domain.ErrForbidden}
	env.svc.SetRevalidator(oauth.NewRevalidator(provider, nil, nil, env.users, env.groups, nil, observ.NewNoopLogger(), oauth.RevalidatorConfig{}))
	_, refresh, _, _ := env.svc.Login(ctx, "alice", "password123")
	if _, _, err := env.svc.Refresh(ctx, refresh); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("revalidator denied: %v", err)
	}
}

func TestLogoutRefreshToken(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	_, refresh, _, _ := env.svc.Login(ctx, "alice", "password123")
	if err := env.svc.Logout(ctx, refresh); err != nil {
		t.Fatalf("logout refresh: %v", err)
	}
	stored, _ := env.users.Get(ctx, u.ID)
	if stored.TokenVersion != 1 {
		t.Fatalf("token version=%d", stored.TokenVersion)
	}
}

func TestCurrentEpochError(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	env.svc.epochs = failingEpochStore{}
	_, _ = env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	access, _, _, err := env.svc.Login(ctx, "alice", "password123")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := env.svc.Resolve(ctx, access); err != nil {
		t.Fatalf("resolve with failing epoch store: %v", err)
	}
}

func TestResolveSessionStaleTokenVersion(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	key, _ := jwt.DeriveSigningKey("secret", "")
	tok := &jwt.SessionToken{UserID: u.ID, Username: "alice", Method: "internal", ExpiresAt: time.Now().Add(time.Hour).Unix(), TokenVersion: 0}
	encoded, _ := jwt.EncodeSession(tok, key)
	if err := env.passSvc.IncrementTokenVersion(ctx, u.ID); err != nil {
		t.Fatalf("increment: %v", err)
	}
	if _, err := env.svc.ResolveSession(ctx, encoded, key); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("stale session token version: %v", err)
	}
}

func TestResolveAPITokenAfterEpochBump(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil)
	u, _ := env.passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	plaintext, _, err := env.svc.tokens.Generate(ctx, u.ID)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if _, err := env.epochs.BumpAuthEpoch(ctx); err != nil {
		t.Fatalf("bump: %v", err)
	}
	id, err := env.svc.Resolve(ctx, plaintext)
	if err != nil || id.UserID != u.ID || id.Method != domain.AuthMethodAPIToken {
		t.Fatalf("api token after epoch bump: %+v %v", id, err)
	}
}

func TestLoginWithoutGroups(t *testing.T) {
	ctx := context.Background()
	users := store.NewMemoryUserStore()
	jwtSvc, err := jwt.NewService(jwt.Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatalf("jwt: %v", err)
	}
	passSvc := password.NewService(users)
	svc := NewService(ServiceConfig{
		Users:     passSvc,
		UserStore: users,
		JWT:       jwtSvc,
		Logger:    observ.NewNoopLogger(),
	})
	u, err := passSvc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	access, refresh, got, err := svc.Login(ctx, "alice", "password123")
	if err != nil || got.ID != u.ID || access == "" || refresh == "" {
		t.Fatalf("login without groups: %v", err)
	}
}
