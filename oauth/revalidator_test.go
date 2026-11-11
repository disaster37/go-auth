package oauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/store"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

type fakeProvider struct {
	groups []string
	err    error
	calls  int
}

func (p *fakeProvider) Name() string                    { return "fake" }
func (p *fakeProvider) LoginURL(AuthorizeParams) string { return "" }
func (p *fakeProvider) Complete(context.Context, CompleteParams) (string, string, *domain.User, error) {
	return "", "", nil, nil
}
func (p *fakeProvider) Revalidate(context.Context, *domain.User) ([]string, error) {
	p.calls++
	return p.groups, p.err
}

func newRevalidator(t *testing.T, p Provider, clk *fakeClock, cfg RevalidatorConfig) (*Revalidator, *store.MemoryUserStore, *store.MemoryGroupStore, *int) {
	t.Helper()
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	_ = groups.Create(context.Background(), &domain.Group{ID: "g1", Name: "dev"})
	revoked := 0
	cfg.Clock = clk.Now
	r := NewRevalidator(p, nil, nil, users, groups, func(context.Context, string) error {
		revoked++
		return nil
	}, observ.NewNoopLogger(), cfg)
	t.Cleanup(r.Close)
	return r, users, groups, &revoked
}

func TestRevalidatorSuccessCaches(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{groups: []string{"dev"}}
	r, users, _, _ := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Hour})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc"}
	_ = users.Create(ctx, u)

	gids, err := r.Check(ctx, u)
	if err != nil || len(gids) != 1 {
		t.Fatalf("check: %v %v", gids, err)
	}
	// Second check within the interval is served from cache.
	if _, err := r.Check(ctx, u); err != nil {
		t.Fatalf("cached check: %v", err)
	}
	if p.calls != 1 {
		t.Fatalf("provider calls=%d want 1", p.calls)
	}
	if r.SessionMaxAge() != 0 {
		t.Fatal("session max age should be zero")
	}
}

func TestRevalidatorRevoked(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{err: domain.ErrForbidden}
	r, users, _, revoked := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Hour})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc"}
	_ = users.Create(ctx, u)

	if _, err := r.Check(ctx, u); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("revoked check: %v", err)
	}
	if *revoked != 1 {
		t.Fatalf("token revoker calls=%d", *revoked)
	}
	stored, _ := users.Get(ctx, u.ID)
	if !stored.Deactivated() {
		t.Fatal("user must be deactivated")
	}
}

func TestRevalidatorExpiredGrace(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{groups: []string{"dev"}}
	r, users, _, _ := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Hour})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc"}
	_ = users.Create(ctx, u)

	if _, err := r.Check(ctx, u); err != nil {
		t.Fatalf("initial check: %v", err)
	}
	// Credential becomes unusable; advance past the cache TTL but within grace.
	p.err = domain.ErrOAuthCredentialExpired
	clk.Advance(2 * time.Minute)
	gids, err := r.Check(ctx, u)
	if err != nil || len(gids) != 1 {
		t.Fatalf("grace check: %v %v", gids, err)
	}
	// Past grace with fail-closed -> deny.
	clk.Advance(2 * time.Hour)
	if _, err := r.Check(ctx, u); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("past grace: %v", err)
	}
}

func TestRevalidatorUnavailableFailOpen(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{groups: []string{"dev"}}
	r, users, _, _ := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Minute, FailOpen: true})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc"}
	_ = users.Create(ctx, u)

	if _, err := r.Check(ctx, u); err != nil {
		t.Fatalf("initial: %v", err)
	}
	p.err = errors.New("network down")
	clk.Advance(2 * time.Minute)
	gids, err := r.Check(ctx, u)
	if err != nil || len(gids) != 1 {
		t.Fatalf("fail-open: %v %v", gids, err)
	}
}

func TestRevalidatorNoCredential(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{err: domain.ErrOAuthNoCredential}
	r, users, groups, _ := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Hour})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc"}
	_ = users.Create(ctx, u)
	_ = groups.AddMember(ctx, "g1", "u1")

	gids, err := r.Check(ctx, u)
	if err != nil || len(gids) != 1 {
		t.Fatalf("no credential: %v %v", gids, err)
	}
}

func TestRevalidatorNotLeader(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{err: domain.ErrOAuthNotLeaderRefresh}
	r, users, groups, _ := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Hour})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc"}
	_ = users.Create(ctx, u)
	_ = groups.AddMember(ctx, "g1", "u1")

	gids, err := r.Check(ctx, u)
	if err != nil || len(gids) != 1 {
		t.Fatalf("not leader: %v %v", gids, err)
	}
}

func TestRevalidatorAlreadyDeactivated(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{groups: []string{"dev"}}
	r, users, _, _ := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Hour})
	now := clk.Now()
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc", DeactivatedAt: &now}
	_ = users.Create(ctx, u)

	if _, err := r.Check(ctx, u); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("deactivated: %v", err)
	}
	if p.calls != 0 {
		t.Fatalf("provider must not be called for a deactivated user, calls=%d", p.calls)
	}
}

func TestRevalidatorRecoveryAfterRelogin(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{now: time.Unix(0, 0)}
	p := &fakeProvider{err: domain.ErrForbidden}
	r, users, _, _ := newRevalidator(t, p, clk, RevalidatorConfig{Interval: time.Minute, Grace: time.Hour})
	u := &domain.User{ID: "u1", Username: "alice", OAuthProvider: "oidc"}
	_ = users.Create(ctx, u)

	if _, err := r.Check(ctx, u); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	// Re-login clears deactivation and the provider now allows.
	stored, _ := users.Get(ctx, u.ID)
	stored.DeactivatedAt = nil
	_ = users.Update(ctx, stored)
	p.err = nil
	p.groups = []string{"dev"}
	if _, err := r.Check(ctx, stored); err != nil {
		t.Fatalf("recovery: %v", err)
	}
}

func TestJitteredTTL(t *testing.T) {
	d := jitteredTTL(stateOK, time.Minute, time.Hour)
	if d < 54*time.Second || d > 66*time.Second {
		t.Fatalf("jitter out of range: %v", d)
	}
	// Unavailable uses min(interval, grace).
	d = jitteredTTL(stateUnavailable, time.Hour, time.Minute)
	if d < 54*time.Second || d > 66*time.Second {
		t.Fatalf("unavailable jitter out of range: %v", d)
	}
}
