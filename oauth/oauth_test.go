package oauth

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/password"
	"github.com/disaster37/go-auth/store"
)

func TestPKCEHelpers(t *testing.T) {
	v1, err := GeneratePKCEVerifier()
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	v2, _ := GeneratePKCEVerifier()
	if v1 == v2 {
		t.Fatal("verifiers must be unique")
	}
	c1 := ComputePKCEChallenge(v1)
	c2 := ComputePKCEChallenge(v1)
	if c1 != c2 {
		t.Fatal("challenge must be deterministic")
	}
	if ComputePKCEChallenge(v1) == ComputePKCEChallenge(v2) {
		t.Fatal("challenges must differ")
	}
	n1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	n2, _ := GenerateNonce()
	if n1 == n2 {
		t.Fatal("nonces must be unique")
	}
}

func TestOrgsIntersect(t *testing.T) {
	if !orgsIntersect([]string{"a", "b"}, []string{"c", "b"}) {
		t.Fatal("expected intersection")
	}
	if orgsIntersect([]string{"a"}, []string{"b"}) {
		t.Fatal("unexpected intersection")
	}
	if orgsIntersect(nil, []string{"b"}) {
		t.Fatal("empty allowed must not intersect")
	}
}

func TestNormalizeGroupList(t *testing.T) {
	got := normalizeGroupList([]string{"b", "a", "b", ""})
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("normalize=%v", got)
	}
	if normalizeGroupList(nil) != nil {
		t.Fatal("empty must be nil")
	}
}

func TestApplyOAuthAdminRole(t *testing.T) {
	// No admin groups configured: no change.
	u := &domain.User{Role: domain.RoleUser}
	if applyOAuthAdminRole(u, nil, []string{"admin"}) {
		t.Fatal("no admin groups must not change role")
	}
	// Promote.
	u = &domain.User{Role: domain.RoleUser}
	if !applyOAuthAdminRole(u, []string{"admins"}, []string{"admins"}) || u.Role != domain.RoleAdmin || !u.OAuthAdmin {
		t.Fatalf("promote failed: %+v", u)
	}
	// Already admin: no change.
	if applyOAuthAdminRole(u, []string{"admins"}, []string{"admins"}) {
		t.Fatal("already admin must not change")
	}
	// Demote.
	if !applyOAuthAdminRole(u, []string{"admins"}, []string{"other"}) || u.Role != domain.RoleUser || u.OAuthAdmin {
		t.Fatalf("demote failed: %+v", u)
	}
	// Manual admin not demoted.
	manual := &domain.User{Role: domain.RoleAdmin, OAuthAdmin: false}
	if applyOAuthAdminRole(manual, []string{"admins"}, []string{"other"}) {
		t.Fatal("manual admin must not be demoted")
	}
}

func newLoginContext(t *testing.T, autoCreate bool) (loginContext, *store.MemoryUserStore, *store.MemoryGroupStore, *jwt.Service) {
	t.Helper()
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	jwtSvc, err := jwt.NewService(jwt.Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatalf("jwt: %v", err)
	}
	lc := loginContext{
		users:        password.NewService(users),
		userStore:    users,
		groups:       groups,
		jwt:          jwtSvc,
		sealer:       testSealer(t),
		logger:       observ.NewNoopLogger(),
		adminGroups:  []string{"admins"},
		defaultGroup: "default",
		autoCreate:   autoCreate,
	}
	return lc, users, groups, jwtSvc
}

func TestCompleteOAuthLoginAutoCreate(t *testing.T) {
	ctx := context.Background()
	lc, users, groups, _ := newLoginContext(t, true)
	_ = groups.Create(ctx, &domain.Group{ID: "g-default", Name: "default"})

	access, refresh, u, err := completeOAuthLogin(ctx, lc, "oidc", "sub-1", "https://iss", "alice",
		[]string{"admins"}, []string{"engineering"}, &Credential{Provider: "oidc", AccessToken: "at"})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected token pair")
	}
	if u.Role != domain.RoleAdmin || !u.OAuthAdmin {
		t.Fatalf("expected admin promotion: %+v", u)
	}
	if u.OAuthTokenCiphertext == "" {
		t.Fatal("expected sealed credential")
	}
	stored, _ := users.Get(ctx, u.ID)
	if stored.OAuthIssuer != "https://iss" {
		t.Fatalf("issuer=%q", stored.OAuthIssuer)
	}
	gs, _ := groups.GroupsForUser(ctx, u.ID)
	if len(gs) == 0 {
		t.Fatal("expected group membership")
	}
}

func TestCompleteOAuthLoginExternal(t *testing.T) {
	ctx := context.Background()
	lc, users, groups, _ := newLoginContext(t, false)
	_ = groups.Create(ctx, &domain.Group{ID: "g-default", Name: "default"})

	// No pre-linked account -> forbidden.
	if _, _, _, err := completeOAuthLogin(ctx, lc, "oidc", "sub-x", "https://iss", "bob", nil, nil, &Credential{}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("unlinked: %v", err)
	}

	// Pre-link an account.
	pre := &domain.User{ID: "u1", Username: "bob", Role: domain.RoleUser, OAuthProvider: "oidc", OAuthIssuer: "https://iss", OAuthID: "sub-x"}
	if err := users.Create(ctx, pre); err != nil {
		t.Fatalf("create pre-linked: %v", err)
	}
	_, _, u, err := completeOAuthLogin(ctx, lc, "oidc", "sub-x", "https://iss", "bob", nil, nil, &Credential{Provider: "oidc"})
	if err != nil {
		t.Fatalf("linked: %v", err)
	}
	if u.ID != "u1" {
		t.Fatalf("expected pre-linked user, got %s", u.ID)
	}
}

func TestEnsureGroupByName(t *testing.T) {
	ctx := context.Background()
	groups := store.NewMemoryGroupStore()
	g, err := ensureGroupByName(ctx, groups, "new-group", observ.NewNoopLogger())
	if err != nil || g == nil || g.Name != "new-group" {
		t.Fatalf("create: %v %v", g, err)
	}
	// Idempotent.
	again, err := ensureGroupByName(ctx, groups, "new-group", observ.NewNoopLogger())
	if err != nil || again.ID != g.ID {
		t.Fatalf("existing: %v %v", again, err)
	}
}

func TestJoinGroupByName(t *testing.T) {
	ctx := context.Background()
	groups := store.NewMemoryGroupStore()
	_ = groups.Create(ctx, &domain.Group{ID: "g1", Name: "dev"})
	joinGroupByName(ctx, groups, "dev", "u1", observ.NewNoopLogger())
	gs, _ := groups.GroupsForUser(ctx, "u1")
	if len(gs) != 1 {
		t.Fatalf("expected membership, got %d", len(gs))
	}
	// Missing group is a no-op.
	joinGroupByName(ctx, groups, "missing", "u1", observ.NewNoopLogger())
}

func TestReconcileMemberships(t *testing.T) {
	ctx := context.Background()
	groups := store.NewMemoryGroupStore()
	u := &domain.User{ID: "u1"}
	gids, err := reconcileMemberships(ctx, groups, observ.NewNoopLogger(), u, []string{"dev", "ops"})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(gids) != 2 {
		t.Fatalf("gids=%v", gids)
	}
	// Remove one.
	gids, err = reconcileMemberships(ctx, groups, observ.NewNoopLogger(), u, []string{"dev"})
	if err != nil || len(gids) != 1 {
		t.Fatalf("reconcile remove: %v %v", gids, err)
	}
}
