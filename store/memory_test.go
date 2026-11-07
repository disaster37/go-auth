package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/disaster37/go-auth/domain"
)

func TestMemoryUserStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryUserStore()
	u := &domain.User{ID: "1", Username: "alice", Role: domain.RoleUser, OAuthProvider: "oidc", OAuthIssuer: "https://iss", OAuthID: "sub-1"}
	if err := s.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Create(ctx, u); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate id: %v", err)
	}
	if err := s.Create(ctx, &domain.User{ID: "2", Username: "alice"}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate username: %v", err)
	}
	if err := s.Create(ctx, &domain.User{ID: "3", Username: "bob", OAuthProvider: "oidc", OAuthID: "sub-1"}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate oauth: %v", err)
	}

	got, err := s.Get(ctx, "1")
	if err != nil || got.Username != "alice" {
		t.Fatalf("get: %v %v", got, err)
	}
	if _, err := s.Get(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if _, err := s.GetByUsername(ctx, "alice"); err != nil {
		t.Fatalf("get by username: %v", err)
	}
	if _, err := s.GetByUsername(ctx, "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get by username missing: %v", err)
	}
	if _, err := s.GetByOAuth(ctx, "oidc", "sub-1"); err != nil {
		t.Fatalf("get by oauth: %v", err)
	}
	if _, err := s.GetByOAuth(ctx, "oidc", "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get by oauth missing: %v", err)
	}
	if _, err := s.GetByExternalIdentity(ctx, "oidc", "https://iss", "sub-1"); err != nil {
		t.Fatalf("get by external: %v", err)
	}
	if _, err := s.GetByExternalIdentity(ctx, "oidc", "x", "y"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get by external missing: %v", err)
	}
	if n, _ := s.Count(ctx); n != 1 {
		t.Fatalf("count=%d", n)
	}
	list, _ := s.List(ctx)
	if len(list) != 1 {
		t.Fatalf("list=%d", len(list))
	}

	u.Username = "alice2"
	if err := s.Update(ctx, u); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, err := s.GetByUsername(ctx, "alice2"); err != nil {
		t.Fatalf("get renamed: %v", err)
	}
	if err := s.Update(ctx, &domain.User{ID: "missing"}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if err := s.Delete(ctx, "1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.Delete(ctx, "1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestMemoryGroupStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryGroupStore()
	g := &domain.Group{ID: "g1", Name: "dev"}
	if err := s.Create(ctx, g); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Create(ctx, g); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate id: %v", err)
	}
	if err := s.Create(ctx, &domain.Group{ID: "g2", Name: "dev"}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := s.GetByName(ctx, "dev"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := s.GetByName(ctx, "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if err := s.AddMember(ctx, "g1", "u1"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.AddMember(ctx, "missing", "u1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("add missing group: %v", err)
	}
	gs, _ := s.GroupsForUser(ctx, "u1")
	if len(gs) != 1 {
		t.Fatalf("groups=%d", len(gs))
	}
	if err := s.RemoveMember(ctx, "g1", "u1"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	gs, _ = s.GroupsForUser(ctx, "u1")
	if len(gs) != 0 {
		t.Fatalf("groups after remove=%d", len(gs))
	}
}

func TestMemoryAPITokenStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryAPITokenStore()
	tok := &domain.APIToken{ID: "t1", UserID: "u1", TokenHash: "h1"}
	if err := s.Upsert(ctx, tok); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := s.GetByHash(ctx, "h1"); err != nil {
		t.Fatalf("get by hash: %v", err)
	}
	if _, err := s.GetByHash(ctx, "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get by hash missing: %v", err)
	}
	if _, err := s.GetByUser(ctx, "u1"); err != nil {
		t.Fatalf("get by user: %v", err)
	}
	if _, err := s.GetByUser(ctx, "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get by user missing: %v", err)
	}
	// Upsert replaces the existing token for the user.
	if err := s.Upsert(ctx, &domain.APIToken{ID: "t2", UserID: "u1", TokenHash: "h2"}); err != nil {
		t.Fatalf("upsert replace: %v", err)
	}
	if _, err := s.GetByHash(ctx, "h1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("old hash should be gone: %v", err)
	}
	if err := s.TouchLastUsed(ctx, "t2", time.Now()); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if err := s.TouchLastUsed(ctx, "missing", time.Now()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("touch missing: %v", err)
	}
	if err := s.Delete(ctx, "u1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.Delete(ctx, "u1"); err != nil {
		t.Fatalf("delete idempotent: %v", err)
	}
}

func TestMemoryEpochStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryEpochStore()
	if e, _ := s.GetAuthEpoch(ctx); e != 0 {
		t.Fatalf("initial epoch=%d", e)
	}
	if e, _ := s.BumpAuthEpoch(ctx); e != 1 {
		t.Fatalf("bump=%d", e)
	}
	if e, _ := s.GetAuthEpoch(ctx); e != 1 {
		t.Fatalf("get after bump=%d", e)
	}
}
