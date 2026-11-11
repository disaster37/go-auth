package apitoken

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/disaster37/go-auth/crypto"
	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/store"
)

func newSealer(t *testing.T) crypto.Sealer {
	t.Helper()
	s, err := crypto.NewAESGCMSealer(make([]byte, 32), nil)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

func TestHashAndCompare(t *testing.T) {
	h := Hash("token")
	if h != Hash("token") {
		t.Fatal("hash must be deterministic")
	}
	if !CompareHashConstantTime(h, Hash("token")) {
		t.Fatal("equal hashes must compare true")
	}
	if CompareHashConstantTime(h, Hash("other")) {
		t.Fatal("different hashes must compare false")
	}
}

func TestServiceLifecycle(t *testing.T) {
	ctx := context.Background()
	tokens := store.NewMemoryAPITokenStore()
	svc := NewService(tokens, Config{Prefix: "ghb_", Sealer: newSealer(t)})

	if svc.Prefix() != "ghb_" {
		t.Fatalf("prefix=%q", svc.Prefix())
	}
	if !svc.Recoverable() {
		t.Fatal("expected recoverable")
	}

	plaintext, tok, err := svc.Generate(ctx, "u1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(plaintext, "ghb_") {
		t.Fatalf("token prefix: %q", plaintext)
	}
	if !svc.HasTokenPrefix(plaintext) {
		t.Fatal("HasTokenPrefix should be true")
	}
	if svc.HasTokenPrefix("dct_x") {
		t.Fatal("HasTokenPrefix should be false")
	}
	if tok.TokenHash != Hash(plaintext) {
		t.Fatal("stored hash mismatch")
	}

	if _, _, err := svc.Generate(ctx, "u1"); !errors.Is(err, domain.ErrTokenExists) {
		t.Fatalf("duplicate generate: %v", err)
	}

	validated, err := svc.Validate(ctx, plaintext)
	if err != nil || validated.UserID != "u1" {
		t.Fatalf("validate: %v %v", validated, err)
	}
	if _, err := svc.Validate(ctx, "ghb_wrong"); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("validate wrong: %v", err)
	}
	if _, err := svc.Validate(ctx, ""); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("validate empty: %v", err)
	}

	revealed, err := svc.Reveal(ctx, "u1")
	if err != nil || revealed != plaintext {
		t.Fatalf("reveal: %q %v", revealed, err)
	}
	if _, err := svc.Reveal(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("reveal missing: %v", err)
	}

	meta, err := svc.Meta(ctx, "u1")
	if err != nil || meta.ID != tok.ID {
		t.Fatalf("meta: %v %v", meta, err)
	}

	newPlain, _, err := svc.Regenerate(ctx, "u1")
	if err != nil || newPlain == plaintext {
		t.Fatalf("regenerate: %v", err)
	}
	if _, err := svc.Validate(ctx, plaintext); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("old token should be invalid: %v", err)
	}

	if err := svc.Revoke(ctx, "u1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.Meta(ctx, "u1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("meta after revoke: %v", err)
	}
}

func TestServiceWithoutSealer(t *testing.T) {
	ctx := context.Background()
	tokens := store.NewMemoryAPITokenStore()
	svc := NewService(tokens, Config{})
	if svc.Prefix() != DefaultPrefix {
		t.Fatalf("default prefix=%q", svc.Prefix())
	}
	if svc.Recoverable() {
		t.Fatal("expected not recoverable")
	}
	plaintext, _, err := svc.Generate(ctx, "u1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := svc.Reveal(ctx, "u1"); !errors.Is(err, domain.ErrTokenNotRecoverable) {
		t.Fatalf("reveal without sealer: %v", err)
	}
	if err := svc.ImportRaw(ctx, "u2", plaintext); err != nil {
		t.Fatalf("import raw: %v", err)
	}
	if _, err := svc.Validate(ctx, plaintext); err != nil {
		t.Fatalf("validate imported: %v", err)
	}
}

func TestRevealNoCiphertext(t *testing.T) {
	ctx := context.Background()
	tokens := store.NewMemoryAPITokenStore()
	_ = tokens.Upsert(ctx, &domain.APIToken{ID: "t1", UserID: "u1", TokenHash: Hash("x")})
	svc := NewService(tokens, Config{Sealer: newSealer(t)})
	if _, err := svc.Reveal(ctx, "u1"); !errors.Is(err, domain.ErrTokenNotRecoverable) {
		t.Fatalf("reveal no ciphertext: %v", err)
	}
}

type failingSealer struct{}

func (failingSealer) SealString(string) (string, error) { return "", errors.New("seal failed") }
func (failingSealer) OpenString(string) (string, error) { return "", errors.New("open failed") }

type failingTokenStore struct {
	getErr    error
	upsertErr error
	touchErr  error
}

func (s *failingTokenStore) Upsert(context.Context, *domain.APIToken) error { return s.upsertErr }
func (s *failingTokenStore) GetByHash(context.Context, string) (*domain.APIToken, error) {
	return nil, s.getErr
}
func (s *failingTokenStore) GetByUser(context.Context, string) (*domain.APIToken, error) {
	return nil, s.getErr
}
func (s *failingTokenStore) Delete(context.Context, string) error { return nil }
func (s *failingTokenStore) TouchLastUsed(context.Context, string, time.Time) error {
	return s.touchErr
}

func TestServiceErrorPaths(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")

	// Non-not-found lookup error is returned.
	svc := NewService(&failingTokenStore{getErr: boom}, Config{})
	if _, _, err := svc.Generate(ctx, "u1"); !errors.Is(err, boom) {
		t.Fatalf("generate lookup: %v", err)
	}

	// Seal failure aborts generation and import.
	svc = NewService(store.NewMemoryAPITokenStore(), Config{Sealer: failingSealer{}})
	if _, _, err := svc.Generate(ctx, "u1"); err == nil {
		t.Fatal("generate seal must fail")
	}
	if err := svc.ImportRaw(ctx, "u1", "plain"); err == nil {
		t.Fatal("import seal must fail")
	}

	// Upsert failure aborts generation and import.
	svc = NewService(&failingTokenStore{getErr: domain.ErrNotFound, upsertErr: boom}, Config{})
	if _, _, err := svc.Generate(ctx, "u1"); !errors.Is(err, boom) {
		t.Fatalf("generate upsert: %v", err)
	}
	if err := svc.ImportRaw(ctx, "u1", "plain"); !errors.Is(err, boom) {
		t.Fatalf("import upsert: %v", err)
	}

	// TouchLastUsed failure is best-effort.
	tokens := store.NewMemoryAPITokenStore()
	_ = tokens.Upsert(ctx, &domain.APIToken{ID: "t1", UserID: "u1", TokenHash: Hash("plain")})
	svc = NewService(&touchFailStore{inner: tokens}, Config{})
	if _, err := svc.Validate(ctx, "plain"); err != nil {
		t.Fatalf("validate with touch failure: %v", err)
	}

	// Reveal decryption failure is wrapped.
	svc = NewService(store.NewMemoryAPITokenStore(), Config{Sealer: failingSealer{}})
	_ = svc.tokens.Upsert(ctx, &domain.APIToken{ID: "t1", UserID: "u1", TokenHash: Hash("plain"), TokenCiphertext: "ct"})
	if _, err := svc.Reveal(ctx, "u1"); err == nil {
		t.Fatal("reveal must fail when decryption fails")
	}
}

type touchFailStore struct {
	inner store.APITokenStore
}

func (s *touchFailStore) Upsert(ctx context.Context, t *domain.APIToken) error {
	return s.inner.Upsert(ctx, t)
}
func (s *touchFailStore) GetByHash(ctx context.Context, h string) (*domain.APIToken, error) {
	return s.inner.GetByHash(ctx, h)
}
func (s *touchFailStore) GetByUser(ctx context.Context, u string) (*domain.APIToken, error) {
	return s.inner.GetByUser(ctx, u)
}
func (s *touchFailStore) Delete(ctx context.Context, u string) error { return s.inner.Delete(ctx, u) }
func (s *touchFailStore) TouchLastUsed(context.Context, string, time.Time) error {
	return errors.New("touch failed")
}

func TestServiceClockAndShortPrefix(t *testing.T) {
	ctx := context.Background()
	fixed := time.Unix(1000, 0)
	svc := NewService(store.NewMemoryAPITokenStore(), Config{Clock: func() time.Time { return fixed }})
	_, tok, err := svc.Generate(ctx, "u1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !tok.CreatedAt.Equal(fixed) {
		t.Fatalf("created at=%v", tok.CreatedAt)
	}
	if svc.HasTokenPrefix("") {
		t.Fatal("empty bearer must not match")
	}
}
