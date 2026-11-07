package jwt

import (
	"errors"
	"testing"
	"time"

	"github.com/disaster37/go-auth/domain"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	s, err := NewService(Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return s
}

func TestNewServiceValidation(t *testing.T) {
	if _, err := NewService(Config{Secret: []byte("short")}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short secret: %v", err)
	}
	s, err := NewService(Config{Secret: []byte("0123456789abcdef0123456789abcdef"), UseHKDF: true})
	if err != nil {
		t.Fatalf("hkdf service: %v", err)
	}
	if s.AccessTTL() != DefaultAccessTTL || s.RefreshTTL() != DefaultRefreshTTL || s.OAuthStateTTL() != DefaultOAuthStateTTL {
		t.Fatal("default TTLs not applied")
	}
}

func TestIssueAndParsePair(t *testing.T) {
	s := newTestService(t)
	u := &domain.User{ID: "u1", Username: "alice", Role: domain.RoleAdmin, TokenVersion: 3}
	access, refresh, err := s.IssuePair(u, []string{"g1"}, 7)
	if err != nil {
		t.Fatalf("issue pair: %v", err)
	}
	ac, err := s.ParseAccess(access)
	if err != nil {
		t.Fatalf("parse access: %v", err)
	}
	if ac.UserID != "u1" || ac.Role != "admin" || ac.TokenVersion != 3 || ac.AuthEpoch != 7 || ac.Type != TypeAccess {
		t.Fatalf("unexpected access claims: %+v", ac)
	}
	rc, err := s.ParseRefresh(refresh)
	if err != nil {
		t.Fatalf("parse refresh: %v", err)
	}
	if rc.Type != TypeRefresh {
		t.Fatalf("refresh type=%q", rc.Type)
	}
	if _, err := s.ParseAccess(refresh); err == nil {
		t.Fatal("refresh token must not parse as access")
	}
	if _, err := s.ParseAccess("garbage"); err == nil {
		t.Fatal("garbage must not parse")
	}
}

func TestOAuthState(t *testing.T) {
	s := newTestService(t)
	state, err := s.IssueOAuthState("/dashboard", "nonce-1", "verifier-1", "oidc")
	if err != nil {
		t.Fatalf("issue state: %v", err)
	}
	claims, err := s.ParseOAuthState(state)
	if err != nil {
		t.Fatalf("parse state: %v", err)
	}
	if claims.Username != "/dashboard" || claims.Nonce != "nonce-1" || claims.CodeVerifier != "verifier-1" || claims.Provider != "oidc" {
		t.Fatalf("unexpected state claims: %+v", claims)
	}
	if _, err := s.ParseAccess(state); err == nil {
		t.Fatal("state must not parse as access")
	}
}

func TestExpiredToken(t *testing.T) {
	now := time.Now().UTC()
	// Issue a token whose exp is already in the past relative to real time.
	s, err := NewService(Config{
		Secret:    []byte("0123456789abcdef0123456789abcdef"),
		AccessTTL: time.Minute,
		Clock:     func() time.Time { return now.Add(-2 * time.Minute) },
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	u := &domain.User{ID: "u1", Username: "alice", Role: domain.RoleUser}
	access, _, _ := s.IssuePair(u, nil, 0)
	if _, err := s.ParseAccess(access); err == nil {
		t.Fatal("expected expired token error")
	}
}

func TestSignErrorPaths(t *testing.T) {
	orig := signToken
	signToken = func(*Claims, []byte) (string, error) { return "", errors.New("sign failed") }
	t.Cleanup(func() { signToken = orig })

	s := newTestService(t)
	u := &domain.User{ID: "u1", Username: "alice", Role: domain.RoleUser}
	if _, _, err := s.IssuePair(u, nil, 0); err == nil {
		t.Fatal("expected issue pair error")
	}
	if _, err := s.IssueOAuthState("/", "n", "v", "p"); err == nil {
		t.Fatal("expected oauth state error")
	}
}
