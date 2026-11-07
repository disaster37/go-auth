package goauth

import (
	"testing"

	"github.com/disaster37/go-auth/domain"
)

func TestIdentityAliases(t *testing.T) {
	id := &Identity{UserID: "u1", Role: RoleAdmin, Method: AuthMethodJWT}
	if !id.IsAdmin() {
		t.Fatal("expected admin")
	}
	if RoleAdmin != domain.RoleAdmin || RoleUser != domain.RoleUser {
		t.Fatal("role constants mismatch")
	}
	if AuthMethodJWT != domain.AuthMethodJWT || AuthMethodSession != domain.AuthMethodSession ||
		AuthMethodAPIToken != domain.AuthMethodAPIToken || AuthMethodLegacyToken != domain.AuthMethodLegacyToken ||
		AuthMethodOIDC != domain.AuthMethodOIDC || AuthMethodInternal != domain.AuthMethodInternal {
		t.Fatal("auth method constants mismatch")
	}
	u := &domain.User{ID: "u1"}
	if u.ID != "u1" {
		t.Fatal("user alias mismatch")
	}
	g := &domain.Group{ID: "g1"}
	if g.ID != "g1" {
		t.Fatal("group alias mismatch")
	}
	tok := &domain.APIToken{ID: "t1"}
	if tok.ID != "t1" {
		t.Fatal("apitoken alias mismatch")
	}
}
