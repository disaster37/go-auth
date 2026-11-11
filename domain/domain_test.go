package domain

import (
	"errors"
	"testing"
	"time"
)

func TestParseRole(t *testing.T) {
	tests := []struct {
		in      string
		want    Role
		wantErr bool
	}{
		{"admin", RoleAdmin, false},
		{"user", RoleUser, false},
		{"", "", true},
		{"root", "", true},
	}
	for _, tt := range tests {
		got, err := ParseRole(tt.in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("ParseRole(%q) err=%v wantErr=%v", tt.in, err, tt.wantErr)
		}
		if got != tt.want {
			t.Fatalf("ParseRole(%q)=%q want %q", tt.in, got, tt.want)
		}
		if tt.wantErr && !errors.Is(err, ErrValidation) {
			t.Fatalf("ParseRole(%q) err=%v not ErrValidation", tt.in, err)
		}
	}
}

func TestIdentity(t *testing.T) {
	var nilID *Identity
	if nilID.IsAdmin() {
		t.Fatal("nil identity must not be admin")
	}
	if nilID.HasGroup("x") {
		t.Fatal("nil identity must not have groups")
	}
	id := &Identity{Role: RoleAdmin, GroupIDs: []string{"a", "b"}}
	if !id.IsAdmin() {
		t.Fatal("expected admin")
	}
	if !id.HasGroup("b") {
		t.Fatal("expected group b")
	}
	if id.HasGroup("c") {
		t.Fatal("unexpected group c")
	}
}

func TestUserDeactivated(t *testing.T) {
	var nilUser *User
	if nilUser.Deactivated() {
		t.Fatal("nil user must not be deactivated")
	}
	u := &User{}
	if u.Deactivated() {
		t.Fatal("zero user must not be deactivated")
	}
	now := time.Now()
	u.DeactivatedAt = &now
	if !u.Deactivated() {
		t.Fatal("expected deactivated")
	}
}
