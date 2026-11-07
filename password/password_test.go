package password

import (
	"context"
	"errors"
	"testing"

	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/store"
)

func TestValidateUsername(t *testing.T) {
	valid := []string{"ab", "alice", "a.b-c_d", "A1"}
	for _, u := range valid {
		if err := ValidateUsername(u); err != nil {
			t.Fatalf("ValidateUsername(%q)=%v", u, err)
		}
	}
	invalid := []string{"", "a", "-ab", ".ab", "a b", "a/b", string(make([]byte, 100))}
	for _, u := range invalid {
		if err := ValidateUsername(u); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("ValidateUsername(%q) expected ErrValidation, got %v", u, err)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("12345678"); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := ValidatePassword("short"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short: %v", err)
	}
	if err := ValidatePassword(string(make([]byte, 73))); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("long: %v", err)
	}
}

func TestHashVerify(t *testing.T) {
	h, err := Hash("password123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !Verify(h, "password123") {
		t.Fatal("verify should succeed")
	}
	if Verify(h, "wrong") {
		t.Fatal("verify should fail")
	}
	if _, err := HashWithCost("password123", 1); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad cost: %v", err)
	}
	if _, err := HashWithCost("password123", 99); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad cost high: %v", err)
	}
	EqualizeTiming("anything")
}

func newService(t *testing.T) (*Service, *store.MemoryUserStore, *store.MemoryGroupStore) {
	t.Helper()
	users := store.NewMemoryUserStore()
	groups := store.NewMemoryGroupStore()
	_ = groups.Create(context.Background(), &domain.Group{ID: "g-default", Name: "default"})
	svc := NewService(users, WithGroups(groups, "default"), WithBcryptCost(10))
	return svc, users, groups
}

func TestServiceCreateAndAuthenticate(t *testing.T) {
	ctx := context.Background()
	svc, _, groups := newService(t)

	u, err := svc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.PasswordHash == "" {
		t.Fatal("password hash must be set")
	}
	gs, _ := groups.GroupsForUser(ctx, u.ID)
	if len(gs) != 1 {
		t.Fatalf("expected default group membership, got %d", len(gs))
	}

	got, err := svc.Authenticate(ctx, "alice", "password123")
	if err != nil || got.ID != u.ID {
		t.Fatalf("authenticate: %v %v", got, err)
	}
	if _, err := svc.Authenticate(ctx, "alice", "wrong"); !errors.Is(err, domain.ErrInvalidCredential) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "unknown", "password123"); !errors.Is(err, domain.ErrInvalidCredential) {
		t.Fatalf("unknown user: %v", err)
	}

	if _, err := svc.CreateUser(ctx, "bad user", "password123", domain.RoleUser); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad username: %v", err)
	}
	if _, err := svc.CreateUser(ctx, "bob", "short", domain.RoleUser); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad password: %v", err)
	}
	if _, err := svc.CreateUser(ctx, "bob", "password123", domain.Role("root")); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad role: %v", err)
	}
}

func TestServicePasswordChanges(t *testing.T) {
	ctx := context.Background()
	svc, users, _ := newService(t)
	u, _ := svc.CreateUser(ctx, "alice", "password123", domain.RoleUser)

	if err := svc.ChangePassword(ctx, u.ID, "wrong", "newpassword1"); !errors.Is(err, domain.ErrInvalidCredential) {
		t.Fatalf("wrong current: %v", err)
	}
	if err := svc.ChangePassword(ctx, u.ID, "password123", "newpassword1"); err != nil {
		t.Fatalf("change: %v", err)
	}
	after, _ := users.Get(ctx, u.ID)
	if after.TokenVersion != 1 {
		t.Fatalf("token version=%d", after.TokenVersion)
	}
	if _, err := svc.Authenticate(ctx, "alice", "newpassword1"); err != nil {
		t.Fatalf("authenticate new: %v", err)
	}

	if err := svc.ResetPassword(ctx, u.ID, "resetpass1"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	after, _ = users.Get(ctx, u.ID)
	if after.TokenVersion != 2 {
		t.Fatalf("token version after reset=%d", after.TokenVersion)
	}
	if err := svc.ResetPassword(ctx, u.ID, "short"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("reset short: %v", err)
	}
	if err := svc.IncrementTokenVersion(ctx, u.ID); err != nil {
		t.Fatalf("increment: %v", err)
	}
	after, _ = users.Get(ctx, u.ID)
	if after.TokenVersion != 3 {
		t.Fatalf("token version after increment=%d", after.TokenVersion)
	}
	if err := svc.IncrementTokenVersion(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("increment missing: %v", err)
	}
}

func TestEnsureOAuthUser(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newService(t)

	u, created, err := svc.EnsureOAuthUser(ctx, "oidc", "sub-1", "alice")
	if err != nil || !created {
		t.Fatalf("create oauth user: %v created=%v", err, created)
	}
	again, created, err := svc.EnsureOAuthUser(ctx, "oidc", "sub-1", "alice")
	if err != nil || created || again.ID != u.ID {
		t.Fatalf("existing oauth user: %v created=%v", err, created)
	}
	// Username collision gets a suffix.
	other, created, err := svc.EnsureOAuthUser(ctx, "oidc", "sub-2", "alice")
	if err != nil || !created {
		t.Fatalf("collision create: %v", err)
	}
	if other.Username != "alice-2" {
		t.Fatalf("expected alice-2, got %q", other.Username)
	}
}

func TestServiceOptions(t *testing.T) {
	users := store.NewMemoryUserStore()
	svc := NewService(users, WithLogger(nil), WithBcryptCost(10))
	if svc.logger == nil {
		t.Fatal("logger must default to noop")
	}
}

type failingGroupStore struct{}

func (failingGroupStore) GetByName(context.Context, string) (*domain.Group, error) {
	return &domain.Group{ID: "g1", Name: "default"}, nil
}
func (failingGroupStore) Create(context.Context, *domain.Group) error { return nil }
func (failingGroupStore) GroupsForUser(context.Context, string) ([]*domain.Group, error) {
	return nil, nil
}
func (failingGroupStore) AddMember(context.Context, string, string) error {
	return errors.New("add member failed")
}
func (failingGroupStore) RemoveMember(context.Context, string, string) error { return nil }

func TestHashWithCostBcryptError(t *testing.T) {
	if _, err := HashWithCost(string(make([]byte, 73)), 10); err == nil {
		t.Fatal("bcrypt must reject passwords longer than 72 bytes")
	}
}

func TestServiceErrorPaths(t *testing.T) {
	ctx := context.Background()
	svc, users, _ := newService(t)
	u, _ := svc.CreateUser(ctx, "alice", "password123", domain.RoleUser)

	if _, err := svc.CreateUser(ctx, "alice", "password123", domain.RoleUser); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate user: %v", err)
	}
	if err := svc.ChangePassword(ctx, "missing", "password123", "newpassword1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("change missing: %v", err)
	}
	if err := svc.ResetPassword(ctx, "missing", "newpassword1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("reset missing: %v", err)
	}

	// An invalid configured cost surfaces from setPassword.
	badCost := NewService(users, WithBcryptCost(1))
	if err := badCost.ChangePassword(ctx, u.ID, "password123", "newpassword1"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad cost change: %v", err)
	}
	if _, err := badCost.CreateUser(ctx, "bob", "password123", domain.RoleUser); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad cost create: %v", err)
	}
}

func TestAutoJoinDefaultGroupPaths(t *testing.T) {
	ctx := context.Background()
	users := store.NewMemoryUserStore()
	// Missing default group is a no-op.
	svc := NewService(users, WithGroups(store.NewMemoryGroupStore(), "default"))
	if _, err := svc.CreateUser(ctx, "alice", "password123", domain.RoleUser); err != nil {
		t.Fatalf("create without group: %v", err)
	}
	// AddMember failure is logged, not returned.
	svc = NewService(users, WithGroups(failingGroupStore{}, ""))
	if _, err := svc.CreateUser(ctx, "bob", "password123", domain.RoleUser); err != nil {
		t.Fatalf("create with failing group store: %v", err)
	}
}

func TestServiceOptionsNonNil(t *testing.T) {
	users := store.NewMemoryUserStore()
	svc := NewService(users, WithLogger(observ.NewNoopLogger()), WithGroups(nil, ""))
	if svc.logger == nil {
		t.Fatal("logger must be set")
	}
	if svc.groups != nil {
		t.Fatal("groups must be nil")
	}
}

type stubUserStore struct {
	getByOAuthErr    error
	getByUsernameErr error
	createErr        error
	alwaysExists     bool
}

func (s *stubUserStore) Create(context.Context, *domain.User) error { return s.createErr }
func (s *stubUserStore) Get(context.Context, string) (*domain.User, error) {
	return nil, domain.ErrNotFound
}
func (s *stubUserStore) GetByUsername(context.Context, string) (*domain.User, error) {
	if s.alwaysExists {
		return &domain.User{ID: "existing"}, nil
	}
	return nil, s.getByUsernameErr
}
func (s *stubUserStore) GetByOAuth(context.Context, string, string) (*domain.User, error) {
	return nil, s.getByOAuthErr
}
func (s *stubUserStore) List(context.Context) ([]*domain.User, error) { return nil, nil }
func (s *stubUserStore) Update(context.Context, *domain.User) error   { return nil }
func (s *stubUserStore) Delete(context.Context, string) error         { return nil }
func (s *stubUserStore) Count(context.Context) (int, error)           { return 0, nil }

func TestEnsureOAuthUserErrors(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")

	svc := NewService(&stubUserStore{getByOAuthErr: boom})
	if _, _, err := svc.EnsureOAuthUser(ctx, "oidc", "sub", "alice"); !errors.Is(err, boom) {
		t.Fatalf("oauth lookup: %v", err)
	}

	svc = NewService(&stubUserStore{getByOAuthErr: domain.ErrNotFound, getByUsernameErr: boom})
	if _, _, err := svc.EnsureOAuthUser(ctx, "oidc", "sub", "alice"); !errors.Is(err, boom) {
		t.Fatalf("username lookup: %v", err)
	}

	svc = NewService(&stubUserStore{getByOAuthErr: domain.ErrNotFound, getByUsernameErr: domain.ErrNotFound, createErr: boom})
	if _, _, err := svc.EnsureOAuthUser(ctx, "oidc", "sub", "alice"); !errors.Is(err, boom) {
		t.Fatalf("create: %v", err)
	}

	svc = NewService(&stubUserStore{getByOAuthErr: domain.ErrNotFound, alwaysExists: true})
	if _, _, err := svc.EnsureOAuthUser(ctx, "oidc", "sub", "alice"); err == nil {
		t.Fatal("exhausted username search must error")
	}
}

func TestChangePasswordValidation(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newService(t)
	u, _ := svc.CreateUser(ctx, "alice", "password123", domain.RoleUser)
	if err := svc.ChangePassword(ctx, u.ID, "password123", "short"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short new password: %v", err)
	}

	oauthUser, _, err := svc.EnsureOAuthUser(ctx, "oidc", "sub", "bob")
	if err != nil {
		t.Fatalf("oauth user: %v", err)
	}
	if err := svc.ChangePassword(ctx, oauthUser.ID, "anything", "newpassword1"); !errors.Is(err, domain.ErrInvalidCredential) {
		t.Fatalf("passwordless user: %v", err)
	}
}

func TestCreateUserWithoutGroups(t *testing.T) {
	ctx := context.Background()
	svc := NewService(store.NewMemoryUserStore())
	if _, err := svc.CreateUser(ctx, "alice", "password123", domain.RoleUser); err != nil {
		t.Fatalf("create: %v", err)
	}
}
