// Package password provides bcrypt hashing, timing-equalized authentication
// (CWE-208), username/password validation, and TokenVersion-bumping password
// change/reset helpers.
package password

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/crypto/bcrypt"

	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/store"
)

const (
	// MinPasswordLength is the minimum accepted password length in bytes.
	MinPasswordLength = 8
	// MaxPasswordLength is bcrypt's 72-byte input limit.
	MaxPasswordLength = 72
	// DefaultBcryptCost is the default bcrypt cost.
	DefaultBcryptCost = 10
	// MinBcryptCost is the minimum accepted bcrypt cost.
	MinBcryptCost = 10
	// MaxBcryptCost is the maximum accepted bcrypt cost.
	MaxBcryptCost = 31
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$`)

// dummyPasswordHash is a valid bcrypt hash compared against when a login
// attempt targets an unknown user (or a user without a password), so the
// response timing does not reveal whether the username exists (CWE-208).
var dummyPasswordHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("timing-equalization-dummy"), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("generate dummy hash: %v", err))
	}
	return h
}()

// ValidateUsername checks ^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$.
func ValidateUsername(username string) error {
	if !usernameRe.MatchString(username) {
		return fmt.Errorf("username must match ^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$: %w", domain.ErrValidation)
	}
	return nil
}

// ValidatePassword checks 8 <= len(password) <= 72 bytes.
func ValidatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters: %w", MinPasswordLength, domain.ErrValidation)
	}
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("password must be at most %d characters (bcrypt limit): %w", MaxPasswordLength, domain.ErrValidation)
	}
	return nil
}

// Hash generates a bcrypt hash at DefaultBcryptCost.
func Hash(password string) (string, error) {
	return HashWithCost(password, DefaultBcryptCost)
}

// HashWithCost generates a bcrypt hash at the given cost.
func HashWithCost(password string, cost int) (string, error) {
	if cost < MinBcryptCost || cost > MaxBcryptCost {
		return "", fmt.Errorf("bcrypt cost must be between %d and %d: %w", MinBcryptCost, MaxBcryptCost, domain.ErrValidation)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// Verify compares a bcrypt hash with password in constant time.
func Verify(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// EqualizeTiming performs a dummy bcrypt comparison against a precomputed hash
// so unknown-user login paths take the same CPU time as known-user paths
// (CWE-208).
func EqualizeTiming(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(password))
}

// Service implements user CRUD and password logic.
type Service struct {
	users        store.UserStore
	groups       store.GroupStore
	defaultGroup string
	logger       observ.Logger
	cost         int
}

// ServiceOption configures a Service.
type ServiceOption func(*Service)

// WithLogger sets the logger.
func WithLogger(logger observ.Logger) ServiceOption {
	return func(s *Service) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// WithBcryptCost sets the bcrypt cost.
func WithBcryptCost(cost int) ServiceOption {
	return func(s *Service) { s.cost = cost }
}

// WithGroups wires a GroupStore and the default group new users join.
func WithGroups(groups store.GroupStore, defaultGroup string) ServiceOption {
	return func(s *Service) {
		s.groups = groups
		s.defaultGroup = defaultGroup
	}
}

// NewService returns a Service.
func NewService(users store.UserStore, opts ...ServiceOption) *Service {
	s := &Service{
		users:  users,
		logger: observ.NewNoopLogger(),
		cost:   DefaultBcryptCost,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// CreateUser creates a new user with the given credentials and role.
func (s *Service) CreateUser(ctx context.Context, username, rawPassword string, role domain.Role) (*domain.User, error) {
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := ValidatePassword(rawPassword); err != nil {
		return nil, err
	}
	if _, err := domain.ParseRole(string(role)); err != nil {
		return nil, err
	}
	hash, err := HashWithCost(rawPassword, s.cost)
	if err != nil {
		return nil, err
	}
	u := &domain.User{
		ID:           newID(),
		Username:     username,
		Role:         role,
		PasswordHash: hash,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	s.logger.Info("user created", map[string]any{"user_id": u.ID, "username": u.Username})
	s.autoJoinDefaultGroup(ctx, u)
	return u, nil
}

// Authenticate validates the username/password and returns the user. It never
// reveals which part failed, and performs a bcrypt comparison even for unknown
// users so timing does not leak username existence (CWE-208).
func (s *Service) Authenticate(ctx context.Context, username, rawPassword string) (*domain.User, error) {
	u, err := s.users.GetByUsername(ctx, username)
	if err != nil || u.PasswordHash == "" {
		EqualizeTiming(rawPassword)
		return nil, domain.ErrInvalidCredential
	}
	if !Verify(u.PasswordHash, rawPassword) {
		return nil, domain.ErrInvalidCredential
	}
	return u, nil
}

// ChangePassword verifies the current password before setting a new one. The
// change bumps TokenVersion in the same persisted update so every outstanding
// JWT is revoked.
func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return err
	}
	if u.PasswordHash == "" || !Verify(u.PasswordHash, currentPassword) {
		return domain.ErrInvalidCredential
	}
	u.TokenVersion++
	return s.setPassword(ctx, u, newPassword)
}

// ResetPassword sets a new password for a user (admin-set; no current-password
// check) and bumps TokenVersion.
func (s *Service) ResetPassword(ctx context.Context, userID, newPassword string) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return err
	}
	u.TokenVersion++
	return s.setPassword(ctx, u, newPassword)
}

// IncrementTokenVersion bumps the user's TokenVersion, revoking every JWT
// issued before the bump (logout).
func (s *Service) IncrementTokenVersion(ctx context.Context, userID string) error {
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return fmt.Errorf("load user for token version bump: %w", err)
	}
	u.TokenVersion++
	return s.users.Update(ctx, u)
}

// EnsureOAuthUser returns the existing OAuth user, or creates a new one with a
// unique username (suffixing on collision). The bool is true when a new user
// was created.
func (s *Service) EnsureOAuthUser(ctx context.Context, provider, oauthID, username string) (*domain.User, bool, error) {
	if existing, err := s.users.GetByOAuth(ctx, provider, oauthID); err == nil {
		return existing, false, nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return nil, false, err
	}

	candidate := username
	for i := 2; ; i++ {
		_, err := s.users.GetByUsername(ctx, candidate)
		if errors.Is(err, domain.ErrNotFound) {
			break
		}
		if err != nil {
			return nil, false, err
		}
		if i > 1000 {
			return nil, false, fmt.Errorf("could not find unique username for %s", username)
		}
		candidate = fmt.Sprintf("%s-%d", username, i)
	}

	u := &domain.User{
		ID:            newID(),
		Username:      candidate,
		Role:          domain.RoleUser,
		OAuthProvider: provider,
		OAuthID:       oauthID,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, false, err
	}
	s.logger.Info("oauth user created", map[string]any{
		"user_id":        u.ID,
		"username":       u.Username,
		"oauth_provider": provider,
	})
	return u, true, nil
}

func (s *Service) setPassword(ctx context.Context, u *domain.User, newPassword string) error {
	hash, err := HashWithCost(newPassword, s.cost)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	return s.users.Update(ctx, u)
}

func (s *Service) autoJoinDefaultGroup(ctx context.Context, u *domain.User) {
	if s.groups == nil {
		return
	}
	name := s.defaultGroup
	if name == "" {
		name = "default"
	}
	g, err := s.groups.GetByName(ctx, name)
	if err != nil {
		return
	}
	if err := s.groups.AddMember(ctx, g.ID, u.ID); err != nil {
		s.logger.Warn("auto-assign to default group failed", map[string]any{"user_id": u.ID, "group": name})
	}
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate id: %v", err))
	}
	return hex.EncodeToString(b)
}
