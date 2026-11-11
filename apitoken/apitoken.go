// Package apitoken implements configurable-prefix API token lifecycle
// (dct_, ghb_), SHA-256 hashing, constant-time validation, and at-rest
// encryption via crypto.Sealer.
package apitoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/disaster37/go-auth/crypto"
	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/store"
)

const (
	// DefaultPrefix is the default API token prefix.
	DefaultPrefix = "dct_"
	// DefaultRandomBytes is the number of CSPRNG bytes in a generated token.
	DefaultRandomBytes = 32
	// DisplayPrefixLength is the number of leading characters stored for
	// display.
	DisplayPrefixLength = 12
)

// Hash returns the SHA-256 hex of the plaintext token.
func Hash(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// CompareHashConstantTime compares two token hashes in constant time.
func CompareHashConstantTime(hashA, hashB string) bool {
	return subtle.ConstantTimeCompare([]byte(hashA), []byte(hashB)) == 1
}

// Config configures a Service.
type Config struct {
	Prefix string        // default "dct_"
	Sealer crypto.Sealer // optional; nil disables plaintext recovery
	Logger observ.Logger
	Clock  func() time.Time
}

// Service implements API token generate/regenerate/revoke/validate.
type Service struct {
	tokens store.APITokenStore
	prefix string
	sealer crypto.Sealer
	logger observ.Logger
	clock  func() time.Time
}

// NewService returns a Service.
func NewService(tokens store.APITokenStore, cfg Config) *Service {
	prefix := cfg.Prefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	logger := cfg.Logger
	if logger == nil {
		logger = observ.NewNoopLogger()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Service{tokens: tokens, prefix: prefix, sealer: cfg.Sealer, logger: logger, clock: clock}
}

// Prefix returns the configured token prefix.
func (s *Service) Prefix() string { return s.prefix }

// HasTokenPrefix reports whether bearer carries the configured token prefix.
func (s *Service) HasTokenPrefix(bearer string) bool {
	return len(bearer) >= len(s.prefix) && bearer[:len(s.prefix)] == s.prefix
}

// Recoverable reports whether plaintext recovery is enabled.
func (s *Service) Recoverable() bool { return s.sealer != nil }

// Generate creates a new token for the user. Returns ErrTokenExists if the user
// already has one. The plaintext token is returned exactly once.
func (s *Service) Generate(ctx context.Context, userID string) (string, *domain.APIToken, error) {
	if _, err := s.tokens.GetByUser(ctx, userID); err == nil {
		return "", nil, domain.ErrTokenExists
	} else if !isNotFound(err) {
		return "", nil, err
	}
	return s.upsertNew(ctx, userID)
}

// Regenerate replaces the user's token; the old token is invalid immediately.
// The plaintext token is returned exactly once.
func (s *Service) Regenerate(ctx context.Context, userID string) (string, *domain.APIToken, error) {
	return s.upsertNew(ctx, userID)
}

func (s *Service) upsertNew(ctx context.Context, userID string) (string, *domain.APIToken, error) {
	plaintext, err := s.newPlaintext()
	if err != nil {
		return "", nil, err
	}
	t := s.newAPIToken(userID, plaintext)
	ct, err := s.seal(plaintext)
	if err != nil {
		return "", nil, err
	}
	t.TokenCiphertext = ct
	if err := s.tokens.Upsert(ctx, t); err != nil {
		return "", nil, err
	}
	s.logger.Info("api token issued", map[string]any{"token_id": t.ID, "user_id": userID})
	return plaintext, t, nil
}

// Revoke deletes the user's token (no error if none exists).
func (s *Service) Revoke(ctx context.Context, userID string) error {
	return s.tokens.Delete(ctx, userID)
}

// Meta returns the masked metadata for the user's token (ErrNotFound if none).
func (s *Service) Meta(ctx context.Context, userID string) (*domain.APIToken, error) {
	return s.tokens.GetByUser(ctx, userID)
}

// Reveal returns the plaintext token for the user. Returns ErrNotFound when no
// token exists and ErrTokenNotRecoverable when recovery is unavailable.
func (s *Service) Reveal(ctx context.Context, userID string) (string, error) {
	t, err := s.tokens.GetByUser(ctx, userID)
	if err != nil {
		return "", err
	}
	if t.TokenCiphertext == "" || s.sealer == nil {
		return "", domain.ErrTokenNotRecoverable
	}
	pt, err := s.sealer.OpenString(t.TokenCiphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt token: %w", err)
	}
	return pt, nil
}

// Validate looks up a token by its hash. On success it best-effort touches
// LastUsedAt (errors are logged, never returned).
func (s *Service) Validate(ctx context.Context, plaintext string) (*domain.APIToken, error) {
	if plaintext == "" {
		return nil, domain.ErrUnauthenticated
	}
	t, err := s.tokens.GetByHash(ctx, Hash(plaintext))
	if err != nil {
		return nil, domain.ErrUnauthenticated
	}
	if err := s.tokens.TouchLastUsed(ctx, t.ID, s.clock()); err != nil {
		s.logger.Warn("touch last_used failed", map[string]any{"token_id": t.ID})
	}
	return t, nil
}

// ImportRaw upserts a token for a user using a known plaintext value (used by
// legacy token migration).
func (s *Service) ImportRaw(ctx context.Context, userID, plaintext string) error {
	t := s.newAPIToken(userID, plaintext)
	ct, err := s.seal(plaintext)
	if err != nil {
		return err
	}
	t.TokenCiphertext = ct
	if ct == "" {
		s.logger.Warn("api token imported without encryption key; token will not be recoverable", map[string]any{"user_id": userID})
	}
	return s.tokens.Upsert(ctx, t)
}

func (s *Service) newPlaintext() (string, error) {
	b := make([]byte, DefaultRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return fmt.Sprintf("%s%s", s.prefix, hex.EncodeToString(b)), nil
}

func (s *Service) newAPIToken(userID, plaintext string) *domain.APIToken {
	prefix := plaintext
	if len(prefix) > DisplayPrefixLength {
		prefix = prefix[:DisplayPrefixLength]
	}
	return &domain.APIToken{
		ID:        newID(),
		UserID:    userID,
		TokenHash: Hash(plaintext),
		Prefix:    prefix,
		CreatedAt: s.clock(),
	}
}

func (s *Service) seal(plaintext string) (string, error) {
	if s.sealer == nil {
		return "", nil
	}
	ct, err := s.sealer.SealString(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt token: %w", err)
	}
	return ct, nil
}

func isNotFound(err error) bool {
	return errors.Is(err, domain.ErrNotFound)
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate id: %v", err))
	}
	return hex.EncodeToString(b)
}
