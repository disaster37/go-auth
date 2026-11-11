package domain

import (
	"context"
	"time"
)

// APIToken is a stored API token. TokenHash and TokenCiphertext are never
// serialized (CWE-532).
type APIToken struct {
	ID              string     `json:"id"`
	UserID          string     `json:"user_id"`
	TokenHash       string     `json:"-"`
	TokenCiphertext string     `json:"-"`
	Prefix          string     `json:"prefix"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
}

// LegacyTokenValidator validates a static/flat-file bearer token fallback.
type LegacyTokenValidator interface {
	ValidateToken(ctx context.Context, token string) (string, error)
}
