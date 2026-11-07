// Package store defines the minimal persistence interfaces used by go-auth and
// provides thread-safe in-memory reference implementations for tests and
// single-node setups.
package store

import (
	"context"
	"time"

	"github.com/disaster37/go-auth/domain"
)

// UserStore persists user accounts.
type UserStore interface {
	Create(ctx context.Context, u *domain.User) error
	Get(ctx context.Context, id string) (*domain.User, error)
	GetByUsername(ctx context.Context, username string) (*domain.User, error)
	GetByOAuth(ctx context.Context, provider, oauthID string) (*domain.User, error)
	List(ctx context.Context) ([]*domain.User, error)
	Update(ctx context.Context, u *domain.User) error
	Delete(ctx context.Context, id string) error
	Count(ctx context.Context) (int, error)
}

// ExternalIdentityStore is an optional extension of UserStore for multi-provider
// (providerID, issuer, subject) lookups.
type ExternalIdentityStore interface {
	GetByExternalIdentity(ctx context.Context, providerID, issuer, subject string) (*domain.User, error)
}

// GroupStore maps OAuth groups to stored group records.
type GroupStore interface {
	GetByName(ctx context.Context, name string) (*domain.Group, error)
	Create(ctx context.Context, g *domain.Group) error
	GroupsForUser(ctx context.Context, userID string) ([]*domain.Group, error)
	AddMember(ctx context.Context, groupID, userID string) error
	RemoveMember(ctx context.Context, groupID, userID string) error
}

// APITokenStore persists API tokens.
type APITokenStore interface {
	Upsert(ctx context.Context, t *domain.APIToken) error
	GetByHash(ctx context.Context, tokenHash string) (*domain.APIToken, error)
	GetByUser(ctx context.Context, userID string) (*domain.APIToken, error)
	Delete(ctx context.Context, userID string) error
	TouchLastUsed(ctx context.Context, id string, at time.Time) error
}

// EpochStore tracks the cluster-wide AuthEpoch for global session invalidation.
type EpochStore interface {
	GetAuthEpoch(ctx context.Context) (int64, error)
	BumpAuthEpoch(ctx context.Context) (int64, error)
}
