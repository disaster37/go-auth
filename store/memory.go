package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/disaster37/go-auth/domain"
)

func externalKey(providerID, issuer, subject string) string {
	return fmt.Sprintf("%s\x00%s\x00%s", providerID, issuer, subject)
}

// MemoryUserStore is a thread-safe in-memory UserStore and
// ExternalIdentityStore.
type MemoryUserStore struct {
	mu         sync.RWMutex
	byID       map[string]*domain.User
	byUsername map[string]string
	byOAuth    map[string]string
	byExternal map[string]string
}

// NewMemoryUserStore returns an empty MemoryUserStore.
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		byID:       make(map[string]*domain.User),
		byUsername: make(map[string]string),
		byOAuth:    make(map[string]string),
		byExternal: make(map[string]string),
	}
}

func oauthKey(provider, oauthID string) string {
	return fmt.Sprintf("%s\x00%s", provider, oauthID)
}

// Create stores a copy of u, rejecting duplicate IDs, usernames, or OAuth
// identities.
func (s *MemoryUserStore) Create(_ context.Context, u *domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[u.ID]; ok {
		return fmt.Errorf("%w: user id %q", domain.ErrConflict, u.ID)
	}
	if _, ok := s.byUsername[u.Username]; ok {
		return fmt.Errorf("%w: username %q", domain.ErrConflict, u.Username)
	}
	if u.OAuthID != "" {
		if _, ok := s.byOAuth[oauthKey(u.OAuthProvider, u.OAuthID)]; ok {
			return fmt.Errorf("%w: oauth identity", domain.ErrConflict)
		}
	}
	s.storeLocked(u)
	return nil
}

func (s *MemoryUserStore) storeLocked(u *domain.User) {
	cp := *u
	s.byID[u.ID] = &cp
	s.byUsername[u.Username] = u.ID
	if u.OAuthID != "" {
		s.byOAuth[oauthKey(u.OAuthProvider, u.OAuthID)] = u.ID
		s.byExternal[externalKey(u.OAuthProvider, u.OAuthIssuer, u.OAuthID)] = u.ID
	}
}

// Get returns a copy of the user with the given ID.
func (s *MemoryUserStore) Get(_ context.Context, id string) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: user %q", domain.ErrNotFound, id)
	}
	cp := *u
	return &cp, nil
}

// GetByUsername returns a copy of the user with the given username.
func (s *MemoryUserStore) GetByUsername(_ context.Context, username string) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byUsername[username]
	if !ok {
		return nil, fmt.Errorf("%w: username %q", domain.ErrNotFound, username)
	}
	cp := *s.byID[id]
	return &cp, nil
}

// GetByOAuth returns a copy of the user bound to (provider, oauthID).
func (s *MemoryUserStore) GetByOAuth(_ context.Context, provider, oauthID string) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byOAuth[oauthKey(provider, oauthID)]
	if !ok {
		return nil, fmt.Errorf("%w: oauth identity", domain.ErrNotFound)
	}
	cp := *s.byID[id]
	return &cp, nil
}

// GetByExternalIdentity returns a copy of the user bound to
// (providerID, issuer, subject).
func (s *MemoryUserStore) GetByExternalIdentity(_ context.Context, providerID, issuer, subject string) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byExternal[externalKey(providerID, issuer, subject)]
	if !ok {
		return nil, fmt.Errorf("%w: external identity", domain.ErrNotFound)
	}
	cp := *s.byID[id]
	return &cp, nil
}

// List returns copies of every stored user.
func (s *MemoryUserStore) List(_ context.Context) ([]*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*domain.User, 0, len(s.byID))
	for _, u := range s.byID {
		cp := *u
		out = append(out, &cp)
	}
	return out, nil
}

// Update replaces an existing user, maintaining the lookup indexes.
func (s *MemoryUserStore) Update(_ context.Context, u *domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.byID[u.ID]
	if !ok {
		return fmt.Errorf("%w: user %q", domain.ErrNotFound, u.ID)
	}
	if old.Username != u.Username {
		delete(s.byUsername, old.Username)
	}
	if old.OAuthID != "" {
		delete(s.byOAuth, oauthKey(old.OAuthProvider, old.OAuthID))
		delete(s.byExternal, externalKey(old.OAuthProvider, old.OAuthIssuer, old.OAuthID))
	}
	s.storeLocked(u)
	return nil
}

// Delete removes the user with the given ID.
func (s *MemoryUserStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("%w: user %q", domain.ErrNotFound, id)
	}
	delete(s.byID, id)
	delete(s.byUsername, u.Username)
	if u.OAuthID != "" {
		delete(s.byOAuth, oauthKey(u.OAuthProvider, u.OAuthID))
		delete(s.byExternal, externalKey(u.OAuthProvider, u.OAuthIssuer, u.OAuthID))
	}
	return nil
}

// Count returns the number of stored users.
func (s *MemoryUserStore) Count(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID), nil
}

// MemoryGroupStore is a thread-safe in-memory GroupStore.
type MemoryGroupStore struct {
	mu      sync.RWMutex
	byID    map[string]*domain.Group
	byName  map[string]string
	members map[string]map[string]struct{}
}

// NewMemoryGroupStore returns an empty MemoryGroupStore.
func NewMemoryGroupStore() *MemoryGroupStore {
	return &MemoryGroupStore{
		byID:    make(map[string]*domain.Group),
		byName:  make(map[string]string),
		members: make(map[string]map[string]struct{}),
	}
}

// Create stores a copy of g, rejecting duplicate IDs or names.
func (s *MemoryGroupStore) Create(_ context.Context, g *domain.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[g.ID]; ok {
		return fmt.Errorf("%w: group id %q", domain.ErrConflict, g.ID)
	}
	if _, ok := s.byName[g.Name]; ok {
		return fmt.Errorf("%w: group name %q", domain.ErrConflict, g.Name)
	}
	cp := *g
	s.byID[g.ID] = &cp
	s.byName[g.Name] = g.ID
	return nil
}

// GetByName returns a copy of the group with the given name.
func (s *MemoryGroupStore) GetByName(_ context.Context, name string) (*domain.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byName[name]
	if !ok {
		return nil, fmt.Errorf("%w: group %q", domain.ErrNotFound, name)
	}
	cp := *s.byID[id]
	return &cp, nil
}

// GroupsForUser returns copies of the groups the user belongs to.
func (s *MemoryGroupStore) GroupsForUser(_ context.Context, userID string) ([]*domain.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*domain.Group, 0)
	for gid, members := range s.members {
		if _, ok := members[userID]; !ok {
			continue
		}
		if g, ok := s.byID[gid]; ok {
			cp := *g
			out = append(out, &cp)
		}
	}
	return out, nil
}

// AddMember adds userID to groupID (idempotent).
func (s *MemoryGroupStore) AddMember(_ context.Context, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[groupID]; !ok {
		return fmt.Errorf("%w: group %q", domain.ErrNotFound, groupID)
	}
	if s.members[groupID] == nil {
		s.members[groupID] = make(map[string]struct{})
	}
	s.members[groupID][userID] = struct{}{}
	return nil
}

// RemoveMember removes userID from groupID (idempotent).
func (s *MemoryGroupStore) RemoveMember(_ context.Context, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.members[groupID], userID)
	return nil
}

// MemoryAPITokenStore is a thread-safe in-memory APITokenStore.
type MemoryAPITokenStore struct {
	mu     sync.RWMutex
	byID   map[string]*domain.APIToken
	byHash map[string]string
	byUser map[string]string
}

// NewMemoryAPITokenStore returns an empty MemoryAPITokenStore.
func NewMemoryAPITokenStore() *MemoryAPITokenStore {
	return &MemoryAPITokenStore{
		byID:   make(map[string]*domain.APIToken),
		byHash: make(map[string]string),
		byUser: make(map[string]string),
	}
}

// Upsert stores a copy of t, replacing any existing token for the same user.
func (s *MemoryAPITokenStore) Upsert(_ context.Context, t *domain.APIToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if oldID, ok := s.byUser[t.UserID]; ok {
		if old, ok := s.byID[oldID]; ok {
			delete(s.byHash, old.TokenHash)
		}
		delete(s.byID, oldID)
	}
	cp := *t
	s.byID[t.ID] = &cp
	s.byHash[t.TokenHash] = t.ID
	s.byUser[t.UserID] = t.ID
	return nil
}

// GetByHash returns a copy of the token with the given hash.
func (s *MemoryAPITokenStore) GetByHash(_ context.Context, tokenHash string) (*domain.APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[tokenHash]
	if !ok {
		return nil, fmt.Errorf("%w: token", domain.ErrNotFound)
	}
	cp := *s.byID[id]
	return &cp, nil
}

// GetByUser returns a copy of the token owned by userID.
func (s *MemoryAPITokenStore) GetByUser(_ context.Context, userID string) (*domain.APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byUser[userID]
	if !ok {
		return nil, fmt.Errorf("%w: token", domain.ErrNotFound)
	}
	cp := *s.byID[id]
	return &cp, nil
}

// Delete removes the token owned by userID (no error when none exists).
func (s *MemoryAPITokenStore) Delete(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byUser[userID]
	if !ok {
		return nil
	}
	if t, ok := s.byID[id]; ok {
		delete(s.byHash, t.TokenHash)
	}
	delete(s.byID, id)
	delete(s.byUser, userID)
	return nil
}

// TouchLastUsed records the last-used timestamp for the token with the given ID.
func (s *MemoryAPITokenStore) TouchLastUsed(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("%w: token %q", domain.ErrNotFound, id)
	}
	ts := at
	t.LastUsedAt = &ts
	return nil
}

// MemoryEpochStore is a thread-safe in-memory EpochStore.
type MemoryEpochStore struct {
	mu    sync.Mutex
	epoch int64
}

// NewMemoryEpochStore returns an empty MemoryEpochStore.
func NewMemoryEpochStore() *MemoryEpochStore { return &MemoryEpochStore{} }

// GetAuthEpoch returns the current epoch.
func (s *MemoryEpochStore) GetAuthEpoch(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch, nil
}

// BumpAuthEpoch increments and returns the epoch.
func (s *MemoryEpochStore) BumpAuthEpoch(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch++
	return s.epoch, nil
}
