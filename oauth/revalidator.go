package oauth

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/store"
)

const (
	// defaultRevalidateInterval is the successful-check cache TTL.
	defaultRevalidateInterval = 5 * time.Minute
	// defaultRevalidateGrace is the offline grace window.
	defaultRevalidateGrace = time.Hour
	// maxEntryAge is the maximum age of a cache entry before it is swept.
	maxEntryAge = 24 * time.Hour
	// sweepInterval is how often the background sweeper runs.
	sweepInterval = 10 * time.Minute
)

// RevalidatorConfig configures a Revalidator.
type RevalidatorConfig struct {
	Interval      time.Duration
	Grace         time.Duration
	FailOpen      bool
	SessionMaxAge time.Duration
	Clock         func() time.Time
}

func (c RevalidatorConfig) withDefaults() RevalidatorConfig {
	if c.Interval <= 0 {
		c.Interval = defaultRevalidateInterval
	}
	if c.Grace <= 0 {
		c.Grace = defaultRevalidateGrace
	}
	if c.Clock == nil {
		c.Clock = func() time.Time { return time.Now().UTC() }
	}
	return c
}

type revalidationState int

const (
	stateOK          revalidationState = iota // IdP check succeeded
	stateRevoked                              // positive revocation
	stateUnavailable                          // IdP unreachable
	stateExpired                              // credential unusable; non-destructive
)

type revalidationEntry struct {
	state      revalidationState
	groupIDs   []string
	checkedAt  time.Time
	lastGood   time.Time
	expiresAt  time.Time
	inflight   chan struct{}
	credential string
}

// Revalidator enforces IdP group-membership revalidation behind a bounded,
// single-flight cache with leader-only refresh.
type Revalidator struct {
	provider     Provider
	mapper       *GroupMapper
	adminGroups  []string
	userStore    store.UserStore
	groups       store.GroupStore
	tokenRevoker func(ctx context.Context, userID string) error
	logger       observ.Logger
	cfg          RevalidatorConfig
	clock        func() time.Time

	mu    sync.Mutex
	cache map[string]*revalidationEntry

	stop      chan struct{}
	closeOnce sync.Once
}

// NewRevalidator returns a Revalidator and starts its background sweeper.
func NewRevalidator(
	provider Provider,
	mapper *GroupMapper,
	adminGroups []string,
	userStore store.UserStore,
	groups store.GroupStore,
	tokenRevoker func(ctx context.Context, userID string) error,
	logger observ.Logger,
	cfg RevalidatorConfig,
) *Revalidator {
	if logger == nil {
		logger = observ.NewNoopLogger()
	}
	cfg = cfg.withDefaults()
	r := &Revalidator{
		provider:     provider,
		mapper:       mapper,
		adminGroups:  adminGroups,
		userStore:    userStore,
		groups:       groups,
		tokenRevoker: tokenRevoker,
		logger:       logger,
		cfg:          cfg,
		clock:        cfg.Clock,
		cache:        make(map[string]*revalidationEntry),
		stop:         make(chan struct{}),
	}
	go r.sweepLoop()
	return r
}

// Close stops the background sweeper.
func (r *Revalidator) Close() {
	r.closeOnce.Do(func() { close(r.stop) })
}

func (r *Revalidator) sweepLoop() {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			now := r.clock()
			r.mu.Lock()
			for uid, entry := range r.cache {
				if entry.inflight == nil && now.Sub(entry.checkedAt) > maxEntryAge {
					delete(r.cache, uid)
				}
			}
			r.mu.Unlock()
		}
	}
}

// SessionMaxAge returns the configured session max age.
func (r *Revalidator) SessionMaxAge() time.Duration { return r.cfg.SessionMaxAge }

// Check returns the user's current effective group IDs, enforcing IdP
// revalidation behind a bounded cache. It returns a non-nil error only when
// access must be DENIED.
func (r *Revalidator) Check(ctx context.Context, u *domain.User) ([]string, error) {
	for {
		r.mu.Lock()
		entry := r.cache[u.ID]
		if entry == nil {
			entry = &revalidationEntry{inflight: make(chan struct{})}
			r.cache[u.ID] = entry
			r.mu.Unlock()
			r.refresh(ctx, u, entry)
			r.finish(entry)
			continue
		}
		if entry.inflight != nil {
			wait := entry.inflight
			r.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-wait:
			}
			continue
		}
		now := r.clock()
		if r.fresh(entry, u, now) {
			gids, err := r.serve(entry, u, now)
			r.mu.Unlock()
			return gids, err
		}
		entry.inflight = make(chan struct{})
		r.mu.Unlock()
		r.refresh(ctx, u, entry)
		r.finish(entry)
	}
}

func (r *Revalidator) fresh(entry *revalidationEntry, u *domain.User, now time.Time) bool {
	if entry.state == stateRevoked && u.DeactivatedAt == nil {
		return false
	}
	if entry.state == stateExpired && entry.credential != u.OAuthTokenCiphertext {
		return false
	}
	if entry.expiresAt.IsZero() {
		return false
	}
	return now.Before(entry.expiresAt)
}

func (r *Revalidator) serve(entry *revalidationEntry, u *domain.User, now time.Time) ([]string, error) {
	switch entry.state {
	case stateOK:
		return entry.groupIDs, nil
	case stateRevoked:
		return nil, domain.ErrSessionRevoked
	case stateUnavailable, stateExpired:
		reason := "IdP unreachable"
		if entry.state == stateExpired {
			reason = "credential expired, cannot verify membership"
		}
		withinGrace := !entry.lastGood.IsZero() && now.Sub(entry.lastGood) <= r.cfg.Grace
		if withinGrace && len(entry.groupIDs) > 0 {
			r.logger.Warn(fmt.Sprintf("oauth: %s within grace, serving last-known-good", reason), map[string]any{"user_id": u.ID})
			return entry.groupIDs, nil
		}
		if r.cfg.FailOpen && len(entry.groupIDs) > 0 {
			r.logger.Error(fmt.Sprintf("oauth: %s past grace, serving last-known-good (fail-open)", reason), nil, map[string]any{"user_id": u.ID})
			return entry.groupIDs, nil
		}
		r.logger.Error(fmt.Sprintf("oauth: %s past grace, denying (fail-closed)", reason), nil, map[string]any{"user_id": u.ID})
		return nil, domain.ErrUnauthenticated
	default:
		return nil, domain.ErrUnauthenticated
	}
}

func (r *Revalidator) finish(entry *revalidationEntry) {
	r.mu.Lock()
	ch := entry.inflight
	entry.inflight = nil
	r.mu.Unlock()
	close(ch)
}

func (r *Revalidator) refresh(ctx context.Context, u *domain.User, entry *revalidationEntry) {
	now := r.clock()
	entry.credential = u.OAuthTokenCiphertext

	if u.DeactivatedAt != nil {
		entry.state = stateRevoked
		entry.checkedAt = now
		entry.expiresAt = now.Add(jitteredTTL(stateRevoked, r.cfg.Interval, r.cfg.Grace))
		return
	}

	groups, err := r.provider.Revalidate(ctx, u)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrOAuthNoCredential):
			r.logger.Debug("oauth: no stored credential, allowing (bounded by session_max_age)", map[string]any{"user_id": u.ID})
			gids := groupsForUser(ctx, r.groups, u.ID)
			entry.state = stateOK
			entry.groupIDs = groupIDs(gids)
			entry.checkedAt = now
			entry.lastGood = now
			entry.expiresAt = now.Add(jitteredTTL(stateOK, r.cfg.Interval, r.cfg.Grace))
			return
		case errors.Is(err, domain.ErrOAuthCredentialExpired):
			r.logger.Warn("oauth: credential expired, cannot verify membership", map[string]any{"user_id": u.ID})
			entry.state = stateExpired
			entry.checkedAt = now
			entry.expiresAt = now.Add(jitteredTTL(stateExpired, r.cfg.Interval, r.cfg.Grace))
			return
		case errors.Is(err, domain.ErrOAuthNotLeaderRefresh):
			r.logger.Debug("oauth: refresh requires cluster leadership, serving replicated membership", map[string]any{"user_id": u.ID})
			entry.state = stateUnavailable
			gs := groupsForUser(ctx, r.groups, u.ID)
			entry.groupIDs = groupIDs(gs)
			entry.lastGood = now
			entry.checkedAt = now
			entry.expiresAt = now.Add(jitteredTTL(stateUnavailable, r.cfg.Interval, r.cfg.Grace))
			return
		case errors.Is(err, domain.ErrForbidden), errors.Is(err, domain.ErrSessionRevoked):
			r.revoke(ctx, u)
			entry.state = stateRevoked
			entry.checkedAt = now
			entry.expiresAt = now.Add(jitteredTTL(stateRevoked, r.cfg.Interval, r.cfg.Grace))
			return
		default:
			entry.state = stateUnavailable
			entry.checkedAt = now
			entry.expiresAt = now.Add(jitteredTTL(stateUnavailable, r.cfg.Interval, r.cfg.Grace))
			return
		}
	}

	mapped := mapGroups(r.mapper, groups)
	if gids, rerr := reconcileMemberships(ctx, r.groups, r.logger, u, mapped); rerr != nil {
		r.logger.Warn("oauth: membership reconciliation failed during revalidation", map[string]any{"user_id": u.ID})
	} else {
		u.OAuthGroupIDs = gids
	}
	u.OAuthGroups = normalizeGroupList(groups)
	if roleChanged := applyOAuthAdminRole(u, r.adminGroups, groups); roleChanged {
		r.logger.Info("oauth: admin role changed via admin_groups (revalidation)", map[string]any{
			"user_id": u.ID, "role": u.Role, "oauth_admin": u.OAuthAdmin,
		})
	}
	if err := r.userStore.Update(ctx, u); err != nil {
		r.logger.Warn("oauth: persist revalidated user failed", map[string]any{"user_id": u.ID})
	}
	entry.credential = u.OAuthTokenCiphertext
	entry.state = stateOK
	gs := groupsForUser(ctx, r.groups, u.ID)
	entry.groupIDs = groupIDs(gs)
	entry.checkedAt = now
	entry.lastGood = now
	entry.expiresAt = now.Add(jitteredTTL(stateOK, r.cfg.Interval, r.cfg.Grace))
}

func (r *Revalidator) revoke(_ context.Context, u *domain.User) {
	now := r.clock()
	u.DeactivatedAt = &now

	persistCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := r.userStore.Update(persistCtx, u); err != nil {
		r.logger.Warn("oauth: deactivate user failed (not leader?)", map[string]any{"user_id": u.ID})
	}
	if r.tokenRevoker != nil {
		if err := r.tokenRevoker(persistCtx, u.ID); err != nil && !errors.Is(err, domain.ErrNotFound) {
			r.logger.Warn("oauth: revoke api token failed", map[string]any{"user_id": u.ID})
		}
	}
	r.logger.Warn("oauth: membership revalidation revoked access", map[string]any{
		"user_id": u.ID, "username": u.Username, "oauth_provider": u.OAuthProvider,
	})
}

var jitterRng = func() *rand.Rand {
	var seed int64
	_ = binary.Read(crand.Reader, binary.BigEndian, &seed)
	return rand.New(rand.NewSource(seed)) // #nosec G404
}()

var jitterRngMu sync.Mutex

func jitteredTTL(state revalidationState, interval, grace time.Duration) time.Duration {
	base := interval
	if state == stateUnavailable && grace > 0 && grace < base {
		base = grace
	}
	jitterRngMu.Lock()
	f := jitterRng.Float64()
	jitterRngMu.Unlock()
	return time.Duration(float64(base) * (0.9 + f*0.2)) //nolint:gosec // G404: cache jitter needs no cryptographic randomness.
}
