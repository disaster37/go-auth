// Package oauth implements generic OIDC and GitHub OAuth2 providers, PKCE
// (S256), OIDC nonce, multi-audience azp verification, email_verified
// enforcement, userinfo merge, a 1 MiB response cap, cross-origin redirect
// refusal, allowed_endpoints validation, a regex GroupMapper, encrypted
// Credential storage, and a single-flight Revalidator with leader-only refresh.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/disaster37/go-auth/crypto"
	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/password"
	"github.com/disaster37/go-auth/store"
)

const (
	// DefaultDiscoveryTimeout bounds OIDC provider discovery.
	DefaultDiscoveryTimeout = 15 * time.Second
	// DefaultHTTPTimeout is the default OAuth HTTP client timeout.
	DefaultHTTPTimeout = 15 * time.Second
	// MaxResponseBodyBytes caps provider responses (CWE-400).
	MaxResponseBodyBytes = 1 << 20 // 1 MiB
)

// AuthorizeParams holds the parameters for building an authorization URL.
type AuthorizeParams struct {
	State         string
	Nonce         string // OIDC nonce claim (optional but recommended for OIDC)
	CodeChallenge string // PKCE S256 challenge (optional)
}

// CompleteParams holds the callback inputs for exchanging an authorization code.
type CompleteParams struct {
	Code          string
	ExpectedNonce string // verified against IDToken.Nonce when non-empty
	CodeVerifier  string // PKCE S256 verifier sent to the token endpoint when non-empty
}

// Provider is an OAuth2/OIDC identity provider.
type Provider interface {
	Name() string
	LoginURL(params AuthorizeParams) string
	Complete(ctx context.Context, params CompleteParams) (access, refresh string, u *domain.User, err error)
	Revalidate(ctx context.Context, u *domain.User) ([]string, error)
}

// GeneratePKCEVerifier returns a 32-byte CSPRNG PKCE code_verifier (RFC 7636).
func GeneratePKCEVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate pkce verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ComputePKCEChallenge returns the S256 code_challenge for verifier.
func ComputePKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateNonce returns a 16-byte CSPRNG nonce (base64url).
func GenerateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// orgsIntersect reports whether any element of allowed is present in have.
func orgsIntersect(allowed, have []string) bool {
	hset := make(map[string]struct{}, len(have))
	for _, h := range have {
		hset[h] = struct{}{}
	}
	for _, a := range allowed {
		if _, ok := hset[a]; ok {
			return true
		}
	}
	return false
}

// normalizeGroupList de-duplicates (preserving first occurrence, dropping empty
// strings) and sorts a group-name list for stable storage and display.
func normalizeGroupList(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// mapGroups applies the configured mapper, or returns the upstream groups
// unchanged when no mapping rules are configured.
func mapGroups(mapper *GroupMapper, groups []string) []string {
	if mapper.Active() {
		return mapper.Map(groups)
	}
	return groups
}

// applyOAuthAdminRole promotes/demotes u's role based on whether any raw
// upstream group matches adminGroups. It never takes ownership of a
// manually-promoted admin. Returns true when the role changed.
func applyOAuthAdminRole(u *domain.User, adminGroups, upstreamGroups []string) bool {
	if len(adminGroups) == 0 {
		return false
	}
	match := orgsIntersect(adminGroups, upstreamGroups)
	if match && u.Role != domain.RoleAdmin {
		u.Role = domain.RoleAdmin
		u.OAuthAdmin = true
		return true
	}
	if !match && u.OAuthAdmin {
		u.Role = domain.RoleUser
		u.OAuthAdmin = false
		return true
	}
	return false
}

// loginContext carries the shared dependencies for the post-verification tail.
type loginContext struct {
	users        *password.Service
	userStore    store.UserStore
	groups       store.GroupStore
	jwt          *jwt.Service
	sealer       crypto.Sealer
	logger       observ.Logger
	adminGroups  []string
	defaultGroup string
	autoCreate   bool
	epoch        func() int64
}

// completeOAuthLogin is the shared post-verification tail for both OAuth
// providers: resolve the local user, clear any prior deactivation, reconcile
// OAuth-managed memberships, fall back to the default group, persist the stored
// credential, and issue a JWT pair.
func completeOAuthLogin(
	ctx context.Context,
	lc loginContext,
	provider, oauthID, issuer, username string,
	upstreamGroups, mappedGroups []string,
	credential *Credential,
) (access, refresh string, u *domain.User, err error) {
	u, err = resolveOAuthUser(ctx, lc, provider, oauthID, issuer, username)
	if err != nil {
		return "", "", nil, err
	}

	// A successful IdP login re-authorizes: clear any prior deactivation.
	u.DeactivatedAt = nil

	var memberGroups []*domain.Group
	if lc.groups != nil {
		if oauthGids, rerr := reconcileMemberships(ctx, lc.groups, lc.logger, u, mappedGroups); rerr != nil {
			lc.logger.Warn("oauth: membership reconciliation failed", map[string]any{"user_id": u.ID})
		} else {
			u.OAuthGroupIDs = oauthGids
		}
		memberGroups, _ = lc.groups.GroupsForUser(ctx, u.ID)
		if len(memberGroups) == 0 {
			joinGroupByName(ctx, lc.groups, defaultGroupName(lc.defaultGroup), u.ID, lc.logger)
			memberGroups, _ = lc.groups.GroupsForUser(ctx, u.ID)
		}
	}

	u.OAuthGroups = normalizeGroupList(upstreamGroups)
	if roleChanged := applyOAuthAdminRole(u, lc.adminGroups, upstreamGroups); roleChanged {
		lc.logger.Info("oauth: admin role changed via admin_groups", map[string]any{
			"user_id": u.ID, "oauth_provider": provider, "role": u.Role, "oauth_admin": u.OAuthAdmin,
		})
	}

	ct, err := SealCredential(lc.sealer, credential)
	if err != nil {
		return "", "", nil, fmt.Errorf("encrypt oauth credential: %w", err)
	}
	u.OAuthTokenCiphertext = ct

	if err := lc.userStore.Update(ctx, u); err != nil {
		return "", "", nil, fmt.Errorf("persist oauth user: %w", err)
	}

	access, refresh, err = lc.jwt.IssuePair(u, groupIDs(memberGroups), currentEpoch(lc.epoch))
	return access, refresh, u, err
}

// currentEpoch returns the current AuthEpoch via the optional provider, or 0
// when none is configured.
func currentEpoch(epoch func() int64) int64 {
	if epoch == nil {
		return 0
	}
	return epoch()
}

func resolveOAuthUser(ctx context.Context, lc loginContext, provider, oauthID, issuer, username string) (*domain.User, error) {
	if lc.autoCreate {
		u, _, err := lc.users.EnsureOAuthUser(ctx, provider, oauthID, username)
		if err != nil {
			return nil, err
		}
		u.OAuthIssuer = issuer
		return u, nil
	}
	ext, ok := lc.userStore.(store.ExternalIdentityStore)
	if !ok {
		return nil, fmt.Errorf("user store does not support external identities: %w", domain.ErrForbidden)
	}
	u, err := ext.GetByExternalIdentity(ctx, provider, issuer, oauthID)
	if err != nil {
		return nil, fmt.Errorf("no account linked for external identity: %w", domain.ErrForbidden)
	}
	return u, nil
}

func defaultGroupName(configured string) string {
	if configured == "" {
		return "default"
	}
	return configured
}

func groupsForUser(ctx context.Context, groups store.GroupStore, userID string) []*domain.Group {
	if groups == nil {
		return nil
	}
	gs, _ := groups.GroupsForUser(ctx, userID)
	return gs
}

func groupIDs(gs []*domain.Group) []string {
	if len(gs) == 0 {
		return nil
	}
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.ID)
	}
	return out
}

// ensureGroupByName resolves the group named name, creating it when missing.
// It returns (nil, nil) for an invalid name and (nil, err) on a store error.
func ensureGroupByName(ctx context.Context, groups store.GroupStore, name string, logger observ.Logger) (*domain.Group, error) {
	if groups == nil {
		return nil, nil
	}
	g, err := groups.GetByName(ctx, name)
	if err == nil {
		return g, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return nil, fmt.Errorf("get group %q: %w", name, err)
	}
	g = &domain.Group{ID: newID(), Name: name}
	if err := groups.Create(ctx, g); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return groups.GetByName(ctx, name)
		}
		return nil, fmt.Errorf("create group %q: %w", name, err)
	}
	logger.Info("oauth: auto-created mapped group", map[string]any{"group": name})
	return g, nil
}

// joinGroupByName best-effort adds userID to the named group.
func joinGroupByName(ctx context.Context, groups store.GroupStore, name, userID string, logger observ.Logger) {
	if groups == nil {
		return
	}
	g, err := groups.GetByName(ctx, name)
	if err != nil {
		logger.Warn("oauth: group not found, skipping", map[string]any{"group": name})
		return
	}
	if err := groups.AddMember(ctx, g.ID, userID); err != nil {
		logger.Warn("oauth: group auto-join failed", map[string]any{"group": name})
	}
}

// reconcileMemberships applies the desired OAuth-managed memberships for u:
// add memberships for names that newly resolve (auto-creating the group when
// missing), remove memberships for previously OAuth-managed names that no
// longer resolve. Manually-assigned memberships are never touched.
func reconcileMemberships(ctx context.Context, groups store.GroupStore, logger observ.Logger, u *domain.User, mappedNames []string) ([]string, error) {
	if groups == nil {
		return nil, nil
	}
	wanted := make(map[string]bool, len(mappedNames))
	for _, name := range mappedNames {
		g, err := ensureGroupByName(ctx, groups, name, logger)
		if err != nil {
			logger.Warn("oauth: ensure mapped group failed, skipping", map[string]any{"group": name})
			continue
		}
		if g == nil {
			continue
		}
		wanted[g.ID] = true
	}

	previous := make(map[string]bool, len(u.OAuthGroupIDs))
	for _, gid := range u.OAuthGroupIDs {
		previous[gid] = true
	}

	for gid := range wanted {
		if !previous[gid] {
			if err := groups.AddMember(ctx, gid, u.ID); err != nil {
				return nil, fmt.Errorf("add oauth group %s: %w", gid, err)
			}
		}
	}
	for gid := range previous {
		if !wanted[gid] {
			if err := groups.RemoveMember(ctx, gid, u.ID); err != nil {
				return nil, fmt.Errorf("remove oauth group %s: %w", gid, err)
			}
		}
	}

	out := make([]string, 0, len(wanted))
	for gid := range wanted {
		out = append(out, gid)
	}
	sort.Strings(out)
	u.OAuthGroupIDs = out
	return out, nil
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate id: %v", err))
	}
	return hex.EncodeToString(b)
}

// constantTimeEqual compares two strings in constant time.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
