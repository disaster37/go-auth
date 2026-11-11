// Package goauth is the turnkey facade unifying bearer/cookie resolution,
// login, refresh, logout, and OAuth completion over the go-auth subpackages.
package goauth

import (
	"context"
	"time"

	"github.com/disaster37/go-auth/apitoken"
	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/jwt"
	"github.com/disaster37/go-auth/oauth"
	"github.com/disaster37/go-auth/observ"
	"github.com/disaster37/go-auth/password"
	"github.com/disaster37/go-auth/store"
)

// ServiceConfig wires the Service dependencies.
type ServiceConfig struct {
	Users       *password.Service
	UserStore   store.UserStore
	Groups      store.GroupStore
	Epochs      store.EpochStore
	Tokens      *apitoken.Service
	JWT         *jwt.Service
	Legacy      domain.LegacyTokenValidator
	Revalidator *oauth.Revalidator
	Logger      observ.Logger
}

// Service resolves credentials to identities and handles login/refresh/logout.
type Service struct {
	users       *password.Service
	userStore   store.UserStore
	groups      store.GroupStore
	epochs      store.EpochStore
	tokens      *apitoken.Service
	jwt         *jwt.Service
	legacy      domain.LegacyTokenValidator
	revalidator *oauth.Revalidator
	logger      observ.Logger
}

// NewService returns a Service.
func NewService(cfg ServiceConfig) *Service {
	logger := cfg.Logger
	if logger == nil {
		logger = observ.NewNoopLogger()
	}
	return &Service{
		users:       cfg.Users,
		userStore:   cfg.UserStore,
		groups:      cfg.Groups,
		epochs:      cfg.Epochs,
		tokens:      cfg.Tokens,
		jwt:         cfg.JWT,
		legacy:      cfg.Legacy,
		revalidator: cfg.Revalidator,
		logger:      logger,
	}
}

// SetRevalidator wires the OAuth membership revalidator.
func (s *Service) SetRevalidator(r *oauth.Revalidator) { s.revalidator = r }

// Resolve maps a bearer token to an Identity. Resolution order:
//  1. empty bearer -> ErrUnauthenticated
//  2. API token prefix -> API token
//  3. JWT access token
//  4. legacy flat-file fallback
//  5. ErrUnauthenticated
func (s *Service) Resolve(ctx context.Context, bearer string) (*domain.Identity, error) {
	if bearer == "" {
		return nil, domain.ErrUnauthenticated
	}

	if s.tokens != nil && s.tokens.HasTokenPrefix(bearer) {
		tok, err := s.tokens.Validate(ctx, bearer)
		if err != nil {
			s.logger.Debug("api token validate failed", nil)
			return nil, domain.ErrUnauthenticated
		}
		return s.identityForUser(ctx, tok.UserID, domain.AuthMethodAPIToken, 0, 0)
	}

	if s.jwt != nil {
		if claims, err := s.jwt.ParseAccess(bearer); err == nil {
			return s.identityForUser(ctx, claims.UserID, domain.AuthMethodJWT, claims.TokenVersion, claims.AuthEpoch)
		}
	}

	if s.legacy != nil {
		if _, err := s.legacy.ValidateToken(ctx, bearer); err == nil {
			return &domain.Identity{
				UserID:   "legacy",
				Username: "legacy",
				Role:     domain.RoleAdmin,
				Method:   domain.AuthMethodLegacyToken,
			}, nil
		}
	}

	s.logger.Debug("unauthenticated: no matching credential", nil)
	return nil, domain.ErrUnauthenticated
}

// ResolveSession decodes a compact session token and resolves its principal.
func (s *Service) ResolveSession(ctx context.Context, sessionCookie string, secret [32]byte) (*domain.Identity, error) {
	if sessionCookie == "" {
		return nil, domain.ErrUnauthenticated
	}
	tok, err := jwt.DecodeSession(sessionCookie, secret, time.Now().UTC())
	if err != nil {
		return nil, domain.ErrUnauthenticated
	}
	if tok.UserID == "" {
		return nil, domain.ErrUnauthenticated
	}
	return s.identityForUser(ctx, tok.UserID, domain.AuthMethodSession, tok.TokenVersion, tok.AuthEpoch)
}

// identityForUser loads a fresh user and group membership, enforcing
// deactivation, TokenVersion, AuthEpoch, and OAuth revalidation.
func (s *Service) identityForUser(ctx context.Context, userID string, method domain.AuthMethod, tokenVersion int, authEpoch int64) (*domain.Identity, error) {
	u, err := s.userStore.Get(ctx, userID)
	if err != nil {
		s.logger.Debug("resolved user missing", map[string]any{"user_id": userID})
		return nil, domain.ErrUnauthenticated
	}
	// TokenVersion and AuthEpoch are revocation counters carried by JWT and
	// session tokens. API tokens are revoked independently (Revoke/Delete) and
	// must not be invalidated by a global AuthEpoch bump.
	if (method == domain.AuthMethodJWT || method == domain.AuthMethodSession) && u.TokenVersion != tokenVersion {
		s.logger.Debug("stale token version; session revoked", map[string]any{"user_id": u.ID})
		return nil, domain.ErrSessionRevoked
	}
	if (method == domain.AuthMethodJWT || method == domain.AuthMethodSession) && s.epochs != nil {
		current, err := s.epochs.GetAuthEpoch(ctx)
		if err == nil && current != authEpoch {
			s.logger.Debug("stale auth epoch; session revoked", map[string]any{"user_id": u.ID})
			return nil, domain.ErrSessionRevoked
		}
	}
	gids, err := s.loadAuthorizedGroups(ctx, u)
	if err != nil {
		return nil, err
	}
	return &domain.Identity{
		UserID:   u.ID,
		Username: u.Username,
		Role:     u.Role,
		GroupIDs: gids,
		Method:   method,
	}, nil
}

func (s *Service) loadAuthorizedGroups(ctx context.Context, u *domain.User) ([]string, error) {
	if u.Deactivated() {
		s.logger.Debug("user deactivated by IdP revalidation", map[string]any{"user_id": u.ID})
		return nil, domain.ErrUnauthenticated
	}
	if u.OAuthProvider != "" && s.revalidator != nil {
		gids, err := s.revalidator.Check(ctx, u)
		if err != nil {
			s.logger.Warn("oauth revalidation denied", map[string]any{"user_id": u.ID, "oauth_provider": u.OAuthProvider})
			return nil, domain.ErrUnauthenticated
		}
		return gids, nil
	}
	if s.groups == nil {
		return nil, nil
	}
	gids, _ := s.groups.GroupsForUser(ctx, u.ID)
	return groupIDs(gids), nil
}

// Login authenticates a user and issues a fresh JWT pair.
func (s *Service) Login(ctx context.Context, username, rawPassword string) (access, refresh string, u *domain.User, err error) {
	u, err = s.users.Authenticate(ctx, username, rawPassword)
	if err != nil {
		s.logger.Debug("login failed", map[string]any{"username": username})
		return "", "", nil, err
	}
	var gids []*domain.Group
	if s.groups != nil {
		gids, _ = s.groups.GroupsForUser(ctx, u.ID)
	}
	access, refresh, err = s.jwt.IssuePair(u, groupIDs(gids), s.currentEpoch(ctx))
	if err != nil {
		return "", "", nil, err
	}
	s.logger.Info("login succeeded", map[string]any{"username": username})
	return access, refresh, u, nil
}

// Refresh validates a refresh token, reloads the user, enforces session max age
// and revalidation, and issues a new pair (rotation).
func (s *Service) Refresh(ctx context.Context, refreshToken string) (access, refresh string, err error) {
	claims, err := s.jwt.ParseRefresh(refreshToken)
	if err != nil {
		return "", "", domain.ErrUnauthenticated
	}
	u, err := s.userStore.Get(ctx, claims.UserID)
	if err != nil {
		return "", "", domain.ErrUnauthenticated
	}
	if claims.TokenVersion != u.TokenVersion {
		s.logger.Debug("stale refresh token version; session revoked", map[string]any{"user_id": u.ID})
		return "", "", domain.ErrSessionRevoked
	}
	if s.revalidator != nil && u.OAuthProvider != "" {
		if maxAge := s.revalidator.SessionMaxAge(); maxAge > 0 && claims.IssuedAt != nil {
			if age := time.Since(claims.IssuedAt.Time); age > maxAge {
				s.logger.Warn("oauth session exceeded max age; re-login required", map[string]any{"user_id": u.ID})
				return "", "", domain.ErrSessionRevoked
			}
		}
	}
	gids, err := s.loadAuthorizedGroups(ctx, u)
	if err != nil {
		return "", "", err
	}
	return s.jwt.IssuePair(u, gids, s.currentEpoch(ctx))
}

// Logout revokes every JWT issued before the call by bumping the user's
// TokenVersion.
func (s *Service) Logout(ctx context.Context, bearer string) error {
	userID, err := s.userIDFromToken(bearer)
	if err != nil {
		return err
	}
	return s.users.IncrementTokenVersion(ctx, userID)
}

func (s *Service) userIDFromToken(bearer string) (string, error) {
	if bearer == "" {
		return "", domain.ErrUnauthenticated
	}
	if claims, err := s.jwt.ParseAccess(bearer); err == nil {
		return claims.UserID, nil
	}
	if claims, err := s.jwt.ParseRefresh(bearer); err == nil {
		return claims.UserID, nil
	}
	return "", domain.ErrUnauthenticated
}

func (s *Service) currentEpoch(ctx context.Context) int64 {
	if s.epochs == nil {
		return 0
	}
	epoch, err := s.epochs.GetAuthEpoch(ctx)
	if err != nil {
		return 0
	}
	return epoch
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
