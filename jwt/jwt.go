// Package jwt issues and parses HS256 JWT access/refresh/oauth-state tokens and
// compact HMAC-SHA256 session tokens, both with HKDF-SHA256 key derivation,
// TokenVersion, and AuthEpoch revocation.
package jwt

import (
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/disaster37/go-auth/domain"
)

const (
	// TypeAccess is the access-token typ claim.
	TypeAccess = "access"
	// TypeRefresh is the refresh-token typ claim.
	TypeRefresh = "refresh"
	// TypeOAuthState is the oauth-state-token typ claim.
	TypeOAuthState = "oauth_state"

	// DefaultAccessTTL is the default access-token lifetime.
	DefaultAccessTTL = 15 * time.Minute
	// DefaultRefreshTTL is the default refresh-token lifetime.
	DefaultRefreshTTL = 7 * 24 * time.Hour
	// DefaultOAuthStateTTL is the default oauth-state-token lifetime.
	DefaultOAuthStateTTL = 10 * time.Minute

	// MinSecretLength is the minimum accepted JWT secret length in bytes.
	MinSecretLength = 32
	// JWTHKDFInfo is the HKDF domain-separation info for JWT signing keys.
	JWTHKDFInfo = "go-auth.jwt.signing.v1"
	// SessionHKDFInfo is the HKDF domain-separation info for session signing
	// keys.
	SessionHKDFInfo = "go-auth.session.signing.v1"
)

// Claims is the JWT body issued by the Service.
type Claims struct {
	UserID       string   `json:"uid"`
	Username     string   `json:"username"`
	Role         string   `json:"role"`
	GroupIDs     []string `json:"groups,omitempty"`
	Type         string   `json:"typ"` // "access" | "refresh" | "oauth_state"
	Nonce        string   `json:"nonce,omitempty"`
	CodeVerifier string   `json:"cv,omitempty"` // PKCE code_verifier bound to oauth_state
	Provider     string   `json:"prv,omitempty"`
	TokenVersion int      `json:"token_version"`
	AuthEpoch    int64    `json:"auth_epoch,omitempty"`
	jwtv5.RegisteredClaims
}

// Config configures a JWT Service.
type Config struct {
	Secret        []byte
	UseHKDF       bool // when true, derives a 32-byte key via HKDF-SHA256(Secret, JWTHKDFInfo)
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	OAuthStateTTL time.Duration
	Clock         func() time.Time
}

// Service issues and parses HS256 JWTs.
type Service struct {
	key           []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
	oauthStateTTL time.Duration
	clock         func() time.Time
}

// NewService returns a Service. The secret must be at least MinSecretLength
// bytes. When UseHKDF is set the signing key is derived via HKDF-SHA256.
func NewService(cfg Config) (*Service, error) {
	if len(cfg.Secret) < MinSecretLength {
		return nil, fmt.Errorf("jwt secret must be at least %d bytes (got %d): %w", MinSecretLength, len(cfg.Secret), domain.ErrValidation)
	}
	key := cfg.Secret
	if cfg.UseHKDF {
		derived, err := DeriveSigningKey(string(cfg.Secret), JWTHKDFInfo)
		if err != nil {
			return nil, err
		}
		key = derived[:]
	}
	accessTTL := cfg.AccessTTL
	if accessTTL <= 0 {
		accessTTL = DefaultAccessTTL
	}
	refreshTTL := cfg.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = DefaultRefreshTTL
	}
	stateTTL := cfg.OAuthStateTTL
	if stateTTL <= 0 {
		stateTTL = DefaultOAuthStateTTL
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Service{
		key:           append([]byte(nil), key...),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
		oauthStateTTL: stateTTL,
		clock:         clock,
	}, nil
}

// AccessTTL returns the configured access-token TTL.
func (s *Service) AccessTTL() time.Duration { return s.accessTTL }

// RefreshTTL returns the configured refresh-token TTL.
func (s *Service) RefreshTTL() time.Duration { return s.refreshTTL }

// OAuthStateTTL returns the configured oauth-state-token TTL.
func (s *Service) OAuthStateTTL() time.Duration { return s.oauthStateTTL }

// IssuePair returns signed access + refresh tokens for the user.
func (s *Service) IssuePair(u *domain.User, groupIDs []string, authEpoch int64) (access, refresh string, err error) {
	access, err = s.issue(u, groupIDs, authEpoch, TypeAccess, s.accessTTL)
	if err != nil {
		return "", "", fmt.Errorf("issue access: %w", err)
	}
	refresh, err = s.issue(u, groupIDs, authEpoch, TypeRefresh, s.refreshTTL)
	if err != nil {
		return "", "", fmt.Errorf("issue refresh: %w", err)
	}
	return access, refresh, nil
}

// ParseAccess validates the signature, expiry, and typ=="access".
func (s *Service) ParseAccess(token string) (*Claims, error) {
	return s.parse(token, TypeAccess, "parse access token")
}

// ParseRefresh validates the signature, expiry, and typ=="refresh".
func (s *Service) ParseRefresh(token string) (*Claims, error) {
	return s.parse(token, TypeRefresh, "parse refresh token")
}

// ParseOAuthState validates an OAuth state token.
func (s *Service) ParseOAuthState(token string) (*Claims, error) {
	return s.parse(token, TypeOAuthState, "parse oauth state")
}

// IssueOAuthState issues a short-lived state token for the OAuth flow. The
// redirect path is carried in the Username claim, the login-CSRF nonce in the
// Nonce claim, the PKCE verifier in CodeVerifier, and the provider ID in
// Provider.
func (s *Service) IssueOAuthState(redirectPath, nonce, codeVerifier, provider string) (string, error) {
	claims := s.claims(TypeOAuthState, s.oauthStateTTL)
	claims.Username = redirectPath
	claims.Nonce = nonce
	claims.CodeVerifier = codeVerifier
	claims.Provider = provider
	tok, err := s.sign(claims)
	if err != nil {
		return "", fmt.Errorf("sign oauth state: %w", err)
	}
	return tok, nil
}

func (s *Service) issue(u *domain.User, groupIDs []string, authEpoch int64, typ string, ttl time.Duration) (string, error) {
	claims := s.claims(typ, ttl)
	claims.UserID = u.ID
	claims.Username = u.Username
	claims.Role = string(u.Role)
	claims.GroupIDs = groupIDs
	claims.TokenVersion = u.TokenVersion
	claims.AuthEpoch = authEpoch
	return s.sign(claims)
}

func (s *Service) claims(typ string, ttl time.Duration) *Claims {
	now := s.clock()
	return &Claims{
		Type: typ,
		RegisteredClaims: jwtv5.RegisteredClaims{
			IssuedAt:  jwtv5.NewNumericDate(now),
			ExpiresAt: jwtv5.NewNumericDate(now.Add(ttl)),
		},
	}
}

var signToken = func(claims *Claims, key []byte) (string, error) {
	return jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims).SignedString(key)
}

func (s *Service) sign(claims *Claims) (string, error) {
	return signToken(claims, s.key)
}

func (s *Service) parse(token, wantTyp, label string) (*Claims, error) {
	claims := &Claims{}
	if _, err := jwtv5.ParseWithClaims(token, claims, func(*jwtv5.Token) (interface{}, error) {
		return s.key, nil
	}, jwtv5.WithValidMethods([]string{"HS256"})); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if claims.Type != wantTyp {
		return nil, fmt.Errorf("%s: unexpected token type %q, want %q", label, claims.Type, wantTyp)
	}
	return claims, nil
}
