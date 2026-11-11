package domain

import "fmt"

// Role is a coarse authorization role.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// ParseRole validates and returns a Role.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleAdmin:
		return RoleAdmin, nil
	case RoleUser:
		return RoleUser, nil
	default:
		return "", fmt.Errorf("%w: unknown role %q", ErrValidation, s)
	}
}

// AuthMethod identifies how a principal was authenticated.
type AuthMethod string

const (
	AuthMethodJWT         AuthMethod = "jwt"
	AuthMethodSession     AuthMethod = "session"
	AuthMethodAPIToken    AuthMethod = "api_token"
	AuthMethodLegacyToken AuthMethod = "legacy_token"
	AuthMethodOIDC        AuthMethod = "oidc"
	AuthMethodInternal    AuthMethod = "internal"
)

// Identity is the resolved principal handed to the consuming application.
type Identity struct {
	UserID    string     `json:"user_id"`
	Username  string     `json:"username"`
	Role      Role       `json:"role"`
	GroupIDs  []string   `json:"group_ids,omitempty"`
	Method    AuthMethod `json:"method"`
	Provider  string     `json:"provider,omitempty"`
	Issuer    string     `json:"issuer,omitempty"`
	Subject   string     `json:"subject,omitempty"`
	SessionID string     `json:"session_id,omitempty"`
}

// IsAdmin reports whether the identity carries the admin role.
func (i *Identity) IsAdmin() bool {
	return i != nil && i.Role == RoleAdmin
}

// HasGroup reports whether the identity is a member of groupID.
func (i *Identity) HasGroup(groupID string) bool {
	if i == nil {
		return false
	}
	for _, g := range i.GroupIDs {
		if g == groupID {
			return true
		}
	}
	return false
}
