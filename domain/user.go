package domain

import "time"

// User is a stored account. PasswordHash and OAuthTokenCiphertext are never
// serialized (CWE-532).
type User struct {
	ID                   string     `json:"id"`
	Username             string     `json:"username"`
	Role                 Role       `json:"role"`
	PasswordHash         string     `json:"-"`
	OAuthProvider        string     `json:"oauth_provider,omitempty"`
	OAuthIssuer          string     `json:"oauth_issuer,omitempty"`
	OAuthID              string     `json:"oauth_id,omitempty"`
	OAuthTokenCiphertext string     `json:"-"`
	OAuthGroupIDs        []string   `json:"oauth_group_ids,omitempty"`
	OAuthGroups          []string   `json:"oauth_groups,omitempty"`
	OAuthAdmin           bool       `json:"oauth_admin,omitempty"`
	DeactivatedAt        *time.Time `json:"deactivated_at,omitempty"`
	TokenVersion         int        `json:"token_version"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// Deactivated reports whether the account has been deactivated.
func (u *User) Deactivated() bool {
	return u != nil && u.DeactivatedAt != nil
}

// Group is a stored group record.
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
