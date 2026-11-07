// Package domain holds the pure entities, value types, and sentinel errors
// shared across every go-auth package. It imports the standard library only.
package domain

import "errors"

// Sentinel errors matched via errors.Is across all packages.
var (
	ErrUnauthenticated        = errors.New("auth: unauthenticated")
	ErrInvalidCredential      = errors.New("auth: invalid credentials")
	ErrForbidden              = errors.New("auth: forbidden")
	ErrSessionRevoked         = errors.New("auth: session revoked")
	ErrOAuthCredentialExpired = errors.New("auth: oauth credential expired; re-authentication required")
	ErrOAuthNoCredential      = errors.New("auth: no stored oauth credential")
	ErrOAuthNotLeaderRefresh  = errors.New("auth: oauth refresh requires cluster leadership")
	ErrNotFound               = errors.New("auth: not found")
	ErrConflict               = errors.New("auth: resource already exists")
	ErrTokenExists            = errors.New("auth: api token already exists")
	ErrTokenNotRecoverable    = errors.New("auth: api token not recoverable")
	ErrValidation             = errors.New("auth: validation error")
	ErrRateLimited            = errors.New("auth: too many attempts; try again later")
	ErrIPBanned               = errors.New("auth: client IP is temporarily banned")
	ErrOriginNotAllowed       = errors.New("auth: origin not allowed")
	ErrNotLeader              = errors.New("auth: not the cluster leader")
)
