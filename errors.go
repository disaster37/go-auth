package goauth

import "github.com/disaster37/go-auth/domain"

// Sentinel errors re-exported from domain for ergonomic top-level usage.
var (
	ErrUnauthenticated        = domain.ErrUnauthenticated
	ErrInvalidCredential      = domain.ErrInvalidCredential
	ErrForbidden              = domain.ErrForbidden
	ErrSessionRevoked         = domain.ErrSessionRevoked
	ErrOAuthCredentialExpired = domain.ErrOAuthCredentialExpired
	ErrOAuthNoCredential      = domain.ErrOAuthNoCredential
	ErrOAuthNotLeaderRefresh  = domain.ErrOAuthNotLeaderRefresh
	ErrNotFound               = domain.ErrNotFound
	ErrConflict               = domain.ErrConflict
	ErrTokenExists            = domain.ErrTokenExists
	ErrTokenNotRecoverable    = domain.ErrTokenNotRecoverable
	ErrValidation             = domain.ErrValidation
	ErrRateLimited            = domain.ErrRateLimited
	ErrIPBanned               = domain.ErrIPBanned
	ErrOriginNotAllowed       = domain.ErrOriginNotAllowed
	ErrNotLeader              = domain.ErrNotLeader
)
