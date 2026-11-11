package goauth

import (
	"errors"
	"testing"

	"github.com/disaster37/go-auth/domain"
)

func TestErrorAliases(t *testing.T) {
	pairs := []struct {
		alias  error
		target error
	}{
		{ErrUnauthenticated, domain.ErrUnauthenticated},
		{ErrInvalidCredential, domain.ErrInvalidCredential},
		{ErrForbidden, domain.ErrForbidden},
		{ErrSessionRevoked, domain.ErrSessionRevoked},
		{ErrOAuthCredentialExpired, domain.ErrOAuthCredentialExpired},
		{ErrOAuthNoCredential, domain.ErrOAuthNoCredential},
		{ErrOAuthNotLeaderRefresh, domain.ErrOAuthNotLeaderRefresh},
		{ErrNotFound, domain.ErrNotFound},
		{ErrConflict, domain.ErrConflict},
		{ErrTokenExists, domain.ErrTokenExists},
		{ErrTokenNotRecoverable, domain.ErrTokenNotRecoverable},
		{ErrValidation, domain.ErrValidation},
		{ErrRateLimited, domain.ErrRateLimited},
		{ErrIPBanned, domain.ErrIPBanned},
		{ErrOriginNotAllowed, domain.ErrOriginNotAllowed},
		{ErrNotLeader, domain.ErrNotLeader},
	}
	for _, p := range pairs {
		if !errors.Is(p.alias, p.target) {
			t.Fatalf("alias %v does not match %v", p.alias, p.target)
		}
	}
}
