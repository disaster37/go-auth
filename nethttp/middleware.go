// Package nethttp is an optional net/http adapter providing middleware and
// handlers without pulling any external router.
package nethttp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	goauth "github.com/disaster37/go-auth"
	"github.com/disaster37/go-auth/domain"
	"github.com/disaster37/go-auth/httpcookie"
	"github.com/disaster37/go-auth/secguard"
)

type contextKey struct{}

var identityKey contextKey

// IdentityFromContext returns the Identity stored by RequireAuth, or nil.
func IdentityFromContext(ctx context.Context) *domain.Identity {
	id, _ := ctx.Value(identityKey).(*domain.Identity)
	return id
}

// ContextWithIdentity stores id in ctx.
func ContextWithIdentity(ctx context.Context, id *domain.Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// ExtractBearer returns the bearer credential from the Authorization header,
// the access cookie, or (when allowQueryToken) the "token" query parameter.
func ExtractBearer(r *http.Request, accessCookieName string, allowQueryToken bool) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if accessCookieName != "" {
		if c, err := r.Cookie(accessCookieName); err == nil && c.Value != "" {
			return c.Value
		}
	}
	if allowQueryToken {
		if t := r.URL.Query().Get("token"); t != "" {
			return t
		}
	}
	return ""
}

// RequireAuth resolves the request credential and stores the Identity in the
// request context, rejecting unauthenticated requests.
func RequireAuth(svc *goauth.Service, cookieCfg httpcookie.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer := ExtractBearer(r, cookieCfg.AccessName, false)
			id, err := svc.Resolve(r.Context(), bearer)
			if err != nil {
				WriteError(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithIdentity(r.Context(), id)))
		})
	}
}

// RequireAdmin requires an authenticated admin identity.
func RequireAdmin(svc *goauth.Service, cookieCfg httpcookie.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer := ExtractBearer(r, cookieCfg.AccessName, false)
			id, err := svc.Resolve(r.Context(), bearer)
			if err != nil {
				WriteError(w, err)
				return
			}
			if !id.IsAdmin() {
				WriteError(w, domain.ErrForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithIdentity(r.Context(), id)))
		})
	}
}

// SecurityHeadersMiddleware applies browser hardening headers.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range secguard.DefaultSecurityHeaders(r.URL.Path, r.TLS != nil) {
			w.Header().Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}

// MutationOriginMiddleware rejects cross-origin mutating browser requests.
func MutationOriginMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := secguard.CheckMutationOrigin(r.Method, r.Header.Get("Origin"), r.Header.Get("Referer"), allowedOrigins); err != nil {
				WriteError(w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BanCheckMiddleware rejects requests from banned client IPs.
func BanCheckMiddleware(tracker *secguard.BanTracker, behindProxy bool, trustedCIDRs []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, err := secguard.GetRealIPFromRequest(r, behindProxy, trustedCIDRs)
			if err != nil {
				WriteError(w, domain.ErrUnauthenticated)
				return
			}
			if tracker.IsBanned(ip.String()) {
				WriteError(w, domain.ErrIPBanned)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WriteError maps an error to an HTTP status and writes a JSON error body.
func WriteError(w http.ResponseWriter, err error) {
	status, message := StatusCodeForError(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// StatusCodeForError maps an error to an HTTP status code and client message.
func StatusCodeForError(err error) (int, string) {
	switch {
	case errors.Is(err, domain.ErrValidation):
		return http.StatusBadRequest, "validation error"
	case errors.Is(err, domain.ErrUnauthenticated),
		errors.Is(err, domain.ErrInvalidCredential),
		errors.Is(err, domain.ErrSessionRevoked),
		errors.Is(err, domain.ErrOAuthCredentialExpired):
		return http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, domain.ErrForbidden),
		errors.Is(err, domain.ErrOriginNotAllowed),
		errors.Is(err, domain.ErrIPBanned):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, domain.ErrNotFound),
		errors.Is(err, domain.ErrTokenNotRecoverable):
		return http.StatusNotFound, "not found"
	case errors.Is(err, domain.ErrConflict),
		errors.Is(err, domain.ErrTokenExists):
		return http.StatusConflict, "conflict"
	case errors.Is(err, domain.ErrRateLimited):
		return http.StatusTooManyRequests, "too many requests"
	case errors.Is(err, domain.ErrNotLeader):
		return http.StatusServiceUnavailable, "service unavailable"
	default:
		return http.StatusInternalServerError, "internal error"
	}
}
