package secguard

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/disaster37/go-auth/domain"
)

// DefaultSecurityHeaders returns the browser hardening headers for a response
// (CWE-693). Cache-Control is set for API paths; HSTS is set only over TLS.
func DefaultSecurityHeaders(path string, isTLS bool) map[string]string {
	headers := map[string]string{
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "frame-ancestors 'none'",
	}
	if strings.HasPrefix(path, "/api/") {
		headers["Cache-Control"] = "no-store"
	}
	if isTLS {
		headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
	}
	return headers
}

// ExtractRequestOrigin returns the request's Origin header, or the origin
// derived from the Referer header when Origin is absent.
func ExtractRequestOrigin(originHeader, refererHeader string) string {
	if originHeader != "" {
		return originHeader
	}
	if refererHeader == "" {
		return ""
	}
	u, err := url.Parse(refererHeader)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}

// CheckMutationOrigin rejects cross-origin mutating browser requests by
// validating the Origin (falling back to the Referer origin) against the
// allowed origins (CWE-352). Requests without either header (non-browser
// clients) pass through. An empty allowlist or "*" allows any origin.
func CheckMutationOrigin(method, originHeader, refererHeader string, allowedOrigins []string) error {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return nil
	}
	origin := ExtractRequestOrigin(originHeader, refererHeader)
	if origin == "" {
		return nil
	}
	if len(allowedOrigins) == 0 {
		return nil
	}
	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return nil
		}
	}
	return domain.ErrOriginNotAllowed
}
