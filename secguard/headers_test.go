package secguard

import (
	"errors"
	"net/http"
	"testing"

	"github.com/disaster37/go-auth/domain"
)

func TestDefaultSecurityHeaders(t *testing.T) {
	h := DefaultSecurityHeaders("/api/v1/things", true)
	for _, k := range []string{"X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy", "Cache-Control", "Strict-Transport-Security"} {
		if h[k] == "" {
			t.Fatalf("missing header %s", k)
		}
	}
	h = DefaultSecurityHeaders("/ui", false)
	if h["Cache-Control"] != "" {
		t.Fatal("non-api path must not set Cache-Control")
	}
	if h["Strict-Transport-Security"] != "" {
		t.Fatal("non-TLS must not set HSTS")
	}
}

func TestExtractRequestOrigin(t *testing.T) {
	if got := ExtractRequestOrigin("https://a.com", "https://b.com"); got != "https://a.com" {
		t.Fatalf("origin header: %q", got)
	}
	if got := ExtractRequestOrigin("", "https://b.com/path"); got != "https://b.com" {
		t.Fatalf("referer: %q", got)
	}
	if got := ExtractRequestOrigin("", ""); got != "" {
		t.Fatalf("empty: %q", got)
	}
	if got := ExtractRequestOrigin("", "not-a-url"); got != "" {
		t.Fatalf("bad referer: %q", got)
	}
}

func TestCheckMutationOrigin(t *testing.T) {
	allowed := []string{"https://app.example.com"}
	if err := CheckMutationOrigin(http.MethodGet, "https://evil.com", "", allowed); err != nil {
		t.Fatalf("GET must pass: %v", err)
	}
	if err := CheckMutationOrigin(http.MethodPost, "", "", allowed); err != nil {
		t.Fatalf("no origin must pass: %v", err)
	}
	if err := CheckMutationOrigin(http.MethodPost, "https://app.example.com", "", allowed); err != nil {
		t.Fatalf("allowed origin must pass: %v", err)
	}
	if err := CheckMutationOrigin(http.MethodPost, "https://evil.com", "", allowed); !errors.Is(err, domain.ErrOriginNotAllowed) {
		t.Fatalf("disallowed origin: %v", err)
	}
	if err := CheckMutationOrigin(http.MethodPost, "https://evil.com", "", nil); err != nil {
		t.Fatalf("empty allowlist must pass: %v", err)
	}
	if err := CheckMutationOrigin(http.MethodPost, "https://evil.com", "", []string{"*"}); err != nil {
		t.Fatalf("wildcard must pass: %v", err)
	}
}
