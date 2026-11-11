package nethttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sgbantracker "github.com/disaster37/go-secguard/bantracker"
	sgdomain "github.com/disaster37/go-secguard/domain"
)

func TestMutationOriginMiddlewareRejectsDisallowedOrigin(t *testing.T) {
	handler := MutationOriginMiddleware([]string{"https://app.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestMutationOriginMiddlewareLowercaseMethod(t *testing.T) {
	handler := MutationOriginMiddleware([]string{"https://app.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("post", "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed lowercase method status=%d", rec.Code)
	}

	req = httptest.NewRequest("post", "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed lowercase method status=%d", rec.Code)
	}
}

func TestBanCheckMiddlewareParity(t *testing.T) {
	tracker := sgbantracker.New(10, nil)
	tracker.RecordAndBan("203.0.113.5", "fp", 1, time.Minute, time.Minute)
	handler := BanCheckMiddleware(tracker, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned status=%d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "bad:addr:extra"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("malformed remote addr status=%d", rec.Code)
	}
}

func TestStatusCodeForSecguardErrors(t *testing.T) {
	tests := []struct {
		err    error
		status int
	}{
		{sgdomain.ErrValidation, http.StatusBadRequest},
		{sgdomain.ErrInvalidIP, http.StatusBadRequest},
		{sgdomain.ErrInvalidCIDR, http.StatusBadRequest},
		{sgdomain.ErrOriginNotAllowed, http.StatusForbidden},
		{sgdomain.ErrIPBanned, http.StatusForbidden},
		{sgdomain.ErrRateLimited, http.StatusTooManyRequests},
		{sgdomain.ErrAccountLocked, http.StatusTooManyRequests},
	}
	for _, tt := range tests {
		status, _ := StatusCodeForError(tt.err)
		if status != tt.status {
			t.Fatalf("StatusCodeForError(%v)=%d want %d", tt.err, status, tt.status)
		}
	}
}

func TestSecurityHeadersMiddlewareAPIPath(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api", nil))
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q", got)
	}
}
