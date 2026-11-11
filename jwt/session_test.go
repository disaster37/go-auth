package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/disaster37/go-auth/domain"
)

func TestDeriveSigningKey(t *testing.T) {
	k1, err := DeriveSigningKey("secret", "info")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	k2, _ := DeriveSigningKey("secret", "info")
	if k1 != k2 {
		t.Fatal("derivation must be deterministic")
	}
	k3, _ := DeriveSigningKey("secret", "")
	if k1 == k3 {
		t.Fatal("empty info must default to SessionHKDFInfo, differing from custom info")
	}
}

func TestValidateSecret(t *testing.T) {
	if err := ValidateSecret(""); err != nil {
		t.Fatalf("empty allowed: %v", err)
	}
	if err := ValidateSecret("short"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short: %v", err)
	}
	if err := ValidateSecret("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("valid: %v", err)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	key, _ := DeriveSigningKey("secret", "")
	tok := &SessionToken{UserID: "u1", Username: "alice", Method: "internal", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	encoded, err := EncodeSession(tok, key)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeSession(encoded, key, time.Now())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.UserID != "u1" || decoded.Username != "alice" {
		t.Fatalf("unexpected decoded: %+v", decoded)
	}
}

func TestDecodeSessionErrors(t *testing.T) {
	key, _ := DeriveSigningKey("secret", "")
	otherKey, _ := DeriveSigningKey("other", "")
	tok := &SessionToken{UserID: "u1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	encoded, _ := EncodeSession(tok, key)

	if _, err := DecodeSession("no-dot", key, time.Now()); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("no dot: %v", err)
	}
	if _, err := DecodeSession(encoded, otherKey, time.Now()); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("wrong key: %v", err)
	}
	expired := &SessionToken{UserID: "u1", ExpiresAt: time.Now().Add(-time.Hour).Unix()}
	encExpired, _ := EncodeSession(expired, key)
	if _, err := DecodeSession(encExpired, key, time.Now()); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("expired: %v", err)
	}
}

func TestGenerateRandomHex(t *testing.T) {
	a, err := GenerateRandomHex()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, _ := GenerateRandomHex()
	if a == b || len(a) != 32 {
		t.Fatalf("unexpected random hex %q %q", a, b)
	}
}

func signPayload(payload string, key [32]byte) string {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(payload))
	return fmt.Sprintf("%s.%s", payload, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
}

func TestDecodeSessionMalformedPayload(t *testing.T) {
	key, _ := DeriveSigningKey("secret", "")
	// Valid signature over a non-base64 payload.
	if _, err := DecodeSession(signPayload("!!!", key), key, time.Now()); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("bad base64: %v", err)
	}
	// Valid signature over base64 of invalid JSON.
	payload := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	if _, err := DecodeSession(signPayload(payload, key), key, time.Now()); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("bad json: %v", err)
	}
}

func TestParseAccessWrongKey(t *testing.T) {
	s := newTestService(t)
	other, _ := NewService(Config{Secret: []byte("abcdef0123456789abcdef0123456789")})
	u := &domain.User{ID: "u1", Username: "alice", Role: domain.RoleUser}
	access, _, _ := other.IssuePair(u, nil, 0)
	if _, err := s.ParseAccess(access); err == nil {
		t.Fatal("token signed with another key must not parse")
	}
}

func TestDeriveSigningKeyError(t *testing.T) {
	orig := deriveHKDF
	deriveHKDF = func([]byte, string) ([]byte, error) { return nil, errors.New("hkdf failed") }
	t.Cleanup(func() { deriveHKDF = orig })
	if _, err := DeriveSigningKey("secret", "info"); err == nil {
		t.Fatal("expected derivation error")
	}
	if _, err := NewService(Config{Secret: []byte("0123456789abcdef0123456789abcdef"), UseHKDF: true}); err == nil {
		t.Fatal("expected service derivation error")
	}
}

func TestEncodeSessionMarshalError(t *testing.T) {
	orig := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	t.Cleanup(func() { jsonMarshal = orig })
	key, _ := DeriveSigningKey("secret", "")
	if _, err := EncodeSession(&SessionToken{}, key); err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestGenerateRandomHexError(t *testing.T) {
	orig := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("rand failed") }
	t.Cleanup(func() { randRead = orig })
	if _, err := GenerateRandomHex(); err == nil {
		t.Fatal("expected random error")
	}
}
