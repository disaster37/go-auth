package jwt

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/disaster37/go-auth/domain"
)

// SessionToken is the lightweight HMAC-SHA256 session token (gohookbridge
// compatible). UserID/Issuer/Subject bind the session to a resolved principal;
// Username is display-only and must never be used for authorization decisions.
type SessionToken struct {
	UserID       string   `json:"user_id,omitempty"`
	Username     string   `json:"username,omitempty"`
	Role         string   `json:"role,omitempty"`
	Method       string   `json:"method"` // "internal" | "oidc"
	Provider     string   `json:"provider,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	ExpiresAt    int64    `json:"expires_at"`
	Groups       []string `json:"groups,omitempty"`
	SessionID    string   `json:"sid,omitempty"`
	TokenVersion int      `json:"token_version,omitempty"`
	AuthEpoch    int64    `json:"auth_epoch,omitempty"`
}

// DeriveSigningKey derives a 32-byte HMAC-SHA256 signing key from secret using
// HKDF-SHA256 with the given domain-separation info string (defaulting to
// SessionHKDFInfo when empty).
func DeriveSigningKey(secret string, info string) ([32]byte, error) {
	var key [32]byte
	if info == "" {
		info = SessionHKDFInfo
	}
	derived, err := deriveHKDF([]byte(secret), info)
	if err != nil {
		return key, fmt.Errorf("derive session signing key: %w", err)
	}
	copy(key[:], derived)
	return key, nil
}

var deriveHKDF = func(secret []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, info, 32)
}

// ValidateSecret rejects weak session secrets (CWE-326). An empty secret is
// allowed (the caller auto-generates one); otherwise it must be at least
// MinSecretLength characters.
func ValidateSecret(secret string) error {
	if secret == "" {
		return nil
	}
	if len(secret) < MinSecretLength {
		return fmt.Errorf("session secret must be at least %d characters (got %d): %w", MinSecretLength, len(secret), domain.ErrValidation)
	}
	return nil
}

var jsonMarshal = json.Marshal

// EncodeSession signs and encodes a session token as
// base64url(payload).base64url(hmac).
func EncodeSession(token *SessionToken, key [32]byte) (string, error) {
	data, err := jsonMarshal(token)
	if err != nil {
		return "", fmt.Errorf("marshal session token: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", encoded, sig), nil
}

// DecodeSession verifies and decodes a session token, rejecting tokens whose
// ExpiresAt is before now.
func DecodeSession(tokenStr string, key [32]byte, now time.Time) (*SessionToken, error) {
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format: %w", domain.ErrUnauthenticated)
	}
	encoded, sigB64 := parts[0], parts[1]

	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(encoded))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sigB64), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid token signature: %w", domain.ErrUnauthenticated)
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode session token: %w", domain.ErrUnauthenticated)
	}
	var token SessionToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("unmarshal session token: %w", domain.ErrUnauthenticated)
	}
	if token.ExpiresAt < now.Unix() {
		return nil, fmt.Errorf("token expired: %w", domain.ErrSessionRevoked)
	}
	return &token, nil
}

var randRead = rand.Read

// GenerateRandomHex returns a random 16-byte value encoded as 32 hex chars.
func GenerateRandomHex() (string, error) {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("generate random hex: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}
