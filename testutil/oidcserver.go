package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// MockOIDCServer is an in-process OIDC provider signing RS256 ID tokens with a
// generated RSA key and serving discovery, JWKS, token, and userinfo endpoints.
type MockOIDCServer struct {
	Server *httptest.Server

	mu  sync.Mutex
	key *rsa.PrivateKey
	kid string

	// Configurable identity claims.
	ClientID      string
	Subject       string
	Username      string
	Email         string
	EmailVerified bool
	Groups        []string
	Nonce         string
	Audience      []string
	AZP           string

	// Behavior overrides.
	TokenStatus       int
	UserinfoStatus    int
	UserinfoFailOnce  bool
	OversizedBody     bool
	OmitIDToken       bool
	OmitEmailVerified bool
	AccessToken       string
	RefreshToken      string

	// ExtraUserinfoClaims are merged into the userinfo response only.
	ExtraUserinfoClaims map[string]any

	// Counters.
	TokenRequests    int
	UserinfoRequests int
}

// NewMockOIDCServer starts a mock OIDC provider and registers its shutdown with
// t.Cleanup.
func NewMockOIDCServer(t testing.TB) *MockOIDCServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	m := &MockOIDCServer{
		key:           key,
		kid:           "test-key",
		ClientID:      "test-client",
		Subject:       "user-123",
		Username:      "alice",
		Email:         "alice@example.com",
		EmailVerified: true,
		Groups:        []string{"dev"},
		AccessToken:   "access-token",
		RefreshToken:  "refresh-token",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks", m.handleJWKS)
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/userinfo", m.handleUserinfo)
	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Server.Close)
	return m
}

// Issuer returns the mock provider's issuer URL.
func (m *MockOIDCServer) Issuer() string { return m.Server.URL }

// IDToken returns a signed RS256 ID token reflecting the current claims.
func (m *MockOIDCServer) IDToken() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	claims := jwtv5.MapClaims{
		"iss":                m.Server.URL,
		"sub":                m.Subject,
		"aud":                m.audienceLocked(),
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
		"preferred_username": m.Username,
		"email":              m.Email,
		"groups":             m.Groups,
	}
	if !m.OmitEmailVerified {
		claims["email_verified"] = m.EmailVerified
	}
	if m.Nonce != "" {
		claims["nonce"] = m.Nonce
	}
	if m.AZP != "" {
		claims["azp"] = m.AZP
	}
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
	tok.Header["kid"] = m.kid
	return tok.SignedString(m.key)
}

func (m *MockOIDCServer) audienceLocked() []string {
	if len(m.Audience) > 0 {
		return m.Audience
	}
	return []string{m.ClientID}
}

func (m *MockOIDCServer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                m.Server.URL,
		"authorization_endpoint":                fmt.Sprintf("%s/authorize", m.Server.URL),
		"token_endpoint":                        fmt.Sprintf("%s/token", m.Server.URL),
		"userinfo_endpoint":                     fmt.Sprintf("%s/userinfo", m.Server.URL),
		"jwks_uri":                              fmt.Sprintf("%s/jwks", m.Server.URL),
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (m *MockOIDCServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pub := m.key.PublicKey
	writeJSON(w, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": m.kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (m *MockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.TokenRequests++
	status := m.TokenStatus
	access := m.AccessToken
	refresh := m.RefreshToken
	omitIDToken := m.OmitIDToken
	m.mu.Unlock()

	if status != 0 {
		http.Error(w, `{"error":"invalid_grant"}`, status)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	body := map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"refresh_token": refresh,
		"expires_in":    3600,
	}
	if !omitIDToken {
		idToken, err := m.IDToken()
		if err != nil {
			http.Error(w, "sign id token", http.StatusInternalServerError)
			return
		}
		body["id_token"] = idToken
	}
	writeJSON(w, body)
}

func (m *MockOIDCServer) handleUserinfo(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	m.UserinfoRequests++
	status := m.UserinfoStatus
	if m.UserinfoFailOnce {
		m.UserinfoFailOnce = false
		status = http.StatusUnauthorized
	}
	oversized := m.OversizedBody
	claims := map[string]any{
		"sub":                m.Subject,
		"preferred_username": m.Username,
		"email":              m.Email,
		"email_verified":     m.EmailVerified,
		"groups":             m.Groups,
	}
	for k, v := range m.ExtraUserinfoClaims {
		claims[k] = v
	}
	m.mu.Unlock()

	if status != 0 {
		http.Error(w, `{"error":"invalid_token"}`, status)
		return
	}
	if oversized {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"sub":"%s"}`, strings.Repeat("a", 2<<20))
		return
	}
	writeJSON(w, claims)
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}
