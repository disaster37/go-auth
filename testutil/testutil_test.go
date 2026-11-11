package testutil

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestFakeClock(t *testing.T) {
	start := time.Unix(1000, 0)
	c := NewFakeClock(start)
	if !c.Now().Equal(start) {
		t.Fatalf("now=%v", c.Now())
	}
	c.Advance(time.Minute)
	if !c.Now().Equal(start.Add(time.Minute)) {
		t.Fatalf("after advance=%v", c.Now())
	}
}

func TestFreeListener(t *testing.T) {
	l := FreeListener(t)
	defer func() { _ = l.Close() }()
	if l.Addr() == nil {
		t.Fatal("expected listener address")
	}
}

func TestMockOIDCServer(t *testing.T) {
	m := NewMockOIDCServer(t)
	if m.Issuer() == "" {
		t.Fatal("expected issuer")
	}

	// Discovery.
	resp, err := http.Get(m.Issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var disc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if disc["issuer"] != m.Issuer() {
		t.Fatalf("issuer mismatch: %v", disc["issuer"])
	}

	// JWKS.
	resp, err = http.Get(m.Issuer() + "/jwks")
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var jwks map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if _, ok := jwks["keys"]; !ok {
		t.Fatal("missing keys")
	}

	// Token endpoint.
	resp, err = http.Post(m.Issuer()+"/token", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tok map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if tok["id_token"] == nil || tok["access_token"] != "access-token" {
		t.Fatalf("token response: %v", tok)
	}
	if m.TokenRequests != 1 {
		t.Fatalf("token requests=%d", m.TokenRequests)
	}

	// Userinfo.
	resp, err = http.Get(m.Issuer() + "/userinfo")
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var ui map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&ui); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if ui["sub"] != m.Subject {
		t.Fatalf("userinfo sub=%v", ui["sub"])
	}

	// IDToken.
	idToken, err := m.IDToken()
	if err != nil || idToken == "" {
		t.Fatalf("id token: %v", err)
	}
}

func TestMockOIDCServerOverrides(t *testing.T) {
	m := NewMockOIDCServer(t)
	m.TokenStatus = http.StatusBadRequest
	resp, err := http.Post(m.Issuer()+"/token", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	m.UserinfoStatus = http.StatusUnauthorized
	resp, err = http.Get(m.Issuer() + "/userinfo")
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo status=%d", resp.StatusCode)
	}

	m.UserinfoStatus = 0
	m.OversizedBody = true
	resp, err = http.Get(m.Issuer() + "/userinfo")
	if err != nil {
		t.Fatalf("oversized: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if len(body) < 1<<20 {
		t.Fatalf("expected oversized body, got %d bytes", len(body))
	}
}

func TestMockOIDCServerAudienceDefault(t *testing.T) {
	m := NewMockOIDCServer(t)
	tok, err := m.IDToken()
	if err != nil || tok == "" {
		t.Fatalf("id token: %v", err)
	}
	m.Audience = []string{"a", "b"}
	tok, err = m.IDToken()
	if err != nil || tok == "" {
		t.Fatalf("multi-audience id token: %v", err)
	}
}

func TestMockOIDCServerTokenFormError(t *testing.T) {
	m := NewMockOIDCServer(t)
	resp, err := http.Post(m.Issuer()+"/token", "application/x-www-form-urlencoded", strings.NewReader("%zz"))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestMockOIDCServerOmitIDToken(t *testing.T) {
	m := NewMockOIDCServer(t)
	m.OmitIDToken = true
	resp, err := http.Post(m.Issuer()+"/token", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tok map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := tok["id_token"]; ok {
		t.Fatal("id_token must be omitted")
	}
}
