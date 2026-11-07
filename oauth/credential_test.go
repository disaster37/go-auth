package oauth

import (
	"testing"
	"time"

	"github.com/disaster37/go-auth/crypto"
)

func testSealer(t *testing.T) crypto.Sealer {
	t.Helper()
	s, err := crypto.NewAESGCMSealer(make([]byte, 32), nil)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

func TestCredentialRoundTrip(t *testing.T) {
	sealer := testSealer(t)
	cred := &Credential{Provider: "oidc", AccessToken: "at", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour)}
	sealed, err := SealCredential(sealer, cred)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := OpenCredential(sealer, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened.AccessToken != "at" || opened.RefreshToken != "rt" || opened.Provider != "oidc" {
		t.Fatalf("opened=%+v", opened)
	}
}

func TestCredentialEdgeCases(t *testing.T) {
	sealer := testSealer(t)
	if got, err := SealCredential(nil, &Credential{}); err != nil || got != "" {
		t.Fatalf("nil sealer seal: %q %v", got, err)
	}
	if got, err := SealCredential(sealer, nil); err != nil || got != "" {
		t.Fatalf("nil credential seal: %q %v", got, err)
	}
	if got, err := OpenCredential(sealer, ""); err != nil || got != nil {
		t.Fatalf("empty open: %v %v", got, err)
	}
	if _, err := OpenCredential(nil, "ciphertext"); err == nil {
		t.Fatal("nil sealer open must error")
	}
	if _, err := OpenCredential(sealer, "not-valid"); err == nil {
		t.Fatal("invalid ciphertext must error")
	}
}
