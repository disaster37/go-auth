package crypto

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	k1, err := DeriveKey(secret, "info-a")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	k2, _ := DeriveKey(secret, "info-a")
	if k1 != k2 {
		t.Fatal("derivation must be deterministic")
	}
	k3, _ := DeriveKey(secret, "info-b")
	if k1 == k3 {
		t.Fatal("different info must yield different keys")
	}
	if _, err := DeriveKey([]byte("short"), "x"); !errors.Is(err, ErrSecretTooShort) {
		t.Fatalf("short secret: %v", err)
	}
	// Empty info defaults to DefaultHKDFInfo.
	if _, err := DeriveKey(secret, ""); err != nil {
		t.Fatalf("empty info: %v", err)
	}
}

func TestAESGCMSealerRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s, err := NewAESGCMSealer(key, []byte("aad"))
	if err != nil {
		t.Fatalf("new sealer: %v", err)
	}
	sealed, err := s.SealString("hello world")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !strings.Contains(sealed, `"alg":"A256GCM"`) {
		t.Fatalf("expected JSON envelope, got %s", sealed)
	}
	opened, err := s.OpenString(sealed)
	if err != nil || opened != "hello world" {
		t.Fatalf("open: %q %v", opened, err)
	}
	if got, _ := s.OpenString(""); got != "" {
		t.Fatalf("empty open=%q", got)
	}
}

func TestAESGCMSealerRawBase64Compat(t *testing.T) {
	key := make([]byte, 32)
	s, _ := NewAESGCMSealer(key, nil)
	raw, err := s.SealBytes([]byte("raw-value"))
	if err != nil {
		t.Fatalf("seal bytes: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	opened, err := s.OpenString(encoded)
	if err != nil || opened != "raw-value" {
		t.Fatalf("open raw: %q %v", opened, err)
	}
}

func TestAESGCMSealerErrors(t *testing.T) {
	if _, err := NewAESGCMSealer([]byte("short"), nil); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("short key: %v", err)
	}
	key := make([]byte, 32)
	s, _ := NewAESGCMSealer(key, nil)
	if _, err := s.OpenBytes([]byte("x")); !errors.Is(err, ErrCiphertextShort) {
		t.Fatalf("short ciphertext: %v", err)
	}
	if _, err := s.OpenString("not-base64!!!"); err == nil {
		t.Fatal("expected decode error")
	}
	// Wrong AAD fails to open the raw format.
	s2, _ := NewAESGCMSealer(key, []byte("other"))
	raw, _ := s.SealBytes([]byte("secret"))
	if _, err := s2.OpenBytes(raw); err == nil {
		t.Fatal("expected AAD mismatch error")
	}
	// Unsupported envelope.
	if _, err := s.OpenString(`{"alg":"BAD","ver":9,"ct":"x"}`); err == nil {
		t.Fatal("expected unsupported envelope error")
	}
}

func TestNewDerivedSealer(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	s, err := NewDerivedSealer(secret, "info", nil)
	if err != nil {
		t.Fatalf("derived sealer: %v", err)
	}
	sealed, _ := s.SealString("v")
	got, err := s.OpenString(sealed)
	if err != nil || got != "v" {
		t.Fatalf("roundtrip: %q %v", got, err)
	}
	if _, err := NewDerivedSealer([]byte("short"), "info", nil); !errors.Is(err, ErrSecretTooShort) {
		t.Fatalf("short secret: %v", err)
	}
}

func TestOpenEnvelopeErrors(t *testing.T) {
	key := make([]byte, 32)
	s, _ := NewAESGCMSealer(key, nil)
	sealed, err := s.SealString("value")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Wrong key cannot decrypt a valid envelope.
	other, _ := NewAESGCMSealer(bytes.Repeat([]byte{1}, 32), nil)
	if _, err := other.OpenString(sealed); err == nil {
		t.Fatal("wrong key must fail")
	}

	cases := []string{
		`{"alg":"A256GCM","ver":1,"non":"!!!","ct":"x"}`,
		`{"alg":"A256GCM","ver":1,"non":"eA==","ct":"!!!"}`,
		`{"alg":"A256GCM","ver":1,"non":"eA==","ct":"eA==","ctx":"!!!"}`,
		`{"ct":"eA=="}`,
	}
	for _, c := range cases {
		if _, err := s.OpenString(c); err == nil {
			t.Fatalf("expected error for %s", c)
		}
	}
}

func TestSealBytesRoundTrip(t *testing.T) {
	s, _ := NewAESGCMSealer(make([]byte, 32), []byte("ctx"))
	sealed, err := s.SealBytes([]byte("payload"))
	if err != nil {
		t.Fatalf("seal bytes: %v", err)
	}
	plain, err := s.OpenBytes(sealed)
	if err != nil || string(plain) != "payload" {
		t.Fatalf("open bytes: %q %v", plain, err)
	}
}

func TestInvalidInternalKey(t *testing.T) {
	bad := &AESGCMSealer{key: []byte("short")}
	if _, err := bad.SealBytes([]byte("x")); err == nil {
		t.Fatal("SealBytes must fail with an invalid key")
	}
	if _, err := bad.SealString("x"); err == nil {
		t.Fatal("SealString must fail with an invalid key")
	}
	if _, err := bad.OpenBytes(make([]byte, 12)); err == nil {
		t.Fatal("OpenBytes must fail with an invalid key")
	}
	valid, _ := NewAESGCMSealer(make([]byte, 32), nil)
	sealed, _ := valid.SealString("x")
	if _, err := bad.OpenString(sealed); err == nil {
		t.Fatal("OpenString must fail with an invalid key")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

func TestSealerInjectedErrors(t *testing.T) {
	s, _ := NewAESGCMSealer(make([]byte, 32), nil)

	origRand := randRead
	randRead = errReader{}
	if _, err := s.SealBytes([]byte("x")); err == nil {
		t.Fatal("SealBytes must fail when the nonce source fails")
	}
	if _, err := s.SealString("x"); err == nil {
		t.Fatal("SealString must fail when the nonce source fails")
	}
	randRead = origRand

	origMarshal := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	if _, err := s.SealString("x"); err == nil {
		t.Fatal("SealString must fail when marshaling fails")
	}
	jsonMarshal = origMarshal

	origHKDF := deriveHKDF
	deriveHKDF = func([]byte, string) ([]byte, error) { return nil, errors.New("hkdf failed") }
	if _, err := DeriveKey([]byte("0123456789abcdef"), "info"); err == nil {
		t.Fatal("DeriveKey must fail when HKDF fails")
	}
	deriveHKDF = origHKDF

	sealed, _ := s.SealString("x")
	origGCM := newGCM
	newGCM = func(cipher.Block) (cipher.AEAD, error) { return nil, errors.New("gcm failed") }
	if _, err := s.SealBytes([]byte("x")); err == nil {
		t.Fatal("SealBytes must fail when GCM creation fails")
	}
	if _, err := s.SealString("x"); err == nil {
		t.Fatal("SealString must fail when GCM creation fails")
	}
	if _, err := s.OpenBytes(make([]byte, 12)); err == nil {
		t.Fatal("OpenBytes must fail when GCM creation fails")
	}
	if _, err := s.OpenString(sealed); err == nil {
		t.Fatal("OpenString must fail when GCM creation fails")
	}
	newGCM = origGCM
}
