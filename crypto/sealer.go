// Package crypto provides at-rest encryption compatible with
// github.com/disaster37/raft/storage.Sealer and the AES-256-GCM envelopes used
// by dagger-kubernetes and gohookbridge.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// DefaultHKDFInfo is the default domain-separation info string for
	// HKDF-SHA256 key derivation.
	DefaultHKDFInfo = "go-auth-at-rest-aes-256-gcm-v1"
	// MinSecretLength is the minimum input secret length (in bytes) for HKDF
	// derivation.
	MinSecretLength = 16
	// AES256KeySize is the required AES-256 key length in bytes.
	AES256KeySize = 32
)

var (
	// ErrSecretTooShort is returned when an HKDF input secret is shorter than
	// MinSecretLength.
	ErrSecretTooShort = errors.New("crypto: secret must be at least 16 bytes")
	// ErrInvalidKeySize is returned when an AES key is not 32 bytes.
	ErrInvalidKeySize = errors.New("crypto: AES key must be 32 bytes")
	// ErrCiphertextShort is returned when a sealed value is too short to hold a
	// nonce.
	ErrCiphertextShort = errors.New("crypto: ciphertext too short")
)

// Sealer is the minimal interface for sealing/opening strings at rest. Any
// *github.com/disaster37/raft/storage.AESGCMKeeper satisfies this interface
// directly without an adapter.
type Sealer interface {
	SealString(plain string) (string, error)
	OpenString(stored string) (string, error)
}

// DeriveKey derives a 32-byte key from secret using RFC 5869 HKDF-SHA256 with
// the given domain-separation info string (defaulting to DefaultHKDFInfo when
// empty).
func DeriveKey(secret []byte, info string) ([32]byte, error) {
	var key [32]byte
	if len(secret) < MinSecretLength {
		return key, fmt.Errorf("%w (got %d)", ErrSecretTooShort, len(secret))
	}
	if info == "" {
		info = DefaultHKDFInfo
	}
	derived, err := deriveHKDF(secret, info)
	if err != nil {
		return key, fmt.Errorf("derive AES-256 key via HKDF: %w", err)
	}
	copy(key[:], derived)
	return key, nil
}

var deriveHKDF = func(secret []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, info, AES256KeySize)
}

// encryptedValue is the JSON envelope of one at-rest encrypted value. It is
// wire-compatible with github.com/disaster37/raft/storage.EncryptedValue.
type encryptedValue struct {
	KID string `json:"kid"`
	Alg string `json:"alg"`
	Ver int    `json:"ver"`
	Non string `json:"non"`
	Ctx string `json:"ctx"`
	Ct  string `json:"ct"`
}

// AESGCMSealer implements Sealer using AES-256-GCM with optional AAD context.
// SealString emits the JSON envelope format; OpenString accepts both the JSON
// envelope and the raw base64(nonce||ciphertext||tag) format used by
// dagger-kubernetes.
type AESGCMSealer struct {
	key []byte
	aad []byte
}

// NewAESGCMSealer returns a sealer for a raw 32-byte AES-256 key.
func NewAESGCMSealer(key []byte, aad []byte) (*AESGCMSealer, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("%w (got %d)", ErrInvalidKeySize, len(key))
	}
	return &AESGCMSealer{key: append([]byte(nil), key...), aad: append([]byte(nil), aad...)}, nil
}

// NewDerivedSealer derives a 32-byte key from secret via HKDF-SHA256 and
// returns a sealer using it.
func NewDerivedSealer(secret []byte, info string, aad []byte) (*AESGCMSealer, error) {
	key, err := DeriveKey(secret, info)
	if err != nil {
		return nil, err
	}
	return NewAESGCMSealer(key[:], aad)
}

func (s *AESGCMSealer) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := newGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return gcm, nil
}

var newGCM = cipher.NewGCM

// SealBytes encrypts plain and returns nonce||ciphertext||tag.
func (s *AESGCMSealer) SealBytes(plain []byte) ([]byte, error) {
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randRead, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plain, s.aad), nil
}

// OpenBytes reverses SealBytes.
func (s *AESGCMSealer) OpenBytes(sealed []byte) ([]byte, error) {
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, ErrCiphertextShort
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, s.aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt at-rest value: %w", err)
	}
	return plain, nil
}

// SealString seals plaintext and returns the JSON envelope.
func (s *AESGCMSealer) SealString(plain string) (string, error) {
	gcm, err := s.gcm()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randRead, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, []byte(plain), s.aad)
	ev := encryptedValue{
		KID: "primary",
		Alg: "A256GCM",
		Ver: 1,
		Non: base64.StdEncoding.EncodeToString(nonce),
		Ctx: base64.StdEncoding.EncodeToString(s.aad),
		Ct:  base64.StdEncoding.EncodeToString(ct),
	}
	data, err := jsonMarshal(ev)
	if err != nil {
		return "", fmt.Errorf("marshal at-rest envelope: %w", err)
	}
	return string(data), nil
}

var (
	randRead    = rand.Reader
	jsonMarshal = json.Marshal
)

// OpenString opens a stored value. It accepts the JSON envelope format and the
// raw base64(nonce||ciphertext||tag) format. An empty value returns "".
func (s *AESGCMSealer) OpenString(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	var ev encryptedValue
	if err := json.Unmarshal([]byte(stored), &ev); err == nil && ev.Alg != "" && ev.Ct != "" {
		return s.openEnvelope(ev)
	}
	sealed, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	plain, err := s.OpenBytes(sealed)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *AESGCMSealer) openEnvelope(ev encryptedValue) (string, error) {
	if ev.Alg != "A256GCM" || ev.Ver != 1 {
		return "", fmt.Errorf("unsupported at-rest envelope alg=%q ver=%d", ev.Alg, ev.Ver)
	}
	nonce, err := base64.StdEncoding.DecodeString(ev.Non)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ev.Ct)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	ctx, err := base64.StdEncoding.DecodeString(ev.Ctx)
	if err != nil {
		return "", fmt.Errorf("decode context: %w", err)
	}
	gcm, err := s.gcm()
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, ct, ctx)
	if err != nil {
		return "", fmt.Errorf("decrypt at-rest value: %w", err)
	}
	return string(plain), nil
}
