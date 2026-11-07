package jwt

import (
	"testing"
	"time"
)

func FuzzParseAccess(f *testing.F) {
	s, _ := NewService(Config{Secret: []byte("0123456789abcdef0123456789abcdef")})
	f.Add("garbage")
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = s.ParseAccess(token)
	})
}

func FuzzDecodeSession(f *testing.F) {
	key, _ := DeriveSigningKey("secret", "")
	f.Add("garbage")
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = DecodeSession(token, key, time.Now())
	})
}
