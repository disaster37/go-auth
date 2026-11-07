package oauth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/disaster37/go-auth/crypto"
)

// Credential is the upstream OAuth credential captured at login and persisted
// encrypted on domain.User.OAuthTokenCiphertext.
type Credential struct {
	Provider     string    `json:"provider"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

// SealCredential JSON-encodes c and seals it with sealer. A nil sealer returns
// ("", nil): credential persistence is disabled.
func SealCredential(sealer crypto.Sealer, c *Credential) (string, error) {
	if c == nil || sealer == nil {
		return "", nil
	}
	b, err := json.Marshal(c) // #nosec G117
	if err != nil {
		return "", fmt.Errorf("marshal oauth credential: %w", err)
	}
	return sealer.SealString(string(b))
}

// OpenCredential reverses SealCredential. It returns (nil, nil) when ciphertext
// is empty.
func OpenCredential(sealer crypto.Sealer, ciphertext string) (*Credential, error) {
	if ciphertext == "" {
		return nil, nil
	}
	if sealer == nil {
		return nil, fmt.Errorf("oauth credential stored but no sealer configured")
	}
	pt, err := sealer.OpenString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt oauth credential: %w", err)
	}
	var c Credential
	if err := json.Unmarshal([]byte(pt), &c); err != nil {
		return nil, fmt.Errorf("decode oauth credential: %w", err)
	}
	return &c, nil
}
