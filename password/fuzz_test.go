package password

import "testing"

func FuzzValidateUsername(f *testing.F) {
	f.Add("alice")
	f.Add("")
	f.Add("a.b-c_d")
	f.Fuzz(func(t *testing.T, username string) {
		_ = ValidateUsername(username)
	})
}

func FuzzValidatePassword(f *testing.F) {
	f.Add("password123")
	f.Add("")
	f.Fuzz(func(t *testing.T, password string) {
		_ = ValidatePassword(password)
	})
}
