package httpcookie

import "testing"

func FuzzSafeRedirectPath(f *testing.F) {
	f.Add("/dashboard", "/")
	f.Add("//evil.com", "/")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, redirect, def string) {
		got := SafeRedirectPath(redirect, def)
		if got == "" {
			t.Fatal("SafeRedirectPath must never return empty")
		}
	})
}
