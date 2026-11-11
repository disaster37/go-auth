package httpcookie

import "testing"

func TestSafeRedirectPath(t *testing.T) {
	tests := []struct {
		redirect string
		def      string
		want     string
	}{
		{"/dashboard", "/", "/dashboard"},
		{"", "/home", "/home"},
		{"", "", "/"},
		{"https://evil.com", "/", "/"},
		{"//evil.com", "/", "/"},
		{"/\\evil.com", "/", "/"},
		{"/path\\x", "/", "/"},
		{"/path\r\nSet-Cookie: x", "/", "/"},
		{"/path\x00", "/", "/"},
		{"/path\x7f", "/", "/"},
		{"relative", "/", "/"},
		{"/ok?q=1", "/", "/ok?q=1"},
	}
	for _, tt := range tests {
		if got := SafeRedirectPath(tt.redirect, tt.def); got != tt.want {
			t.Fatalf("SafeRedirectPath(%q, %q)=%q want %q", tt.redirect, tt.def, got, tt.want)
		}
	}
}
