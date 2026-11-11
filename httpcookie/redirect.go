package httpcookie

import "strings"

// SafeRedirectPath validates a post-login redirect target against CWE-601. It
// rejects empty, non-"/", "//", "/\", "\", CR/LF, and ASCII control characters,
// returning defaultPath (or "/" when defaultPath is empty).
func SafeRedirectPath(redirect, defaultPath string) string {
	fallback := defaultPath
	if fallback == "" {
		fallback = "/"
	}
	if redirect == "" {
		return fallback
	}
	if !strings.HasPrefix(redirect, "/") {
		return fallback
	}
	if strings.HasPrefix(redirect, "//") || strings.HasPrefix(redirect, "/\\") {
		return fallback
	}
	if strings.ContainsAny(redirect, "\\\r\n") {
		return fallback
	}
	for _, r := range redirect {
		if r < 0x20 || r == 0x7f {
			return fallback
		}
	}
	return redirect
}
