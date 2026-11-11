package secguard

import "testing"

func FuzzExtractRealIP(f *testing.F) {
	f.Add("10.0.0.1:1234", "1.2.3.4", "5.6.7.8")
	f.Add("203.0.113.5", "", "")
	f.Fuzz(func(t *testing.T, remoteAddr, xff, xrip string) {
		trusted, _ := ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
		_, _ = ExtractRealIP(remoteAddr, xff, xrip, true, trusted)
	})
}

func FuzzCheckMutationOrigin(f *testing.F) {
	f.Add("POST", "https://a.com", "https://b.com")
	f.Add("GET", "", "")
	f.Fuzz(func(t *testing.T, method, origin, referer string) {
		_ = CheckMutationOrigin(method, origin, referer, []string{"https://a.com"})
	})
}
