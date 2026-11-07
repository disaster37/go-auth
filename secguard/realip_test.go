package secguard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseTrustedProxyCIDRs(t *testing.T) {
	nets, err := ParseTrustedProxyCIDRs([]string{"10.0.0.0/8", "192.168.1.1", "  ", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("nets=%d", len(nets))
	}
	if _, err := ParseTrustedProxyCIDRs([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if _, err := ParseTrustedProxyCIDRs([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestExtractRealIP(t *testing.T) {
	trusted, _ := ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})

	// Not behind proxy: peer is returned.
	ip, err := ExtractRealIP("203.0.113.5:1234", "1.2.3.4", "", false, trusted)
	if err != nil || ip.String() != "203.0.113.5" {
		t.Fatalf("not behind proxy: %v %v", ip, err)
	}
	// Behind proxy but untrusted peer: peer is returned.
	ip, _ = ExtractRealIP("203.0.113.5:1234", "1.2.3.4", "", true, trusted)
	if ip.String() != "203.0.113.5" {
		t.Fatalf("untrusted peer: %v", ip)
	}
	// Behind proxy, trusted peer: rightmost untrusted XFF entry wins.
	ip, _ = ExtractRealIP("10.0.0.1:1234", "1.2.3.4, 10.0.0.2", "", true, trusted)
	if ip.String() != "1.2.3.4" {
		t.Fatalf("xff walk: %v", ip)
	}
	// X-Real-IP fallback.
	ip, _ = ExtractRealIP("10.0.0.1:1234", "", "9.9.9.9", true, trusted)
	if ip.String() != "9.9.9.9" {
		t.Fatalf("x-real-ip: %v", ip)
	}
	// No forwarded headers: peer.
	ip, _ = ExtractRealIP("10.0.0.1:1234", "", "", true, trusted)
	if ip.String() != "10.0.0.1" {
		t.Fatalf("no headers: %v", ip)
	}
	// Bare IP remote addr.
	ip, err = ExtractRealIP("203.0.113.5", "", "", false, nil)
	if err != nil || ip.String() != "203.0.113.5" {
		t.Fatalf("bare ip: %v %v", ip, err)
	}
	// Invalid remote addr.
	if _, err := ExtractRealIP("bad:addr:extra", "", "", false, nil); err == nil {
		t.Fatal("expected error for invalid remote addr")
	}
}

func TestGetRealIPFromRequest(t *testing.T) {
	trusted, _ := ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	ip, err := GetRealIPFromRequest(r, true, trusted)
	if err != nil || ip.String() != "1.2.3.4" {
		t.Fatalf("get real ip: %v %v", ip, err)
	}
}

func TestIPInAny(t *testing.T) {
	nets, _ := ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if !ipInAny(net.ParseIP("10.1.2.3"), nets) {
		t.Fatal("expected in range")
	}
	if ipInAny(net.ParseIP("11.1.2.3"), nets) {
		t.Fatal("expected out of range")
	}
}

func TestExtractRealIPEdgeCases(t *testing.T) {
	trusted, _ := ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	// Invalid XFF entries are skipped; trusted candidates are skipped.
	ip, err := ExtractRealIP("10.0.0.1:1234", "not-an-ip, 10.0.0.2, 1.2.3.4", "", true, trusted)
	if err != nil || ip.String() != "1.2.3.4" {
		t.Fatalf("xff edge: %v %v", ip, err)
	}
	// Invalid X-Real-IP falls back to the peer.
	ip, _ = ExtractRealIP("10.0.0.1:1234", "", "not-an-ip", true, trusted)
	if ip.String() != "10.0.0.1" {
		t.Fatalf("x-real-ip fallback: %v", ip)
	}
	// Bare IPv6 address.
	ip, err = ExtractRealIP("2001:db8::1", "", "", false, nil)
	if err != nil || ip.String() != "2001:db8::1" {
		t.Fatalf("ipv6: %v %v", ip, err)
	}
	// Bare IPv6 trusted proxy CIDR.
	nets, err := ParseTrustedProxyCIDRs([]string{"2001:db8::1"})
	if err != nil || len(nets) != 1 {
		t.Fatalf("ipv6 cidr: %v %v", nets, err)
	}
}

func TestExtractRealIPInvalidHost(t *testing.T) {
	if _, err := ExtractRealIP("bad:1234", "", "", false, nil); err == nil {
		t.Fatal("invalid host must error")
	}
	trusted, _ := ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	// All XFF entries are trusted: fall back to X-Real-IP.
	ip, err := ExtractRealIP("10.0.0.1:1234", "10.0.0.2, 10.0.0.3", "9.9.9.9", true, trusted)
	if err != nil || ip.String() != "9.9.9.9" {
		t.Fatalf("all-trusted xff: %v %v", ip, err)
	}
}
