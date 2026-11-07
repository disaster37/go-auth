package secguard

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ParseTrustedProxyCIDRs parses a list of CIDRs/IPs into networks. Bare IPs are
// treated as /32 (or /128). Invalid entries return an error.
func ParseTrustedProxyCIDRs(entries []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			_, n, err := net.ParseCIDR(e)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", e, err)
			}
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %q", e)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseRemoteIP(remoteAddr string) (net.IP, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		if ip := net.ParseIP(remoteAddr); ip != nil {
			return ip, nil
		}
		return nil, fmt.Errorf("invalid RemoteAddr %q: %w", remoteAddr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q", host)
	}
	return ip, nil
}

// ExtractRealIP extracts the client IP. Forwarded headers (X-Forwarded-For,
// X-Real-IP) are honored only when behindReverseProxy is enabled AND the direct
// peer is inside a trusted-proxy CIDR. XFF is walked right-to-left, skipping
// trusted proxies, so a client cannot spoof its address by prepending an
// untrusted value (CWE-348).
func ExtractRealIP(remoteAddr, xForwardedFor, xRealIP string, behindReverseProxy bool, trustedCIDRs []*net.IPNet) (net.IP, error) {
	peer, err := parseRemoteIP(remoteAddr)
	if err != nil {
		return nil, err
	}
	if !behindReverseProxy || !ipInAny(peer, trustedCIDRs) {
		return peer, nil
	}
	if xForwardedFor != "" {
		parts := strings.Split(xForwardedFor, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := net.ParseIP(strings.TrimSpace(parts[i]))
			if candidate == nil {
				continue
			}
			if ipInAny(candidate, trustedCIDRs) {
				continue
			}
			return candidate, nil
		}
	}
	if xRealIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(xRealIP)); ip != nil {
			return ip, nil
		}
	}
	return peer, nil
}

// GetRealIPFromRequest extracts the client IP from an *http.Request.
func GetRealIPFromRequest(r *http.Request, behindReverseProxy bool, trustedCIDRs []*net.IPNet) (net.IP, error) {
	return ExtractRealIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), behindReverseProxy, trustedCIDRs)
}
