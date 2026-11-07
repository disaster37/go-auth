package secguard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type banEntry struct {
	fingerprint string
	timestamp   time.Time
}

// BanInfo describes an active ban.
type BanInfo struct {
	IP             string    `json:"ip"`
	Until          time.Time `json:"until"`
	UniqueFailures int       `json:"unique_failures"`
}

// BanTracker counts unique credential failures per IP and bans suspicious
// clients (credential stuffing), while tolerating a single misconfigured client
// repeating the same credential.
type BanTracker struct {
	mu        sync.Mutex
	failures  map[string][]banEntry
	banned    map[string]time.Time
	lastSweep time.Time
	max       int
	clock     func() time.Time
}

// NewBanTracker returns a BanTracker bounded to maxEntries IPs.
func NewBanTracker(maxEntries int, clock func() time.Time) *BanTracker {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &BanTracker{
		failures: make(map[string][]banEntry),
		banned:   make(map[string]time.Time),
		max:      maxEntries,
		clock:    clock,
	}
}

// IsBanned reports whether ip is currently banned.
func (bt *BanTracker) IsBanned(ip string) bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	until, ok := bt.banned[ip]
	if !ok {
		return false
	}
	if bt.clock().Before(until) {
		return true
	}
	delete(bt.banned, ip)
	return false
}

// RecordAndBan records a credential failure for ip and bans it when the number
// of unique fingerprints within window reaches maxUniqueFailures. It returns
// true when the IP is banned as a result of this call.
func (bt *BanTracker) RecordAndBan(ip, fingerprint string, maxUniqueFailures int, banDuration, window time.Duration) bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	now := bt.clock()
	bt.maybeSweepLocked(now, window)
	bt.recordFailureLocked(ip, fingerprint, window, now)
	return bt.banIfSuspiciousLocked(ip, maxUniqueFailures, banDuration, window, now)
}

func (bt *BanTracker) recordFailureLocked(ip, fingerprint string, window time.Duration, now time.Time) {
	windowStart := now.Add(-window)
	entries := bt.failures[ip]
	for _, e := range entries {
		if e.timestamp.After(windowStart) && e.fingerprint == fingerprint {
			return
		}
	}
	valid := entries[:0]
	for _, e := range entries {
		if e.timestamp.After(windowStart) {
			valid = append(valid, e)
		}
	}
	if _, exists := bt.failures[ip]; !exists && len(bt.failures) >= bt.max {
		bt.evictOldestLocked()
	}
	bt.failures[ip] = append(valid, banEntry{fingerprint: fingerprint, timestamp: now})
}

func (bt *BanTracker) banIfSuspiciousLocked(ip string, maxUniqueFailures int, banDuration, window time.Duration, now time.Time) bool {
	fingerprints := make(map[string]struct{})
	valid := bt.failures[ip][:0]
	for _, e := range bt.failures[ip] {
		if now.Sub(e.timestamp) <= window {
			valid = append(valid, e)
			fingerprints[e.fingerprint] = struct{}{}
		}
	}
	bt.failures[ip] = valid
	if len(fingerprints) >= maxUniqueFailures {
		bt.banned[ip] = now.Add(banDuration)
		return true
	}
	return false
}

// ListBans returns the currently active bans.
func (bt *BanTracker) ListBans() []BanInfo {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	now := bt.clock()
	bans := make([]BanInfo, 0, len(bt.banned))
	for ip, until := range bt.banned {
		if now.Before(until) {
			fingerprints := make(map[string]struct{})
			for _, e := range bt.failures[ip] {
				fingerprints[e.fingerprint] = struct{}{}
			}
			bans = append(bans, BanInfo{IP: ip, Until: until, UniqueFailures: len(fingerprints)})
		} else {
			delete(bt.banned, ip)
		}
	}
	return bans
}

// Unban removes any ban for ip.
func (bt *BanTracker) Unban(ip string) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	delete(bt.banned, ip)
}

// Sweep removes expired failure entries and expired bans.
func (bt *BanTracker) Sweep(window time.Duration) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	now := bt.clock()
	bt.lastSweep = now
	bt.sweepLocked(now, window)
}

func (bt *BanTracker) maybeSweepLocked(now time.Time, window time.Duration) {
	if !bt.lastSweep.IsZero() && now.Sub(bt.lastSweep) < window {
		return
	}
	bt.lastSweep = now
	bt.sweepLocked(now, window)
}

func (bt *BanTracker) sweepLocked(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	for ip, entries := range bt.failures {
		kept := entries[:0]
		for _, e := range entries {
			if e.timestamp.After(cutoff) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(bt.failures, ip)
		} else {
			bt.failures[ip] = kept
		}
	}
	for ip, until := range bt.banned {
		if !now.Before(until) {
			delete(bt.banned, ip)
		}
	}
}

func (bt *BanTracker) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for ip, entries := range bt.failures {
		if len(entries) == 0 {
			delete(bt.failures, ip)
			continue
		}
		last := entries[len(entries)-1].timestamp
		if first || last.Before(oldest) {
			oldestKey, oldest, first = ip, last, false
		}
	}
	if !first {
		delete(bt.failures, oldestKey)
	}
}

// FingerprintLogin returns a stable SHA-256 fingerprint of a login username.
func FingerprintLogin(username string) string {
	return fingerprint(fmt.Sprintf("login:%s", username))
}

// FingerprintToken returns a stable SHA-256 fingerprint of a token.
func FingerprintToken(token string) string {
	return fingerprint(fmt.Sprintf("token:%s", token))
}

// FingerprintSignature returns a stable SHA-256 fingerprint of a channel
// signature.
func FingerprintSignature(channel, signatureValue string) string {
	return fingerprint(fmt.Sprintf("signature:%s:%s", channel, signatureValue))
}

func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
