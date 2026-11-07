// Package secguard provides rate limiting, exponential lockout,
// credential-stuffing ban tracking, right-to-left trusted-proxy client IP
// extraction, security headers, and CSRF mutation origin validation.
package secguard

import (
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultMaxFailedAttempts is the number of consecutive failures after
	// which lockouts start (CWE-307).
	DefaultMaxFailedAttempts = 5
	// DefaultBaseLockout is the first lockout duration once the threshold is
	// reached; it doubles with every further failure.
	DefaultBaseLockout = 30 * time.Second
	// DefaultMaxLockout caps the exponential lockout growth.
	DefaultMaxLockout = 15 * time.Minute
	// DefaultEntryTTL is how long an idle failure record is kept.
	DefaultEntryTTL = 30 * time.Minute
	// DefaultMaxEntries bounds the tracker map (CWE-770).
	DefaultMaxEntries = 4096
	// MaxLockoutShift caps the exponential shift so the duration computation
	// cannot overflow.
	MaxLockoutShift = 16
)

// LockoutConfig configures a LockoutLimiter.
type LockoutConfig struct {
	MaxFailedAttempts int
	BaseLockout       time.Duration
	MaxLockout        time.Duration
	EntryTTL          time.Duration
	MaxEntries        int
	Clock             func() time.Time
}

func (c LockoutConfig) withDefaults() LockoutConfig {
	if c.MaxFailedAttempts <= 0 {
		c.MaxFailedAttempts = DefaultMaxFailedAttempts
	}
	if c.BaseLockout <= 0 {
		c.BaseLockout = DefaultBaseLockout
	}
	if c.MaxLockout <= 0 {
		c.MaxLockout = DefaultMaxLockout
	}
	if c.EntryTTL <= 0 {
		c.EntryTTL = DefaultEntryTTL
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = DefaultMaxEntries
	}
	if c.Clock == nil {
		c.Clock = func() time.Time { return time.Now().UTC() }
	}
	return c
}

type lockoutEntry struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

// LockoutLimiter tracks failed authentication attempts per key and imposes
// exponentially growing lockouts after repeated failures (CWE-307).
type LockoutLimiter struct {
	mu      sync.Mutex
	entries map[string]*lockoutEntry
	cfg     LockoutConfig
}

// NewLockoutLimiter returns a LockoutLimiter.
func NewLockoutLimiter(cfg LockoutConfig) *LockoutLimiter {
	return &LockoutLimiter{entries: make(map[string]*lockoutEntry), cfg: cfg.withDefaults()}
}

// LoginLimitKey returns the lockout key for a username + client IP.
func LoginLimitKey(username, clientIP string) string {
	return fmt.Sprintf("login:%s:%s", username, clientIP)
}

// PasswordChangeLimitKey returns the lockout key for a user ID + client IP.
func PasswordChangeLimitKey(userID, clientIP string) string {
	return fmt.Sprintf("password:%s:%s", userID, clientIP)
}

// Allow reports whether key may attempt authentication right now.
func (l *LockoutLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Clock()
	l.sweepLocked(now)
	info, ok := l.entries[key]
	if !ok {
		return true
	}
	return !now.Before(info.lockedUntil)
}

// RecordFailure records a failed attempt and returns the lockout duration it
// triggered (0 when the failure did not yet cause a lockout).
func (l *LockoutLimiter) RecordFailure(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Clock()
	l.sweepLocked(now)
	info, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.cfg.MaxEntries {
			l.evictOldestLocked()
		}
		info = &lockoutEntry{}
		l.entries[key] = info
	}
	info.failures++
	info.lastSeen = now
	if info.failures < l.cfg.MaxFailedAttempts {
		return 0
	}
	shift := info.failures - l.cfg.MaxFailedAttempts
	if shift > MaxLockoutShift {
		shift = MaxLockoutShift
	}
	lock := l.cfg.BaseLockout << shift
	if lock > l.cfg.MaxLockout {
		lock = l.cfg.MaxLockout
	}
	info.lockedUntil = now.Add(lock)
	return lock
}

// RecordSuccess clears the failure history for key.
func (l *LockoutLimiter) RecordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (l *LockoutLimiter) sweepLocked(now time.Time) {
	for k, info := range l.entries {
		if now.Sub(info.lastSeen) > l.cfg.EntryTTL && !now.Before(info.lockedUntil) {
			delete(l.entries, k)
		}
	}
}

func (l *LockoutLimiter) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, info := range l.entries {
		if first || info.lastSeen.Before(oldestTime) {
			oldestKey, oldestTime, first = k, info.lastSeen, false
		}
	}
	if !first {
		delete(l.entries, oldestKey)
	}
}
