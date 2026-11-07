package secguard

import (
	"sync"
	"time"
)

// RateLimiter is a bounded sliding-window per-key request limiter.
type RateLimiter struct {
	mu        sync.Mutex
	entries   map[string][]time.Time
	lastSweep time.Time
	max       int
	clock     func() time.Time
}

// NewRateLimiter returns a RateLimiter bounded to maxEntries keys.
func NewRateLimiter(maxEntries int, clock func() time.Time) *RateLimiter {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &RateLimiter{entries: make(map[string][]time.Time), max: maxEntries, clock: clock}
}

// Allow reports whether key may make another request within window.
func (rl *RateLimiter) Allow(key string, maxRequests int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.clock()
	rl.maybeSweepLocked(now, window)

	times := rl.entries[key]
	valid := times[:0]
	for _, t := range times {
		if t.After(now.Add(-window)) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= maxRequests {
		rl.entries[key] = valid
		return false
	}
	if _, exists := rl.entries[key]; !exists && len(rl.entries) >= rl.max {
		rl.evictOldestLocked()
	}
	rl.entries[key] = append(valid, now)
	return true
}

// Sweep removes keys with no timestamps within window.
func (rl *RateLimiter) Sweep(window time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.sweepLocked(rl.clock(), window)
}

func (rl *RateLimiter) maybeSweepLocked(now time.Time, window time.Duration) {
	if !rl.lastSweep.IsZero() && now.Sub(rl.lastSweep) < window {
		return
	}
	rl.lastSweep = now
	rl.sweepLocked(now, window)
}

func (rl *RateLimiter) sweepLocked(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	for k, times := range rl.entries {
		if len(times) == 0 || times[len(times)-1].Before(cutoff) {
			delete(rl.entries, k)
		}
	}
}

func (rl *RateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, times := range rl.entries {
		if len(times) == 0 {
			delete(rl.entries, k)
			continue
		}
		last := times[len(times)-1]
		if first || last.Before(oldest) {
			oldestKey, oldest, first = k, last, false
		}
	}
	if !first {
		delete(rl.entries, oldestKey)
	}
}

// LoginThrottle bounds repeated failed logins per account.
type LoginThrottle struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	max      int
	clock    func() time.Time
}

// NewLoginThrottle returns a LoginThrottle bounded to maxEntries keys.
func NewLoginThrottle(maxEntries int, clock func() time.Time) *LoginThrottle {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &LoginThrottle{attempts: make(map[string][]time.Time), max: maxEntries, clock: clock}
}

// Allow reports whether the account may attempt another login.
func (lt *LoginThrottle) Allow(key string, maxAttempts int, window time.Duration) bool {
	if maxAttempts <= 0 {
		maxAttempts = 10
	}
	lt.mu.Lock()
	defer lt.mu.Unlock()
	now := lt.clock()
	cutoff := now.Add(-window)
	valid := lt.attempts[key][:0]
	for _, t := range lt.attempts[key] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= maxAttempts {
		lt.attempts[key] = valid
		return false
	}
	if _, exists := lt.attempts[key]; !exists && len(lt.attempts) >= lt.max {
		lt.evictOldestLocked()
	}
	lt.attempts[key] = append(valid, now)
	return true
}

// Clear resets the throttle state for a key after a successful login.
func (lt *LoginThrottle) Clear(key string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.attempts, key)
}

func (lt *LoginThrottle) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, times := range lt.attempts {
		if len(times) == 0 {
			delete(lt.attempts, k)
			continue
		}
		last := times[len(times)-1]
		if first || last.Before(oldest) {
			oldestKey, oldest, first = k, last, false
		}
	}
	if !first {
		delete(lt.attempts, oldestKey)
	}
}
