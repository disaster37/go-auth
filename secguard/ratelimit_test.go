package secguard

import (
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	rl := NewRateLimiter(2, clk.Now)
	window := time.Minute
	if !rl.Allow("k", 2, window) {
		t.Fatal("first request allowed")
	}
	if !rl.Allow("k", 2, window) {
		t.Fatal("second request allowed")
	}
	if rl.Allow("k", 2, window) {
		t.Fatal("third request must be denied")
	}
	clk.Advance(2 * window)
	if !rl.Allow("k", 2, window) {
		t.Fatal("request allowed after window")
	}
	rl.Sweep(window)
}

func TestRateLimiterEviction(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	rl := NewRateLimiter(1, clk.Now)
	rl.Allow("a", 5, time.Minute)
	rl.Allow("b", 5, time.Minute) // evicts a
	if len(rl.entries) > 1 {
		t.Fatalf("entries=%d", len(rl.entries))
	}
}

func TestLoginThrottle(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	lt := NewLoginThrottle(10, clk.Now)
	window := time.Minute
	first := lt.Allow("k", 2, window)
	second := lt.Allow("k", 2, window)
	if !first || !second {
		t.Fatal("first two attempts allowed")
	}
	if lt.Allow("k", 2, window) {
		t.Fatal("third attempt denied")
	}
	lt.Clear("k")
	if !lt.Allow("k", 2, window) {
		t.Fatal("attempt allowed after clear")
	}
	// maxAttempts <= 0 defaults to 10.
	for i := 0; i < 10; i++ {
		lt.Allow("z", 0, window)
	}
	if lt.Allow("z", 0, window) {
		t.Fatal("default max attempts should deny the 11th")
	}
}

func TestLoginThrottleEviction(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	lt := NewLoginThrottle(1, clk.Now)
	lt.Allow("a", 5, time.Minute)
	lt.Allow("b", 5, time.Minute)
	if len(lt.attempts) > 1 {
		t.Fatalf("attempts=%d", len(lt.attempts))
	}
}

func TestLimiterDefaultsAndEmptyEntries(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	rl := NewRateLimiter(0, nil)
	if rl.max != DefaultMaxEntries {
		t.Fatalf("default max=%d", rl.max)
	}
	rl.entries["empty"] = nil
	rl.Sweep(time.Minute)
	if _, ok := rl.entries["empty"]; ok {
		t.Fatal("empty entry must be swept")
	}

	rl = NewRateLimiter(1, clk.Now)
	rl.entries["empty"] = nil
	rl.Allow("a", 1, time.Minute)
	if _, ok := rl.entries["empty"]; ok {
		t.Fatal("empty entry must be evicted")
	}

	lt := NewLoginThrottle(0, nil)
	if lt.max != DefaultMaxEntries {
		t.Fatalf("default max=%d", lt.max)
	}
	lt = NewLoginThrottle(1, clk.Now)
	lt.attempts["empty"] = nil
	lt.Allow("a", 1, time.Minute)
	if _, ok := lt.attempts["empty"]; ok {
		t.Fatal("empty attempt entry must be evicted")
	}
}

func TestEvictOldestAllEmpty(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	rl := NewRateLimiter(1, clk.Now)
	rl.entries["empty"] = nil
	rl.evictOldestLocked()
	if _, ok := rl.entries["empty"]; ok {
		t.Fatal("empty entry must be removed")
	}

	lt := NewLoginThrottle(1, clk.Now)
	lt.attempts["empty"] = nil
	lt.evictOldestLocked()
	if _, ok := lt.attempts["empty"]; ok {
		t.Fatal("empty attempt entry must be removed")
	}
}
