package secguard

import (
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func TestLockoutLimiter(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	l := NewLockoutLimiter(LockoutConfig{Clock: clk.Now})
	key := LoginLimitKey("alice", "1.2.3.4")

	if !l.Allow(key) {
		t.Fatal("fresh key must be allowed")
	}
	for i := 0; i < DefaultMaxFailedAttempts-1; i++ {
		if d := l.RecordFailure(key); d != 0 {
			t.Fatalf("failure %d triggered lockout %v", i, d)
		}
	}
	if d := l.RecordFailure(key); d != DefaultBaseLockout {
		t.Fatalf("threshold lockout=%v want %v", d, DefaultBaseLockout)
	}
	if l.Allow(key) {
		t.Fatal("locked key must not be allowed")
	}
	clk.Advance(DefaultBaseLockout)
	if !l.Allow(key) {
		t.Fatal("key must be allowed after lockout expires")
	}
	// Next failure doubles the lockout.
	if d := l.RecordFailure(key); d != 2*DefaultBaseLockout {
		t.Fatalf("second lockout=%v", d)
	}
}

func TestLockoutLimiterCap(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	l := NewLockoutLimiter(LockoutConfig{Clock: clk.Now, MaxFailedAttempts: 1, BaseLockout: time.Second, MaxLockout: 4 * time.Second})
	key := "k"
	var last time.Duration
	for i := 0; i < 20; i++ {
		last = l.RecordFailure(key)
	}
	if last != 4*time.Second {
		t.Fatalf("lockout cap=%v want 4s", last)
	}
}

func TestLockoutRecordSuccess(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	l := NewLockoutLimiter(LockoutConfig{Clock: clk.Now, MaxFailedAttempts: 1})
	key := "k"
	l.RecordFailure(key)
	l.RecordSuccess(key)
	if !l.Allow(key) {
		t.Fatal("success must clear the lockout")
	}
}

func TestLockoutSweepAndEvict(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	l := NewLockoutLimiter(LockoutConfig{Clock: clk.Now, EntryTTL: time.Minute, MaxEntries: 2})
	l.RecordFailure("a")
	l.RecordFailure("b")
	l.RecordFailure("c") // triggers eviction of the oldest
	if len(l.entries) > 2 {
		t.Fatalf("entries=%d exceeds max", len(l.entries))
	}
	clk.Advance(2 * time.Minute)
	l.Allow("a") // triggers sweep
	if len(l.entries) != 0 {
		t.Fatalf("entries after sweep=%d", len(l.entries))
	}
}

func TestLimitKeys(t *testing.T) {
	if LoginLimitKey("u", "ip") == PasswordChangeLimitKey("u", "ip") {
		t.Fatal("login and password keys must differ")
	}
}

func TestLockoutSweepKeepsLockedEntry(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	l := NewLockoutLimiter(LockoutConfig{Clock: clk.Now, MaxFailedAttempts: 1, BaseLockout: 10 * time.Minute, EntryTTL: time.Minute})
	l.RecordFailure("k")
	clk.Advance(2 * time.Minute)
	if l.Allow("k") {
		t.Fatal("entry must remain locked")
	}
	if len(l.entries) != 1 {
		t.Fatalf("locked entry must not be swept, entries=%d", len(l.entries))
	}
	clk.Advance(10 * time.Minute)
	if !l.Allow("k") {
		t.Fatal("lockout must expire")
	}
	if len(l.entries) != 0 {
		t.Fatalf("expired entry must be swept, entries=%d", len(l.entries))
	}
}

func TestLockoutDefaults(t *testing.T) {
	l := NewLockoutLimiter(LockoutConfig{})
	if l.cfg.MaxFailedAttempts != DefaultMaxFailedAttempts ||
		l.cfg.BaseLockout != DefaultBaseLockout ||
		l.cfg.MaxLockout != DefaultMaxLockout ||
		l.cfg.EntryTTL != DefaultEntryTTL ||
		l.cfg.MaxEntries != DefaultMaxEntries ||
		l.cfg.Clock == nil {
		t.Fatalf("defaults not applied: %+v", l.cfg)
	}
}

func TestLockoutNoOverflow(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	// A large BaseLockout combined with many failures must clamp to MaxLockout
	// rather than overflowing int64 (which would silently disable the lockout).
	l := NewLockoutLimiter(LockoutConfig{Clock: clk.Now, MaxFailedAttempts: 1, BaseLockout: 7 * 24 * time.Hour, MaxLockout: 15 * time.Minute})
	key := "k"
	var last time.Duration
	for i := 0; i < 20; i++ {
		last = l.RecordFailure(key)
	}
	if last != 15*time.Minute {
		t.Fatalf("lockout=%v want 15m", last)
	}
	if l.Allow(key) {
		t.Fatal("key must remain locked")
	}
}
