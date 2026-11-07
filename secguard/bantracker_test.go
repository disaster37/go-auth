package secguard

import (
	"testing"
	"time"
)

func TestBanTracker(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	bt := NewBanTracker(10, clk.Now)
	window := time.Minute
	ban := 10 * time.Minute

	if bt.IsBanned("1.1.1.1") {
		t.Fatal("fresh IP must not be banned")
	}
	// Same fingerprint repeated does not accumulate unique failures.
	for i := 0; i < 5; i++ {
		if bt.RecordAndBan("1.1.1.1", "fp-same", 3, ban, window) {
			t.Fatal("repeated fingerprint must not ban")
		}
	}
	// Distinct fingerprints trigger a ban.
	bt.RecordAndBan("1.1.1.1", "fp-a", 3, ban, window)
	bt.RecordAndBan("1.1.1.1", "fp-b", 3, ban, window)
	if !bt.RecordAndBan("1.1.1.1", "fp-c", 3, ban, window) {
		t.Fatal("third unique fingerprint must ban")
	}
	if !bt.IsBanned("1.1.1.1") {
		t.Fatal("IP must be banned")
	}
	bans := bt.ListBans()
	if len(bans) != 1 || bans[0].IP != "1.1.1.1" || bans[0].UniqueFailures < 3 {
		t.Fatalf("bans=%+v", bans)
	}
	bt.Unban("1.1.1.1")
	if bt.IsBanned("1.1.1.1") {
		t.Fatal("IP must be unbanned")
	}
}

func TestBanTrackerExpiry(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	bt := NewBanTracker(10, clk.Now)
	bt.RecordAndBan("1.1.1.1", "fp", 1, time.Minute, time.Minute)
	if !bt.IsBanned("1.1.1.1") {
		t.Fatal("expected ban")
	}
	clk.Advance(2 * time.Minute)
	if bt.IsBanned("1.1.1.1") {
		t.Fatal("ban must expire")
	}
	bt.Sweep(time.Minute)
}

func TestBanTrackerEviction(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	bt := NewBanTracker(1, clk.Now)
	bt.RecordAndBan("a", "fp", 5, time.Minute, time.Minute)
	bt.RecordAndBan("b", "fp", 5, time.Minute, time.Minute)
	if len(bt.failures) > 1 {
		t.Fatalf("failures=%d", len(bt.failures))
	}
}

func TestFingerprints(t *testing.T) {
	if FingerprintLogin("alice") == FingerprintLogin("bob") {
		t.Fatal("login fingerprints must differ")
	}
	if FingerprintToken("t") == FingerprintToken("u") {
		t.Fatal("token fingerprints must differ")
	}
	if FingerprintSignature("c", "s") == FingerprintSignature("c", "t") {
		t.Fatal("signature fingerprints must differ")
	}
	f1 := FingerprintLogin("alice")
	f2 := FingerprintLogin("alice")
	if f1 != f2 {
		t.Fatal("fingerprints must be deterministic")
	}
}

func TestBanTrackerDefaultsAndSweep(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	bt := NewBanTracker(0, nil)
	if bt.max != DefaultMaxEntries {
		t.Fatalf("default max=%d", bt.max)
	}

	bt = NewBanTracker(1, clk.Now)
	bt.failures["empty"] = nil
	bt.RecordAndBan("a", "fp", 5, time.Minute, time.Minute)
	if _, ok := bt.failures["empty"]; ok {
		t.Fatal("empty failure entry must be evicted")
	}

	// Second call within the window skips the sweep; after the window it sweeps.
	bt.RecordAndBan("a", "fp2", 5, time.Minute, time.Minute)
	clk.Advance(2 * time.Minute)
	bt.RecordAndBan("b", "fp", 5, time.Minute, time.Minute)
	if _, ok := bt.failures["a"]; ok {
		t.Fatal("stale failures must be swept")
	}
}

func TestBanTrackerSweepKeepsFresh(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	bt := NewBanTracker(10, clk.Now)
	bt.RecordAndBan("1.1.1.1", "fp", 5, time.Minute, time.Minute)
	bt.Sweep(time.Minute)
	if len(bt.failures["1.1.1.1"]) != 1 {
		t.Fatalf("fresh failure must be kept: %+v", bt.failures)
	}
}

func TestBanTrackerEvictAllEmpty(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	bt := NewBanTracker(1, clk.Now)
	bt.failures["empty"] = nil
	bt.evictOldestLocked()
	if _, ok := bt.failures["empty"]; ok {
		t.Fatal("empty failure entry must be removed")
	}
}

func TestBanTrackerListBansExpired(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	bt := NewBanTracker(10, clk.Now)
	bt.RecordAndBan("1.1.1.1", "fp", 1, time.Minute, time.Minute)
	clk.Advance(2 * time.Minute)
	if bans := bt.ListBans(); len(bans) != 0 {
		t.Fatalf("expired bans must be omitted: %+v", bans)
	}
}
