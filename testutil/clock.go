// Package testutil provides deterministic test helpers: a fake clock and an
// in-process mock OIDC server with RSA JWKS signing.
package testutil

import (
	"net"
	"sync"
	"testing"
	"time"
)

// FakeClock is a thread-safe manually-advanced clock.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock returns a FakeClock initialized to initial.
func NewFakeClock(initial time.Time) *FakeClock {
	return &FakeClock{now: initial}
}

// Now returns the current fake time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// FreeListener returns a listener bound to an ephemeral loopback port. Tests
// must hand it to the server under test rather than probing-then-closing a
// port, which races with concurrent test binaries.
func FreeListener(t testing.TB) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free listener: %v", err)
	}
	return l
}
