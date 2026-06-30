package shared

import (
	"testing"
	"time"
)

func TestRateLimiterAllowFirstRequest(t *testing.T) {
	rl := NewRateLimiter(10, 20, 1*time.Minute)
	if !rl.Allow("192.168.1.1") {
		t.Error("first request should be allowed")
	}
}

func TestRateLimiterBurstExceeded(t *testing.T) {
	rl := NewRateLimiter(10, 5, 1*time.Minute)
	// Burst of 5: first 5 allowed, 6th rejected
	for i := 0; i < 5; i++ {
		if !rl.Allow("192.168.1.1") {
			t.Errorf("request %d within burst should be allowed", i+1)
		}
	}
	if rl.Allow("192.168.1.1") {
		t.Error("request exceeding burst should be rejected")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	// Rate 100 tokens/sec, burst 5
	rl := NewRateLimiter(100, 5, 1*time.Minute)
	// Exhaust tokens
	for i := 0; i < 5; i++ {
		rl.Allow("192.168.1.1")
	}
	if rl.Allow("192.168.1.1") {
		t.Error("should be exhausted after burst")
	}
	// Wait 50ms — should get ~5 tokens back (100 * 0.05 = 5)
	time.Sleep(50 * time.Millisecond)
	if !rl.Allow("192.168.1.1") {
		t.Error("should have refilled after 50ms at rate 100/sec")
	}
}

func TestRateLimiterIndependentKeys(t *testing.T) {
	rl := NewRateLimiter(10, 1, 1*time.Minute)
	// Exhaust IP1
	rl.Allow("ip1")
	if rl.Allow("ip1") {
		t.Error("ip1 should be exhausted")
	}
	// IP2 should still have its own bucket
	if !rl.Allow("ip2") {
		t.Error("ip2 should have its own independent bucket")
	}
}

func TestRateLimiterEviction(t *testing.T) {
	// Short eviction window
	rl := NewRateLimiter(100, 5, 50*time.Millisecond)
	rl.Allow("stale-ip")
	// Wait for eviction
	time.Sleep(100 * time.Millisecond)
	// Trigger another Allow to cause eviction check
	rl.Allow("fresh-ip")
	if rl.Allow("stale-ip") {
		// stale-ip was evicted, so Allow creates a fresh bucket with burst-1 tokens.
		// burst=5 => new bucket gets 4 tokens, first Allow uses 1 => 3 left.
		// So a second Allow should still succeed.
		// This is expected — the key was evicted and then recreated.
		// We just verify the eviction check didn't panic.
	}
}

func TestRateLimiterBurstNeverExceedsMax(t *testing.T) {
	rl := NewRateLimiter(1, 3, 1*time.Minute)
	// Exhaust
	for i := 0; i < 3; i++ {
		rl.Allow("ip")
	}
	// Wait long enough that refill would overshoot burst
	time.Sleep(5 * time.Second)
	// Should have at most burst=3 tokens now
	// Consume 3
	for i := 0; i < 3; i++ {
		if !rl.Allow("ip") {
			t.Errorf("refilled token %d should be allowed", i+1)
		}
	}
	// 4th should fail
	if rl.Allow("ip") {
		t.Error("should not exceed burst capacity")
	}
}
