// Package shared provides utilities shared across Dagger modules.
package shared

import (
	"sync"
	"time"
)

// bucket is a token bucket for rate limiting a single source (IP).
type bucket struct {
	tokens    float64
	lastRefill time.Time
}

// RateLimiter is a simple per-key token bucket rate limiter.
// It is safe for concurrent use.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	burst    float64 // max tokens
	evictAfter time.Duration
	lastEvict time.Time
}

// NewRateLimiter creates a RateLimiter with the given rate (tokens/sec) and burst.
// Stale entries are evicted after evictAfter of inactivity.
func NewRateLimiter(rate, burst float64, evictAfter time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets:    make(map[string]*bucket),
		rate:       rate,
		burst:      burst,
		evictAfter: evictAfter,
		lastEvict:  time.Now(),
	}
}

// Allow reports whether a request from key is allowed.
// It refills tokens and deducts one token if allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Periodic eviction of stale entries
	if now.Sub(rl.lastEvict) > rl.evictAfter {
		rl.evictStaleLocked(now)
		rl.lastEvict = now
	}

	b, ok := rl.buckets[key]
	if !ok {
		// New bucket: start with full burst minus the one we consume
		b = &bucket{
			tokens:    rl.burst - 1,
			lastRefill: now,
		}
		rl.buckets[key] = b
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastRefill = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// evictStaleLocked removes entries that have not been seen since evictAfter.
// Must be called with mu held.
func (rl *RateLimiter) evictStaleLocked(now time.Time) {
	for key, b := range rl.buckets {
		if now.Sub(b.lastRefill) > rl.evictAfter {
			delete(rl.buckets, key)
		}
	}
}
