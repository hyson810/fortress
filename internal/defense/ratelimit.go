package defense

import (
	"container/list"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimitState holds per-IP token bucket state.
type RateLimitState struct {
	Tokens     float64   `json:"tokens"`
	LastRefill time.Time `json:"last_refill"`
	Allowed    int64     `json:"allowed"`
	Denied     int64     `json:"denied"`
	BurstLimit int       `json:"burst_limit"`
}

// TokenBucket implements a per-IP token bucket rate limiter backed by
// nftables sets on Linux. On non-Linux systems it degrades to an
// in-memory only mode suitable for observation and logging.
type TokenBucket struct {
	mu           sync.Mutex
	states       map[string]*RateLimitState
	lruList      *list.List
	lruIndex     map[string]*list.Element
	capacity     int
	ratePerSec   float64
	refillRate   float64
	maxEntries   int
	nftEnabled   bool
	nftTable     string
	cleanupTicker *time.Ticker
	stopCh       chan struct{}
}

// lruEntry pairs an IP with its position in the LRU list.
type lruEntry struct {
	IP string
}

// RateLimitConfig configures a TokenBucket rate limiter.
type RateLimitConfig struct {
	Capacity    int     // max tokens per bucket
	RatePerSec  float64 // tokens added per second
	MaxEntries  int     // max tracked IPs before LRU eviction
}

// DefaultRateLimitConfig returns sensible defaults for rate limiting.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Capacity:   10,
		RatePerSec: 2.0,
		MaxEntries: 50000,
	}
}

// NewTokenBucket creates a new TokenBucket with the given configuration.
func NewTokenBucket(cfg RateLimitConfig) *TokenBucket {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 10
	}
	if cfg.RatePerSec <= 0 {
		cfg.RatePerSec = 2.0
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 50000
	}

	tb := &TokenBucket{
		states:     make(map[string]*RateLimitState),
		lruList:    list.New(),
		lruIndex:   make(map[string]*list.Element),
		capacity:   cfg.Capacity,
		ratePerSec: cfg.RatePerSec,
		refillRate: cfg.RatePerSec / float64(time.Second), // per-nanosecond refill
		maxEntries: cfg.MaxEntries,
		nftTable:   "fortress",
		stopCh:     make(chan struct{}),
	}

	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("nft"); err == nil {
			tb.nftEnabled = true
			tb.initNFTablesSet()
		} else {
			log.Printf("[ratelimit] nft not available — running in observe-only mode")
		}
	} else {
		log.Printf("[ratelimit] non-Linux OS (%s) — running in observe-only mode", runtime.GOOS)
	}

	go tb.cleanup()
	return tb
}

// initNFTablesSet creates the nftables set used for dynamic rate limiting.
func (tb *TokenBucket) initNFTablesSet() {
	cmds := [][]string{
		{"nft", "add", "table", "inet", tb.nftTable},
		{"nft", "add", "set", "inet", tb.nftTable, "ratelimit4",
			"{ type ipv4_addr; flags timeout; }"},
	}
	for _, cmd := range cmds {
		exec.Command(cmd[0], cmd[1:]...).Run()
	}
}

// Allow checks whether the given IP is allowed to proceed. It consumes one
// token from the bucket. Returns true if the request is allowed.
func (tb *TokenBucket) Allow(ip string) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	state := tb.getOrCreateStateLocked(ip)
	now := time.Now()
	tb.refillLocked(state, now)

	if state.Tokens >= 1.0 {
		state.Tokens -= 1.0
		atomic.AddInt64(&state.Allowed, 1)
		return true
	}

	atomic.AddInt64(&state.Denied, 1)
	return false
}

// IsRateLimited checks whether the given IP is currently rate limited
// (has fewer than 1 token available) without consuming any tokens.
func (tb *TokenBucket) IsRateLimited(ip string) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	state, ok := tb.states[ip]
	if !ok {
		return false
	}

	now := time.Now()
	tb.refillLocked(state, now)
	return state.Tokens < 1.0
}

// SetBurst overrides the burst capacity for a specific IP.
func (tb *TokenBucket) SetBurst(ip string, burst int) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	state := tb.getOrCreateStateLocked(ip)
	state.BurstLimit = burst
	if state.Tokens > float64(burst) {
		state.Tokens = float64(burst)
	}
}

// GetRateLimitStats returns allowed/denied counters for an IP.
func (tb *TokenBucket) GetRateLimitStats(ip string) (allowed, denied int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	state, ok := tb.states[ip]
	if !ok {
		return 0, 0
	}
	return atomic.LoadInt64(&state.Allowed), atomic.LoadInt64(&state.Denied)
}

// ResetStats zeroes the rate-limit counters for an IP.
func (tb *TokenBucket) ResetStats(ip string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	state, ok := tb.states[ip]
	if !ok {
		return
	}
	atomic.StoreInt64(&state.Allowed, 0)
	atomic.StoreInt64(&state.Denied, 0)
}

// BlockIPNFT adds the IP to the nftables rate-limit set with a timeout.
func (tb *TokenBucket) BlockIPNFT(ip string, timeout time.Duration) error {
	if !tb.nftEnabled {
		return nil
	}

	cmd := exec.Command("nft", "add", "element", "inet", tb.nftTable, "ratelimit4",
		fmt.Sprintf("{ %s timeout %ds }", ip, int(timeout.Seconds())))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ratelimit nft block %s: %w (%s)", ip, err, string(out))
	}
	return nil
}

// TrackedIPCount returns the number of IPs currently being tracked.
func (tb *TokenBucket) TrackedIPCount() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return len(tb.states)
}

// getOrCreateStateLocked returns existing state or creates a new entry,
// maintaining the LRU list. Must be called with mu held.
func (tb *TokenBucket) getOrCreateStateLocked(ip string) *RateLimitState {
	if state, ok := tb.states[ip]; ok {
		tb.touchLRULocked(ip)
		return state
	}

	// Evict oldest if at capacity.
	if len(tb.states) >= tb.maxEntries {
		tb.evictOldestLocked()
	}

	state := &RateLimitState{
		Tokens:     float64(tb.capacity),
		LastRefill: time.Now(),
		BurstLimit: tb.capacity,
	}
	tb.states[ip] = state
	el := tb.lruList.PushFront(&lruEntry{IP: ip})
	tb.lruIndex[ip] = el
	return state
}

// refillLocked updates token count based on elapsed time. Must be called
// with mu held.
func (tb *TokenBucket) refillLocked(state *RateLimitState, now time.Time) {
	elapsed := now.Sub(state.LastRefill)
	if elapsed <= 0 {
		return
	}
	state.LastRefill = now

	add := float64(elapsed) * tb.refillRate
	state.Tokens += add

	maxTokens := float64(tb.capacity)
	if state.BurstLimit > 0 {
		maxTokens = float64(state.BurstLimit)
	}
	if state.Tokens > maxTokens {
		state.Tokens = maxTokens
	}
}

// touchLRULocked moves an IP to the front of the LRU list.
func (tb *TokenBucket) touchLRULocked(ip string) {
	if el, ok := tb.lruIndex[ip]; ok {
		tb.lruList.MoveToFront(el)
	}
}

// evictOldestLocked removes the least-recently-used entry.
func (tb *TokenBucket) evictOldestLocked() {
	el := tb.lruList.Back()
	if el == nil {
		return
	}
	entry := el.Value.(*lruEntry)
	delete(tb.states, entry.IP)
	delete(tb.lruIndex, entry.IP)
	tb.lruList.Remove(el)
}

// cleanup periodically evicts stale entries that haven't been accessed
// in over 10 minutes.
func (tb *TokenBucket) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tb.purgeStale(10 * time.Minute)
		case <-tb.stopCh:
			return
		}
	}
}

// purgeStale removes entries whose last refill is older than maxAge.
func (tb *TokenBucket) purgeStale(maxAge time.Duration) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	for ip, state := range tb.states {
		if now.Sub(state.LastRefill) > maxAge && atomic.LoadInt64(&state.Allowed)+atomic.LoadInt64(&state.Denied) == 0 {
			if el, ok := tb.lruIndex[ip]; ok {
				tb.lruList.Remove(el)
				delete(tb.lruIndex, ip)
			}
			delete(tb.states, ip)
		}
	}
}

// Stop halts the cleanup goroutine. The TokenBucket should not be used
// after calling Stop.
func (tb *TokenBucket) Stop() {
	close(tb.stopCh)
}
