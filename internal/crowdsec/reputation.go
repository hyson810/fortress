package crowdsec

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// ReputationResult holds CrowdSec reputation data for an IP.
type ReputationResult struct {
	IP          string
	Exists      bool
	Labels      []string
	AttackCount int
	LastSeen    time.Time
	Score       int
}

type cacheEntry struct {
	result    ReputationResult
	expiresAt time.Time
}

// ReputationClient queries IP reputation with a built-in LRU cache.
type ReputationClient struct {
	cfg    ReputationConfig
	cache  map[string]*cacheEntry // LRU: map for O(1) lookup
	order  []string               // LRU order (front = most recent)
	mu     sync.Mutex
	client *http.Client
}

// NewReputationClient creates a new ReputationClient.
func NewReputationClient(cfg ReputationConfig) *ReputationClient {
	return &ReputationClient{
		cfg:   cfg,
		cache: make(map[string]*cacheEntry),
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

// Query returns reputation for an IP. Checks cache first; on miss, returns empty
// (no live query to avoid blocking pipeline). Live API query can be added later
// when a CAPI key is configured.
func (r *ReputationClient) Query(ctx context.Context, ip string) (*ReputationResult, bool) {
	r.mu.Lock()
	if entry, ok := r.cache[ip]; ok {
		if time.Now().Before(entry.expiresAt) {
			// Move to front (most recently used)
			r.touch(ip)
			r.mu.Unlock()
			return &entry.result, entry.result.Exists
		}
		// Expired -- remove
		delete(r.cache, ip)
		r.removeOrder(ip)
	}
	r.mu.Unlock()

	// No cache hit -- return empty (don't block pipeline with HTTP)
	return &ReputationResult{IP: ip, Exists: false}, false
}

// Store manually inserts a reputation result (for testing or batch updates).
func (r *ReputationClient) Store(result ReputationResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Evict if at capacity
	if len(r.cache) >= r.cfg.CacheSize {
		r.evictOldest()
	}

	r.cache[result.IP] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(r.cfg.CacheTTL),
	}
	r.prepend(result.IP)
}

// touch moves ip to front of order list.
func (r *ReputationClient) touch(ip string) {
	r.removeOrder(ip)
	r.order = append([]string{ip}, r.order...)
}

func (r *ReputationClient) prepend(ip string) {
	r.order = append([]string{ip}, r.order...)
}

func (r *ReputationClient) removeOrder(ip string) {
	for i, v := range r.order {
		if v == ip {
			r.order = append(r.order[:i], r.order[i+1:]...)
			return
		}
	}
}

func (r *ReputationClient) evictOldest() {
	if len(r.order) == 0 {
		return
	}
	oldest := r.order[len(r.order)-1]
	r.order = r.order[:len(r.order)-1]
	delete(r.cache, oldest)
}

// Size returns number of cached entries.
func (r *ReputationClient) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cache)
}
