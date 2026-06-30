package crowdsec

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestReputationQuery_Empty(t *testing.T) {
	cfg := ReputationConfig{
		CacheSize: 1024,
		CacheTTL:  10 * time.Minute,
		Timeout:   3 * time.Second,
	}
	client := NewReputationClient(cfg)

	result, ok := client.Query(context.Background(), "192.0.2.1")
	if ok {
		t.Error("Query for unknown IP should return false")
	}
	if result.Exists {
		t.Error("Query for unknown IP should have Exists=false")
	}
	if result.IP != "192.0.2.1" {
		t.Errorf("result.IP = %q, want %q", result.IP, "192.0.2.1")
	}
}

func TestReputationStoreAndQuery(t *testing.T) {
	cfg := ReputationConfig{
		CacheSize: 1024,
		CacheTTL:  10 * time.Minute,
		Timeout:   3 * time.Second,
	}
	client := NewReputationClient(cfg)

	stored := ReputationResult{
		IP:          "203.0.113.5",
		Exists:      true,
		Labels:      []string{"ssh-scanner", "bruteforce"},
		AttackCount: 42,
		LastSeen:    time.Now().Add(-1 * time.Hour),
		Score:       85,
	}
	client.Store(stored)

	got, ok := client.Query(context.Background(), "203.0.113.5")
	if !ok {
		t.Fatal("Query should return true for stored IP")
	}
	if !got.Exists {
		t.Error("stored result should have Exists=true")
	}
	if len(got.Labels) != 2 || got.Labels[0] != "ssh-scanner" {
		t.Errorf("Labels = %v, want [ssh-scanner bruteforce]", got.Labels)
	}
	if got.AttackCount != 42 {
		t.Errorf("AttackCount = %d, want 42", got.AttackCount)
	}
	if got.Score != 85 {
		t.Errorf("Score = %d, want 85", got.Score)
	}
}

func TestReputationCacheExpiry(t *testing.T) {
	cfg := ReputationConfig{
		CacheSize: 1024,
		CacheTTL:  50 * time.Millisecond,
		Timeout:   3 * time.Second,
	}
	client := NewReputationClient(cfg)

	client.Store(ReputationResult{
		IP:     "198.51.100.1",
		Exists: true,
		Score:  50,
	})

	// Should be fresh immediately
	_, ok := client.Query(context.Background(), "198.51.100.1")
	if !ok {
		t.Fatal("Query should return true immediately after store")
	}

	// Wait for expiry
	time.Sleep(60 * time.Millisecond)

	// Should be expired now
	got, ok := client.Query(context.Background(), "198.51.100.1")
	if ok {
		t.Error("Query should return false after TTL expiry")
	}
	if got.Exists {
		t.Error("Result should have Exists=false after expiry")
	}
}

func TestReputationCacheEviction(t *testing.T) {
	cfg := ReputationConfig{
		CacheSize: 3,
		CacheTTL:  10 * time.Minute,
		Timeout:   3 * time.Second,
	}
	client := NewReputationClient(cfg)

	// Fill cache with 3 items
	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		client.Store(ReputationResult{IP: ip, Exists: true, Score: i})
	}

	// Adding a 4th item should evict the oldest ("10.0.0.0")
	client.Store(ReputationResult{IP: "10.0.0.3", Exists: true, Score: 99})

	// 10.0.0.0 should be evicted (oldest)
	_, ok := client.Query(context.Background(), "10.0.0.0")
	if ok {
		t.Error("oldest entry (10.0.0.0) should be evicted")
	}

	// 10.0.0.1, 10.0.0.2, and 10.0.0.3 should still be in cache
	_, ok = client.Query(context.Background(), "10.0.0.1")
	if !ok {
		t.Error("10.0.0.1 should still be in cache")
	}
	_, ok = client.Query(context.Background(), "10.0.0.2")
	if !ok {
		t.Error("10.0.0.2 should still be in cache")
	}
	_, ok = client.Query(context.Background(), "10.0.0.3")
	if !ok {
		t.Error("10.0.0.3 should be in cache")
	}

	// Size should be 3
	if size := client.Size(); size != 3 {
		t.Errorf("cache size = %d, want 3", size)
	}
}

func TestReputationConcurrentAccess(t *testing.T) {
	cfg := ReputationConfig{
		CacheSize: 100,
		CacheTTL:  10 * time.Minute,
		Timeout:   3 * time.Second,
	}
	client := NewReputationClient(cfg)

	var wg sync.WaitGroup
	n := 50

	// Concurrent stores
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", id)
			client.Store(ReputationResult{
				IP:     ip,
				Exists: id%2 == 0,
				Score:  id,
			})
		}(i)
	}
	wg.Wait()

	// Concurrent queries
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", id)
			client.Query(context.Background(), ip)
		}(i)
	}
	wg.Wait()

	// Verify no races and cache size is reasonable
	if size := client.Size(); size == 0 {
		t.Error("cache should have entries after concurrent stores")
	}
}
