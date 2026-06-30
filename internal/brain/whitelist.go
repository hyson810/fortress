package brain

import (
	"sync"
	"time"
)

// LearnedWhitelist automatically identifies safe IPs from traffic patterns.
// IPs with consistently benign behavior accumulate trust and can be
// auto-whitelisted to avoid false positives against friendly traffic.
type LearnedWhitelist struct {
	entries map[string]*trustEntry
	maxSize int

	mu sync.RWMutex
}

type trustEntry struct {
	IP             string
	TrustScore     float64 // 0.0 = unknown, 1.0 = fully trusted
	FirstSeen      time.Time
	LastSeen       time.Time
	Observations   int
	ConsistentDays int // consecutive days with benign behavior
	Behaviors      []string
	DecayRate      float64 // per-day trust decay
}

// NewLearnedWhitelist creates a dynamic whitelist learner.
func NewLearnedWhitelist(maxEntries int) *LearnedWhitelist {
	return &LearnedWhitelist{
		entries: make(map[string]*trustEntry),
		maxSize: maxEntries,
	}
}

// IsAutoWhitelisted returns true if the IP has earned sufficient trust (>0.95).
func (lw *LearnedWhitelist) IsAutoWhitelisted(ip string) bool {
	lw.mu.RLock()
	defer lw.mu.RUnlock()
	e, ok := lw.entries[ip]
	return ok && e.TrustScore >= 0.95
}

// IsManualWhitelisted checks against an external static list.
func (lw *LearnedWhitelist) IsManualWhitelisted(ip string, staticList []string) bool {
	for _, wl := range staticList {
		if wl == ip {
			return true
		}
	}
	return false
}

// LearnFromTraffic updates trust for an IP based on observed behavior.
// benign=true increases trust, benign=false decreases it.
func (lw *LearnedWhitelist) LearnFromTraffic(ip, behavior string, benign bool) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	e, ok := lw.entries[ip]
	if !ok {
		if len(lw.entries) >= lw.maxSize {
			lw.evictOldest()
		}
		e = &trustEntry{
			IP:        ip,
			FirstSeen: time.Now(),
			DecayRate: 0.01, // 1% trust decay per day
		}
		lw.entries[ip] = e
	}

	e.LastSeen = time.Now()
	e.Observations++

	// Trim behavior history
	if len(e.Behaviors) > 100 {
		e.Behaviors = e.Behaviors[len(e.Behaviors)-100:]
	}
	e.Behaviors = append(e.Behaviors, behavior)

	if benign {
		// Increase trust: logistic growth toward 1.0
		growth := 0.05 * (1.0 - e.TrustScore)
		e.TrustScore += growth

		// Track consistency
		if time.Since(e.FirstSeen) > 24*time.Hour*time.Duration(e.ConsistentDays+1) {
			e.ConsistentDays++
		}
	} else {
		// Decrease trust: faster decay on bad behavior
		penalty := 0.15 * e.TrustScore
		e.TrustScore -= penalty
		e.ConsistentDays = 0
	}

	// Clamp
	if e.TrustScore < 0 {
		e.TrustScore = 0
	}
	if e.TrustScore > 1.0 {
		e.TrustScore = 1.0
	}
}

// DecayTrust applies time-based trust decay for all entries.
// Should be called periodically (e.g., hourly).
func (lw *LearnedWhitelist) DecayTrust() {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	now := time.Now()
	for ip, e := range lw.entries {
		daysSince := now.Sub(e.LastSeen).Hours() / 24
		if daysSince > 0 {
			e.TrustScore -= e.DecayRate * daysSince
			if e.TrustScore < 0 {
				e.TrustScore = 0
			}
		}
		// Remove entries with zero trust after 7 days of inactivity
		if e.TrustScore <= 0 && daysSince > 7 {
			delete(lw.entries, ip)
		}
	}
}

// ExportWhitelist returns all IPs with trust >= threshold for swarm sharing.
func (lw *LearnedWhitelist) ExportWhitelist(threshold float64) []string {
	lw.mu.RLock()
	defer lw.mu.RUnlock()

	var result []string
	for ip, e := range lw.entries {
		if e.TrustScore >= threshold {
			result = append(result, ip)
		}
	}
	return result
}

// TrustLevel returns the trust score for an IP.
func (lw *LearnedWhitelist) TrustLevel(ip string) float64 {
	lw.mu.RLock()
	defer lw.mu.RUnlock()
	if e, ok := lw.entries[ip]; ok {
		return e.TrustScore
	}
	return 0
}

// MergePeers incorporates whitelist entries from swarm peers.
// Lower-trust entries don't overwrite higher-trust ones.
func (lw *LearnedWhitelist) MergePeers(peerEntries map[string]float64) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	for ip, peerTrust := range peerEntries {
		if existing, ok := lw.entries[ip]; ok {
			// Keep the higher trust score
			if peerTrust > existing.TrustScore {
				existing.TrustScore = peerTrust
			}
		} else {
			if len(lw.entries) >= lw.maxSize {
				lw.evictOldest()
			}
			lw.entries[ip] = &trustEntry{
				IP:         ip,
				TrustScore: peerTrust,
				FirstSeen:  time.Now(),
				LastSeen:   time.Now(),
				DecayRate:  0.01,
			}
		}
	}
}

// Size returns the number of tracked entries.
func (lw *LearnedWhitelist) Size() int {
	lw.mu.RLock()
	defer lw.mu.RUnlock()
	return len(lw.entries)
}

// evictOldest removes the entry with the oldest LastSeen (caller holds lock).
func (lw *LearnedWhitelist) evictOldest() {
	var oldestIP string
	var oldestTime time.Time
	for ip, e := range lw.entries {
		if oldestIP == "" || e.LastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = e.LastSeen
		}
	}
	if oldestIP != "" {
		delete(lw.entries, oldestIP)
	}
}
