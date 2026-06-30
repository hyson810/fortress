package defense

import (
	"log"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ReputationScore represents an IP's threat score from 0.0 (fully trusted)
// to 1.0 (highly hostile).
type ReputationScore float64

const (
	ReputationTrusted ReputationScore = 0.0
	ReputationUnknown ReputationScore = 0.3
	ReputationHostile ReputationScore = 1.0

	// Thresholds for classification.
	highRiskThreshold ReputationScore = 0.7
	lowRiskThreshold  ReputationScore = 0.3

	// Default TTL for reputation entries.
	defaultReputationTTL = 24 * time.Hour
)

// ReputationFactors holds the individual components that contribute to an
// IP's reputation score.
type ReputationFactors struct {
	WhoisAge        float64 `json:"whois_age"`        // 0=new, 1=established
	ASNReputation   float64 `json:"asn_reputation"`   // 0=clean, 1=notorious
	CountryRisk     float64 `json:"country_risk"`     // country-based risk index
	HistoricalScore float64 `json:"historical_score"` // past attack history
	SwarmVotes      float64 `json:"swarm_votes"`      // peer consensus
	AttackFrequency float64 `json:"attack_frequency"` // recent attack count factor
}

// ReputationEntry stores the computed reputation for a single IP.
type ReputationEntry struct {
	IP          string            `json:"ip"`
	Score       ReputationScore   `json:"score"`
	Factors     ReputationFactors `json:"factors"`
	LastUpdated time.Time         `json:"last_updated"`
	LastSeen    time.Time         `json:"last_seen"`
	AttackTypes []string          `json:"attack_types,omitempty"`
	ttl         time.Duration
}

// IsExpired returns true if the entry has exceeded its TTL.
func (re *ReputationEntry) IsExpired() bool {
	if re.ttl <= 0 {
		re.ttl = defaultReputationTTL
	}
	return time.Since(re.LastUpdated) > re.ttl
}

// ReputationDB is an in-memory IP reputation database with per-entry TTL.
type ReputationDB struct {
	mu          sync.RWMutex
	entries     map[string]*ReputationEntry
	defaultTTL  time.Duration
	maxEntries  int
	highRiskASN map[string]float64  // known bad ASNs with severity
	highRiskCC  map[string]float64  // high-risk country codes
	stopCh      chan struct{}
}

// NewReputationDB creates a new reputation database with the given maximum
// number of entries.
func NewReputationDB(maxEntries int) *ReputationDB {
	if maxEntries <= 0 {
		maxEntries = 100000
	}

	db := &ReputationDB{
		entries:    make(map[string]*ReputationEntry),
		defaultTTL: defaultReputationTTL,
		maxEntries: maxEntries,
		highRiskASN: map[string]float64{
			"AS16276":  0.9, // OVH (common hosting for attacks)
			"AS36352":  0.7, // ColoCrossing
			"AS53667":  0.6, // FranTech
		},
		highRiskCC: map[string]float64{
			"KP": 0.9, // North Korea
			"IR": 0.7, // Iran
			"RU": 0.5, // Russia
			"CN": 0.4, // China
		},
		stopCh: make(chan struct{}),
	}

	go db.cleanupLoop()
	return db
}

// AddHighRiskASN registers an ASN with elevated risk for scoring.
func (db *ReputationDB) AddHighRiskASN(asn string, score float64) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.highRiskASN[asn] = score
}

// AddHighRiskCountry registers a country code with elevated risk.
func (db *ReputationDB) AddHighRiskCountry(cc string, score float64) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.highRiskCC[strings.ToUpper(cc)] = score
}

// Query returns the reputation score for an IP. If the IP has not been seen
// before, it returns ReputationUnknown (0.3) with a default entry.
func (db *ReputationDB) Query(ip string) ReputationScore {
	db.mu.RLock()
	entry, ok := db.entries[ip]
	db.mu.RUnlock()

	if ok && !entry.IsExpired() {
		return entry.Score
	}

	return ReputationUnknown
}

// GetEntry returns the full reputation entry for an IP or nil if not found
// or expired.
func (db *ReputationDB) GetEntry(ip string) *ReputationEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()

	entry, ok := db.entries[ip]
	if !ok || entry.IsExpired() {
		return nil
	}
	// Return a copy to avoid races.
	copyEntry := *entry
	copyEntry.AttackTypes = make([]string, len(entry.AttackTypes))
	copy(copyEntry.AttackTypes, entry.AttackTypes)
	return &copyEntry
}

// UpdateFromIntel recomputes reputation score factors from threat intel data.
func (db *ReputationDB) UpdateFromIntel(intel *IntelResult) {
	if intel == nil {
		return
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	entry := db.getOrCreateLocked(intel.IP)

	// ASN reputation factor.
	entry.Factors.ASNReputation = db.scoreASNLocked(intel.ASN)

	// Country risk factor.
	entry.Factors.CountryRisk = db.scoreCountryLocked(intel.Country)

	// Whois age heuristic: if we have an ASN and Org, age is likely > 0.
	// This is a heuristic proxy since whois doesn't always give creation dates.
	if intel.Org != "" {
		entry.Factors.WhoisAge = 0.5 // neutral — we know it's registered
	} else {
		entry.Factors.WhoisAge = 0.0 // no org = possibly ephemeral
	}

	entry.LastUpdated = time.Now()
	entry.ttl = db.defaultTTL
	db.recalcScoreLocked(entry)
}

// UpdateFromAttack increases the reputation score for an IP based on a
// detected attack type.
func (db *ReputationDB) UpdateFromAttack(ip string, attackType string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	entry := db.getOrCreateLocked(ip)
	entry.LastSeen = time.Now()
	entry.LastUpdated = time.Now()

	// Track attack types without duplicates.
	found := false
	for _, t := range entry.AttackTypes {
		if t == attackType {
			found = true
			break
		}
	}
	if !found {
		entry.AttackTypes = append(entry.AttackTypes, attackType)
	}

	// Adjust attack frequency factor.
	entry.Factors.AttackFrequency = math.Min(1.0, float64(len(entry.AttackTypes))*0.15)

	// Attack-type severity multiplier.
	severity := attackSeverity(attackType)
	entry.Factors.HistoricalScore = math.Min(1.0, entry.Factors.HistoricalScore+severity)

	entry.ttl = db.defaultTTL
	db.recalcScoreLocked(entry)

	log.Printf("[reputation] %s attack from %s: %s (score=%.2f)", attackType, ip, attackType, entry.Score)
}

// IsHighRisk returns true if the IP has a reputation score above 0.7.
func (db *ReputationDB) IsHighRisk(ip string) bool {
	return db.Query(ip) > highRiskThreshold
}

// ExportHighRisk returns a list of all IPs with reputation scores above the
// high-risk threshold.
func (db *ReputationDB) ExportHighRisk() []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var ips []string
	for ip, e := range db.entries {
		if e.IsExpired() {
			continue
		}
		if e.Score > highRiskThreshold {
			ips = append(ips, ip)
		}
	}
	return ips
}

// ExportForBlocklist returns IPs that should be blocked based on reputation
// and the given threshold.
func (db *ReputationDB) ExportForBlocklist(threshold ReputationScore) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var ips []string
	for ip, e := range db.entries {
		if e.IsExpired() {
			continue
		}
		if e.Score >= threshold {
			ips = append(ips, ip)
		}
	}
	return ips
}

// MergeWithPeers integrates reputation data from swarm peers. When conflicts
// arise, the higher score wins.
func (db *ReputationDB) MergeWithPeers(entries []*ReputationEntry) {
	db.mu.Lock()
	defer db.mu.Unlock()

	for _, peer := range entries {
		if peer == nil {
			continue
		}

		existing, ok := db.entries[peer.IP]
		if !ok || existing.IsExpired() {
			// New or expired entry — adopt peer data.
			entry := *peer
			entry.AttackTypes = make([]string, len(peer.AttackTypes))
			copy(entry.AttackTypes, peer.AttackTypes)
			entry.ttl = db.defaultTTL
			db.entries[peer.IP] = &entry
			continue
		}

		// Merge: adopt the higher score.
		if peer.Score > existing.Score {
			existing.Score = peer.Score
			existing.Factors = peer.Factors
			existing.LastUpdated = time.Now()
			existing.ttl = db.defaultTTL
		}

		// Always merge swarm votes.
		existing.Factors.SwarmVotes = math.Min(1.0,
			existing.Factors.SwarmVotes+peer.Factors.SwarmVotes)

		// Merge attack types.
		for _, at := range peer.AttackTypes {
			found := false
			for _, eat := range existing.AttackTypes {
				if eat == at {
					found = true
					break
				}
			}
			if !found {
				existing.AttackTypes = append(existing.AttackTypes, at)
			}
		}

		db.recalcScoreLocked(existing)
	}

	log.Printf("[reputation] merged %d peer entries", len(entries))
}

// TopThreats returns the top N highest-scored IPs, sorted descending.
func (db *ReputationDB) TopThreats(n int) []*ReputationEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()

	type scored struct {
		ip    string
		entry *ReputationEntry
	}

	list := make([]scored, 0, len(db.entries))
	for ip, e := range db.entries {
		if e.IsExpired() {
			continue
		}
		list = append(list, scored{ip, e})
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].entry.Score > list[j].entry.Score
	})

	out := make([]*ReputationEntry, 0, n)
	for i := 0; i < n && i < len(list); i++ {
		copy := *list[i].entry
		out = append(out, &copy)
	}
	return out
}

// Count returns the number of active entries in the database.
func (db *ReputationDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	n := 0
	for _, e := range db.entries {
		if !e.IsExpired() {
			n++
		}
	}
	return n
}

// ScoreDistribution returns buckets of score ranges for monitoring.
func (db *ReputationDB) ScoreDistribution() map[string]int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	dist := map[string]int{
		"0.0-0.2": 0,
		"0.2-0.4": 0,
		"0.4-0.6": 0,
		"0.6-0.8": 0,
		"0.8-1.0": 0,
	}

	for _, e := range db.entries {
		if e.IsExpired() {
			continue
		}
		switch {
		case e.Score < 0.2:
			dist["0.0-0.2"]++
		case e.Score < 0.4:
			dist["0.2-0.4"]++
		case e.Score < 0.6:
			dist["0.4-0.6"]++
		case e.Score < 0.8:
			dist["0.6-0.8"]++
		default:
			dist["0.8-1.0"]++
		}
	}
	return dist
}

// Stop halts the cleanup goroutine.
func (db *ReputationDB) Stop() {
	close(db.stopCh)
}

// getOrCreateLocked returns an existing entry or creates one with defaults.
// Must be called with mu held.
func (db *ReputationDB) getOrCreateLocked(ip string) *ReputationEntry {
	if entry, ok := db.entries[ip]; ok && !entry.IsExpired() {
		return entry
	}

	// Evict oldest if at capacity.
	if len(db.entries) >= db.maxEntries {
		db.evictOldestLocked()
	}

	entry := &ReputationEntry{
		IP:   ip,
		Score: ReputationScore(ReputationUnknown),
		Factors: ReputationFactors{
			WhoisAge:  0.5,
			CountryRisk: db.scoreCountryForIPLocked(ip),
		},
		LastUpdated: time.Now(),
		ttl:         db.defaultTTL,
	}
	db.entries[ip] = entry
	return entry
}

// recalcScoreLocked computes the weighted reputation score from factor
// components. Must be called with mu held.
func (db *ReputationDB) recalcScoreLocked(entry *ReputationEntry) {
	f := entry.Factors

	// Weighted combination of factors.
	score := 0.0 +
		(1.0-f.WhoisAge)*0.15 +       // newer domains = higher risk
		f.ASNReputation*0.20 +        // ASN reputation
		f.CountryRisk*0.15 +          // country risk
		f.HistoricalScore*0.25 +      // historical attacks
		f.SwarmVotes*0.10 +           // peer consensus
		f.AttackFrequency*0.15        // attack frequency

	entry.Score = ReputationScore(math.Min(1.0, math.Max(0.0, score)))
}

// scoreASNLocked returns a reputation factor for an ASN.
func (db *ReputationDB) scoreASNLocked(asn string) float64 {
	if score, ok := db.highRiskASN[asn]; ok {
		return score
	}
	return 0.0
}

// scoreCountryLocked returns a risk factor for a country code.
func (db *ReputationDB) scoreCountryLocked(cc string) float64 {
	cc = strings.ToUpper(cc)
	if score, ok := db.highRiskCC[cc]; ok {
		return score
	}
	return 0.05 // baseline slight risk for unknown
}

// scoreCountryForIPLocked attempts a naive country lookup. Since we can't
// do GeoIP without external data, this returns 0.05 baseline.
func (db *ReputationDB) scoreCountryForIPLocked(ip string) float64 {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0.0
	}

	// Check if it's a private/reserved IP.
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() {
		return 0.0 // trusted
	}

	return 0.05 // unknown — will be updated via UpdateFromIntel
}

// evictOldestLocked removes the entry with the oldest LastUpdated time.
func (db *ReputationDB) evictOldestLocked() {
	var oldest string
	var oldestTime time.Time

	for ip, e := range db.entries {
		if oldest == "" || e.LastUpdated.Before(oldestTime) {
			oldest = ip
			oldestTime = e.LastUpdated
		}
	}

	if oldest != "" {
		delete(db.entries, oldest)
	}
}

// cleanupLoop periodically removes expired entries.
func (db *ReputationDB) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			db.purgeExpired()
		case <-db.stopCh:
			return
		}
	}
}

// purgeExpired removes all entries that have exceeded their TTL.
func (db *ReputationDB) purgeExpired() {
	db.mu.Lock()
	defer db.mu.Unlock()

	for ip, e := range db.entries {
		if e.IsExpired() {
			delete(db.entries, ip)
		}
	}
}

// attackSeverity returns a score increment for different attack types.
func attackSeverity(attackType string) float64 {
	switch attackType {
	case "syn_flood":
		return 0.20
	case "udp_flood":
		return 0.18
	case "dns_amplification":
		return 0.25
	case "brute_force":
		return 0.15
	case "port_scan":
		return 0.10
	case "web_attack":
		return 0.15
	case "c2_beacon":
		return 0.30
	case "data_exfiltration":
		return 0.35
	case "ransomware":
		return 0.40
	case "malware_delivery":
		return 0.30
	default:
		return 0.05
	}
}
