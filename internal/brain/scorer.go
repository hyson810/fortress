package brain

import (
	"log"
	"math"
	"net"
	"sync"
	"time"
)

// ThreatLevel represents the severity of a detected threat
type ThreatLevel int

const (
	LevelNone     ThreatLevel = 0
	LevelLow      ThreatLevel = 25
	LevelMedium   ThreatLevel = 50
	LevelHigh     ThreatLevel = 75
	LevelCritical ThreatLevel = 100
)

func (l ThreatLevel) String() string {
	switch {
	case l >= LevelCritical: return "CRITICAL"
	case l >= LevelHigh:     return "HIGH"
	case l >= LevelMedium:   return "MEDIUM"
	case l >= LevelLow:      return "LOW"
	default:                 return "NONE"
	}
}

// DetectionWeights mirrors the Python scorer.py DETECTOR_WEIGHTS
type DetectionWeights struct {
	ScanDetect     float64
	FloodDetect    float64
	AnomalyDetect  float64
	DNSDetect      float64
	BruteForce     float64
	ARPDetect      float64
	HoneypotTrip   float64
	IntelMatch     float64
	FingerprintHit float64
}

// DefaultWeights returns the default detector weight configuration.
func DefaultWeights() DetectionWeights {
	return DetectionWeights{
		ScanDetect:     2.5,
		FloodDetect:    3.0,
		AnomalyDetect:  2.0,
		DNSDetect:      1.5,
		BruteForce:     3.5,
		ARPDetect:      4.0,
		HoneypotTrip:   5.0,
		IntelMatch:     2.0,
		FingerprintHit: 1.0,
	}
}

// AggressiveWeights returns detector weights tuned for active defense.
// Thresholds are lower, response is faster, and honeypot/intel matches
// carry more weight to accelerate escalation.
func AggressiveWeights() DetectionWeights {
	return DetectionWeights{
		ScanDetect:     3.5,
		FloodDetect:    4.5,
		AnomalyDetect:  3.0,
		DNSDetect:      2.5,
		BruteForce:     5.0,
		ARPDetect:      5.5,
		HoneypotTrip:   7.0,
		IntelMatch:     3.0,
		FingerprintHit: 2.0,
	}
}

// IPRecord tracks per-IP threat state
type IPRecord struct {
	IP              string
	FirstSeen       time.Time
	LastSeen        time.Time
	OpenPorts       int
	ScanScore       float64
	FloodScore      float64
	AnomalyScore    float64
	HoneypotScore   float64
	IntelScore      float64
	TotalScore      float64
	Level           ThreatLevel
	ResponseLevel   ResponseLevel
	Banned          bool
	BanExpires      time.Time
	HoneypotTripped bool
	IntelMatches    []string
	EvidencePath    string
}

// Scorer is the central threat scoring engine
type Scorer struct {
	mu       sync.RWMutex
	records  map[string]*IPRecord
	weights  DetectionWeights
	banTime  time.Duration
	maxSize  int
}

// NewScorer creates a threat scorer with the given weights
func NewScorer(weights DetectionWeights, banDuration time.Duration, maxRecords int) *Scorer {
	return &Scorer{
		records: make(map[string]*IPRecord),
		weights: weights,
		banTime: banDuration,
		maxSize: maxRecords,
	}
}

// GetOrCreate returns existing record or creates new one
func (s *Scorer) GetOrCreate(ip string) *IPRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r, ok := s.records[ip]; ok {
		r.LastSeen = time.Now()
		return r
	}

	// Evict oldest if at capacity
	if len(s.records) >= s.maxSize {
		var oldest string
		var oldestTime time.Time
		for k, v := range s.records {
			if oldest == "" || v.LastSeen.Before(oldestTime) {
				oldest = k
				oldestTime = v.LastSeen
			}
		}
		delete(s.records, oldest)
	}

	r := &IPRecord{
		IP:        ip,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	s.records[ip] = r
	return r
}

// AddScanScore increments scan detection score
func (s *Scorer) AddScanScore(ip string, ports int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r := s.records[ip]
	if r == nil {
		return
	}
	r.OpenPorts = ports
	// Score scales with port count using log to avoid linear runaway
	r.ScanScore = math.Log2(float64(ports+1)) * s.weights.ScanDetect
	s.recalc(r)
}

// AddFloodScore increments flood detection score
func (s *Scorer) AddFloodScore(ip string, pps float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r := s.records[ip]
	if r == nil {
		return
	}
	// Exponential scaling for high PPS
	r.FloodScore = math.Pow(pps/100, 1.5) * s.weights.FloodDetect
	s.recalc(r)
}

// AddAnomalyScore adds anomaly detection contribution
func (s *Scorer) AddAnomalyScore(ip string, zScore float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r := s.records[ip]
	if r == nil {
		return
	}
	r.AnomalyScore = math.Max(0, zScore-2.0) * s.weights.AnomalyDetect
	s.recalc(r)
}

// AddHoneypotTrip fires when an attacker interacts with a honeypot
func (s *Scorer) AddHoneypotTrip(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r := s.records[ip]
	if r == nil {
		return
	}
	r.HoneypotTripped = true
	r.HoneypotScore += s.weights.HoneypotTrip
	s.recalc(r)
}

// AddIntelMatch records an OSINT threat intel match
func (s *Scorer) AddIntelMatch(ip string, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r := s.records[ip]
	if r == nil {
		return
	}
	r.IntelMatches = append(r.IntelMatches, source)
	r.IntelScore += s.weights.IntelMatch
	s.recalc(r)
}

// BoostSubnetNeighbors adds a score boost to all tracked IPs in the same /24
// subnet as the given IP. This implements the V3.1 "子网免疫" (subnet immunity)
// feature: when one host in a /24 is malicious, neighbors are likely compromised
// too (botnet nodes, pivoted hosts, or lateral movement).
//
// The boost is small (10-20% of the triggering IP's score) to avoid false
// positives while still elevating neighbors for operator attention.
func (s *Scorer) BoostSubnetNeighbors(ip string, ratio float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ratio <= 0 {
		ratio = 0.15 // default: 15% boost
	}

	triggerIP := net.ParseIP(ip)
	if triggerIP == nil {
		return
	}
	triggerIP = triggerIP.To4()
	if triggerIP == nil {
		return // IPv6 not yet supported for subnet boost
	}

	r, ok := s.records[ip]
	if !ok {
		return
	}
	boost := r.TotalScore * ratio

	// Scan all tracked IPs for same /24.
	triggerPrefix := triggerIP.Mask(net.CIDRMask(24, 32))
	boosted := 0
	for otherIP, otherR := range s.records {
		if otherIP == ip {
			continue
		}
		parsed := net.ParseIP(otherIP)
		if parsed == nil {
			continue
		}
		parsed = parsed.To4()
		if parsed == nil {
			continue
		}
		otherPrefix := parsed.Mask(net.CIDRMask(24, 32))
		if triggerPrefix.Equal(otherPrefix) {
			// Add to ScanScore (not TotalScore) because recalc resets
			// TotalScore from component scores.
			otherR.ScanScore += boost
			s.recalc(otherR)
			boosted++
		}
	}

	if boosted > 0 {
		log.Printf("[scorer] subnet boost: %s triggered %.1f boost to %d /24 neighbors",
			ip, boost, boosted)
	}
}

// recalc recalculates total score and threat level (caller holds lock)
func (s *Scorer) recalc(r *IPRecord) {
	r.TotalScore = r.ScanScore + r.FloodScore + r.AnomalyScore + r.HoneypotScore + r.IntelScore

	switch {
	case r.TotalScore >= 85:
		r.Level = LevelCritical
	case r.TotalScore >= 60:
		r.Level = LevelHigh
	case r.TotalScore >= 35:
		r.Level = LevelMedium
	case r.TotalScore >= 10:
		r.Level = LevelLow
	default:
		r.Level = LevelNone
	}
}

// ShouldCounterstrike returns true if autonomous counterstrike is warranted
func (s *Scorer) ShouldCounterstrike(ip string, threshold float64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.records[ip]
	if !ok {
		return false
	}
	return r.TotalScore >= threshold
}

// GetTop prints the top-N most threatening IPs
func (s *Scorer) Top(n int) []*IPRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type scored struct {
		ip    string
		score float64
	}
	var sorted []scored
	for ip, r := range s.records {
		sorted = append(sorted, scored{ip, r.TotalScore})
	}

	// Simple bubble sort (small N, fine for real-time)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].score > sorted[i].score {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	result := make([]*IPRecord, 0, n)
	for i := 0; i < len(sorted) && i < n; i++ {
		if r, ok := s.records[sorted[i].ip]; ok {
			result = append(result, r)
		}
	}
	return result
}

// GetScore returns the total score and response level for an IP.
func (s *Scorer) GetScore(ip string) (float64, ResponseLevel) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[ip]
	if !ok {
		return 0, ResponseA
	}
	return r.TotalScore, r.ResponseLevel
}
