package brain

import (
	"sync"
	"time"

	"github.com/fortress/v6/internal/engine"
)

// DetectorWeights holds the per-detector score multipliers.
// Each weight is applied to a raw score of 100 per alert.
type DetectorWeights struct {
	PacketFlood, PacketScan, FlowScan, BehaviorEntropy, DNSTunnel,
	HTTPAttack, BruteForce, AnomalyL1, AnomalyL2, JA3Malicious,
	OSAnomaly, HoneypotHit, ARPSpoof float64
}

// DefaultWeights returns a conservative weight configuration suitable for
// most production deployments.
func DefaultWeights() DetectorWeights {
	return DetectorWeights{
		PacketFlood: 0.10, PacketScan: 0.10, FlowScan: 0.10,
		BehaviorEntropy: 0.08, DNSTunnel: 0.07, HTTPAttack: 0.10,
		BruteForce: 0.08, AnomalyL1: 0.07, AnomalyL2: 0.07,
		JA3Malicious: 0.05, OSAnomaly: 0.03, HoneypotHit: 0.30, ARPSpoof: 0.08,
	}
}

// AggressiveWeights returns elevated weights that trigger responses earlier.
func AggressiveWeights() DetectorWeights {
	w := DefaultWeights()
	w.PacketFlood = 0.15
	w.HTTPAttack = 0.15
	w.HoneypotHit = 0.35
	w.BruteForce = 0.12
	return w
}

// ResponseLevel encodes the four-tier defensive posture.
type ResponseLevel int

const (
	ResponseA ResponseLevel = iota // 0–25: Silent observation, log only
	ResponseB                       // 25–50: Active recon — WHOIS, rate limit, abuse draft
	ResponseC                       // 50–75: Predator — tarpit, honeypot, ban, OSINT, attack scan
	ResponseD                       // 75–100: Black hole — LLM deception, full weapon chain, swarm
)

// IPRecord accumulates threat signals for a single IP address.
type IPRecord struct {
	IP              string
	FirstSeen       time.Time
	LastSeen        time.Time
	TotalScore      float64
	ScanScore       float64
	FloodScore      float64
	AnomalyScore    float64
	HoneypotScore   float64
	IntelScore      float64
	ThreatCount     int
	HoneypotTripped bool
	Banned          bool
	ResponseLevel   ResponseLevel
}

// Scorer is the central threat scoring engine.
//
// It consumes threats from all seven detection engines, applies
// per-detector weights, and maps cumulative scores onto a four-tier
// response ladder (A/B/C/D).  It also tracks honeypot trips and
// external intelligence matches.
type Scorer struct {
	mu          sync.RWMutex
	records     map[string]*IPRecord
	weights     DetectorWeights
	banDuration time.Duration
	maxRecords  int
}

// NewScorer creates a new Scorer with the given weights, ban duration
// (in seconds), and maximum record capacity.
func NewScorer(weights DetectorWeights, banDurationSec, maxRecords int) *Scorer {
	return &Scorer{
		records:     make(map[string]*IPRecord),
		weights:     weights,
		banDuration: time.Duration(banDurationSec) * time.Second,
		maxRecords:  maxRecords,
	}
}

func (s *Scorer) getOrCreate(ip string) *IPRecord {
	r, ok := s.records[ip]
	if !ok {
		if len(s.records) >= s.maxRecords {
			s.evictOldest()
		}
		r = &IPRecord{IP: ip, FirstSeen: time.Now()}
		s.records[ip] = r
	}
	r.LastSeen = time.Now()
	return r
}

func (s *Scorer) evictOldest() {
	var oldest string
	var oldestT time.Time
	for ip, r := range s.records {
		if oldest == "" || r.LastSeen.Before(oldestT) {
			oldest = ip
			oldestT = r.LastSeen
		}
	}
	if oldest != "" {
		delete(s.records, oldest)
	}
}

// AddThreat processes a single engine.Threat, incrementing the
// corresponding score bucket for the source IP.
func (s *Scorer) AddThreat(threat engine.Threat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.getOrCreate(threat.IP)
	r.ThreatCount++
	switch threat.Type {
	case "SYN洪水", "UDP洪水", "ICMP洪水":
		r.FloodScore += s.weights.PacketFlood * 100
	case "SYN扫描", "FIN扫描", "Xmas扫描", "NULL扫描", "快速扫描", "中速扫描", "慢速扫描":
		r.ScanScore += s.weights.PacketScan * 100
	case "流量异常":
		r.AnomalyScore += s.weights.BehaviorEntropy * 100
	case "DNS隧道":
		r.AnomalyScore += s.weights.DNSTunnel * 100
	case "SQL注入攻击", "XSS攻击", "路径遍历攻击":
		r.AnomalyScore += s.weights.HTTPAttack * 100
	case "SSH爆破", "HTTP爆破":
		r.AnomalyScore += s.weights.BruteForce * 100
	case "混合异常":
		r.AnomalyScore += s.weights.AnomalyL1 * 100
	case "ARP应答":
		r.AnomalyScore += s.weights.ARPSpoof * 100
	}
	s.recalc(r)
}

// AddHoneypotTrip records that an IP interacted with a honeypot,
// applying the (typically high) honeypot weight.
func (s *Scorer) AddHoneypotTrip(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.getOrCreate(ip)
	r.HoneypotScore += s.weights.HoneypotHit * 100
	r.HoneypotTripped = true
	s.recalc(r)
}

// AddIntelMatch records an external intelligence hit for an IP.
func (s *Scorer) AddIntelMatch(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.getOrCreate(ip)
	r.IntelScore += 10
	s.recalc(r)
}

func (s *Scorer) recalc(r *IPRecord) {
	r.TotalScore = r.ScanScore + r.FloodScore + r.AnomalyScore + r.HoneypotScore + r.IntelScore
}

// GetScore returns the current cumulative score and response level for an IP.
func (s *Scorer) GetScore(ip string) (float64, ResponseLevel) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[ip]
	if !ok {
		return 0, ResponseA
	}
	return r.TotalScore, r.ResponseLevel
}

// ShouldCounterstrike returns true when the IP score meets or exceeds
// the given threshold.
func (s *Scorer) ShouldCounterstrike(ip string, threshold float64) bool {
	score, _ := s.GetScore(ip)
	return score >= threshold
}

// RecordCount returns the number of IP records currently tracked.
func (s *Scorer) RecordCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// CleanupStale decays every record and removes those whose decayed
// score falls below the floor after maxAge since last seen.
func (s *Scorer) CleanupStale(floor float64, maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for ip, r := range s.records {
		if time.Since(r.LastSeen) > maxAge {
			decayed := DecayScore(r.TotalScore, r.LastSeen, defaultHalfLife)
			if decayed < floor {
				delete(s.records, ip)
				removed++
			}
		}
	}
	return removed
}
