// Package brain implements the Fortress AI engine: threat scoring, pattern
// recognition, and predictive defense.
//
// classifier.go provides ML-style attack type classification using
// heuristic pattern matching against observed threat signals.
package brain

import (
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// AttackType — enumeration of known attack vectors
// ---------------------------------------------------------------------------

// AttackType classifies the kind of attack observed.
type AttackType int

const (
	AttackUnknown        AttackType = iota // 0 — unclassified
	AttackSYNFlood                          // 1
	AttackUDPFlood                          // 2
	AttackPortScan                          // 3
	AttackDNSTunnel                         // 4
	AttackSQLInjection                      // 5
	AttackXSS                               // 6
	AttackPathTraversal                     // 7
	AttackSSHBruteForce                      // 8
	AttackHTTPBruteForce                     // 9
	AttackARPSpoof                           // 10
	AttackCobaltStrike                       // 11
	AttackMetasploit                         // 12
	AttackAPT                                // 13
	AttackDataExfiltration                   // 14
)

// String returns a human-readable label for the attack type.
func (a AttackType) String() string {
	switch a {
	case AttackUnknown:
		return "Unknown"
	case AttackSYNFlood:
		return "SYN Flood"
	case AttackUDPFlood:
		return "UDP Flood"
	case AttackPortScan:
		return "Port Scan"
	case AttackDNSTunnel:
		return "DNS Tunnel"
	case AttackSQLInjection:
		return "SQL Injection"
	case AttackXSS:
		return "XSS"
	case AttackPathTraversal:
		return "Path Traversal"
	case AttackSSHBruteForce:
		return "SSH Brute Force"
	case AttackHTTPBruteForce:
		return "HTTP Brute Force"
	case AttackARPSpoof:
		return "ARP Spoof"
	case AttackCobaltStrike:
		return "Cobalt Strike"
	case AttackMetasploit:
		return "Metasploit"
	case AttackAPT:
		return "APT"
	case AttackDataExfiltration:
		return "Data Exfiltration"
	default:
		return fmt.Sprintf("AttackType(%d)", int(a))
	}
}

// SeverityByType maps each attack type to its base severity multiplier (0-1).
// These are heuristics derived from common CVSS distributions and incident
// response priorities.
var SeverityByType = map[AttackType]float64{
	AttackUnknown:        0.3,
	AttackSYNFlood:       0.6,
	AttackUDPFlood:       0.6,
	AttackPortScan:       0.2,
	AttackDNSTunnel:      0.7,
	AttackSQLInjection:   0.9,
	AttackXSS:            0.5,
	AttackPathTraversal:  0.7,
	AttackSSHBruteForce:   0.8,
	AttackHTTPBruteForce:  0.7,
	AttackARPSpoof:        0.9,
	AttackCobaltStrike:    0.95,
	AttackMetasploit:      0.85,
	AttackAPT:             1.0,
	AttackDataExfiltration: 0.95,
}

// Threat wraps an IPRecord with additional classification metadata used
// by the classifier. It intentionally embeds the *IPRecord so callers
// can access all existing fields while the classifier adds its own
// observations on top.
type Threat struct {
	*IPRecord
	// ObservationWindow is how long this IP has been tracked.
	ObservationWindow time.Duration
	// PacketRate is the observed packets-per-second average.
	PacketRate float64
	// PortsScanned is the count of unique destination ports contacted.
	PortsScanned int
	// DNSQueries is the count of DNS queries observed from this IP.
	DNSQueries int
	// HTTPPaths is the set of HTTP paths requested (for injection/XSS detection).
	HTTPPaths []string
	// ProtocolHints contains protocol-level flags observed (e.g. "syn", "ack", "fin").
	ProtocolHints []string
	// PayloadSamples contains a small sample of payload snippets for pattern matching.
	PayloadSamples []string
	// Intensity is a merged threat intensity score (0-100) combining all signals.
	Intensity float64
}

// NewThreat creates a Threat wrapper from an IPRecord with defaults.
func NewThreat(r *IPRecord) *Threat {
	return &Threat{
		IPRecord:    r,
		Intensity:   r.TotalScore,
	}
}

// ---------------------------------------------------------------------------
// classificationRule — internal rule for heuristic matching
// ---------------------------------------------------------------------------

type classificationRule struct {
	attackType AttackType
	// match returns a confidence [0,1] that the threat matches this type.
	match func(t *Threat) float64
}

// ---------------------------------------------------------------------------
// ClassifyAttack — the primary entry point
// ---------------------------------------------------------------------------

// ClassifyAttack analyzes a set of threats and determines the most likely
// attack type using heuristic rules. Returns the dominant attack type and
// a confidence score [0,1].
//
// When multiple threats are provided, the classifier looks for correlated
// patterns across them (e.g., many IPs performing the same kind of probe).
// For a single threat, it matches against individual signal profiles.
func ClassifyAttack(threats []Threat) (AttackType, float64) {
	if len(threats) == 0 {
		return AttackUnknown, 0
	}

	rules := classificationRules()

	// Aggregate scores across all rules
	scores := make(map[AttackType]float64)
	var totalWeight float64

	for _, t := range threats {
		for _, rule := range rules {
			conf := rule.match(&t)
			if conf > 0 {
				scores[rule.attackType] += conf
				totalWeight += conf
			}
		}
	}

	if totalWeight == 0 {
		return AttackUnknown, 0
	}

	// Find highest-scoring attack type
	var best AttackType
	var bestScore float64
	for at, s := range scores {
		if s > bestScore {
			bestScore = s
			best = at
		}
	}

	// Normalize confidence to [0,1]
	confidence := bestScore / totalWeight
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.1 {
		return AttackUnknown, confidence
	}

	return best, confidence
}

// ---------------------------------------------------------------------------
// ClassifySingle — convenience wrapper for a single threat
// ---------------------------------------------------------------------------

// ClassifySingle classifies a single threat and returns the attack type
// with its confidence score.
func ClassifySingle(t *Threat) (AttackType, float64) {
	return ClassifyAttack([]Threat{*t})
}

// ---------------------------------------------------------------------------
// classificationRules — all heuristic detection rules
// ---------------------------------------------------------------------------

func classificationRules() []classificationRule {
	return []classificationRule{
		// SYN flood: high packet rate + SYN protocol hint + high flood score
		{
			attackType: AttackSYNFlood,
			match: func(t *Threat) float64 {
				if t.FloodScore < 10 {
					return 0
				}
				hasSYN := containsHint(t.ProtocolHints, "syn")
				if !hasSYN {
					return 0.1
				}
				conf := minFloat64(1.0, t.FloodScore/80.0)
				if t.PacketRate > 500 {
					conf = minFloat64(1.0, conf+0.2)
				}
				return conf
			},
		},
		// UDP flood: high packet rate + no TCP flags + high flood score
		{
			attackType: AttackUDPFlood,
			match: func(t *Threat) float64 {
				if t.FloodScore < 10 {
					return 0
				}
				hasTCP := containsHint(t.ProtocolHints, "syn") ||
					containsHint(t.ProtocolHints, "ack") ||
					containsHint(t.ProtocolHints, "fin")
				if hasTCP {
					return 0
				}
				conf := minFloat64(1.0, t.FloodScore/80.0)
				if t.PacketRate > 1000 {
					conf = minFloat64(1.0, conf+0.3)
				}
				return conf
			},
		},
		// Port scan: high scan score + multiple ports + low flood
		{
			attackType: AttackPortScan,
			match: func(t *Threat) float64 {
				if t.ScanScore < 5 {
					return 0
				}
				conf := minFloat64(1.0, t.ScanScore/30.0)
				if t.PortsScanned >= 10 {
					conf = minFloat64(1.0, conf+0.3)
				}
				if t.PortsScanned >= 100 {
					conf = minFloat64(1.0, conf+0.3)
				}
				// Lower confidence if there is also a flood
				if t.FloodScore > 20 {
					conf *= 0.5
				}
				return conf
			},
		},
		// DNS tunnel: high DNS query count + anomaly score
		{
			attackType: AttackDNSTunnel,
			match: func(t *Threat) float64 {
				if t.DNSQueries < 50 {
					return 0
				}
				conf := minFloat64(1.0, float64(t.DNSQueries)/500.0)
				if t.AnomalyScore > 5 {
					conf = minFloat64(1.0, conf+0.3)
				}
				// Long payloads in DNS suggest tunneling
				for _, s := range t.PayloadSamples {
					if len(s) > 200 {
						conf = minFloat64(1.0, conf+0.2)
						break
					}
				}
				return conf
			},
		},
		// SQL injection: SQL keywords in payloads or HTTP paths
		{
			attackType: AttackSQLInjection,
			match: func(t *Threat) float64 {
				indicators := []string{
					"select", "union", "insert", "update", "delete",
					"drop table", "exec(", "1=1", "1'='1",
					"information_schema", "sleep(", "benchmark(",
				}
				return payloadMatchConfidence(t, indicators)
			},
		},
		// XSS: script tags or event handlers in payloads/HTTP paths
		{
			attackType: AttackXSS,
			match: func(t *Threat) float64 {
				indicators := []string{
					"<script", "javascript:", "onerror=", "onload=",
					"alert(", "document.cookie", "<img", "<svg",
					"<iframe", "eval(",
				}
				return payloadMatchConfidence(t, indicators)
			},
		},
		// Path traversal: dot-dot patterns in paths or payloads
		{
			attackType: AttackPathTraversal,
			match: func(t *Threat) float64 {
				indicators := []string{
					"../", "..\\", "/etc/passwd", "/etc/shadow",
					"c:\\windows", "boot.ini", "wp-config", ".htaccess",
					"%2e%2e", "%2f", "\\x2e\\x2e",
				}
				return payloadMatchConfidence(t, indicators)
			},
		},
		// SSH brute force: multiple ports scanned including 22 + anomaly
		{
			attackType: AttackSSHBruteForce,
			match: func(t *Threat) float64 {
				if t.PortsScanned < 2 {
					return 0
				}
				hasPort22 := false
				for _, h := range t.ProtocolHints {
					if strings.Contains(h, "22") || strings.Contains(h, "ssh") {
						hasPort22 = true
						break
					}
				}
				if !hasPort22 && t.ScanScore < 5 {
					return 0
				}
				conf := minFloat64(1.0, t.AnomalyScore/20.0+0.2)
				if t.PacketRate > 100 {
					conf = minFloat64(1.0, conf+0.3)
				}
				return conf
			},
		},
		// HTTP brute force: paths targeting login endpoints + high rate
		{
			attackType: AttackHTTPBruteForce,
			match: func(t *Threat) float64 {
				loginPaths := []string{
					"/login", "/wp-login", "/admin", "/signin",
					"/auth", "/oauth", "/api/login", ".php",
				}
				conf := pathPrefixMatchConfidence(t, loginPaths)
				if conf > 0 && t.PacketRate > 50 {
					conf = minFloat64(1.0, conf+0.2)
				}
				if t.AnomalyScore > 10 {
					conf = minFloat64(1.0, conf+0.2)
				}
				return conf
			},
		},
		// ARP spoof: ARP protocol hints + honeypot trip
		{
			attackType: AttackARPSpoof,
			match: func(t *Threat) float64 {
				hasARP := containsHint(t.ProtocolHints, "arp")
				if !hasARP && !t.HoneypotTripped {
					return 0
				}
				conf := 0.5
				if hasARP {
					conf = 0.7
				}
				if t.HoneypotTripped {
					conf = minFloat64(1.0, conf+0.3)
				}
				return conf
			},
		},
		// Cobalt Strike: known C2 beacon patterns in payload
		{
			attackType: AttackCobaltStrike,
			match: func(t *Threat) float64 {
				indicators := []string{
					"MZ", "ReflectiveLoader", "beacon",
					"Cookie:", "microsoft.com/", "jquery",
					"MSF", "meterpreter",
				}
				conf := payloadMatchConfidence(t, indicators)
				if conf > 0 && t.HoneypotTripped {
					conf = minFloat64(1.0, conf+0.2)
				}
				return conf
			},
		},
		// Metasploit: meterpreter/reverse shell patterns
		{
			attackType: AttackMetasploit,
			match: func(t *Threat) float64 {
				indicators := []string{
					"meterpreter", "reverse_tcp", "bind_tcp",
					"exploit/", "auxiliary/", "payload/",
					"shell_reverse", "metsvc",
				}
				return payloadMatchConfidence(t, indicators)
			},
		},
		// APT: high intel score + long observation window + high total score
		{
			attackType: AttackAPT,
			match: func(t *Threat) float64 {
				if t.IntelScore < 5 {
					return 0
				}
				conf := minFloat64(1.0, t.IntelScore/20.0)
				if t.ObservationWindow > 24*time.Hour {
					conf = minFloat64(1.0, conf+0.3)
				}
				if t.TotalScore >= 60 {
					conf = minFloat64(1.0, conf+0.2)
				}
				if len(t.IntelMatches) >= 2 {
					conf = minFloat64(1.0, conf+0.2)
				}
				return conf
			},
		},
		// Data exfiltration: large payloads + high anomaly + outbound connections
		{
			attackType: AttackDataExfiltration,
			match: func(t *Threat) float64 {
				conf := 0.0
				hasLargePayload := false
				for _, s := range t.PayloadSamples {
					if len(s) > 1024 {
						hasLargePayload = true
						break
					}
				}
				if hasLargePayload {
					conf += 0.4
				}
				if t.AnomalyScore > 5 {
					conf += 0.3
				}
				if t.PacketRate > 200 {
					conf += 0.3
				}
				return minFloat64(1.0, conf)
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// payloadMatchConfidence scans HTTP paths and payload samples for the given
// indicator strings. Each unique indicator found increases the confidence.
func payloadMatchConfidence(t *Threat, indicators []string) float64 {
	hits := 0
	for _, path := range t.HTTPPaths {
		lower := strings.ToLower(path)
		for _, ind := range indicators {
			if strings.Contains(lower, ind) {
				hits++
				break // count at most one hit per path
			}
		}
	}
	for _, sample := range t.PayloadSamples {
		lower := strings.ToLower(sample)
		for _, ind := range indicators {
			if strings.Contains(lower, ind) {
				hits++
				break // count at most one hit per sample
			}
		}
	}

	if hits == 0 {
		return 0
	}

	// Each unique indicator found adds confidence.
	// More hits give higher confidence, capped at 1.0.
	conf := minFloat64(1.0, float64(hits)/float64(len(indicators))*2.0)
	if conf < 0.15 {
		return 0
	}
	return conf
}

// pathPrefixMatchConfidence checks how many HTTP paths contain any of the
// given prefixes/patterns.
func pathPrefixMatchConfidence(t *Threat, patterns []string) float64 {
	hits := 0
	for _, path := range t.HTTPPaths {
		lower := strings.ToLower(path)
		for _, pat := range patterns {
			if strings.Contains(lower, pat) {
				hits++
				break
			}
		}
	}
	if hits == 0 {
		return 0
	}
	conf := minFloat64(1.0, float64(hits)/float64(len(t.HTTPPaths))*1.5)
	if conf < 0.15 {
		return 0
	}
	return conf
}

// containsHint checks whether any protocol hint (case-insensitive) matches.
func containsHint(hints []string, target string) bool {
	target = strings.ToLower(target)
	for _, h := range hints {
		if strings.Contains(strings.ToLower(h), target) {
			return true
		}
	}
	return false
}

// minFloat64 returns the smaller of two float64 values. Defined here to avoid
// importing the math package for this single function.
func minFloat64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// ClassifyFromRecords — convenience to classify directly from IPRecords
// ---------------------------------------------------------------------------

// ClassifyFromRecords classifies a set of IPRecords by converting them to
// Threats with minimal defaults. This is the quick-path entry point for
// callers that don't have enriched Threat data.
func ClassifyFromRecords(records []*IPRecord) (AttackType, float64) {
	threats := make([]Threat, 0, len(records))
	for _, r := range records {
		t := NewThreat(r)
		t.ObservationWindow = r.LastSeen.Sub(r.FirstSeen)
		t.PortsScanned = r.OpenPorts
		if r.HoneypotTripped {
			t.ProtocolHints = append(t.ProtocolHints, "honeypot")
		}
		threats = append(threats, *t)
	}
	return ClassifyAttack(threats)
}

// ---------------------------------------------------------------------------
// Classifier — stateful classifier with history
// ---------------------------------------------------------------------------

// Classifier maintains classification state and history for trend tracking.
type Classifier struct {
	history []ClassificationResult
}

// ClassificationResult captures a single classification event.
type ClassificationResult struct {
	Time       time.Time
	AttackType AttackType
	Confidence float64
	IPCount    int
}

// NewClassifier creates a new stateful Classifier.
func NewClassifier() *Classifier {
	return &Classifier{
		history: make([]ClassificationResult, 0, 100),
	}
}

// Classify runs classification and records the result in history.
func (c *Classifier) Classify(threats []Threat) (AttackType, float64) {
	at, conf := ClassifyAttack(threats)
	c.history = append(c.history, ClassificationResult{
		Time:       time.Now(),
		AttackType: at,
		Confidence: conf,
		IPCount:    len(threats),
	})
	// Keep last 100 results
	if len(c.history) > 100 {
		c.history = c.history[len(c.history)-100:]
	}
	return at, conf
}

// DominantType returns the most frequent attack type in recent history.
func (c *Classifier) DominantType() (AttackType, int) {
	counts := make(map[AttackType]int)
	for _, r := range c.history {
		counts[r.AttackType]++
	}
	var best AttackType
	var bestCount int
	for at, count := range counts {
		if count > bestCount {
			bestCount = count
			best = at
		}
	}
	return best, bestCount
}

// RecentResults returns the last n classification results.
func (c *Classifier) RecentResults(n int) []ClassificationResult {
	if n <= 0 || n > len(c.history) {
		n = len(c.history)
	}
	start := len(c.history) - n
	result := make([]ClassificationResult, n)
	copy(result, c.history[start:])
	return result
}
