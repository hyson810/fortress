// Package brain — Cross-Layer Temporal Correlation Engine.
//
// Enhanced from V4: now tracks per-IP multi-layer attack patterns and
// assigns rising scores when an attacker probes multiple detection layers.
// Hot technique #3: 跨层时序关联 — detects complex multi-stage attacks
// by correlating events across L1-L7 + Shield + Honeypot over time.
package brain

import (
	"sync"
	"time"
)

// LayerID identifies which detection layer triggered an alert.
type LayerID int

const (
	LayerL1Packet     LayerID = 1  // Packet inspector — flood, flags
	LayerL2Flow              = 2  // Flow analyzer — port scan
	LayerL3Behavior          = 3  // Behavior analyzer — entropy
	LayerL4DNS               = 4  // DNS tunnel detector
	LayerL5HTTP              = 5  // HTTP inspector + brute force
	LayerL6Anomaly           = 6  // Hybrid anomaly detector
	LayerL7Fingerprint       = 7  // JA3 + OS fingerprint
	LayerShield              = 8  // Host-level shield
	LayerHoneypot            = 9  // Honeypot interaction
	LayerSwarm               = 10 // Swarm threat intel
)

// alertEntry records a single alert with its source layer.
type alertEntry struct {
	Time    time.Time
	IP      string
	Type    string
	Layer   LayerID
	Score   float64
}

// CorrelationEngine tracks alerts across all detection layers and detects:
// 1. Coordinated attacks (multiple IPs, same behavior)
// 2. Multi-layer attacks (same IP, multiple layers in time window)
// 3. Slow-burn attacks (spread over long period, below per-window thresholds)
type CorrelationEngine struct {
	mu     sync.Mutex
	alerts []alertEntry
}

const (
	maxCorrelationAlerts   = 500
	correlationWindow      = 120 * time.Second // 2-minute correlation window
	multiLayerWindow       = 300 * time.Second // 5-minute multi-layer window
	minCorrelatedIPs       = 3
	slowBurnWindow         = 600 * time.Second // 10-minute slow-burn window
	slowBurnThreshold      = 5                 // alerts per IP in slow-burn window
)

// NewCorrelationEngine creates an enhanced cross-layer correlation engine.
func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{
		alerts: make([]alertEntry, 0, maxCorrelationAlerts),
	}
}

// Feed records a new alert with its detection layer.
func (ce *CorrelationEngine) Feed(ip, alertType string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.alerts = append(ce.alerts, alertEntry{
		Time: time.Now(), IP: ip, Type: alertType, Layer: 0,
	})
	if len(ce.alerts) > maxCorrelationAlerts {
		ce.alerts = ce.alerts[len(ce.alerts)-maxCorrelationAlerts:]
	}
}

// FeedWithLayer records an alert with layer information for cross-layer detection.
func (ce *CorrelationEngine) FeedWithLayer(ip, alertType string, layer LayerID, score float64) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.alerts = append(ce.alerts, alertEntry{
		Time: time.Now(), IP: ip, Type: alertType, Layer: layer, Score: score,
	})
	if len(ce.alerts) > maxCorrelationAlerts {
		ce.alerts = ce.alerts[len(ce.alerts)-maxCorrelationAlerts:]
	}
}

// CrossLayerResult describes a cross-layer correlation finding.
type CrossLayerResult struct {
	IP          string   `json:"ip"`
	LayersHit   []LayerID `json:"layers_hit"`
	LayerCount  int      `json:"layer_count"`
	ScoreBoost  float64  `json:"score_boost"`
	TimeSpan    float64  `json:"time_span"` // seconds between first and last alert
	Description string   `json:"description"`
}

// CheckCrossLayer returns cross-layer correlation results for all tracked IPs.
// An attacker hitting 3+ different detection layers gets a score multiplier.
func (ce *CorrelationEngine) CheckCrossLayer() []CrossLayerResult {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-multiLayerWindow)

	// Build per-IP layer activity map
	type ipActivity struct {
		layers    map[LayerID]struct{}
		firstSeen time.Time
		lastSeen  time.Time
		totalAlerts int
	}
	ipMap := make(map[string]*ipActivity)

	for _, a := range ce.alerts {
		if a.Time.Before(cutoff) {
			continue
		}
		act, ok := ipMap[a.IP]
		if !ok {
			act = &ipActivity{
				layers:    make(map[LayerID]struct{}),
				firstSeen: a.Time,
			}
			ipMap[a.IP] = act
		}
		if a.Layer > 0 {
			act.layers[a.Layer] = struct{}{}
		}
		if a.Time.After(act.lastSeen) {
			act.lastSeen = a.Time
		}
		act.totalAlerts++
	}

	var results []CrossLayerResult
	for ip, act := range ipMap {
		if len(act.layers) < 2 {
			continue // single-layer attacks aren't cross-layer
		}

		boost := 0.0
		desc := ""

		// Score based on how many distinct layers
		switch {
		case len(act.layers) >= 5:
			boost = 2.0
			desc = "全层攻击 — 攻击者触及5+检测层"
		case len(act.layers) >= 4:
			boost = 1.6
			desc = "多层攻击 — 触及4个检测层"
		case len(act.layers) >= 3:
			boost = 1.3
			desc = "跨层攻击 — 触及3个检测层"
		default:
			boost = 1.15
			desc = "双层面攻击 — 触及2个检测层"
		}

		timeSpan := act.lastSeen.Sub(act.firstSeen).Seconds()

		// Build layer list
		var layers []LayerID
		for l := range act.layers {
			layers = append(layers, l)
		}

		results = append(results, CrossLayerResult{
			IP:          ip,
			LayersHit:   layers,
			LayerCount:  len(act.layers),
			ScoreBoost:  boost,
			TimeSpan:    timeSpan,
			Description: desc,
		})
	}

	return results
}

// CheckSlowBurn finds attackers that stay below individual thresholds
// but have persistent activity over a long period.
func (ce *CorrelationEngine) CheckSlowBurn() []string {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-slowBurnWindow)
	ipCount := make(map[string]int)

	for _, a := range ce.alerts {
		if a.Time.Before(cutoff) {
			continue
		}
		ipCount[a.IP]++
	}

	var slowBurning []string
	for ip, count := range ipCount {
		if count >= slowBurnThreshold {
			// Count how many other IPs have similar counts (coordinated slow burn)
			coordinated := 0
			for _, c := range ipCount {
				if c >= slowBurnThreshold {
					coordinated++
				}
			}
			if coordinated >= minCorrelatedIPs {
				slowBurning = append(slowBurning, ip)
			}
		}
	}
	return slowBurning
}

// Check examines recent alerts for coordinated cross-IP attacks.
// Returns (nil, 0) when no correlation is detected.
func (ce *CorrelationEngine) Check() ([]string, float64) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-correlationWindow)
	ipSet := make(map[string]struct{})
	typeSet := make(map[string]struct{})
	for i := len(ce.alerts) - 1; i >= 0; i-- {
		a := ce.alerts[i]
		if a.Time.Before(cutoff) {
			break
		}
		ipSet[a.IP] = struct{}{}
		typeSet[a.Type] = struct{}{}
	}
	if len(ipSet) >= minCorrelatedIPs && len(typeSet) <= 3 {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		multiplier := 1.0 + 0.1*float64(len(ipSet))
		if multiplier > 1.5 {
			multiplier = 1.5
		}
		return ips, multiplier
	}
	return nil, 0
}

// Evict prunes old entries.
func (ce *CorrelationEngine) Evict(deadlineUnix float64) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	cutoff := time.Now().Add(-slowBurnWindow)
	keep := 0
	for _, a := range ce.alerts {
		if !a.Time.Before(cutoff) {
			ce.alerts[keep] = a
			keep++
		}
	}
	ce.alerts = ce.alerts[:keep]
	_ = deadlineUnix
}

// MultiLayerScore returns a score multiplier for an IP based on how many
// layers it has triggered. Returns 1.0 if no multi-layer activity.
func (ce *CorrelationEngine) MultiLayerScore(ip string) float64 {
	results := ce.CheckCrossLayer()
	for _, r := range results {
		if r.IP == ip {
			return r.ScoreBoost
		}
	}
	return 1.0
}
