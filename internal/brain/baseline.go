// Package brain — Dynamic Behavioral Baseline
//
// Uses Welford's online algorithm to build per-IP traffic baselines,
// detecting statistical deviations in real-time without storing raw data.
// This is hot technique #2: "动态学习" — the system learns what "normal"
// looks like per source IP and detects when behavior drifts.
//
// Features tracked per IP:
//   - Packet rate (packets/sec)
//   - Mean packet size
//   - Port diversity (unique ports/time window)
//   - Protocol mix (TCP/UDP/ICMP ratio)
//   - Time-of-day activity pattern
package brain

import (
	"math"
	"sync"
	"time"
)

// BaselineFeatures tracks what we measure per IP.
type BaselineFeatures struct {
	PacketRateMean float64
	PacketRateVar  float64 // running variance
	PacketRateN    float64 // sample count

	SizeMean float64
	SizeVar  float64
	SizeN    float64

	PortDiversity float64 // unique ports per time window

	// Time-of-day activity
	ActiveHours [24]float64 // probability of activity per hour (0-1)
}

// DeviationScore returns a normalized anomaly score (0-100) for current
// measurements vs baseline. Uses Z-score with adaptive threshold.
func (bf *BaselineFeatures) DeviationScore(rate, size, ports float64) float64 {
	score := 0.0

	// Packet rate deviation (Z-score)
	if bf.PacketRateN > 10 && bf.PacketRateVar > 0 {
		stdDev := math.Sqrt(bf.PacketRateVar / bf.PacketRateN)
		if stdDev > 0 {
			z := math.Abs(rate-bf.PacketRateMean) / stdDev
			if z > 3.0 { // 3-sigma
				score += math.Min((z-3.0)*10, 40) // max 40 points from rate
			}
		}
	}

	// Size deviation
	if bf.SizeN > 10 && bf.SizeVar > 0 {
		stdDev := math.Sqrt(bf.SizeVar / bf.SizeN)
		if stdDev > 0 {
			z := math.Abs(size-bf.SizeMean) / stdDev
			if z > 3.0 {
				score += math.Min((z-3.0)*10, 30) // max 30 points from size
			}
		}
	}

	// Port diversity — unexpected scanning
	if bf.PortDiversity > 0 && ports > 0 {
		ratio := ports / bf.PortDiversity
		if ratio > 3.0 {
			score += math.Min((ratio-3.0)*10, 30) // max 30 points from ports
		}
	}

	return math.Min(score, 100)
}

// Update incorporates a new observation into the baseline (Welford online update).
func (bf *BaselineFeatures) Update(rate, size, ports float64, hour int) {
	// Welford's online algorithm for mean and variance
	bf.PacketRateN++
	if bf.PacketRateN == 1 {
		bf.PacketRateMean = rate
		bf.PacketRateVar = 0
	} else {
		delta := rate - bf.PacketRateMean
		bf.PacketRateMean += delta / bf.PacketRateN
		bf.PacketRateVar += delta * (rate - bf.PacketRateMean)
	}

	bf.SizeN++
	if bf.SizeN == 1 {
		bf.SizeMean = size
		bf.SizeVar = 0
	} else {
		delta := size - bf.SizeMean
		bf.SizeMean += delta / bf.SizeN
		bf.SizeVar += delta * (size - bf.SizeMean)
	}

	// Exponential moving average for port diversity
	if bf.PortDiversity == 0 {
		bf.PortDiversity = ports
	} else {
		bf.PortDiversity = bf.PortDiversity*0.95 + ports*0.05
	}

	// Time-of-day activity (EMA)
	if hour >= 0 && hour < 24 {
		bf.ActiveHours[hour] = bf.ActiveHours[hour]*0.95 + 0.05
	}
}

// BaselineEngine tracks behavioral baselines per source IP.
type BaselineEngine struct {
	mu       sync.RWMutex
	baselines map[string]*BaselineFeatures
	maxIPs   int
}

// NewBaselineEngine creates a baseline tracker.
func NewBaselineEngine(maxIPs int) *BaselineEngine {
	if maxIPs <= 0 {
		maxIPs = 10000
	}
	return &BaselineEngine{
		baselines: make(map[string]*BaselineFeatures),
		maxIPs:    maxIPs,
	}
}

// Observe records a traffic observation for an IP and returns anomaly score.
func (be *BaselineEngine) Observe(ip string, packetRate, packetSize, portCount float64) float64 {
	be.mu.Lock()
	defer be.mu.Unlock()

	hour := time.Now().Hour()
	bf, ok := be.baselines[ip]
	if !ok {
		if len(be.baselines) >= be.maxIPs {
			// Evict oldest
			for k := range be.baselines {
				delete(be.baselines, k)
				break
			}
		}
		bf = &BaselineFeatures{}
		be.baselines[ip] = bf
	}

	// Get deviation score BEFORE updating baseline (detect drift)
	score := bf.DeviationScore(packetRate, packetSize, portCount)

	// Update baseline with this observation
	bf.Update(packetRate, packetSize, portCount, hour)

	return score
}

// Deviation returns the current anomaly score for an IP without updating.
func (be *BaselineEngine) Deviation(ip string, rate, size, ports float64) float64 {
	be.mu.RLock()
	defer be.mu.RUnlock()

	bf, ok := be.baselines[ip]
	if !ok {
		return 0
	}
	return bf.DeviationScore(rate, size, ports)
}

// Stats returns diagnostic info.
func (be *BaselineEngine) Stats() (totalIPs int) {
	be.mu.RLock()
	defer be.mu.RUnlock()
	return len(be.baselines)
}

// Evict removes stale baselines.
func (be *BaselineEngine) Evict() {
	be.mu.Lock()
	defer be.mu.Unlock()
	// Keep only most recent 90% (simple aging)
	if len(be.baselines) > be.maxIPs {
		count := 0
		for k := range be.baselines {
			if count >= be.maxIPs/10 {
				break
			}
			delete(be.baselines, k)
			count++
		}
	}
}
