// Package engines implements L2+ hybrid anomaly detection combining per-flow
// EMA Z-Score analysis (Layer 1) with Count-Min Sketch structural anomaly
// detection (Layer 2), matching the Python HybridAnomalyDetector.
package engines

import (
	"fmt"
	"hash/fnv"
	"math"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	defaultAlpha         = 0.01
	defaultMaxFlows      = 10000
	defaultZThreshold    = 4.0
	defaultL2Threshold   = 6.0
	defaultMinSamples    = 5
	defaultBurstWindowMs = 100

	aggressiveZThreshold = 3.0
	aggressiveL2Threshold = 4.5
	aggressiveMinSamples  = 3

	cmsRows           = 4
	cmsCols           = 65536
	cmsDecayThreshold = 10_000_000
	maxSizeBucket     = 63
	sizeBucketDiv     = 256

	epsilon = 0.001
)

// Feature indices for the 6-dimensional anomaly vector.
const (
	featPktSize = iota
	featIAT
	featFlagsBitmask
	featPayloadEntropy
	featBurstCount
	featSymmetry
	featCount
)

var featureNames = [...]string{
	"pkt_size",
	"iat",
	"flags_bitmask",
	"payload_entropy",
	"burst_count",
	"symmetry",
}

// ---------------------------------------------------------------------------
// CountMinSketch — probabilistic frequency estimator for structural anomaly
// ---------------------------------------------------------------------------

// CountMinSketch is a 4-row Count-Min Sketch with FNV-32a hashing.
// It estimates how many times a fingerprint has been seen; rare
// fingerprints indicate structural anomalies.
type CountMinSketch struct {
	counters [cmsRows][cmsCols]uint32
	total    uint64
}

// Insert increments the counters for the given fingerprint.
// Triggers decay (right-shift all counters by 1) when total exceeds
// cmsDecayThreshold (10M).
func (c *CountMinSketch) Insert(fingerprint string) {
	for row := 0; row < cmsRows; row++ {
		col := c.hash(row, fingerprint)
		c.counters[row][col]++
	}
	c.total++
	if c.total >= cmsDecayThreshold {
		c.decay()
	}
}

// Estimate returns the minimum counter value across all rows for the
// given fingerprint. Lower values indicate rarer (more anomalous) patterns.
func (c *CountMinSketch) Estimate(fingerprint string) int {
	minVal := uint32(math.MaxUint32)
	for row := 0; row < cmsRows; row++ {
		col := c.hash(row, fingerprint)
		if c.counters[row][col] < minVal {
			minVal = c.counters[row][col]
		}
	}
	return int(minVal)
}

// hash returns a column index for the given row and fingerprint using
// FNV-32a seeded with the row index.
func (c *CountMinSketch) hash(row int, fingerprint string) uint32 {
	h := fnv.New32a()
	h.Write([]byte{byte(row)})
	h.Write([]byte(fingerprint))
	return h.Sum32() % cmsCols
}

// decay right-shifts all counters by 1 (approximate halving) and halves
// the total count to maintain relative frequency estimates.
func (c *CountMinSketch) decay() {
	for row := 0; row < cmsRows; row++ {
		for col := 0; col < cmsCols; col++ {
			c.counters[row][col] >>= 1
		}
	}
	c.total >>= 1
}

// anomalyScore computes the structural anomaly score for a fingerprint.
// Returns -log((estimate + 0.5) / total). A higher score means the
// fingerprint is rarer relative to the overall traffic baseline.
func (c *CountMinSketch) anomalyScore(fingerprint string) float64 {
	if c.total == 0 {
		return 0
	}
	est := c.Estimate(fingerprint)
	if est == 0 {
		return c.l2Threshold() + 1 // unseen pattern is highly anomalous
	}
	ratio := (float64(est) + 0.5) / float64(c.total)
	return -math.Log(ratio)
}

// l2Threshold is a placeholder — actual threshold is owned by the detector.
// Needed to return a sentinel value for unseen fingerprints.
func (c *CountMinSketch) l2Threshold() float64 {
	return defaultL2Threshold
}

// ---------------------------------------------------------------------------
// featureStats — online mean, variance, and EMA tracking for one feature
// ---------------------------------------------------------------------------

// featureStats tracks the EMA, Welford mean/variance, and deviation EMA
// for a single feature dimension. All updates are immutable: callers must
// replace the struct via value copy or pointer mutation.
type featureStats struct {
	ema    float64
	mean   float64
	m2     float64
	n      int
	devEma float64
}

// update incorporates a new observation and returns the current Z-Score
// (number of standard deviations from the EMA). On the first observation
// the stats are initialized and the Z-Score is 0.
func (fs *featureStats) update(val float64, alpha float64) float64 {
	if fs.n == 0 {
		fs.ema = val
		fs.mean = val
		fs.n = 1
		return 0
	}

	// EMA
	fs.ema = alpha*val + (1-alpha)*fs.ema

	// Welford online mean and M2
	fs.n++
	delta := val - fs.mean
	fs.mean += delta / float64(fs.n)
	delta2 := val - fs.mean
	fs.m2 += delta * delta2

	// Deviation EMA (tracks typical absolute error)
	dev := math.Abs(val - fs.ema)
	if fs.n == 2 {
		fs.devEma = dev
	} else {
		fs.devEma = alpha*dev + (1-alpha)*fs.devEma
	}

	// Standard deviation (unbiased when n >= 2)
	var std float64
	if fs.n >= 2 {
		std = math.Sqrt(fs.m2 / float64(fs.n-1))
	}

	return math.Abs(val-fs.ema) / (std + epsilon)
}

// isReady returns true when enough samples have been collected for
// a reliable Z-Score.
func (fs *featureStats) isReady(minSamples int) bool {
	return fs.n >= minSamples
}

// ---------------------------------------------------------------------------
// FlowStats — per-IP flow state for the hybrid anomaly detector
// ---------------------------------------------------------------------------

// FlowStats holds the rolling statistics for a single source IP.
type FlowStats struct {
	lastSeen    time.Time
	lastPktTime time.Time
	features    [featCount]featureStats
	bytesSent   int
	bytesRecv   int
	burstTimes  []time.Time // sliding window for burst detection
	flagsBitmask int
}

// newFlowStats creates a new FlowStats with the current time.
func newFlowStats(now time.Time) *FlowStats {
	return &FlowStats{
		lastSeen:    now,
		lastPktTime: now,
	}
}

// ---------------------------------------------------------------------------
// HybridAnomalyDetector — two-layer anomaly detection
// ---------------------------------------------------------------------------

// HybridAnomalyDetector combines per-flow EMA Z-Score analysis (Layer 1)
// with a Count-Min Sketch structural anomaly detector (Layer 2).
//
// Layer 1: Tracks 6 features per source IP using Welford online variance
// and alerts when |val - ema| / (std + epsilon) exceeds the Z threshold.
//
// Layer 2: Builds a communication-pattern fingerprint and uses a
// Count-Min Sketch to estimate its rarity. Alerts when the negative
// log-probability exceeds the L2 threshold.
type HybridAnomalyDetector struct {
	mu          sync.Mutex
	flows       map[string]*FlowStats
	sketch      *CountMinSketch
	alpha       float64
	maxFlows    int
	zThreshold  float64
	l2Threshold float64
	minSamples  int
	burstWindow time.Duration
	whitelisted func(string) bool
}

// NewHybridAnomalyDetector creates a HybridAnomalyDetector with default
// thresholds. Set aggressive=true for lower detection thresholds suitable
// for high-security environments.
func NewHybridAnomalyDetector(cfg *config.Config, aggressive bool) *HybridAnomalyDetector {
	zThresh := defaultZThreshold
	l2Thresh := defaultL2Threshold
	minSamp := defaultMinSamples

	if aggressive {
		zThresh = aggressiveZThreshold
		l2Thresh = aggressiveL2Threshold
		minSamp = aggressiveMinSamples
	}

	return &HybridAnomalyDetector{
		flows:       make(map[string]*FlowStats),
		sketch:      &CountMinSketch{},
		alpha:       defaultAlpha,
		maxFlows:    defaultMaxFlows,
		zThreshold:  zThresh,
		l2Threshold: l2Thresh,
		minSamples:  minSamp,
		burstWindow: defaultBurstWindowMs * time.Millisecond,
		whitelisted: cfg.IsWhitelisted,
	}
}

// Feed processes a packet from srcIP to dstIP and returns any anomaly
// threats detected. The method is safe for concurrent use.
//
// Parameters:
//   - srcIP, dstIP: source and destination IP addresses
//   - srcPort, dstPort: source and destination ports
//   - protocol: "TCP", "UDP", or "ICMP"
//   - pktSize: packet size in bytes
//   - tcpFlags: encoded TCP flag bitmask (SYN=1, SYNACK=2, FIN=4, RST=8, PSH=16)
//   - payloadEntropy: Shannon entropy of the packet payload
func (h *HybridAnomalyDetector) Feed(srcIP, dstIP string, srcPort, dstPort uint16, protocol string, pktSize int, tcpFlags int, payloadEntropy float64) []Threat {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.whitelisted != nil && h.whitelisted(srcIP) {
		return nil
	}

	now := time.Now()

	// Get or create flows for both directions (bytes_recv tracking).
	srcFlow := h.getOrCreateFlow(srcIP, now)
	dstFlow := h.getOrCreateFlow(dstIP, now)

	// Update source flow.
	iat := now.Sub(srcFlow.lastPktTime).Seconds()
	srcFlow.lastPktTime = now
	srcFlow.lastSeen = now
	srcFlow.bytesSent += pktSize
	srcFlow.flagsBitmask = tcpFlags

	// Update burst timestamps (sliding 100ms window).
	srcFlow.burstTimes = append(srcFlow.burstTimes, now)
	srcFlow.burstTimes = pruneBurstTimes(srcFlow.burstTimes, now.Add(-h.burstWindow))
	burstCount := len(srcFlow.burstTimes)

	// Update destination flow (tracking bytes received for symmetry).
	dstFlow.lastSeen = now
	dstFlow.bytesRecv += pktSize

	// Compute symmetry: bytes_sent / (bytes_sent + bytes_recv), clamped to [0.5, 1.0].
	totalBytes := srcFlow.bytesSent + srcFlow.bytesRecv
	var symmetry float64
	if totalBytes > 0 {
		symmetry = float64(srcFlow.bytesSent) / float64(totalBytes)
	}
	symmetry = clampSymmetry(symmetry)

	// Extract the 6-dimensional feature vector.
	values := [featCount]float64{
		featPktSize:        float64(pktSize),
		featIAT:            iat,
		featFlagsBitmask:   float64(tcpFlags),
		featPayloadEntropy: payloadEntropy,
		featBurstCount:     float64(burstCount),
		featSymmetry:       symmetry,
	}

	// --- Layer 1: Per-feature EMA Z-Score ---
	var threats []Threat
	for fi := 0; fi < featCount; fi++ {
		fs := &srcFlow.features[fi]
		zScore := fs.update(values[fi], h.alpha)
		if fs.isReady(h.minSamples) && zScore > h.zThreshold {
			threats = append(threats, Threat{
				Type: "流量异常",
				IP:   srcIP,
				Detail: fmt.Sprintf("%s异常 Z=%.2f 当前=%.2f EMA=%.2f",
					featureNames[fi], zScore, values[fi], fs.ema),
			})
			break // One alert per packet per IP is sufficient.
		}
	}

	// --- Layer 2: Count-Min Sketch structural anomaly ---
	sizeBucket := pktSize / sizeBucketDiv
	if sizeBucket > maxSizeBucket {
		sizeBucket = maxSizeBucket
	}
	fingerprint := fmt.Sprintf("%d_%d_%s_%d_%d",
		srcPort, dstPort, protocol, tcpFlags, sizeBucket)

	h.sketch.Insert(fingerprint)
	score := h.sketch.anomalyScore(fingerprint)
	if score > h.l2Threshold {
		threats = append(threats, Threat{
			Type: "结构异常",
			IP:   srcIP,
			Detail: fmt.Sprintf("fingerprint=%s score=%.2f estimate=%d total=%d",
				fingerprint, score, h.sketch.Estimate(fingerprint), h.sketch.total),
		})
	}

	return threats
}

// Evict removes flow records whose last_seen is older than deadline
// (Unix timestamp). Returns the number of flows evicted.
func (h *HybridAnomalyDetector) Evict(deadline float64) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	cutoff := time.Unix(int64(deadline), 0)
	stale := make([]string, 0)

	for ip, flow := range h.flows {
		if flow.lastSeen.Before(cutoff) {
			stale = append(stale, ip)
		}
	}

	for _, ip := range stale {
		delete(h.flows, ip)
	}
	return len(stale)
}

// --- private helpers --------------------------------------------------------

// getOrCreateFlow returns the FlowStats for ip, creating one if needed.
// If the flow table has reached maxFlows, the oldest entry is evicted.
// Caller holds h.mu.
func (h *HybridAnomalyDetector) getOrCreateFlow(ip string, now time.Time) *FlowStats {
	if flow, ok := h.flows[ip]; ok {
		return flow
	}

	// Evict oldest if at capacity.
	if len(h.flows) >= h.maxFlows {
		var oldestIP string
		var oldestTime time.Time
		first := true
		for k, v := range h.flows {
			if first || v.lastSeen.Before(oldestTime) {
				oldestIP = k
				oldestTime = v.lastSeen
				first = false
			}
		}
		if oldestIP != "" {
			delete(h.flows, oldestIP)
		}
	}

	flow := newFlowStats(now)
	h.flows[ip] = flow
	return flow
}

// pruneBurstTimes returns a new slice containing only timestamps at or
// after the cutoff. Returns nil if no timestamps remain.
func pruneBurstTimes(times []time.Time, cutoff time.Time) []time.Time {
	idx := 0
	for idx < len(times) && times[idx].Before(cutoff) {
		idx++
	}
	if idx == 0 {
		return times
	}
	if idx >= len(times) {
		return nil
	}
	kept := make([]time.Time, len(times)-idx)
	copy(kept, times[idx:])
	return kept
}

// clampSymmetry clamps the symmetry value to the range [0.5, 1.0].
// Symmetry values below 0.5 indicate highly asymmetric traffic.
func clampSymmetry(v float64) float64 {
	if v < 0.5 {
		return 0.5
	}
	if v > 1.0 {
		return 1.0
	}
	return v
}
