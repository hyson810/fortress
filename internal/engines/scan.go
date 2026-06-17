// Package engines implements L2 flow-based scan detection, L3 entropy-based
// traffic anomaly detection, and L4 cross-IP attack correlation.
//
//   - FlowAnalyzer: port scan detection across 3 time windows (fast/medium/slow)
//   - BehaviorAnalyzer: Shannon entropy baseline with sigma-deviation alerts
//   - CorrelationEngine: cross-IP coordinated attack detection
package engines

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
)

// ---------------------------------------------------------------------------
// Defaults and constants
// ---------------------------------------------------------------------------

const (
	defaultEntropyWindow  = 60 * time.Second
	entropyDeviation      = 2.5 // standard deviations from baseline mean
	baselineInterval      = 200 // samples between baseline recalculations
	maxFlowRecords        = 500 // per-IP ring buffer capacity
	maxGlobalSamples      = 2000
	maxRecentAlerts       = 100
	correlationWindow     = 60 * time.Second
	correlationMinIPs     = 3
	correlationMaxTypes   = 2
)

var defaultScanWindows = []ScanWindow{
	{Name: "快速扫描", Seconds: 5, PortThreshold: 12},
	{Name: "中速扫描", Seconds: 30, PortThreshold: 25},
	{Name: "慢速扫描", Seconds: 300, PortThreshold: 50},
}

// ---------------------------------------------------------------------------
// ScanWindow
// ---------------------------------------------------------------------------

// ScanWindow defines a time window and the port-count threshold that
// triggers a port scan alert.
type ScanWindow struct {
	Name          string
	Seconds       int
	PortThreshold int
}

// ---------------------------------------------------------------------------
// FlowAnalyzer — L2 port scan detection
// ---------------------------------------------------------------------------

type flowRecord struct {
	Time time.Time
	Port uint16
}

// FlowAnalyzer detects port scans by tracking unique destination ports
// per source IP across multiple time windows (fast, medium, slow).
type FlowAnalyzer struct {
	mu      sync.Mutex
	records map[string][]flowRecord
	windows []ScanWindow
}

// NewFlowAnalyzer creates a FlowAnalyzer with default scan windows.
func NewFlowAnalyzer(cfg *config.Config) *FlowAnalyzer {
	return &FlowAnalyzer{
		records: make(map[string][]flowRecord),
		windows: defaultScanWindows,
	}
}

// Feed ingests a flow record and returns any scan alerts triggered.
// srcIP is the source address, dstPort is the destination port.
func (fa *FlowAnalyzer) Feed(srcIP string, dstPort uint16) []Threat {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	now := time.Now()
	fa.records[srcIP] = append(fa.records[srcIP], flowRecord{Time: now, Port: dstPort})

	records := fa.records[srcIP]
	if len(records) > maxFlowRecords {
		records = records[len(records)-maxFlowRecords:]
		fa.records[srcIP] = records
	}

	var threats []Threat
	for _, w := range fa.windows {
		cutoff := now.Add(-time.Duration(w.Seconds) * time.Second)
		uniquePorts := make(map[uint16]struct{})

		// Iterate backward from newest; stop at first record before cutoff.
		for i := len(records) - 1; i >= 0; i-- {
			if records[i].Time.Before(cutoff) {
				break
			}
			uniquePorts[records[i].Port] = struct{}{}
		}

		if len(uniquePorts) >= w.PortThreshold {
			threats = append(threats, Threat{
				Type:   w.Name,
				IP:     srcIP,
				Detail: fmt.Sprintf("在%d秒内扫描了%d个不同端口", w.Seconds, len(uniquePorts)),
			})
		}
	}
	return threats
}

// Evict removes records older than deadline (Unix timestamp) and deletes
// IPs that have no remaining records. Returns the number of IPs removed.
func (fa *FlowAnalyzer) Evict(deadline float64) int {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	cutoff := time.Unix(int64(deadline), 0)
	removed := 0

	for ip, records := range fa.records {
		kept := pruneFlowRecords(records, cutoff)
		if len(kept) == 0 {
			delete(fa.records, ip)
			removed++
		} else {
			fa.records[ip] = kept
		}
	}
	return removed
}

// pruneFlowRecords returns a new slice containing only records at or after cutoff.
func pruneFlowRecords(records []flowRecord, cutoff time.Time) []flowRecord {
	idx := 0
	for idx < len(records) && records[idx].Time.Before(cutoff) {
		idx++
	}
	if idx == 0 {
		return records
	}
	if idx >= len(records) {
		return nil
	}
	kept := make([]flowRecord, len(records)-idx)
	copy(kept, records[idx:])
	return kept
}

// ---------------------------------------------------------------------------
// BehaviorAnalyzer — L3 entropy-based anomaly detection
// ---------------------------------------------------------------------------

type portSample struct {
	Time time.Time
	Port uint16
}

type ipSample struct {
	Time time.Time
	IP   string
}

// entropyBaseline tracks a running mean and standard deviation using
// Welford's online algorithm.
type entropyBaseline struct {
	Mean  float64
	M2    float64
	Count int
}

// Add incorporates a new entropy observation into the baseline.
func (b *entropyBaseline) Add(value float64) {
	b.Count++
	delta := value - b.Mean
	b.Mean += delta / float64(b.Count)
	delta2 := value - b.Mean
	b.M2 += delta * delta2
}

// Std returns the sample standard deviation (unbiased estimator).
// Returns 0 when fewer than 2 samples exist.
func (b *entropyBaseline) Std() float64 {
	if b.Count < 2 {
		return 0
	}
	return math.Sqrt(b.M2 / float64(b.Count-1))
}

// BehaviorAnalyzer detects traffic anomalies by monitoring Shannon entropy
// of port and IP distributions. When current entropy deviates from the
// rolling baseline by more than 2.5 standard deviations an alert is
// generated.
type BehaviorAnalyzer struct {
	mu               sync.Mutex
	globalPorts      []portSample
	globalIPs        []ipSample
	baselineEntropy  map[string]*entropyBaseline
	entropyWindow    time.Duration
	entropyDeviation float64
	sampleCount      int
}

// NewBehaviorAnalyzer creates a BehaviorAnalyzer with default thresholds.
func NewBehaviorAnalyzer(cfg *config.Config) *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		globalPorts:      make([]portSample, 0, maxGlobalSamples),
		globalIPs:        make([]ipSample, 0, maxGlobalSamples),
		baselineEntropy:  make(map[string]*entropyBaseline),
		entropyWindow:    defaultEntropyWindow,
		entropyDeviation: entropyDeviation,
	}
}

// Feed ingests a traffic sample for baseline tracking. Every baselineInterval
// samples the baseline is recalculated.
func (ba *BehaviorAnalyzer) Feed(srcIP string, dstPort uint16) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	now := time.Now()
	ba.globalPorts = append(ba.globalPorts, portSample{Time: now, Port: dstPort})
	ba.globalIPs = append(ba.globalIPs, ipSample{Time: now, IP: srcIP})

	if len(ba.globalPorts) > maxGlobalSamples {
		ba.globalPorts = ba.globalPorts[len(ba.globalPorts)-maxGlobalSamples:]
	}
	if len(ba.globalIPs) > maxGlobalSamples {
		ba.globalIPs = ba.globalIPs[len(ba.globalIPs)-maxGlobalSamples:]
	}

	ba.sampleCount++
	if ba.sampleCount%baselineInterval == 0 {
		ba.updateBaseline()
	}
}

// Check compares current entropy against the baseline and returns alerts
// for statistically significant deviations (> 2.5σ).
func (ba *BehaviorAnalyzer) Check() []Threat {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	portEntropy := ba.currentPortEntropy()
	ipEntropy := ba.currentIPEntropy()

	var threats []Threat

	if bl, ok := ba.baselineEntropy["port"]; ok && bl.Std() > 0 {
		dev := math.Abs(portEntropy-bl.Mean) / bl.Std()
		if dev > ba.entropyDeviation {
			threats = append(threats, Threat{
				Type:   "流量异常",
				IP:     "",
				Detail: fmt.Sprintf("端口熵值异常: 当前=%.3f, 基线=%.3f±%.3f, 偏离%.1fσ",
					portEntropy, bl.Mean, bl.Std(), dev),
			})
		}
	}

	if bl, ok := ba.baselineEntropy["ip"]; ok && bl.Std() > 0 {
		dev := math.Abs(ipEntropy-bl.Mean) / bl.Std()
		if dev > ba.entropyDeviation {
			threats = append(threats, Threat{
				Type:   "流量异常",
				IP:     "",
				Detail: fmt.Sprintf("IP熵值异常: 当前=%.3f, 基线=%.3f±%.3f, 偏离%.1fσ",
					ipEntropy, bl.Mean, bl.Std(), dev),
			})
		}
	}

	return threats
}

// Evict removes samples older than deadline (Unix timestamp).
// Returns 0 — BehaviorAnalyzer uses global buffers, not per-IP accounting.
func (ba *BehaviorAnalyzer) Evict(deadline float64) int {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	cutoff := time.Unix(int64(deadline), 0)
	ba.globalPorts = prunePortSamples(ba.globalPorts, cutoff)
	ba.globalIPs = pruneIPSamples(ba.globalIPs, cutoff)
	return 0
}

// --- private helpers --------------------------------------------------------

func (ba *BehaviorAnalyzer) currentPortEntropy() float64 {
	cutoff := time.Now().Add(-ba.entropyWindow)
	ports := make([]uint16, 0)
	for i := len(ba.globalPorts) - 1; i >= 0; i-- {
		if ba.globalPorts[i].Time.Before(cutoff) {
			break
		}
		ports = append(ports, ba.globalPorts[i].Port)
	}
	return shannonEntropy(ports)
}

func (ba *BehaviorAnalyzer) currentIPEntropy() float64 {
	cutoff := time.Now().Add(-ba.entropyWindow)
	ips := make([]string, 0)
	for i := len(ba.globalIPs) - 1; i >= 0; i-- {
		if ba.globalIPs[i].Time.Before(cutoff) {
			break
		}
		ips = append(ips, ba.globalIPs[i].IP)
	}
	return shannonEntropy(ips)
}

func (ba *BehaviorAnalyzer) updateBaseline() {
	ba.updateBaselineForKey("port", ba.currentPortEntropy())
	ba.updateBaselineForKey("ip", ba.currentIPEntropy())
}

func (ba *BehaviorAnalyzer) updateBaselineForKey(key string, value float64) {
	bl, ok := ba.baselineEntropy[key]
	if !ok {
		bl = &entropyBaseline{}
		ba.baselineEntropy[key] = bl
	}
	bl.Add(value)
}

func prunePortSamples(samples []portSample, cutoff time.Time) []portSample {
	idx := 0
	for idx < len(samples) && samples[idx].Time.Before(cutoff) {
		idx++
	}
	if idx == 0 {
		return samples
	}
	if idx >= len(samples) {
		return nil
	}
	kept := make([]portSample, len(samples)-idx)
	copy(kept, samples[idx:])
	return kept
}

func pruneIPSamples(samples []ipSample, cutoff time.Time) []ipSample {
	idx := 0
	for idx < len(samples) && samples[idx].Time.Before(cutoff) {
		idx++
	}
	if idx == 0 {
		return samples
	}
	if idx >= len(samples) {
		return nil
	}
	kept := make([]ipSample, len(samples)-idx)
	copy(kept, samples[idx:])
	return kept
}

// ---------------------------------------------------------------------------
// CorrelationEngine — L4 cross-IP attack correlation
// ---------------------------------------------------------------------------

type alertRecord struct {
	Time time.Time
	IP   string
	Type string
}

// CorrelationEngine correlates alerts across multiple IPs to detect
// coordinated/distributed attack patterns.
type CorrelationEngine struct {
	mu           sync.Mutex
	RecentAlerts []alertRecord
}

// NewCorrelationEngine creates a CorrelationEngine.
func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{
		RecentAlerts: make([]alertRecord, 0, maxRecentAlerts),
	}
}

// Feed records an alert for correlation analysis.
func (ce *CorrelationEngine) Feed(ip string, atype string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.RecentAlerts = append(ce.RecentAlerts, alertRecord{Time: time.Now(), IP: ip, Type: atype})
	if len(ce.RecentAlerts) > maxRecentAlerts {
		ce.RecentAlerts = ce.RecentAlerts[len(ce.RecentAlerts)-maxRecentAlerts:]
	}
}

// CheckCorrelation examines recent alerts for coordinated attack patterns.
// Returns a threat if 3+ IPs participate in 2 or fewer attack types within
// a 60-second window, indicating a distributed coordinated attack.
func (ce *CorrelationEngine) CheckCorrelation() []Threat {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-correlationWindow)

	ipSet := make(map[string]struct{})
	typeSet := make(map[string]struct{})

	for i := len(ce.RecentAlerts) - 1; i >= 0; i-- {
		a := ce.RecentAlerts[i]
		if a.Time.Before(cutoff) {
			break
		}
		ipSet[a.IP] = struct{}{}
		typeSet[a.Type] = struct{}{}
	}

	if len(ipSet) >= correlationMinIPs && len(typeSet) <= correlationMaxTypes {
		ipList := sortedKeys(ipSet)
		return []Threat{{
			Type:   "分布式协同攻击",
			IP:     strings.Join(ipList, ","),
			Detail: fmt.Sprintf("检测到%d个IP参与协同攻击, 攻击类型%d种", len(ipSet), len(typeSet)),
		}}
	}

	return nil
}

// Evict removes alerts older than deadline (Unix timestamp).
// Returns the number of alerts removed.
func (ce *CorrelationEngine) Evict(deadline float64) int {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	cutoff := time.Unix(int64(deadline), 0)
	before := len(ce.RecentAlerts)

	idx := 0
	for idx < len(ce.RecentAlerts) && ce.RecentAlerts[idx].Time.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		kept := make([]alertRecord, len(ce.RecentAlerts)-idx)
		copy(kept, ce.RecentAlerts[idx:])
		ce.RecentAlerts = kept
	}

	return before - len(ce.RecentAlerts)
}

// ---------------------------------------------------------------------------
// Generic Shannon entropy
// ---------------------------------------------------------------------------

// shannonEntropy computes the Shannon entropy H(X) = -sum(p(x) * log2(p(x)))
// for a slice of comparable items. Returns 0 for empty input.
func shannonEntropy[T comparable](data []T) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[T]int)
	for _, v := range data {
		counts[v]++
	}
	n := float64(len(data))
	var entropy float64
	for _, count := range counts {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// sortedKeys returns the keys of a string set as a sorted string slice.
func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Deterministic order for stable threat output.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
