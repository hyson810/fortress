package engine

import (
	"math"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/pkg/entropy"
	"github.com/fortress/v6/pkg/welford"
)

const (
	defaultEntropyWindow  = 60 * time.Second
	entropyDeviationSigma = 2.5
	baselineInterval      = 200
	maxGlobalSamples      = 2000
)

type portSample struct {
	Time time.Time
	Port uint16
}

type ipSample struct {
	Time time.Time
	IP   string
}

// BehaviorAnalyzer performs L3 behavioral entropy anomaly detection
// using Welford's online algorithm. It tracks port and IP entropy
// over a sliding window and alerts when entropy deviates from baseline
// by more than entropyDeviationSigma standard deviations.
type BehaviorAnalyzer struct {
	mu            sync.Mutex
	globalPorts   []portSample
	globalIPs     []ipSample
	portBaseline  *welford.Tracker
	ipBaseline    *welford.Tracker
	entropyWindow time.Duration
	devThreshold  float64
	sampleCount   int
}

// NewBehaviorAnalyzer creates a BehaviorAnalyzer with default thresholds.
func NewBehaviorAnalyzer(cfg *config.Config) *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		globalPorts:   make([]portSample, 0, maxGlobalSamples),
		globalIPs:     make([]ipSample, 0, maxGlobalSamples),
		portBaseline:  welford.New(),
		ipBaseline:    welford.New(),
		entropyWindow: defaultEntropyWindow,
		devThreshold:  entropyDeviationSigma,
	}
}

// Feed records a source IP and destination port for entropy tracking.
// Every baselineInterval samples, the current entropy is added to
// the Welford baseline trackers.
func (ba *BehaviorAnalyzer) Feed(srcIP string, dstPort uint16) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	now := time.Now()

	ba.globalPorts = append(ba.globalPorts, portSample{Time: now, Port: dstPort})
	if len(ba.globalPorts) > maxGlobalSamples {
		ba.globalPorts = ba.globalPorts[len(ba.globalPorts)-maxGlobalSamples:]
	}

	ba.globalIPs = append(ba.globalIPs, ipSample{Time: now, IP: srcIP})
	if len(ba.globalIPs) > maxGlobalSamples {
		ba.globalIPs = ba.globalIPs[len(ba.globalIPs)-maxGlobalSamples:]
	}

	ba.sampleCount++
	if ba.sampleCount%baselineInterval == 0 {
		ba.portBaseline.Add(ba.currentPortEntropy())
		ba.ipBaseline.Add(ba.currentIPEntropy())
	}
}

// Check computes current entropy deviations and returns any threats.
func (ba *BehaviorAnalyzer) Check() []Threat {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	var threats []Threat

	pe := ba.currentPortEntropy()
	ie := ba.currentIPEntropy()

	if ba.portBaseline.Std() > 0 {
		dev := math.Abs(pe-ba.portBaseline.Mean()) / ba.portBaseline.Std()
		if dev > ba.devThreshold {
			threats = append(threats, Threat{Type: "流量异常", Detail: "端口熵偏差"})
		}
	}

	if ba.ipBaseline.Std() > 0 {
		dev := math.Abs(ie-ba.ipBaseline.Mean()) / ba.ipBaseline.Std()
		if dev > ba.devThreshold {
			threats = append(threats, Threat{Type: "流量异常", Detail: "IP熵偏差"})
		}
	}

	return threats
}

// currentPortEntropy computes the Shannon entropy of destination ports
// within the sliding entropy window.
func (ba *BehaviorAnalyzer) currentPortEntropy() float64 {
	cutoff := time.Now().Add(-ba.entropyWindow)
	freq := make(map[uint16]uint64)
	for i := len(ba.globalPorts) - 1; i >= 0; i-- {
		if ba.globalPorts[i].Time.Before(cutoff) {
			break
		}
		freq[ba.globalPorts[i].Port]++
	}
	return entropy.Shannon(freq)
}

// currentIPEntropy computes the Shannon entropy of source IPs
// within the sliding entropy window.
func (ba *BehaviorAnalyzer) currentIPEntropy() float64 {
	cutoff := time.Now().Add(-ba.entropyWindow)
	freq := make(map[string]uint64)
	for i := len(ba.globalIPs) - 1; i >= 0; i-- {
		if ba.globalIPs[i].Time.Before(cutoff) {
			break
		}
		freq[ba.globalIPs[i].IP]++
	}
	return entropy.Shannon(freq)
}
