package engine

import (
	"math"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/pkg/cmsketch"
)

const (
	maxFlows         = 10000
	cmsRows          = 4
	cmsCols          = 65536
	emaAlpha         = 0.1
	zThresholdL1     = 4.0
	anomalyThresholdL2 = 6.0
	minSamplesForZ   = 5
)

type featureStats struct {
	EMA  float64
	Mean float64
	M2   float64
	N    int
}

// FlowStats tracks per-IP feature statistics for anomaly detection.
type FlowStats struct {
	IP       string
	LastSeen time.Time
	Features [6]featureStats
}

// HybridAnomalyDetector is the L6 hybrid anomaly engine combining
// EMA Z-Score (Layer 1) with Count-Min Sketch (Layer 2).
type HybridAnomalyDetector struct {
	mu          sync.Mutex
	flows       map[string]*FlowStats
	cms         *cmsketch.CountMin
	packetCount uint64
	ZThresh     float64
	L2Thresh    float64
}

// NewHybridAnomalyDetector creates a new L6 hybrid anomaly detector.
func NewHybridAnomalyDetector(cfg *config.Config) *HybridAnomalyDetector {
	return &HybridAnomalyDetector{
		flows:    make(map[string]*FlowStats),
		cms:      cmsketch.New(cmsRows, cmsCols),
		ZThresh:  zThresholdL1,
		L2Thresh: anomalyThresholdL2,
	}
}

// Feed processes a single packet and returns any detected anomalies.
func (ha *HybridAnomalyDetector) Feed(pkt PacketContext) []Threat {
	ha.mu.Lock()
	defer ha.mu.Unlock()

	ha.packetCount++
	if ha.packetCount%10000000 == 0 {
		ha.cms.Decay()
	}

	fs, ok := ha.flows[pkt.SrcIP]
	if !ok {
		if len(ha.flows) >= maxFlows {
			ha.evictOldest()
		}
		fs = &FlowStats{IP: pkt.SrcIP}
		ha.flows[pkt.SrcIP] = fs
	}
	fs.LastSeen = time.Now()

	featVals := [6]float64{
		float64(pkt.PayloadSize),
		0,
		float64(len(pkt.TCPFlags)),
		0,
		1,
		1,
	}

	var l1Score float64
	for i, val := range featVals {
		st := &fs.Features[i]
		if st.N < minSamplesForZ {
			st.EMA = val
			st.N++
			continue
		}
		delta := val - st.EMA
		st.EMA += emaAlpha * delta
		oldMean := st.Mean
		st.N++
		st.Mean += (val - st.Mean) / float64(st.N)
		st.M2 += (val - oldMean) * (val - st.Mean)
		stddev := float64(0)
		if st.N >= 2 {
			stddev = math.Sqrt(st.M2 / float64(st.N-1))
		}
		if stddev > 0 {
			z := math.Abs(val-st.EMA) / stddev
			if z > ha.ZThresh {
				l1Score += z / ha.ZThresh
			}
		}
	}

	fp := []byte(pkt.SrcIP + pkt.Protocol)
	ha.cms.Add(fp, 1)
	estimate := ha.cms.Estimate(fp)
	total := ha.cms.Total()
	var l2Score float64
	if total > 0 && estimate > 0 {
		l2Score = -math.Log(float64(estimate) / float64(total))
	}

	var threats []Threat
	if l1Score >= 2.0 || l2Score > ha.L2Thresh {
		threats = append(threats, Threat{
			Type:   "混合异常",
			IP:     pkt.SrcIP,
			Detail: "L1+L2异常",
		})
	}
	return threats
}

func (ha *HybridAnomalyDetector) evictOldest() {
	var oldestIP string
	var oldestTime time.Time
	for ip, fs := range ha.flows {
		if oldestIP == "" || fs.LastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = fs.LastSeen
		}
	}
	if oldestIP != "" {
		delete(ha.flows, oldestIP)
	}
}

// EvictIdle removes flows that haven't been seen within the given duration.
func (ha *HybridAnomalyDetector) EvictIdle(idle time.Duration) int {
	ha.mu.Lock()
	defer ha.mu.Unlock()
	cutoff := time.Now().Add(-idle)
	removed := 0
	for ip, fs := range ha.flows {
		if fs.LastSeen.Before(cutoff) {
			delete(ha.flows, ip)
			removed++
		}
	}
	return removed
}
