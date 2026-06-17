package engine

import (
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
)

type flowRecord struct {
	Time time.Time
	Port uint16
}

type scanWindow struct {
	Name      string
	Seconds   int
	Threshold int
}

var defaultScanWindows = []scanWindow{
	{"快速扫描", 5, 12},
	{"中速扫描", 30, 25},
	{"慢速扫描", 300, 50},
}

const maxFlowRecords = 500

type FlowAnalyzer struct {
	mu      sync.Mutex
	records map[string][]flowRecord
	windows []scanWindow
}

func NewFlowAnalyzer(cfg *config.Config) *FlowAnalyzer {
	return &FlowAnalyzer{
		records: make(map[string][]flowRecord),
		windows: defaultScanWindows,
	}
}

// Feed records a flow observation and returns any scan alerts.
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
		for i := len(records) - 1; i >= 0; i-- {
			if records[i].Time.Before(cutoff) {
				break
			}
			uniquePorts[records[i].Port] = struct{}{}
		}
		if len(uniquePorts) >= w.Threshold {
			threats = append(threats, Threat{
				Type:   w.Name,
				IP:     srcIP,
				Detail: "扫描端口数=" + itoa(len(uniquePorts)),
			})
		}
	}
	return threats
}

// Evict removes records older than deadline. Returns count of IPs removed.
func (fa *FlowAnalyzer) Evict(deadline time.Time) int {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	removed := 0
	for ip, records := range fa.records {
		kept := pruneFlowRecords(records, deadline)
		if len(kept) == 0 {
			delete(fa.records, ip)
			removed++
		} else {
			fa.records[ip] = kept
		}
	}
	return removed
}

func pruneFlowRecords(records []flowRecord, cutoff time.Time) []flowRecord {
	for i, r := range records {
		if !r.Time.Before(cutoff) {
			kept := make([]flowRecord, len(records)-i)
			copy(kept, records[i:])
			return kept
		}
	}
	return nil
}

// itoa converts int to string without importing fmt.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 6)
	tmp := n
	for tmp > 0 {
		buf = append([]byte{byte('0' + tmp%10)}, buf...)
		tmp /= 10
	}
	return string(buf)
}
