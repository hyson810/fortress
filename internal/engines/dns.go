// Package engines implements L2 DNS tunnel detection using three heuristics:
//  1. Long query name detection (>52 chars) — data exfiltration
//  2. High Shannon entropy detection (>4.5) — encoded/encrypted payloads
//  3. DNS query flood detection (>30 queries in 30s window)
package engines

import (
	"fmt"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
)

// Default DNS tunnel detection thresholds.
// These match the Python DnsTunnelDetector defaults and can be
// overridden via config when corresponding fields are added to EngineConfig.
const (
	defaultDNSMaxRecords    = 200
	defaultDNSLengthAlarm   = 52
	defaultDNSEntropyThresh = 4.5
	defaultDNSFloodThresh   = 30
	defaultDNSFloodWindowS  = 30
)

// QueryRecord stores a single DNS query event.
type QueryRecord struct {
	Time time.Time
	Name string
}

// DnsTunnelDetector detects DNS tunneling via per-IP query history analysis.
// It tracks query names and timestamps to identify exfiltration channels,
// encoded payloads, and query floods characteristic of DNS tunnels.
type DnsTunnelDetector struct {
	mu            sync.Mutex
	queryHistory  map[string][]QueryRecord
	maxRecords    int
	lengthAlarm   int
	entropyThresh float64
	floodWindow   time.Duration
	floodThresh   int
	whitelisted   func(string) bool
}

// NewDnsTunnelDetector creates a DnsTunnelDetector with default thresholds.
// Future config fields in EngineConfig (e.g. DnsLengthAlarm, DnsEntropyThresh)
// can override these defaults.
func NewDnsTunnelDetector(cfg *config.Config) *DnsTunnelDetector {
	return &DnsTunnelDetector{
		queryHistory:  make(map[string][]QueryRecord),
		maxRecords:    defaultDNSMaxRecords,
		lengthAlarm:   defaultDNSLengthAlarm,
		entropyThresh: defaultDNSEntropyThresh,
		floodWindow:   defaultDNSFloodWindowS * time.Second,
		floodThresh:   defaultDNSFloodThresh,
		whitelisted:   cfg.IsWhitelisted,
	}
}

// Feed records a DNS query from srcIP for the given query name.
// The query is timestamped and appended to the IP's sliding history
// (capped at maxRecords entries, oldest evicted first).
func (d *DnsTunnelDetector) Feed(srcIP, queryName string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	history := d.queryHistory[srcIP]
	history = append(history, QueryRecord{Time: now, Name: queryName})
	if len(history) > d.maxRecords {
		history = history[len(history)-d.maxRecords:]
	}
	d.queryHistory[srcIP] = history
}

// Check analyzes the query history for srcIP and returns any detected threats.
// Three checks are performed:
//  1. Query flood: count queries in the flood window (default 30s)
//  2. Long query: any individual query name exceeding lengthAlarm (default 52)
//  3. High entropy: Shannon entropy of all query names exceeding threshold
//
// Returns nil if no threats are detected or if the IP is whitelisted.
func (d *DnsTunnelDetector) Check(srcIP string) []Threat {
	d.mu.Lock()
	defer d.mu.Unlock()

	history, ok := d.queryHistory[srcIP]
	if !ok || len(history) == 0 {
		return nil
	}

	if d.whitelisted != nil && d.whitelisted(srcIP) {
		return nil
	}

	now := time.Now()
	floodCutoff := now.Add(-d.floodWindow)

	var threats []Threat
	floodCount := 0
	hasLongQuery := false

	// Single backward pass collecting flood count and long query flag.
	for i := len(history) - 1; i >= 0; i-- {
		q := history[i]

		if !q.Time.Before(floodCutoff) {
			floodCount++
		}

		if len(q.Name) > d.lengthAlarm {
			hasLongQuery = true
		}
	}

	// Check 1: Query flood — rapid-fire DNS queries characteristic of tunnels.
	if floodCount >= d.floodThresh {
		threats = append(threats, Threat{
			Type:   "DNS查询洪水",
			IP:     srcIP,
			Detail: fmt.Sprintf("%d次查询/%ds", floodCount, int(d.floodWindow.Seconds())),
		})
	}

	// Check 2: Long query — oversized query names suggest data exfiltration.
	if hasLongQuery {
		threats = append(threats, Threat{
			Type:   "DNS隧道(长查询)",
			IP:     srcIP,
			Detail: fmt.Sprintf("查询名称超过%d字符", d.lengthAlarm),
		})
	}

	// Check 3: High entropy — uniformly distributed characters indicate encoding.
	// Compute entropy over the full history (up to maxRecords=200).
	names := make([]string, len(history))
	for i, q := range history {
		names[i] = q.Name
	}
	if ent := shannonEntropy(names); ent > d.entropyThresh {
		threats = append(threats, Threat{
			Type:   "DNS隧道(高熵)",
			IP:     srcIP,
			Detail: fmt.Sprintf("熵值=%.2f", ent),
		})
	}

	return threats
}

// Evict removes stale IPs whose most recent query is older than deadline
// (Unix timestamp). Returns the number of IPs fully removed.
func (d *DnsTunnelDetector) Evict(deadline float64) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Unix(int64(deadline), 0)
	removed := 0

	for ip, history := range d.queryHistory {
		kept := pruneQueryRecords(history, cutoff)
		if len(kept) == 0 {
			delete(d.queryHistory, ip)
			removed++
		} else {
			d.queryHistory[ip] = kept
		}
	}
	return removed
}

// pruneQueryRecords returns a new slice containing only records at or after
// cutoff, preserving insertion order. Returns nil if no records remain.
func pruneQueryRecords(records []QueryRecord, cutoff time.Time) []QueryRecord {
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
	kept := make([]QueryRecord, len(records)-idx)
	copy(kept, records[idx:])
	return kept
}
