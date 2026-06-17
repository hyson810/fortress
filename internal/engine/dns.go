package engine

import (
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/pkg/entropy"
)

const (
	dnsMaxQueryLen   = 52
	dnsEntropyThresh = 4.5
	dnsFloodThresh   = 30
	dnsFloodWindow   = 30 * time.Second
	dnsMaxHistory    = 200
)

type queryRecord struct {
	Time  time.Time
	Query string
}

// DnsTunnelDetector performs L4 DNS tunnel detection using three heuristics:
//  1. Long query name detection (>52 chars) — data exfiltration
//  2. High Shannon entropy (>4.5) — encoded/encrypted payloads
//  3. Query flood detection (>30 queries in 30s window)
type DnsTunnelDetector struct {
	mu      sync.Mutex
	history map[string][]queryRecord
}

// NewDnsTunnelDetector creates a DnsTunnelDetector with default thresholds.
func NewDnsTunnelDetector(cfg *config.Config) *DnsTunnelDetector {
	return &DnsTunnelDetector{history: make(map[string][]queryRecord)}
}

// Feed records a DNS query from srcIP and returns any threats detected
// for this query. Three checks run inline: query length, entropy, and
// flood frequency.
func (d *DnsTunnelDetector) Feed(srcIP, query string) []Threat {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	d.history[srcIP] = append(d.history[srcIP], queryRecord{Time: now, Query: query})
	if len(d.history[srcIP]) > dnsMaxHistory {
		d.history[srcIP] = d.history[srcIP][len(d.history[srcIP])-dnsMaxHistory:]
	}

	var threats []Threat

	if len(query) > dnsMaxQueryLen {
		threats = append(threats, Threat{Type: "DNS隧道", IP: srcIP, Detail: "查询长度异常"})
	}

	if entropy.Bytes([]byte(query)) > dnsEntropyThresh {
		threats = append(threats, Threat{Type: "DNS隧道", IP: srcIP, Detail: "查询熵异常"})
	}

	count := 0
	cutoff := now.Add(-dnsFloodWindow)
	for _, r := range d.history[srcIP] {
		if r.Time.After(cutoff) {
			count++
		}
	}
	if count >= dnsFloodThresh {
		threats = append(threats, Threat{Type: "DNS隧道", IP: srcIP, Detail: "查询频率异常"})
	}

	return threats
}
