// Package engines implements ICMP tunnel and covert channel detection.
// ICMP tunnels abuse the ICMP protocol (typically echo request/reply) to
// exfiltrate data or establish C2 channels through firewalls that allow
// ICMP but block TCP/UDP. This detector identifies:
//   1. ICMP echo request flooding (DoS precursor)
//   2. ICMP payload anomalies (large/unusual payloads — tunneling indicator)
//   3. ICMP type/code anomaly patterns (covert channel signatures)
package engines

import (
	"fmt"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// Normal ICMP echo payload size is 32-56 bytes (Windows ping: 32, Linux: 56).
	// Anything above 256 bytes is suspicious; above 1024 is almost certainly tunneling.
	icmpNormalPayloadMax = 256
	icmpTunnelPayloadMin = 1024

	// ICMP type constants.
	icmpEchoReply   = 0
	icmpEchoRequest = 8
	icmpTimestamp   = 13
	icmpInfoReq     = 15
	icmpMaskReq     = 17

	// ICMP tunnel detection window.
	icmpTunnelWindow  = 60 * time.Second
	icmpTunnelMinPkts = 10 // minimum packets in window to assess tunneling

	// ICMP fingerprint buffer size.
	icmpBufSize = 128
)

// ICMPType names for reporting.
var icmpTypeNames = map[int]string{
	0:  "EchoReply",
	3:  "DestUnreach",
	8:  "EchoRequest",
	11: "TimeExceeded",
	13: "Timestamp",
	15: "InfoRequest",
	17: "MaskRequest",
}

// ---------------------------------------------------------------------------
// ICMPTunnelDetector
// ---------------------------------------------------------------------------

// icmpRecord tracks ICMP traffic statistics for a single source IP.
type icmpRecord struct {
	lastSeen      time.Time
	packetCount   int
	largePayloads int       // count of packets with payload > icmpNormalPayloadMax
	tunnelPackets int       // count of packets with payload > icmpTunnelPayloadMin
	totalBytes    int64
	icmpTypes     map[int]int // type → count
	firstSeen     time.Time
}

// ICMPTunnelDetector detects ICMP tunneling and covert channel activity.
// It tracks per-IP ICMP traffic patterns and flags anomalies such as:
//   - Unusually large ICMP payloads (data exfiltration over ICMP)
//   - Unusual ICMP type distribution (timestamp/mask requests as C2 beacons)
//   - Sustained high-byte ICMP flows (VPN-over-ICMP tools like icmptx)
type ICMPTunnelDetector struct {
	mu          sync.Mutex
	records     map[string]*icmpRecord
	maxRecords  int
	whitelisted func(string) bool
}

// NewICMPTunnelDetector creates an ICMPTunnelDetector.
func NewICMPTunnelDetector(cfg *config.Config) *ICMPTunnelDetector {
	return &ICMPTunnelDetector{
		records:     make(map[string]*icmpRecord),
		maxRecords:  10000,
		whitelisted: cfg.IsWhitelisted,
	}
}

// Feed processes an ICMP packet from srcIP with the given type, code, and
// payload size. Returns any threats detected.
func (d *ICMPTunnelDetector) Feed(srcIP string, icmpType, icmpCode int, payloadSize int) []Threat {
	if d.whitelisted != nil && d.whitelisted(srcIP) {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	rec := d.getOrCreateLocked(srcIP, now)
	rec.lastSeen = now
	rec.packetCount++
	rec.totalBytes += int64(payloadSize)
	rec.icmpTypes[icmpType]++

	if payloadSize > icmpNormalPayloadMax {
		rec.largePayloads++
	}
	if payloadSize > icmpTunnelPayloadMin {
		rec.tunnelPackets++
	}

	// Evict old records if at capacity.
	if len(d.records) > d.maxRecords {
		d.evictOldestLocked()
	}

	// Only assess after minimum packets collected.
	if rec.packetCount < icmpTunnelMinPkts {
		return nil
	}

	var threats []Threat

	// Check 1: Sustained large ICMP payloads (data tunneling).
	tunnelRatio := float64(rec.tunnelPackets) / float64(rec.packetCount)
	if rec.tunnelPackets >= 5 && tunnelRatio > 0.3 {
		threats = append(threats, Threat{
			Type: "ICMP隧道",
			IP:   srcIP,
			Detail: fmt.Sprintf("大载荷ICMP包=%d/%d (%.0f%%) 总字节=%d",
				rec.tunnelPackets, rec.packetCount, tunnelRatio*100, rec.totalBytes),
		})
	}

	// Check 2: Unusual ICMP types (timestamp/mask requests as covert channel).
	unusualCount := 0
	for _, t := range []int{icmpTimestamp, icmpInfoReq, icmpMaskReq} {
		unusualCount += rec.icmpTypes[t]
	}
	if unusualCount >= 3 {
		threats = append(threats, Threat{
			Type: "ICMP隐蔽信道",
			IP:   srcIP,
			Detail: fmt.Sprintf("异常ICMP类型 timestamp=%d infoReq=%d maskReq=%d (总数=%d)",
				rec.icmpTypes[icmpTimestamp], rec.icmpTypes[icmpInfoReq],
				rec.icmpTypes[icmpMaskReq], rec.packetCount),
		})
	}

	// Check 3: High volume ICMP echo with large payloads (ptunnel/loki signature).
	avgPayload := float64(rec.totalBytes) / float64(rec.packetCount)
	echoCount := rec.icmpTypes[icmpEchoRequest] + rec.icmpTypes[icmpEchoReply]
	if echoCount > 50 && avgPayload > 200 {
		threats = append(threats, Threat{
			Type: "ICMP数据外泄",
			IP:   srcIP,
			Detail: fmt.Sprintf("Echo包=%d 平均载荷=%.0f字节 总流量=%d字节",
				echoCount, avgPayload, rec.totalBytes),
		})
	}

	return threats
}

// Evict removes records older than the deadline (Unix timestamp).
func (d *ICMPTunnelDetector) Evict(deadline float64) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Unix(int64(deadline), 0)
	var stale []string
	for ip, rec := range d.records {
		if rec.lastSeen.Before(cutoff) {
			stale = append(stale, ip)
		}
	}
	for _, ip := range stale {
		delete(d.records, ip)
	}
	return len(stale)
}

// getOrCreateLocked returns the record for ip, creating one if needed.
// Caller holds d.mu.
func (d *ICMPTunnelDetector) getOrCreateLocked(ip string, now time.Time) *icmpRecord {
	if rec, ok := d.records[ip]; ok {
		return rec
	}
	rec := &icmpRecord{
		lastSeen:  now,
		firstSeen: now,
		icmpTypes: make(map[int]int),
	}
	d.records[ip] = rec
	return rec
}

// evictOldestLocked removes the least recently seen record.
// Caller holds d.mu.
func (d *ICMPTunnelDetector) evictOldestLocked() {
	var oldestIP string
	var oldestTime time.Time
	first := true
	for ip, rec := range d.records {
		if first || rec.lastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = rec.lastSeen
			first = false
		}
	}
	if oldestIP != "" {
		delete(d.records, oldestIP)
	}
}

// ActiveIPs returns the number of currently tracked source IPs.
func (d *ICMPTunnelDetector) ActiveIPs() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.records)
}
