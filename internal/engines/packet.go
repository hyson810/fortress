// Package engines implements L1 packet-level flood detection.
//
// PacketInspector detects:
//  1. TCP flag anomalies (SYN/FIN/NULL/Xmas scans)
//  2. SYN flood, UDP flood, ICMP flood (per-IP rate limiting)
//  3. Suspicious port probes (sensitive ports like 22, 445, 3306, etc.)
//  4. ARP replies
package engines

import (
	"log"
	"sort"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
)

// SensitivePorts are ports commonly targeted by scanners and worms.
// These trigger an alert regardless of TCP flag pattern.
var SensitivePorts = map[uint16]bool{
	0:     true, // reserved
	1:     true, // tcpmux
	7:     true, // echo
	9:     true, // discard
	13:    true, // daytime
	19:    true, // chargen
	22:    true, // SSH
	23:    true, // Telnet
	135:   true, // MSRPC
	137:   true, // NetBIOS
	139:   true, // NetBIOS
	445:   true, // SMB
	1433:  true, // MSSQL
	3306:  true, // MySQL
	3389:  true, // RDP
	5432:  true, // PostgreSQL
	6379:  true, // Redis
	27017: true, // MongoDB
	11211: true, // Memcached
}

// flagPatterns maps sorted TCP flag character combinations to Chinese
// threat names, matching the Python L1 PacketInspector classification.
var flagPatterns = map[string]string{
	"S":   "SYN扫描",
	"AS":  "SYN-ACK(可能被扫)",
	"F":   "FIN扫描",
	"FPU": "Xmas扫描",
	"N":   "NULL扫描",
	"FS":  "SYN+FIN异常",
	"RS":  "SYN+RST异常",
}

// normalFlags are flag combos that do not trigger a scan alert on their own
// (they may still trigger flood detection).
var normalFlags = map[string]bool{
	"S":  true,
	"AS": true,
}

// Threat represents a detected packet-level threat.
type Threat struct {
	Type   string // Chinese threat category (e.g. "SYN洪水", "FIN扫描")
	IP     string // Source IP address
	Detail string // Human-readable detail (flags, port, MAC, etc.)
}

// RingBuffer is a fixed-capacity sliding window of timestamps.
// It provides O(1) amortized push and O(n) pruning where n is the
// number of expired entries removed during each PruneBefore call.
type RingBuffer struct {
	buf []time.Time
	cap int
}

// NewRingBuffer creates a ring buffer with the given maximum capacity.
func NewRingBuffer(cap int) *RingBuffer {
	return &RingBuffer{
		buf: make([]time.Time, 0, cap),
		cap: cap,
	}
}

// Push adds a timestamp to the buffer. If the buffer is full the oldest
// entry is dropped before appending, mirroring Python deque(maxlen=N).
func (rb *RingBuffer) Push(t time.Time) {
	if len(rb.buf) >= rb.cap {
		rb.buf = rb.buf[1:]
	}
	rb.buf = append(rb.buf, t)
}

// PruneBefore drops all entries older than the cutoff time.
func (rb *RingBuffer) PruneBefore(cutoff time.Time) {
	i := 0
	for i < len(rb.buf) && rb.buf[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		rb.buf = rb.buf[i:]
	}
}

// Len returns the number of timestamps currently in the buffer.
func (rb *RingBuffer) Len() int {
	return len(rb.buf)
}

// PacketInspector is the L1 packet-level threat detection engine.
// It provides TCP flag anomaly detection, per-IP flood detection
// (SYN/UDP/ICMP), sensitive-port probing alerts, and ARP reply
// monitoring.
type PacketInspector struct {
	mu             sync.Mutex
	synCounter     map[string]*RingBuffer
	udpCounter     map[string]*RingBuffer
	icmpCounter    map[string]*RingBuffer
	synFloodPPS    int
	udpFloodPPS    int
	icmpFloodPPS   int
	whitelisted    func(string) bool
	maxRingBuffers int
}

const (
	defaultMaxRingBuffers = 10000
	ringBufferWarnPercent = 0.8
)

// NewPacketInspector creates a PacketInspector with thresholds from
// the engine configuration.
func NewPacketInspector(cfg *config.Config) *PacketInspector {
	return &PacketInspector{
		synCounter:     make(map[string]*RingBuffer),
		udpCounter:     make(map[string]*RingBuffer),
		icmpCounter:    make(map[string]*RingBuffer),
		synFloodPPS:    cfg.Engine.SynFloodPPS,
		udpFloodPPS:    cfg.Engine.UdpFloodPPS,
		icmpFloodPPS:   cfg.Engine.IcmpFloodPPS,
		whitelisted:    cfg.IsWhitelisted,
		maxRingBuffers: defaultMaxRingBuffers,
	}
}

// ClassifyFlags maps a TCP flag string to its Chinese threat name.
// Flags should be sorted uppercase characters (e.g. "S", "AS", "FPU").
// Returns the threat name, or empty string if the flags are not suspicious.
func (pi *PacketInspector) ClassifyFlags(flags string) string {
	return flagPatterns[flags]
}

// isNormalFlags returns true for flag combinations that are not inherently
// suspicious as scans (though they may still trigger flood detection).
func isNormalFlags(flags string) bool {
	return normalFlags[flags]
}

// checkFlood implements a 1-second sliding window rate check.
// It adds the current timestamp, prunes entries older than 1 second,
// and returns true if the remaining count meets or exceeds the threshold.
//
// Enforces a global cap on ring buffers to prevent memory exhaustion
// from IP spoofing attacks. When at capacity, the emptiest ring buffer
// is evicted to make room. Returns false if tracking is impossible.
func (pi *PacketInspector) checkFlood(ip string, threshold int, counter map[string]*RingBuffer) bool {
	now := time.Now()
	rb, ok := counter[ip]
	if !ok {
		if len(counter) >= pi.maxRingBuffers {
			pi.evictEmptiest(counter)
			if len(counter) >= pi.maxRingBuffers {
				log.Printf("[packet] ring buffer pool exhausted (%d), skipping tracking for %s",
					pi.maxRingBuffers, ip)
				return false
			}
		}
		rb = NewRingBuffer(1000)
		counter[ip] = rb

		// Warn when approaching capacity.
		if float64(len(counter)) >= float64(pi.maxRingBuffers)*ringBufferWarnPercent {
			log.Printf("[packet] ring buffer pool at %.0f%% (%d/%d)",
				float64(len(counter))/float64(pi.maxRingBuffers)*100,
				len(counter), pi.maxRingBuffers)
		}
	}
	rb.Push(now)
	rb.PruneBefore(now.Add(-time.Second))
	return rb.Len() >= threshold
}

// evictEmptiest removes the ring buffer with the fewest entries from the
// given counter map. Used to make room when the global cap is reached.
func (pi *PacketInspector) evictEmptiest(counter map[string]*RingBuffer) {
	var victim string
	minLen := int(^uint(0) >> 1) // max int
	for ip, rb := range counter {
		if n := rb.Len(); n < minLen {
			minLen = n
			victim = ip
		}
	}
	if victim != "" {
		delete(counter, victim)
	}
}

// Feed processes a pre-parsed packet and returns any detected threats.
//
// Parameters are extracted by the Rust/XDP layer before calling:
//   - tcpFlags: sorted TCP flags (e.g. "S", "AS", "FPU"), empty for non-TCP
//   - src: source IP address
//   - dport: destination port (TCP/UDP only)
//   - protocol: "TCP", "UDP", or "ICMP"
//
// ARP replies should use FeedARP instead.
func (pi *PacketInspector) Feed(tcpFlags string, src string, dport uint16, protocol string) []Threat {
	pi.mu.Lock()
	defer pi.mu.Unlock()

	var threats []Threat

	switch protocol {
	case "TCP":
		threats = pi.feedTCP(tcpFlags, src, dport)
	case "UDP":
		threats = pi.feedUDP(src)
	case "ICMP":
		threats = pi.feedICMP(src)
	}

	return threats
}

// feedTCP handles TCP-specific threat detection (flags + flood + ports).
// Caller holds pi.mu.
func (pi *PacketInspector) feedTCP(flags string, src string, dport uint16) []Threat {
	var threats []Threat

	// Determine whether to skip flood/scan alerts for whitelisted IPs.
	// ARP alerts are never skipped; this only affects IP-based threats.
	skip := pi.whitelisted != nil && pi.whitelisted(src)

	if !skip {
		// SYN flood check: pure SYN (no ACK) with rate threshold.
		if containsFlag(flags, 'S') && !containsFlag(flags, 'A') {
			if pi.checkFlood(src, pi.synFloodPPS, pi.synCounter) {
				threats = append(threats, Threat{
					Type:   "SYN洪水",
					IP:     src,
					Detail: "速率 pps",
				})
			}
		}

		// TCP flag anomaly scan classification.
		scanType := pi.ClassifyFlags(flags)
		if scanType != "" && !isNormalFlags(flags) {
			threats = append(threats, Threat{
				Type:   scanType,
				IP:     src,
				Detail: "标志位=" + flags + " 端口=" + formatPort(dport),
			})
		}

		// Sensitive port probe detection.
		if SensitivePorts[dport] {
			threats = append(threats, Threat{
				Type:   "敏感端口探测",
				IP:     src,
				Detail: "目标端口 " + formatPort(dport),
			})
		}
	}

	return threats
}

// feedUDP handles UDP flood detection.
// Caller holds pi.mu.
func (pi *PacketInspector) feedUDP(src string) []Threat {
	if pi.whitelisted != nil && pi.whitelisted(src) {
		return nil
	}

	if pi.checkFlood(src, pi.udpFloodPPS, pi.udpCounter) {
		return []Threat{{Type: "UDP洪水", IP: src}}
	}
	return nil
}

// feedICMP handles ICMP flood detection.
// Caller holds pi.mu.
func (pi *PacketInspector) feedICMP(src string) []Threat {
	if pi.whitelisted != nil && pi.whitelisted(src) {
		return nil
	}

	if pi.checkFlood(src, pi.icmpFloodPPS, pi.icmpCounter) {
		return []Threat{{Type: "ICMP洪水", IP: src}}
	}
	return nil
}

// FeedARP detects an ARP reply (op=2). Unlike IP-based threats, ARP
// replies are ALWAYS reported regardless of whitelist status, as they
// may indicate ARP spoofing.
func (pi *PacketInspector) FeedARP(srcIP, srcMAC string) Threat {
	return Threat{
		Type:   "ARP应答",
		IP:     srcIP,
		Detail: "MAC=" + srcMAC,
	}
}

// Evict removes stale IP entries whose most recent timestamp is older
// than the given deadline. Returns the total number of entries evicted.
func (pi *PacketInspector) Evict(deadline float64) int {
	pi.mu.Lock()
	defer pi.mu.Unlock()

	cutoff := time.Unix(int64(deadline), 0)
	total := 0

	for _, counter := range []map[string]*RingBuffer{pi.synCounter, pi.udpCounter, pi.icmpCounter} {
		stale := make([]string, 0)
		for ip, rb := range counter {
			if rb.Len() == 0 || rb.buf[rb.Len()-1].Before(cutoff) {
				stale = append(stale, ip)
			}
		}
		for _, ip := range stale {
			delete(counter, ip)
		}
		total += len(stale)
	}

	return total
}

// containsFlag reports whether the sorted flag string contains the
// given TCP flag character.
func containsFlag(flags string, flag byte) bool {
	for i := 0; i < len(flags); i++ {
		if flags[i] == flag {
			return true
		}
	}
	return false
}

// formatPort formats a port number as a string for threat details.
func formatPort(port uint16) string {
	if port == 0 {
		return "0"
	}
	// Use a small buffer via fmt-like sprintf but avoid importing fmt.
	buf := make([]byte, 0, 5)
	if port >= 10000 {
		buf = append(buf, byte('0'+port/10000))
		port %= 10000
	}
	if port >= 1000 || len(buf) > 0 {
		buf = append(buf, byte('0'+port/1000))
		port %= 1000
	}
	if port >= 100 || len(buf) > 0 {
		buf = append(buf, byte('0'+port/100))
		port %= 100
	}
	if port >= 10 || len(buf) > 0 {
		buf = append(buf, byte('0'+port/10))
		port %= 10
	}
	buf = append(buf, byte('0'+port))
	return string(buf)
}

// Ensure sort is used (it's needed for the sorted flag key generation
// but Go flagPatterns keys are pre-sorted, so this is a compile-time
// guard — the import is kept for potential future dynamic key sorting).
var _ = sort.Strings
