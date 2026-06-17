package engine

import (
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/pkg/ringbuf"
)

// SensitivePorts — commonly targeted ports
var SensitivePorts = map[uint16]bool{
	22: true, 23: true, 135: true, 137: true, 139: true,
	445: true, 1433: true, 3306: true, 3389: true,
	5432: true, 6379: true, 27017: true, 11211: true,
}

const maxRingBuffers = 10000

// TCP flag patterns for scan detection
var flagPatterns = map[string]string{
	"S": "SYN扫描", "AS": "SYN-ACK", "F": "FIN扫描",
	"FPU": "Xmas扫描", "N": "NULL扫描", "FS": "SYN+FIN异常", "RS": "SYN+RST异常",
}
var normalFlags = map[string]bool{"S": true, "AS": true}

type PacketInspector struct {
	mu           sync.Mutex
	synCounter   map[string]*ringbuf.RingBuffer
	udpCounter   map[string]*ringbuf.RingBuffer
	icmpCounter  map[string]*ringbuf.RingBuffer
	synFloodPPS  int
	udpFloodPPS  int
	icmpFloodPPS int
	whitelisted  func(string) bool
}

func NewPacketInspector(cfg *config.Config) *PacketInspector {
	return &PacketInspector{
		synCounter:   make(map[string]*ringbuf.RingBuffer),
		udpCounter:   make(map[string]*ringbuf.RingBuffer),
		icmpCounter:  make(map[string]*ringbuf.RingBuffer),
		synFloodPPS:  cfg.Engine.SynFloodPPS,
		udpFloodPPS:  cfg.Engine.UdpFloodPPS,
		icmpFloodPPS: cfg.Engine.IcmpFloodPPS,
		whitelisted:  cfg.IsWhitelisted,
	}
}

// Feed processes a packet. tcpFlags is sorted uppercase (e.g. "S", "AS", "FPU").
func (pi *PacketInspector) Feed(tcpFlags, src string, dport uint16, protocol string) []Threat {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	switch protocol {
	case "TCP": return pi.feedTCP(tcpFlags, src, dport)
	case "UDP": return pi.feedUDP(src)
	case "ICMP": return pi.feedICMP(src)
	}
	return nil
}

func (pi *PacketInspector) feedTCP(flags, src string, dport uint16) []Threat {
	var threats []Threat
	if pi.whitelisted != nil && pi.whitelisted(src) { return nil }

	// SYN flood: SYN without ACK, rate-check per IP
	if containsFlag(flags, 'S') && !containsFlag(flags, 'A') {
		if pi.checkFlood(src, pi.synFloodPPS, pi.synCounter) {
			threats = append(threats, Threat{Type: "SYN洪水", IP: src, Detail: "速率 pps"})
		}
	}
	// TCP flag anomaly
	if name := flagPatterns[flags]; name != "" && !normalFlags[flags] {
		threats = append(threats, Threat{Type: name, IP: src, Detail: "标志位=" + flags})
	}
	// Sensitive port probe
	if SensitivePorts[dport] {
		threats = append(threats, Threat{Type: "敏感端口探测", IP: src, Detail: "目标端口"})
	}
	return threats
}

func (pi *PacketInspector) feedUDP(src string) []Threat {
	if pi.whitelisted != nil && pi.whitelisted(src) { return nil }
	if pi.checkFlood(src, pi.udpFloodPPS, pi.udpCounter) {
		return []Threat{{Type: "UDP洪水", IP: src}}
	}
	return nil
}

func (pi *PacketInspector) feedICMP(src string) []Threat {
	if pi.whitelisted != nil && pi.whitelisted(src) { return nil }
	if pi.checkFlood(src, pi.icmpFloodPPS, pi.icmpCounter) {
		return []Threat{{Type: "ICMP洪水", IP: src}}
	}
	return nil
}

func (pi *PacketInspector) FeedARP(srcIP, srcMAC string) Threat {
	return Threat{Type: "ARP应答", IP: srcIP, Detail: "MAC=" + srcMAC}
}

func (pi *PacketInspector) checkFlood(ip string, threshold int, counter map[string]*ringbuf.RingBuffer) bool {
	now := time.Now()
	rb, ok := counter[ip]
	if !ok {
		if len(counter) >= maxRingBuffers {
			pi.evictEmptiest(counter)
		}
		rb = ringbuf.New(1000)
		counter[ip] = rb
	}
	rb.Push(now)
	rb.PruneBefore(now.Add(-time.Second))
	return rb.Len() >= threshold
}

func (pi *PacketInspector) evictEmptiest(counter map[string]*ringbuf.RingBuffer) {
	var minIP string
	minLen := int(^uint(0) >> 1)
	for ip, rb := range counter {
		if rb.Len() < minLen { minLen = rb.Len(); minIP = ip }
	}
	if minIP != "" { delete(counter, minIP) }
}

func containsFlag(flags string, flag byte) bool {
	for i := 0; i < len(flags); i++ {
		if flags[i] == flag { return true }
	}
	return false
}
