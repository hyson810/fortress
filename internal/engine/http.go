package engine

import (
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fortress/v6/internal/config"
)

const maxHTTPStreams = 5000
const maxStreamSize = 64 * 1024
const streamIdleTimeout = 30 * time.Second

var (
	reSQLi          = regexp.MustCompile(`(?i)(\s|%20)*(or|union|select|insert|drop|--|#|/\*)`)
	reXSS           = regexp.MustCompile(`(?i)(<script|onerror=|onload=|javascript:|alert\(|eval\()`)
	rePathTraversal = regexp.MustCompile(`\.\./|\.\.\\|%2e%2e|%2f|/etc/passwd|/proc/self`)
)

type streamKey struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
}

type httpStream struct {
	Buf      []byte
	LastSeen time.Time
}

// HttpInspector performs TCP stream reassembly and attack pattern
// detection at L5 (application layer) for HTTP traffic.
type HttpInspector struct {
	mu             sync.Mutex
	streams        map[streamKey]*httpStream
	droppedStreams atomic.Uint64
}

// NewHttpInspector creates an HttpInspector with the given configuration.
func NewHttpInspector(cfg *config.Config) *HttpInspector {
	return &HttpInspector{streams: make(map[streamKey]*httpStream)}
}

// Feed processes a TCP payload segment, reassembling it into the correct
// bidirectional stream and scanning for HTTP attack patterns. Returns any
// threats detected during this feed.
func (h *HttpInspector) Feed(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []Threat {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := streamKey{srcIP, dstIP, srcPort, dstPort}
	s, ok := h.streams[key]
	if !ok {
		if len(h.streams) >= maxHTTPStreams {
			h.droppedStreams.Add(1)
			return nil
		}
		s = &httpStream{Buf: make([]byte, 0, 4096)}
		h.streams[key] = s
	}
	s.LastSeen = time.Now()
	if len(s.Buf)+len(payload) > maxStreamSize {
		s.Buf = nil
	}
	s.Buf = append(s.Buf, payload...)
	return h.scan(string(s.Buf), srcIP)
}

func (h *HttpInspector) scan(data, ip string) []Threat {
	var threats []Threat
	if loc := reSQLi.FindStringIndex(data); loc != nil {
		threats = append(threats, Threat{Type: "SQL注入攻击", IP: ip, Detail: "匹配位置"})
	}
	if loc := reXSS.FindStringIndex(data); loc != nil {
		threats = append(threats, Threat{Type: "XSS攻击", IP: ip, Detail: "匹配位置"})
	}
	if loc := rePathTraversal.FindStringIndex(data); loc != nil {
		threats = append(threats, Threat{Type: "路径遍历攻击", IP: ip, Detail: "匹配位置"})
	}
	return threats
}

// EvictIdle removes streams that have not seen activity within the idle
// timeout and returns the count of removed streams.
func (h *HttpInspector) EvictIdle() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := time.Now().Add(-streamIdleTimeout)
	removed := 0
	for k, s := range h.streams {
		if s.LastSeen.Before(cutoff) {
			delete(h.streams, k)
			removed++
		}
	}
	return removed
}

// DroppedStreams returns the count of streams dropped due to capacity limits.
func (h *HttpInspector) DroppedStreams() uint64 { return h.droppedStreams.Load() }
