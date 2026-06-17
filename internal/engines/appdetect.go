// Package engines implements L2 HTTP attack detection (SQL injection, XSS,
// path traversal) via TCP stream reassembly and L2 brute-force detection
// (SSH and HTTP authentication attacks) via per-IP rate analysis.
package engines

import (
	"fmt"
	"log"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fortress/v6/internal/config"
)

// ---------------------------------------------------------------------------
// HTTP Inspector — pattern-based attack detection via TCP stream reassembly
// ---------------------------------------------------------------------------

const (
	maxStreamBytes        = 65536
	maxConcurrentStreams  = 5000
	streamIdleSeconds     = 30
)

// Regex patterns for HTTP payload scanning. These match common web attack
// signatures in request bodies, URIs, and headers.
var (
	// reSQLi matches common SQL injection patterns including UNION SELECT,
	// tautologies (' OR 1=1), stacked queries, and DDL/DML keywords.
	reSQLi = regexp.MustCompile(`(?i)(union\s+(all\s+)?select|or\s+['\x22]?\d+['\x22]?\s*=\s*['\x22]?\d+|--[\s\r\n]|;\s*select\s|drop\s+table|insert\s+into\s|exec\s*\(|exec\s+sp_|xp_cmdshell|\bwaitfor\s+delay\b)`)

	// reXSS matches common cross-site scripting vectors including script tags,
	// javascript: URIs, event handlers, and DOM-manipulation calls.
	reXSS = regexp.MustCompile(`(?i)(<script[>\s/]|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|eval\s*\(|<img[^>]+onerror|prompt\s*\(|confirm\s*\()`)

	// rePathTraversal matches directory traversal sequences using both
	// literal and URL-encoded representations.
	rePathTraversal = regexp.MustCompile(`(\.\./|\.\.\\|/etc/passwd|/etc/shadow|%2e%2e%2f|%2e%2e%5c|\.\.%2f|\.\.%5c)`)
)

// streamKey uniquely identifies a TCP stream by its 4-tuple.
type streamKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// httpStream holds the reassembled payload buffer and last activity time
// for an in-progress TCP stream.
type httpStream struct {
	buf        []byte
	lastActive time.Time
}

// HttpInspector reassembles TCP streams and scans HTTP payloads for
// SQL injection, XSS, and path traversal attacks.
//
// Streams are keyed by (srcIP, srcPort, dstIP, dstPort). Payload data
// is appended up to maxStreamBytes. Streams are closed when a FIN or RST
// flag is observed, or when they exceed streamIdleSeconds of inactivity.
type HttpInspector struct {
	mu             sync.Mutex
	streams        map[streamKey]*httpStream
	maxStreamBytes int
	maxConcurrent  int
	streamIdle     time.Duration
	whitelisted    func(string) bool
	droppedStreams atomic.Uint64
}

// NewHttpInspector creates an HttpInspector with default stream limits.
func NewHttpInspector(cfg *config.Config) *HttpInspector {
	return &HttpInspector{
		streams:        make(map[streamKey]*httpStream),
		maxStreamBytes: maxStreamBytes,
		maxConcurrent:  maxConcurrentStreams,
		streamIdle:     streamIdleSeconds * time.Second,
		whitelisted:    cfg.IsWhitelisted,
	}
}

// Feed processes a chunk of HTTP payload data for a given TCP stream.
//
// Parameters:
//   - srcIP, dstIP: source and destination IP addresses
//   - srcPort, dstPort: source and destination TCP ports
//   - payload: the raw bytes from this TCP segment
//   - flags: TCP flag string ("S", "AS", "F", "R", "FR", etc.)
//     A stream is closed (removed) when flags contain "F" or "R".
//
// Returns any threats detected in the accumulated stream payload.
func (h *HttpInspector) Feed(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, flags string) []Threat {
	h.mu.Lock()
	defer h.mu.Unlock()

	key := streamKey{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}

	// Close stream on FIN or RST.
	if containsFlag(flags, 'F') || containsFlag(flags, 'R') {
		delete(h.streams, key)
		return nil
	}

	// Get or create stream, respecting concurrency limit.
	stream, ok := h.streams[key]
	if !ok {
		if len(h.streams) >= h.maxConcurrent {
			n := h.droppedStreams.Add(1)
			if n%1000 == 0 {
				log.Printf("[appdetect] stream limit reached, dropped %d streams", n)
			}
			return nil
		}
		stream = &httpStream{}
		h.streams[key] = stream
	}

	stream.lastActive = time.Now()

	// Append payload, respecting max stream byte limit.
	available := h.maxStreamBytes - len(stream.buf)
	if available <= 0 {
		return nil
	}
	if len(payload) > available {
		payload = payload[:available]
	}
	stream.buf = append(stream.buf, payload...)

	// Scan the accumulated buffer for attack patterns.
	return h.scanPayload(stream.buf, srcIP)
}

// DroppedStreams returns the number of streams dropped due to the
// concurrent stream limit since the inspector was created.
func (h *HttpInspector) DroppedStreams() uint64 {
	return h.droppedStreams.Load()
}

// Evict removes idle streams whose last activity is older than deadline
// (Unix timestamp). Returns the number of streams evicted.
func (h *HttpInspector) Evict(deadline float64) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	cutoff := time.Unix(int64(deadline), 0)
	removed := 0

	for key, stream := range h.streams {
		if stream.lastActive.Before(cutoff) {
			delete(h.streams, key)
			removed++
		}
	}
	return removed
}

// scanPayload checks the payload buffer against all attack patterns.
// Caller holds h.mu.
func (h *HttpInspector) scanPayload(payload []byte, srcIP string) []Threat {
	if h.whitelisted != nil && h.whitelisted(srcIP) {
		return nil
	}

	var threats []Threat

	if loc := reSQLi.FindIndex(payload); loc != nil {
		threats = append(threats, Threat{
			Type:   "SQL注入攻击",
			IP:     srcIP,
			Detail: fmt.Sprintf("匹配位置=%d", loc[0]),
		})
	}

	if loc := reXSS.FindIndex(payload); loc != nil {
		threats = append(threats, Threat{
			Type:   "XSS攻击",
			IP:     srcIP,
			Detail: fmt.Sprintf("匹配位置=%d", loc[0]),
		})
	}

	if loc := rePathTraversal.FindIndex(payload); loc != nil {
		threats = append(threats, Threat{
			Type:   "路径遍历攻击",
			IP:     srcIP,
			Detail: fmt.Sprintf("匹配位置=%d", loc[0]),
		})
	}

	return threats
}

// ---------------------------------------------------------------------------
// Brute-Force Detector — per-IP rate-based brute-force attack detection
// ---------------------------------------------------------------------------

const (
	defaultSSHThreshold  = 10
	defaultSSHWindowSec  = 60
	defaultHTTPThreshold = 15
	defaultHTTPWindowSec = 60
)

// BruteForceDetector tracks per-IP SSH connection attempts and HTTP
// authentication failures to detect brute-force attacks.
//
// SSH detection: counts SYN packets to port 22. An alert fires when
// an IP sends defaultSSHThreshold (10) or more attempts within
// defaultSSHWindowSec (60) seconds.
//
// HTTP detection: counts 401/403 responses. An alert fires when an IP
// receives defaultHTTPThreshold (15) or more failure responses within
// defaultHTTPWindowSec (60) seconds.
type BruteForceDetector struct {
	mu           sync.Mutex
	sshAttempts  map[string]*RingBuffer
	httpFailures map[string]*RingBuffer
	sshThresh    int
	sshWindow    time.Duration
	httpThresh   int
	httpWindow   time.Duration
	whitelisted  func(string) bool
}

// NewBruteForceDetector creates a BruteForceDetector with default thresholds.
func NewBruteForceDetector(cfg *config.Config) *BruteForceDetector {
	return &BruteForceDetector{
		sshAttempts:  make(map[string]*RingBuffer),
		httpFailures: make(map[string]*RingBuffer),
		sshThresh:    defaultSSHThreshold,
		sshWindow:    defaultSSHWindowSec * time.Second,
		httpThresh:   defaultHTTPThreshold,
		httpWindow:   defaultHTTPWindowSec * time.Second,
		whitelisted:  cfg.IsWhitelisted,
	}
}

// FeedSSH records an SSH connection attempt from srcIP (SYN to port 22).
func (b *BruteForceDetector) FeedSSH(srcIP string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	rb := b.ensureRingBuffer(&b.sshAttempts, srcIP)
	rb.Push(time.Now())
}

// FeedHTTPResponse records an HTTP response for srcIP. Only status codes
// 401 (Unauthorized) and 403 (Forbidden) are tracked as failure indicators.
func (b *BruteForceDetector) FeedHTTPResponse(srcIP string, statusCode int) {
	if statusCode != 401 && statusCode != 403 {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	rb := b.ensureRingBuffer(&b.httpFailures, srcIP)
	rb.Push(time.Now())
}

// CheckAll examines all tracked IPs and returns threats for any that exceed
// the brute-force thresholds. Each IP is checked independently; a single IP
// can trigger both SSH and HTTP alerts if both thresholds are exceeded.
func (b *BruteForceDetector) CheckAll() []Threat {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.whitelisted == nil {
		return b.checkAllLocked()
	}

	// Filter whitelisted IPs before checking.
	filtered := &BruteForceDetector{
		sshAttempts:  make(map[string]*RingBuffer),
		httpFailures: make(map[string]*RingBuffer),
		sshThresh:    b.sshThresh,
		sshWindow:    b.sshWindow,
		httpThresh:   b.httpThresh,
		httpWindow:   b.httpWindow,
	}

	for ip, rb := range b.sshAttempts {
		if !b.whitelisted(ip) {
			filtered.sshAttempts[ip] = rb
		}
	}
	for ip, rb := range b.httpFailures {
		if !b.whitelisted(ip) {
			filtered.httpFailures[ip] = rb
		}
	}
	return filtered.checkAllLocked()
}

// checkAllLocked performs the threshold checks. Caller holds mu.
func (b *BruteForceDetector) checkAllLocked() []Threat {
	now := time.Now()
	sshCutoff := now.Add(-b.sshWindow)
	httpCutoff := now.Add(-b.httpWindow)

	var threats []Threat

	// SSH brute-force: count attempts per IP within the window.
	for ip, rb := range b.sshAttempts {
		count := b.countInWindow(rb, sshCutoff)
		if count >= b.sshThresh {
			threats = append(threats, Threat{
				Type:   "SSH暴力破解",
				IP:     ip,
				Detail: fmt.Sprintf("%d次尝试/%ds", count, int(b.sshWindow.Seconds())),
			})
		}
	}

	// HTTP brute-force: count failure responses per IP within the window.
	for ip, rb := range b.httpFailures {
		count := b.countInWindow(rb, httpCutoff)
		if count >= b.httpThresh {
			threats = append(threats, Threat{
				Type:   "HTTP暴力破解",
				IP:     ip,
				Detail: fmt.Sprintf("%d次失败响应/%ds", count, int(b.httpWindow.Seconds())),
			})
		}
	}

	return threats
}

// countInWindow returns the number of timestamps in rb at or after cutoff.
// Caller holds mu; rb must be non-nil.
func (b *BruteForceDetector) countInWindow(rb *RingBuffer, cutoff time.Time) int {
	// Prune old entries first for accurate counting.
	rb.PruneBefore(cutoff)
	return rb.Len()
}

// ensureRingBuffer returns the RingBuffer for ip from the given map,
// creating one (cap 200) if it does not exist.
func (b *BruteForceDetector) ensureRingBuffer(m *map[string]*RingBuffer, ip string) *RingBuffer {
	rb, ok := (*m)[ip]
	if !ok {
		rb = NewRingBuffer(200)
		(*m)[ip] = rb
	}
	return rb
}

// Evict removes stale IPs whose most recent entry is older than deadline
// (Unix timestamp). Returns the total number of IP entries removed.
func (b *BruteForceDetector) Evict(deadline float64) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Unix(int64(deadline), 0)
	total := 0

	for _, m := range []map[string]*RingBuffer{b.sshAttempts, b.httpFailures} {
		stale := make([]string, 0)
		for ip, rb := range m {
			if rb.Len() == 0 || rb.buf[rb.Len()-1].Before(cutoff) {
				stale = append(stale, ip)
			}
		}
		for _, ip := range stale {
			delete(m, ip)
		}
		total += len(stale)
	}

	return total
}
