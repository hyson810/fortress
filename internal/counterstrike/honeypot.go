// Package counterstrike implements multi-protocol honeypots for detecting
// and trapping attackers.
//
// Honeypots:
//   - SSH honeypot (port 2222): captures credential attempts
//   - HTTP honeypot (port 8080): captures web scanning requests
//   - MySQL honeypot (port 3307): captures database connection attempts
//
// HoneypotManager deploys and manages all honeypots concurrently.
package counterstrike

import (
	"bufio"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// HoneypotServer interface
// ---------------------------------------------------------------------------

// HoneypotServer is the interface implemented by all honeypot types.
type HoneypotServer interface {
	Start() error
	Stop() error
	Port() int
	Name() string
	Hits() int
}

// ---------------------------------------------------------------------------
// HitRecord
// ---------------------------------------------------------------------------

// HitRecord captures a single honeypot interaction for audit/logging.
type HitRecord struct {
	Time      time.Time
	Honeypot  string
	RemoteIP  string
	Detail    string
}

// ---------------------------------------------------------------------------
// BaseHoneypot — shared state and helpers for all honeypots
// ---------------------------------------------------------------------------

// BaseHoneypot provides the shared state and lifecycle management for all
// honeypot implementations. Specific honeypots embed this and implement
// the handleConnection method via their own connection loop.
type BaseHoneypot struct {
	port        int
	name        string
	hits        int64
	running     atomic.Bool
	listener    net.Listener
	wg          sync.WaitGroup
	mu          sync.Mutex
	recent      []HitRecord // recent hits for querying
	maxConns    int
	connCount   atomic.Int32
	perIPLimit  int
	ipLimiter   *ipRateLimiter
	connTimeout time.Duration
}

// ipRateLimiter tracks per-IP connection counts with periodic reset.
type ipRateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int
	resetAt time.Time
	window  time.Duration
}

func newIPRateLimiter(window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		counts:  make(map[string]int),
		resetAt: time.Now().Add(window),
		window:  window,
	}
}

// allow returns true and increments the counter if the IP is under the limit.
func (l *ipRateLimiter) allow(ip string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if time.Now().After(l.resetAt) {
		l.counts = make(map[string]int)
		l.resetAt = time.Now().Add(l.window)
	}

	if l.counts[ip] >= limit {
		return false
	}
	l.counts[ip]++
	return true
}

// release decrements the per-IP counter when a connection completes.
func (l *ipRateLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ip] > 0 {
		l.counts[ip]--
	}
}

// newBaseHoneypot initializes common honeypot state.
func newBaseHoneypot(port int, name string) *BaseHoneypot {
	return &BaseHoneypot{
		port:        port,
		name:        name,
		recent:      make([]HitRecord, 0, 100),
		maxConns:    1000,
		perIPLimit:  10,
		ipLimiter:   newIPRateLimiter(60 * time.Second),
		connTimeout: 60 * time.Second,
	}
}

// Port returns the listening port.
func (b *BaseHoneypot) Port() int { return b.port }

// Name returns the honeypot type name.
func (b *BaseHoneypot) Name() string { return b.name }

// Hits returns the total number of recorded hits.
func (b *BaseHoneypot) Hits() int { return int(atomic.LoadInt64(&b.hits)) }

// recordHit increments the hit counter and appends a hit record.
func (b *BaseHoneypot) recordHit(remoteIP, detail string) {
	atomic.AddInt64(&b.hits, 1)
	b.mu.Lock()
	b.recent = append(b.recent, HitRecord{
		Time:     time.Now(),
		Honeypot: b.name,
		RemoteIP: remoteIP,
		Detail:   detail,
	})
	if len(b.recent) > 100 {
		b.recent = b.recent[len(b.recent)-100:]
	}
	b.mu.Unlock()
}

// getRecentHits returns recent hit records within the given time window.
func (b *BaseHoneypot) getRecentHits(windowSeconds int) []HitRecord {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(windowSeconds) * time.Second)
	var result []HitRecord
	for i := len(b.recent) - 1; i >= 0; i-- {
		if b.recent[i].Time.Before(cutoff) {
			break
		}
		result = append(result, b.recent[i])
	}
	return result
}

// hasRecentHit reports whether any recent (60s) hit came from the given IP.
func (b *BaseHoneypot) hasRecentHit(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-60 * time.Second)
	for i := len(b.recent) - 1; i >= 0; i-- {
		if b.recent[i].Time.Before(cutoff) {
			break
		}
		if b.recent[i].RemoteIP == ip {
			return true
		}
	}
	return false
}

// Stop gracefully shuts down the honeypot listener and waits for active
// connections to complete.
func (b *BaseHoneypot) Stop() error {
	b.running.Store(false)
	if b.listener != nil {
		b.listener.Close()
	}
	b.wg.Wait()
	return nil
}

// acceptLoop is called by Start to accept connections.
// Each accepted connection is dispatched to handle in a goroutine.
// Enforces global max connections and per-IP rate limiting.
func (b *BaseHoneypot) acceptLoop(handler func(net.Conn)) {
	defer b.wg.Done()
	for b.running.Load() {
		if b.listener == nil {
			return
		}
		conn, err := b.listener.Accept()
		if err != nil {
			if !b.running.Load() {
				return
			}
			continue
		}

		// Global connection limit.
		if int(b.connCount.Load()) >= b.maxConns {
			log.Printf("[honeypot] %s: max global connections (%d) reached, dropping connection from %s",
				b.name, b.maxConns, conn.RemoteAddr())
			conn.Close()
			continue
		}

		// Per-IP rate limiting.
		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if remoteIP == "" {
			remoteIP = conn.RemoteAddr().String()
		}
		if !b.ipLimiter.allow(remoteIP, b.perIPLimit) {
			log.Printf("[honeypot] %s: per-IP limit (%d) exceeded for %s, dropping connection",
				b.name, b.perIPLimit, remoteIP)
			conn.Close()
			continue
		}

		// Set read deadline to prevent slowloris-style connection holding.
		conn.SetReadDeadline(time.Now().Add(b.connTimeout))

		b.connCount.Add(1)
		b.wg.Add(1)
		go func(c net.Conn, ip string) {
			defer b.wg.Done()
			defer c.Close()
			defer b.connCount.Add(-1)
			defer b.ipLimiter.release(ip)
			handler(c)
		}(conn, remoteIP)
	}
}

// ---------------------------------------------------------------------------
// SSH Honeypot
// ---------------------------------------------------------------------------

// SSHoneypot listens on port 2222, sends a fake OpenSSH banner, captures
// username/password attempts, then closes the connection.
type SSHoneypot struct {
	*BaseHoneypot
}

// NewSSHoneypot creates an SSH honeypot on the given port.
func NewSSHoneypot(port int) *SSHoneypot {
	return &SSHoneypot{
		BaseHoneypot: newBaseHoneypot(port, "SSH"),
	}
}

// Start begins listening and accepting SSH connections.
func (s *SSHoneypot) Start() error {
	addr := formatAddr(s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.running.Store(true)
	s.wg.Add(1)
	go s.acceptLoop(s.handleConnection)
	log.Printf("[honeypot] SSH listening on %s", addr)
	return nil
}

func (s *SSHoneypot) handleConnection(conn net.Conn) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// Send fake SSH banner (SSH-2.0- prefix + server identifier + CRLF).
	banner := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
	conn.Write([]byte(banner))

	reader := bufio.NewReader(conn)

	// Read first line — typically contains the username attempt.
	line1, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	// Read second line — typically contains the password attempt.
	line2, err := reader.ReadString('\n')
	if err != nil {
		// At minimum we captured one line.
		s.recordHit(remoteIP, "banner_read:"+trimCRLF(line1))
		return
	}

	s.recordHit(remoteIP, "user:"+trimCRLF(line1)+" pass:"+trimCRLF(line2))
	log.Printf("[honeypot] SSH hit from %s — credentials captured", remoteIP)
}

// ---------------------------------------------------------------------------
// HTTP Honeypot
// ---------------------------------------------------------------------------

// HTTPHoneypot listens on port 8080, responds with a fake nginx welcome
// page, and logs all incoming HTTP requests.
type HTTPHoneypot struct {
	*BaseHoneypot
}

// NewHTTPHoneypot creates an HTTP honeypot on the given port.
func NewHTTPHoneypot(port int) *HTTPHoneypot {
	return &HTTPHoneypot{
		BaseHoneypot: newBaseHoneypot(port, "HTTP"),
	}
}

// Start begins listening and accepting HTTP connections.
func (h *HTTPHoneypot) Start() error {
	addr := formatAddr(h.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	h.listener = ln
	h.running.Store(true)
	h.wg.Add(1)
	go h.acceptLoop(h.handleConnection)
	log.Printf("[honeypot] HTTP listening on %s", addr)
	return nil
}

func (h *HTTPHoneypot) handleConnection(conn net.Conn) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	reader := bufio.NewReader(conn)

	// Read the HTTP request line.
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	// Read headers until blank line.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	h.recordHit(remoteIP, "req:"+trimCRLF(requestLine))

	// Respond with a fake nginx welcome page.
	conn.Write([]byte(httpFakeResponse))
	log.Printf("[honeypot] HTTP hit from %s", remoteIP)
}

// httpFakeResponse is a realistic nginx welcome page.
const httpFakeResponse = "HTTP/1.1 200 OK\r\n" +
	"Server: nginx/1.24.0\r\n" +
	"Content-Type: text/html; charset=utf-8\r\n" +
	"Connection: close\r\n" +
	"Content-Length: 615\r\n" +
	"\r\n" +
	"<!DOCTYPE html>\r\n" +
	"<html>\r\n" +
	"<head>\r\n" +
	"<title>Welcome to nginx!</title>\r\n" +
	"<style>\r\n" +
	"    body { width: 35em; margin: 0 auto;\r\n" +
	"    font-family: Tahoma, Verdana, Arial, sans-serif; }\r\n" +
	"</style>\r\n" +
	"</head>\r\n" +
	"<body>\r\n" +
	"<h1>Welcome to nginx!</h1>\r\n" +
	"<p>If you see this page, the nginx web server is successfully installed and\r\n" +
	"working. Further configuration is required.</p>\r\n" +
	"\r\n" +
	"<p>For online documentation and support please refer to\r\n" +
	"<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\r\n" +
	"Commercial support is available at\r\n" +
	"<a href=\"http://nginx.com/\">nginx.com</a>.</p>\r\n" +
	"\r\n" +
	"<p><em>Thank you for using nginx.</em></p>\r\n" +
	"</body>\r\n" +
	"</html>\r\n"

// ---------------------------------------------------------------------------
// MySQL Honeypot
// ---------------------------------------------------------------------------

// MySQLHoneypot listens on port 3307, sends a fake MySQL protocol handshake
// packet, captures authentication attempts, then closes the connection.
type MySQLHoneypot struct {
	*BaseHoneypot
}

// NewMySQLHoneypot creates a MySQL honeypot on the given port.
func NewMySQLHoneypot(port int) *MySQLHoneypot {
	return &MySQLHoneypot{
		BaseHoneypot: newBaseHoneypot(port, "MySQL"),
	}
}

// Start begins listening and accepting MySQL connections.
func (m *MySQLHoneypot) Start() error {
	addr := formatAddr(m.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	m.listener = ln
	m.running.Store(true)
	m.wg.Add(1)
	go m.acceptLoop(m.handleConnection)
	log.Printf("[honeypot] MySQL listening on %s", addr)
	return nil
}

func (m *MySQLHoneypot) handleConnection(conn net.Conn) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// Send fake MySQL protocol handshake packet (v10).
	// This mimics MySQL 8.0.35 greeting.
	handshake := buildMySQLHandshake()
	conn.Write(handshake)

	// Read the client's authentication response.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		m.recordHit(remoteIP, "handshake_sent:no_auth")
		return
	}

	// Try to extract username from the auth packet.
	detail := extractMySQLAuthInfo(buf[:n])
	m.recordHit(remoteIP, detail)
	log.Printf("[honeypot] MySQL hit from %s — %s", remoteIP, detail)
}

// buildMySQLHandshake constructs a fake MySQL 8.0 server greeting (v10 protocol).
func buildMySQLHandshake() []byte {
	// MySQL protocol handshake packet structure (v10):
	//   1 byte:  protocol version (0x0a = 10)
	//   n bytes: server version string (null-terminated)
	//   4 bytes: connection ID
	//   8 bytes: auth-plugin-data-part-1 (scramble)
	//   1 byte:  filler (0x00)
	//   2 bytes: capability flags (lower)
	//   1 byte:  character set
	//   2 bytes: status flags
	//   2 bytes: capability flags (upper)
	//   1 byte:  length of auth-plugin-data
	//   10 bytes: reserved (zeros)
	//   n bytes: auth-plugin-data-part-2 (13 - length_of_part1 = 5 bytes + null)
	//   n bytes: auth-plugin name (null-terminated)

	serverVersion := "8.0.35"
	authData1 := []byte{0x7a, 0x6b, 0x3d, 0x5e, 0x1f, 0x4c, 0x2a, 0x19}
	authData2 := []byte{0x33, 0x44, 0x55, 0x66, 0x77, 0x12, 0x34, 0x56, 0x78, 0x2a, 0x3b, 0x4c, 0x00}
	authPlugin := "caching_sha2_password"

	var pkt []byte

	// Payload length placeholder — we fill it at the end.
	// MySQL wire format: 3-byte length + 1-byte sequence number = 4-byte header.
	payload := make([]byte, 0, 256)

	// Protocol version.
	payload = append(payload, 0x0a)

	// Server version (null-terminated).
	payload = append(payload, []byte(serverVersion)...)
	payload = append(payload, 0x00)

	// Connection ID (4 bytes).
	connID := make([]byte, 4)
	binary.LittleEndian.PutUint32(connID, 42)
	payload = append(payload, connID...)

	// Auth-plugin-data-part-1 (8 bytes).
	payload = append(payload, authData1...)

	// Filler.
	payload = append(payload, 0x00)

	// Capability flags (lower 2 bytes).
	// CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG |
	// CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION |
	// CLIENT_PLUGIN_AUTH | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
	capLower := uint16(0xa2ff)
	capLowerBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(capLowerBytes, capLower)
	payload = append(payload, capLowerBytes...)

	// Character set (utf8mb4 = 45 or 0x2d).
	payload = append(payload, 0x2d)

	// Status flags (2 bytes).
	status := make([]byte, 2)
	binary.LittleEndian.PutUint16(status, 0x0002) // SERVER_STATUS_AUTOCOMMIT
	payload = append(payload, status...)

	// Capability flags (upper 2 bytes).
	capUpper := uint16(0x01ff)
	capUpperBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(capUpperBytes, capUpper)
	payload = append(payload, capUpperBytes...)

	// Length of auth-plugin-data (21 = 8 + 13).
	payload = append(payload, byte(len(authData1)+len(authData2)))

	// Reserved (10 bytes of zeros).
	payload = append(payload, make([]byte, 10)...)

	// Auth-plugin-data-part-2 (13 bytes including null terminator).
	payload = append(payload, authData2...)

	// Auth plugin name (null-terminated).
	payload = append(payload, []byte(authPlugin)...)
	payload = append(payload, 0x00)

	// Build the 4-byte header.
	pkt = make([]byte, 0, 4+len(payload))
	length := len(payload)
	pkt = append(pkt, byte(length&0xFF), byte((length>>8)&0xFF), byte((length>>16)&0xFF))
	pkt = append(pkt, 0x00) // sequence number 0
	pkt = append(pkt, payload...)

	return pkt
}

// extractMySQLAuthInfo tries to extract username and authentication method
// from the client's auth response packet.
func extractMySQLAuthInfo(data []byte) string {
	if len(data) < 36 {
		return "auth_packet_received:" + fmtHexBytes(data)
	}

	// Skip 4-byte header + 4-byte client flags + 4-byte max packet + 1-byte charset.
	// + 23 bytes reserved + username (null-terminated).
	pos := 36

	// Read username (null-terminated string).
	username := readNullTerminated(data, pos)
	if username == "" {
		username = "(unknown)"
	}
	pos += len(username) + 1

	// If there's more data, try to read the auth response length and name.
	if pos+1 < len(data) {
		authLen := int(data[pos])
		pos += 1 + authLen

		if pos < len(data) {
			dbName := readNullTerminated(data, pos)
			if dbName != "" {
				return "user:" + username + " db:" + dbName
			}
		}
	}

	return "user:" + username
}

// readNullTerminated reads a null-terminated string from data starting at pos.
func readNullTerminated(data []byte, pos int) string {
	if pos >= len(data) {
		return ""
	}
	end := pos
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[pos:end])
}

// fmtHexBytes formats a byte slice as hex for logging.
func fmtHexBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	const hex = "0123456789abcdef"
	maxLen := 32
	if len(data) < maxLen {
		maxLen = len(data)
	}
	buf := make([]byte, maxLen*2)
	for i := 0; i < maxLen; i++ {
		buf[i*2] = hex[data[i]>>4]
		buf[i*2+1] = hex[data[i]&0x0F]
	}
	if len(data) > maxLen {
		return string(buf) + "..."
	}
	return string(buf)
}

// ---------------------------------------------------------------------------
// HoneypotManager
// ---------------------------------------------------------------------------

// HoneypotManager deploys and manages all honeypots concurrently.
type HoneypotManager struct {
	honeypots []HoneypotServer
}

// NewHoneypotManager creates a HoneypotManager with all honeypot types
// configured on their default ports.
func NewHoneypotManager() *HoneypotManager {
	return &HoneypotManager{
		honeypots: []HoneypotServer{
			NewSSHoneypot(2222),
			NewHTTPHoneypot(8080),
			NewMySQLHoneypot(3307),
		},
	}
}

// StartAll starts all honeypots in separate goroutines.
// Returns the first error encountered, or nil if all started successfully.
func (hm *HoneypotManager) StartAll() error {
	for _, hp := range hm.honeypots {
		if err := hp.Start(); err != nil {
			return err
		}
	}
	log.Printf("[honeypot] All %d honeypots started", len(hm.honeypots))
	return nil
}

// StopAll gracefully shuts down all honeypots.
// Errors from individual stops are collected and the first is returned.
func (hm *HoneypotManager) StopAll() error {
	var firstErr error
	for _, hp := range hm.honeypots {
		if err := hp.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// CheckHit reports whether any honeypot was recently hit by the given IP.
func (hm *HoneypotManager) CheckHit(ip string) bool {
	for _, hp := range hm.honeypots {
		// Type-assert to access hasRecentHit on the underlying BaseHoneypot.
		switch h := hp.(type) {
		case *SSHoneypot:
			if h.hasRecentHit(ip) {
				return true
			}
		case *HTTPHoneypot:
			if h.hasRecentHit(ip) {
				return true
			}
		case *MySQLHoneypot:
			if h.hasRecentHit(ip) {
				return true
			}
		}
	}
	return false
}

// GetRecentHits returns all hit records from all honeypots within the
// given time window (in seconds).
func (hm *HoneypotManager) GetRecentHits(windowSeconds int) []HitRecord {
	var all []HitRecord
	for _, hp := range hm.honeypots {
		switch h := hp.(type) {
		case *SSHoneypot:
			all = append(all, h.getRecentHits(windowSeconds)...)
		case *HTTPHoneypot:
			all = append(all, h.getRecentHits(windowSeconds)...)
		case *MySQLHoneypot:
			all = append(all, h.getRecentHits(windowSeconds)...)
		}
	}
	return all
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// formatAddr formats a port number into a listen address string.
func formatAddr(port int) string {
	buf := make([]byte, 0, 7)
	buf = append(buf, ':')
	buf = append(buf, formatInt(port)...)
	return string(buf)
}

// formatInt formats an integer as a string without importing fmt.
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

// trimCRLF strips trailing \r and \n from a string.
func trimCRLF(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
