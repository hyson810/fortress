package defense

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DNSRecordType mirrors DNS query types we handle.
type DNSRecordType uint16

const (
	dnsTypeA     DNSRecordType = 1
	dnsTypeCNAME DNSRecordType = 5
	dnsTypeAAAA  DNSRecordType = 28
	dnsTypeTXT   DNSRecordType = 16
)

// SinkholeMode controls how the sinkhole responds to blocked queries.
type SinkholeMode int

const (
	SinkholeNXDOMAIN SinkholeMode = iota
	SinkholeSpoofA
	SinkholeSpoofCNAME
)

// SinkholeStat contains aggregate counters for sinkhole activity.
type SinkholeStat struct {
	QueriesReceived int64 `json:"queries_received"`
	QueriesBlocked  int64 `json:"queries_blocked"`
	QueriesRedirect int64 `json:"queries_redirected"`
	QueriesAllowed  int64 `json:"queries_allowed"`
}

// RedirectEntry records a single query that was redirected.
type RedirectEntry struct {
	Domain    string    `json:"domain"`
	QueryType string    `json:"query_type"`
	SourceIP  string    `json:"source_ip"`
	Timestamp time.Time `json:"timestamp"`
}

// SinkholeServer implements a DNS sinkhole that intercepts queries for
// known-malicious domains. On Linux it binds to UDP :53; on other
// platforms it degrades to observe-only mode.
type SinkholeServer struct {
	mu              sync.Mutex
	conn            *net.UDPConn
	running         atomic.Bool
	blacklist       map[string]bool
	mode            SinkholeMode
	spoofA          net.IP
	spoofCNAME      string
	stats           SinkholeStat
	redirectLog     []RedirectEntry
	maxRedirectLog  int
	wg              sync.WaitGroup
}

// NewSinkholeServer creates a new DNS sinkhole server with default settings.
func NewSinkholeServer() *SinkholeServer {
	return &SinkholeServer{
		blacklist:      make(map[string]bool),
		mode:           SinkholeNXDOMAIN,
		spoofA:         net.ParseIP("127.0.0.1"),
		spoofCNAME:     "sinkhole.fortress.local",
		redirectLog:    make([]RedirectEntry, 0, 256),
		maxRedirectLog: 10000,
	}
}

// FeedMaliciousDomains loads a list of blocked domains into the sinkhole.
// Existing domains are preserved; new domains are added.
func (s *SinkholeServer) FeedMaliciousDomains(domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		s.blacklist[d] = true
	}
	log.Printf("[sinkhole] loaded %d malicious domains (total: %d)", len(domains), len(s.blacklist))
}

// SetMode configures the sinkhole response mode.
func (s *SinkholeServer) SetMode(mode SinkholeMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
}

// SpoofNXDOMAIN sets the sinkhole to return NXDOMAIN for blocked queries.
func (s *SinkholeServer) SpoofNXDOMAIN() {
	s.SetMode(SinkholeNXDOMAIN)
	log.Println("[sinkhole] mode: NXDOMAIN")
}

// SpoofA sets the sinkhole to return a spoofed A record for blocked queries.
func (s *SinkholeServer) SpoofA(ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = SinkholeSpoofA
	s.spoofA = ip
	log.Printf("[sinkhole] mode: spoof A -> %s", ip)
}

// SpoofCNAME sets the sinkhole to return a spoofed CNAME for blocked queries.
func (s *SinkholeServer) SpoofCNAME(target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = SinkholeSpoofCNAME
	s.spoofCNAME = target
	log.Printf("[sinkhole] mode: spoof CNAME -> %s", target)
}

// Start binds the sinkhole to UDP port 53 and begins processing queries.
// On non-Linux systems it logs a warning and enters observe-only mode.
func (s *SinkholeServer) Start() error {
	if runtime.GOOS != "linux" {
		log.Printf("[sinkhole] non-Linux OS (%s) — running in observe-only mode", runtime.GOOS)
		return nil
	}

	addr := &net.UDPAddr{Port: 53}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("sinkhole: bind :53: %w (requires root)", err)
	}

	s.mu.Lock()
	s.conn = conn
	s.running.Store(true)
	s.mu.Unlock()

	s.wg.Add(1)
	go s.serve()
	log.Println("[sinkhole] DNS sinkhole started on :53")
	return nil
}

// serve processes incoming DNS queries in a loop.
func (s *SinkholeServer) serve() {
	defer s.wg.Done()

	buf := make([]byte, 512)
	for s.running.Load() {
		s.mu.Lock()
		conn := s.conn
		s.mu.Unlock()

		if conn == nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if s.running.Load() {
				log.Printf("[sinkhole] read: %v", err)
			}
			continue
		}

		atomic.AddInt64(&s.stats.QueriesReceived, 1)

		domain := extractDNSQuestion(buf[:n])
		sourceIP, _, _ := net.SplitHostPort(remote.String())

		s.mu.Lock()
		blocked := s.blacklist[domain]
		s.mu.Unlock()

		if blocked {
			atomic.AddInt64(&s.stats.QueriesBlocked, 1)
			s.logRedirect(domain, "A", sourceIP)
			resp := s.buildSpoofedResponse(buf[:n], domain)
			if resp != nil {
				conn.WriteToUDP(resp, remote)
			}
		} else {
			atomic.AddInt64(&s.stats.QueriesAllowed, 1)
		}
	}
}

// extractDNSQuestion extracts the queried domain name from a raw DNS packet.
// Handles standard DNS label encoding. Returns "unknown" on parse failure.
func extractDNSQuestion(packet []byte) string {
	if len(packet) < 12 {
		return "unknown"
	}

	offset := 12 // Skip DNS header
	labels := make([]string, 0, 4)

	for offset < len(packet) {
		labelLen := int(packet[offset])
		if labelLen == 0 {
			break
		}
		if labelLen > 63 || offset+1+labelLen > len(packet) {
			break
		}
		offset++
		labels = append(labels, string(packet[offset:offset+labelLen]))
		offset += labelLen
	}

	if len(labels) == 0 {
		return "unknown"
	}
	return strings.ToLower(strings.Join(labels, "."))
}

// buildSpoofedResponse builds a DNS response packet based on the current mode.
// Returns nil if the packet cannot be built.
func (s *SinkholeServer) buildSpoofedResponse(query []byte, domain string) []byte {
	s.mu.Lock()
	mode := s.mode
	spoofIP := s.spoofA
	spoofTarget := s.spoofCNAME
	s.mu.Unlock()

	if len(query) < 12 {
		return nil
	}

	switch mode {
	case SinkholeNXDOMAIN:
		return buildNXDOMAIN(query)
	case SinkholeSpoofA:
		return buildAResponse(query, domain, spoofIP)
	case SinkholeSpoofCNAME:
		return buildCNAMEResponse(query, spoofTarget)
	default:
		return buildNXDOMAIN(query)
	}
}

// buildNXDOMAIN constructs a DNS response with the NXDOMAIN status code.
func buildNXDOMAIN(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)

	// Set QR bit (response) and RA (recursion available)
	resp[2] = 0x81
	resp[3] = 0x83 // NXDOMAIN = 3 in the RCODE field

	return resp
}

// buildAResponse constructs a DNS response with a spoofed A record.
func buildAResponse(query []byte, domain string, ip net.IP) []byte {
	headerLen := len(query)
	resp := make([]byte, headerLen+16)

	copy(resp[:headerLen], query)

	// Set QR bit and standard response
	resp[2] = 0x81
	resp[3] = 0x80

	// Answer count = 1
	resp[6] = 0x00
	resp[7] = 0x01

	// Answer section: pointer to name in question
	offset := headerLen
	resp[offset] = 0xc0
	resp[offset+1] = 0x0c
	offset += 2

	// TYPE = A (1)
	resp[offset] = 0x00
	resp[offset+1] = 0x01
	offset += 2

	// CLASS = IN (1)
	resp[offset] = 0x00
	resp[offset+1] = 0x01
	offset += 2

	// TTL = 60 seconds
	resp[offset] = 0x00
	resp[offset+1] = 0x00
	resp[offset+2] = 0x00
	resp[offset+3] = 0x3c
	offset += 4

	// RDLENGTH = 4
	resp[offset] = 0x00
	resp[offset+1] = 0x04
	offset += 2

	// RDATA = IP address
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4(127, 0, 0, 1).To4()
	}
	copy(resp[offset:offset+4], ip4)

	return resp
}

// buildCNAMEResponse constructs a DNS response with a spoofed CNAME record.
func buildCNAMEResponse(query []byte, target string) []byte {
	targetLabels := strings.Split(target, ".")
	cnameLen := 0
	for _, label := range targetLabels {
		cnameLen += 1 + len(label)
	}
	cnameLen++ // null terminator

	headerLen := len(query)
	resp := make([]byte, headerLen+12+cnameLen)

	copy(resp[:headerLen], query)

	resp[2] = 0x81
	resp[3] = 0x80
	resp[6] = 0x00
	resp[7] = 0x01

	offset := headerLen

	// Pointer to name in question
	resp[offset] = 0xc0
	resp[offset+1] = 0x0c
	offset += 2

	// TYPE = CNAME (5)
	resp[offset] = 0x00
	resp[offset+1] = 0x05
	offset += 2

	// CLASS = IN (1)
	resp[offset] = 0x00
	resp[offset+1] = 0x01
	offset += 2

	// TTL = 60
	resp[offset] = 0x00
	resp[offset+1] = 0x00
	resp[offset+2] = 0x00
	resp[offset+3] = 0x3c
	offset += 4

	// RDLENGTH
	rdLen := cnameLen
	resp[offset] = byte(rdLen >> 8)
	resp[offset+1] = byte(rdLen & 0xff)
	offset += 2

	// CNAME data (label-encoded)
	for _, label := range targetLabels {
		resp[offset] = byte(len(label))
		offset++
		copy(resp[offset:], []byte(label))
		offset += len(label)
	}
	resp[offset] = 0x00 // null terminator

	return resp
}

// logRedirect records a blocked query in the redirect log.
func (s *SinkholeServer) logRedirect(domain, queryType, sourceIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.redirectLog = append(s.redirectLog, RedirectEntry{
		Domain:    domain,
		QueryType: queryType,
		SourceIP:  sourceIP,
		Timestamp: time.Now(),
	})

	if len(s.redirectLog) > s.maxRedirectLog {
		s.redirectLog = s.redirectLog[len(s.redirectLog)-s.maxRedirectLog:]
	}
}

// Stop gracefully shuts down the DNS sinkhole server.
func (s *SinkholeServer) Stop() {
	s.running.Store(false)

	s.mu.Lock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()

	s.wg.Wait()
	log.Println("[sinkhole] DNS sinkhole stopped")
}

// Stats returns a copy of the current sinkhole statistics.
func (s *SinkholeServer) Stats() SinkholeStat {
	return SinkholeStat{
		QueriesReceived: atomic.LoadInt64(&s.stats.QueriesReceived),
		QueriesBlocked:  atomic.LoadInt64(&s.stats.QueriesBlocked),
		QueriesRedirect: atomic.LoadInt64(&s.stats.QueriesRedirect),
		QueriesAllowed:  atomic.LoadInt64(&s.stats.QueriesAllowed),
	}
}

// RedirectLog returns a snapshot of the most recent redirect entries.
func (s *SinkholeServer) RedirectLog() []RedirectEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]RedirectEntry, len(s.redirectLog))
	copy(out, s.redirectLog)
	return out
}

// IsBlocked checks whether a domain is on the sinkhole blacklist.
func (s *SinkholeServer) IsBlocked(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blacklist[strings.ToLower(domain)]
}

// BlockedDomainCount returns the number of domains in the blacklist.
func (s *SinkholeServer) BlockedDomainCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.blacklist)
}

// SimulateQuery allows programmatic testing of the sinkhole by simulating
// a DNS query for a domain from a specific IP. Returns true if blocked.
func (s *SinkholeServer) SimulateQuery(domain, sourceIP string) bool {
	atomic.AddInt64(&s.stats.QueriesReceived, 1)
	d := strings.ToLower(domain)

	s.mu.Lock()
	blocked := s.blacklist[d]
	s.mu.Unlock()

	if blocked {
		atomic.AddInt64(&s.stats.QueriesBlocked, 1)
		s.logRedirect(d, "A", sourceIP)
	} else {
		atomic.AddInt64(&s.stats.QueriesAllowed, 1)
	}
	return blocked
}

// ClearStats resets all statistic counters to zero.
func (s *SinkholeServer) ClearStats() {
	atomic.StoreInt64(&s.stats.QueriesReceived, 0)
	atomic.StoreInt64(&s.stats.QueriesBlocked, 0)
	atomic.StoreInt64(&s.stats.QueriesRedirect, 0)
	atomic.StoreInt64(&s.stats.QueriesAllowed, 0)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
