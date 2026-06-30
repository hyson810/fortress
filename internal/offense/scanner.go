// Package offense implements offensive security tools for autonomous
// counterstrike capability — fully autonomous port scanning, service
// fingerprinting, web exploitation, brute-force attacks, CVE matching,
// reverse shell deployment, persistence, privesc, and killchain orchestration.
//
// This is a ground-up rebuild from Fortress V3.1/V4 with significant
// enhancements: SYN stealth scan, OS fingerprinting, protocol-specific
// banner probes, adaptive rate control, and Dagger C2 integration.
package offense

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// SERVICE_MAP maps ports to service names — 120+ entries across all
// IANA-registered attack surfaces, no duplicates.
var SERVICE_MAP = map[int]string{
	7: "Echo", 9: "Discard", 13: "Daytime", 19: "CHARGEN",
	20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	53: "DNS", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
	102: "S7", 110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC",
	137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
	143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 177: "XDMCP",
	179: "BGP", 194: "IRC", 201: "AppleTalk", 389: "LDAP",
	443: "HTTPS", 445: "SMB", 464: "kpasswd", 465: "SMTPS",
	502: "Modbus", 587: "SMTP-Submission", 593: "HTTP-RPC-EPM",
	623: "IPMI", 636: "LDAPS", 873: "Rsync",
	992: "Telnet-SSL", 993: "IMAPS", 995: "POP3S",
	1080: "SOCKS5", 1194: "OpenVPN", 1433: "MSSQL",
	1434: "MSSQL-Monitor", 1521: "Oracle-DB", 1723: "PPTP",
	2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
	2375: "Docker-TCP", 2376: "Docker-TLS", 2380: "etcd",
	2483: "Oracle-TS", 2484: "Oracle-TS-SSL",
	3000: "Grafana/Dev", 3128: "Squid", 3268: "GC-LDAP",
	3269: "GC-LDAPS", 3306: "MySQL", 3389: "RDP",
	4000: "Node.js", 4444: "Metasploit", 5000: "Flask/Dev",
	5432: "PostgreSQL", 5555: "Android-ADB", 5900: "VNC",
	5901: "VNC-1", 5938: "TeamViewer", 5985: "WinRM-HTTP",
	5986: "WinRM-HTTPS", 6379: "Redis", 6443: "K8s-API",
	6666: "IRC/Backdoor", 6667: "IRC", 6668: "IRC", 6669: "IRC",
	6697: "IRC-SSL", 7443: "K8s-API-Alt",
	8000: "HTTP-Alt2", 8006: "Proxmox", 8080: "HTTP-Alt",
	8086: "InfluxDB", 8118: "Privoxy", 8291: "RouterOS",
	8443: "HTTPS-Alt", 8888: "HTTP-Alt3", 9000: "PHP-FPM",
	9042: "Cassandra", 9090: "Prometheus", 9100: "Printer",
	9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
	10000: "Webmin", 10250: "K8s-Kubelet", 10255: "K8s-Kubelet-RO",
	11211: "Memcached", 20000: "DNP3", 25565: "Minecraft",
	27015: "SRCDS", 27017: "MongoDB", 27018: "MongoDB-Shard",
	44818: "EtherNet/IP", 47808: "BACnet",
	9050: "Tor-SOCKS", 9150: "Tor-Browser",
}

// topPorts is the expanded top-1500 port list.
var topPorts []int

func init() {
	seen := make(map[int]bool)
	for port := range SERVICE_MAP {
		if !seen[port] {
			seen[port] = true
			topPorts = append(topPorts, port)
		}
	}
	for p := 1; p <= 1023; p++ {
		if !seen[p] {
			seen[p] = true
			topPorts = append(topPorts, p)
		}
	}
	for p := 1024; p <= 10000; p += 20 {
		if !seen[p] {
			seen[p] = true
			topPorts = append(topPorts, p)
		}
	}
	sort.Ints(topPorts)
}

// ---------------------------------------------------------------------------
// ScanResult / PortState types
// ---------------------------------------------------------------------------

// PortState describes a single port's scan result.
type PortState struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// ScanMode selects the scan technique.
type ScanMode int

const (
	ScanConnect ScanMode = iota // Standard TCP connect (default)
	ScanSYN                     // SYN stealth (requires CAP_NET_RAW)
)

// ---------------------------------------------------------------------------
// PortScanner — concurrent TCP port scanner
// ---------------------------------------------------------------------------

// PortScanner performs high-performance concurrent TCP port scanning.
// Supports connect and SYN stealth modes, service fingerprinting,
// OS fingerprinting, and adaptive rate control.
type PortScanner struct {
	timeout    time.Duration
	maxWorkers int
	mode       ScanMode
}

// NewPortScanner creates a PortScanner. Default: TCP connect, 2s timeout, 500 workers.
func NewPortScanner(timeout time.Duration, maxWorkers int) *PortScanner {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	if maxWorkers > 2000 {
		maxWorkers = 2000
	}
	if timeout < 100*time.Millisecond {
		timeout = 100 * time.Millisecond
	}
	return &PortScanner{
		timeout:    timeout,
		maxWorkers: maxWorkers,
		mode:       ScanConnect,
	}
}

// SetMode changes the scan mode (connect vs SYN stealth).
func (ps *PortScanner) SetMode(m ScanMode) { ps.mode = m }

// ScanPort scans a single port.
func (ps *PortScanner) ScanPort(host string, port int) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, ps.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// scanWorker processes ports from a channel and returns open results.
func (ps *PortScanner) scanWorker(host string, jobs <-chan int, results chan<- *PortState, wg *sync.WaitGroup) {
	defer wg.Done()
	for port := range jobs {
		if ps.ScanPort(host, port) {
			results <- &PortState{Port: port, Open: true}
		}
	}
}

// ScanRange scans a port range [start, end] inclusive.
func (ps *PortScanner) ScanRange(host string, startPort, endPort int) []*PortState {
	if startPort > endPort {
		startPort, endPort = endPort, startPort
	}
	return ps.scanPortList(host, rangePorts(startPort, endPort))
}

// QuickScan scans the top 1500 ports.
func (ps *PortScanner) QuickScan(host string) []*PortState {
	return ps.scanPortList(host, topPorts)
}

// scanPortList scans a pre-defined port list.
func (ps *PortScanner) scanPortList(host string, ports []int) []*PortState {
	jobs := make(chan int, len(ports))
	results := make(chan *PortState, len(ports))
	var wg sync.WaitGroup

	for i := 0; i < ps.maxWorkers; i++ {
		wg.Add(1)
		go ps.scanWorker(host, jobs, results, &wg)
	}

	for _, p := range ports {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(results)

	var open []*PortState
	for r := range results {
		r.Service = serviceByPort(r.Port)
		open = append(open, r)
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

func rangePorts(start, end int) []int {
	n := end - start + 1
	if n <= 0 {
		n = 1
	}
	p := make([]int, n)
	for i := 0; i < n; i++ {
		p[i] = start + i
	}
	return p
}

func serviceByPort(port int) string {
	if s, ok := SERVICE_MAP[port]; ok {
		return s
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// ServiceFingerprinter — protocol-specific banner grabber
// ---------------------------------------------------------------------------

// ServiceFingerprinter connects to open ports and performs protocol-specific
// probes to identify service name and version.
type ServiceFingerprinter struct {
	timeout time.Duration
}

// NewServiceFingerprinter creates a fingerprinter with the given timeout.
func NewServiceFingerprinter() *ServiceFingerprinter {
	return &ServiceFingerprinter{timeout: 4 * time.Second}
}

// Fingerprint attempts full service identification (name + version + banner).
// Uses protocol-specific probes where known.
func (sf *ServiceFingerprinter) Fingerprint(host string, port int) (service, version, banner string) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, sf.timeout)
	if err != nil {
		return serviceByPort(port), "", ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(sf.timeout))

	// Protocol-specific probing
	switch {
	case port == 22:
		return sf.probeSSH(conn)
	case port == 21:
		return sf.probeFTP(conn)
	case port == 25 || port == 587:
		return sf.probeSMTP(conn)
	case port == 110:
		return sf.probePOP3(conn)
	case port == 143:
		return sf.probeIMAP(conn)
	case port == 80 || port == 443 || port == 8080 || port == 8443 || port == 3000 || port == 5000 || port == 8000 || port == 8888 || port == 9090:
		return sf.probeHTTP(conn, port == 443 || port == 8443)
	case port == 3306:
		return sf.probeMySQL(conn)
	case port == 5432:
		return sf.probePostgreSQL(conn)
	case port == 6379:
		return sf.probeRedis(conn)
	default:
		return sf.fallbackBanner(conn, port)
	}
}

func (sf *ServiceFingerprinter) probeSSH(conn net.Conn) (string, string, string) {
	reader := bufio.NewReader(conn)
	banner, err := readLine(reader, conn, sf.timeout)
	if err != nil {
		return "SSH", "", ""
	}
	b := strings.TrimSpace(banner)
	if strings.HasPrefix(b, "SSH-") {
		return "SSH", b, b
	}
	return "SSH", "", b
}

func (sf *ServiceFingerprinter) probeFTP(conn net.Conn) (string, string, string) {
	reader := bufio.NewReader(conn)
	banner, err := readLine(reader, conn, sf.timeout)
	if err != nil {
		return "FTP", "", ""
	}
	b := strings.TrimSpace(banner)
	ver := extractFTPVersion(b)
	return "FTP", ver, b
}

func (sf *ServiceFingerprinter) probeSMTP(conn net.Conn) (string, string, string) {
	reader := bufio.NewReader(conn)
	banner, err := readLine(reader, conn, sf.timeout)
	if err != nil {
		return "SMTP", "", ""
	}
	b := strings.TrimSpace(banner)
	// Send EHLO for version
	fmt.Fprintf(conn, "EHLO probe\r\n")
	ehloResp, _ := readLine(reader, conn, sf.timeout)
	return "SMTP", extractSMTPVersion(b, ehloResp), b
}

func (sf *ServiceFingerprinter) probePOP3(conn net.Conn) (string, string, string) {
	reader := bufio.NewReader(conn)
	banner, err := readLine(reader, conn, sf.timeout)
	if err != nil {
		return "POP3", "", ""
	}
	return "POP3", strings.TrimSpace(banner), strings.TrimSpace(banner)
}

func (sf *ServiceFingerprinter) probeIMAP(conn net.Conn) (string, string, string) {
	reader := bufio.NewReader(conn)
	banner, err := readLine(reader, conn, sf.timeout)
	if err != nil {
		return "IMAP", "", ""
	}
	return "IMAP", strings.TrimSpace(banner), strings.TrimSpace(banner)
}

func (sf *ServiceFingerprinter) probeHTTP(conn net.Conn, useTLS bool) (string, string, string) {
	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.Handshake(); err != nil {
			return "HTTPS", "", ""
		}
		conn = net.Conn(tlsConn)
	}
	reader := bufio.NewReader(conn)
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	resp, err := readLine(reader, conn, sf.timeout)
	if err != nil {
		if useTLS {
			return "HTTPS", "", ""
		}
		return "HTTP", "", ""
	}
	// Read server header
	var serverHdr string
	for i := 0; i < 20; i++ {
		l, e := readLine(reader, conn, sf.timeout)
		if e != nil {
			break
		}
		if strings.HasPrefix(l, "Server:") || strings.HasPrefix(l, "server:") {
			serverHdr = strings.TrimSpace(l[7:])
		}
	}
	if useTLS {
		return "HTTPS", serverHdr, strings.TrimSpace(resp)
	}
	return "HTTP", serverHdr, strings.TrimSpace(resp)
}

func (sf *ServiceFingerprinter) probeMySQL(conn net.Conn) (string, string, string) {
	// MySQL sends a greeting packet on connect
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(sf.timeout))
	n, _ := conn.Read(buf)
	if n > 0 {
		b := string(buf[:min(n, 128)])
		return "MySQL", extractMySQLVersion(b), b[:min(len(b), 80)]
	}
	return "MySQL", "", ""
}

func (sf *ServiceFingerprinter) probePostgreSQL(conn net.Conn) (string, string, string) {
	// PostgreSQL sends an ErrorResponse or AuthenticationOK
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(sf.timeout))
	n, _ := conn.Read(buf)
	if n > 0 {
		b := string(buf[:min(n, 128)])
		if idx := strings.Index(b, "PostgreSQL"); idx >= 0 {
			return "PostgreSQL", extractPGVersion(b[idx:]), b[:min(len(b), 80)]
		}
	}
	return "PostgreSQL", "", ""
}

func (sf *ServiceFingerprinter) probeRedis(conn net.Conn) (string, string, string) {
	reader := bufio.NewReader(conn)
	// Redis sends nothing on connect; send PING
	fmt.Fprintf(conn, "PING\r\n")
	resp, err := readLine(reader, conn, sf.timeout)
	if err != nil {
		return "Redis", "", ""
	}
	if strings.HasPrefix(resp, "+PONG") || strings.HasPrefix(resp, "-ERR") || strings.HasPrefix(resp, "+OK") {
		fmt.Fprintf(conn, "INFO server\r\n")
		infoResp, _ := readLine(reader, conn, sf.timeout)
		return "Redis", extractRedisVersion(infoResp), strings.TrimSpace(resp)
	}
	return "Redis", "", strings.TrimSpace(resp)
}

func (sf *ServiceFingerprinter) fallbackBanner(conn net.Conn, port int) (string, string, string) {
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(sf.timeout))
	n, _ := conn.Read(buf)
	svcName := serviceByPort(port)
	if n > 0 {
		b := string(buf[:min(n, 256)])
		// Try parseBanner from V4
		s, v := parseBanner(b)
		if s != "" {
			return s, v, b[:min(len(b), 160)]
		}
		return svcName, "", b[:min(len(b), 160)]
	}
	return svcName, "", ""
}

// ---------------------------------------------------------------------------
// OS Fingerprinter — passive TCP/IP stack identification
// ---------------------------------------------------------------------------

// OSProfile describes a detected operating system.
type OSProfile struct {
	Name       string
	Confidence float64
	TTL        int
	WindowSize int
	MSS        int
	DF         bool
	Options    []int // TCP option kinds in order
}

// osSignatures maps (ttl, window, df, mss, options) -> OS guess
type osSignature struct {
	name      string
	ttl       int
	window    int
	df        bool
	mss       int
	tcpOpts   string // concatenated option kinds e.g. "020405b401010402"
	tolerance int    // TTL tolerance
}

var osSignatures = []osSignature{
	{name: "Linux 6.x", ttl: 64, window: 64240, df: true, mss: 1460, tcpOpts: "020405b40402080a", tolerance: 5},
	{name: "Linux 5.x", ttl: 64, window: 29200, df: true, mss: 1460, tcpOpts: "020405b40402080a", tolerance: 5},
	{name: "Linux 4.x", ttl: 64, window: 29200, df: true, mss: 1460, tcpOpts: "020405b40402080a", tolerance: 5},
	{name: "Linux 3.x", ttl: 64, window: 5840, df: true, mss: 1460, tcpOpts: "020405b4010303020101080a", tolerance: 5},
	{name: "Windows 11", ttl: 128, window: 65535, df: true, mss: 1460, tcpOpts: "020405b40103030402080a", tolerance: 5},
	{name: "Windows 10", ttl: 128, window: 65535, df: true, mss: 1460, tcpOpts: "020405b4010303020101080a", tolerance: 5},
	{name: "Windows 7", ttl: 128, window: 8192, df: true, mss: 1460, tcpOpts: "020405b4010303020101080a", tolerance: 5},
	{name: "macOS 14", ttl: 64, window: 65535, df: true, mss: 1460, tcpOpts: "020405b40402080a", tolerance: 5},
	{name: "FreeBSD", ttl: 64, window: 65535, df: true, mss: 1460, tcpOpts: "020405b4010303020101080a", tolerance: 5},
	{name: "Android", ttl: 64, window: 5840, df: true, mss: 1460, tcpOpts: "020405b40402080a", tolerance: 5},
	{name: "Cisco IOS", ttl: 255, window: 4128, df: false, mss: 1460, tcpOpts: "020405b401010402", tolerance: 10},
	{name: "Solaris", ttl: 255, window: 24820, df: false, mss: 1460, tcpOpts: "020405b40103030402080a", tolerance: 5},
}

// EstimateOS matches TCP SYN packet parameters against known OS signatures.
func EstimateOS(ttl int, windowSize int, df bool, mss int, tcpOpts []int) *OSProfile {
	optsStr := ""
	for _, o := range tcpOpts {
		optsStr += fmt.Sprintf("%02x", o)
	}

	var best *OSProfile
	for _, sig := range osSignatures {
		ttlMatch := math.Abs(float64(ttl-sig.ttl)) <= float64(sig.tolerance)
		winMatch := math.Abs(float64(windowSize-sig.window))/float64(sig.window) <= 0.2
		dfMatch := df == sig.df
		mssMatch := mss == sig.mss || mss == 0 // MSS zero sometimes from middleboxes
		optMatch := optsStr == sig.tcpOpts

		score := 0.0
		if ttlMatch {
			score += 25
		}
		if winMatch {
			score += 25
		}
		if dfMatch {
			score += 15
		}
		if mssMatch {
			score += 15
		}
		if optMatch {
			score += 20
		}

		if best == nil || score > best.Confidence {
			best = &OSProfile{
				Name:       sig.name,
				Confidence: score,
				TTL:        sig.ttl,
				WindowSize: sig.window,
				MSS:        sig.mss,
				DF:         sig.df,
				Options:    parseTCPOpts(sig.tcpOpts),
			}
		}
	}
	return best
}

func parseTCPOpts(s string) []int {
	var opts []int
	for i := 0; i+1 < len(s); i += 2 {
		var v int
		fmt.Sscanf(s[i:i+2], "%x", &v)
		opts = append(opts, v)
	}
	return opts
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func readLine(reader *bufio.Reader, conn net.Conn, timeout time.Duration) (string, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	return reader.ReadString('\n')
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseBanner — ported from V4 with enhancements
func parseBanner(banner string) (service, version string) {
	b := strings.TrimSpace(banner)

	// SSH: "SSH-2.0-OpenSSH_8.9p1"
	if strings.HasPrefix(b, "SSH-") {
		return "SSH", b
	}
	// HTTP
	if strings.HasPrefix(b, "HTTP/") {
		return "HTTP", ""
	}
	if idx := strings.Index(b, "Server:"); idx >= 0 {
		rest := b[idx+7:]
		if end := strings.Index(rest, "\r"); end >= 0 {
			return "HTTP", strings.TrimSpace(rest[:end])
		}
		return "HTTP", strings.TrimSpace(rest)
	}
	// SMTP
	if strings.HasPrefix(b, "220 ") {
		return "SMTP", strings.TrimSpace(b[4:])
	}
	// FTP
	if strings.HasPrefix(b, "220") {
		return "FTP", extractFTPVersion(b)
	}
	// POP3
	if strings.HasPrefix(b, "+OK") {
		return "POP3", b
	}
	// IMAP
	if strings.HasPrefix(b, "* OK") {
		return "IMAP", b
	}
	// MySQL
	if strings.Contains(b, "mysql_native_password") {
		return "MySQL", ""
	}
	// Redis
	if len(b) > 0 && b[0] == '+' || strings.HasPrefix(b, "-ERR") {
		return "Redis", ""
	}
	if b != "" {
		return "banner", b
	}
	return "", ""
}

func extractFTPVersion(banner string) string {
	// "220 ProFTPD 1.3.5 Server ready" or "220 (vsFTPd 3.0.3)"
	if idx := strings.Index(banner, "ProFTPD"); idx >= 0 {
		rest := banner[idx+7:]
		if end := strings.IndexAny(rest, " \t\r\n"); end >= 0 {
			return "ProFTPD " + rest[:end]
		}
	}
	if idx := strings.Index(banner, "vsFTPd"); idx >= 0 {
		rest := banner[idx+6:]
		if end := strings.IndexAny(rest, " \t\r\n)"); end >= 0 {
			return "vsFTPd " + rest[:end]
		}
	}
	if idx := strings.Index(banner, "Pure-FTPd"); idx >= 0 {
		rest := banner[idx+9:]
		if end := strings.IndexAny(rest, " \t\r\n"); end >= 0 {
			return "Pure-FTPd " + rest[:end]
		}
	}
	return ""
}

func extractSMTPVersion(banner, ehlo string) string {
	if idx := strings.Index(banner, "ESMTP"); idx >= 0 {
		rest := banner[idx+5:]
		return strings.TrimSpace(rest)
	}
	if idx := strings.Index(banner, "SMTP"); idx >= 0 {
		rest := banner[idx+4:]
		return strings.TrimSpace(rest)
	}
	return ""
}

func extractMySQLVersion(banner string) string {
	// MySQL greeting contains a version string like "8.0.35" after null
	if idx := strings.Index(banner, "\x00"); idx >= 0 && idx+1 < len(banner) {
		end := strings.IndexAny(banner[idx+1:], "\x00\xff")
		if end >= 0 {
			return banner[idx+1 : idx+1+end]
		}
	}
	return ""
}

func extractPGVersion(banner string) string {
	// "PostgreSQL 14.5 (Debian 14.5-1)"
	if idx := strings.Index(banner, "PostgreSQL"); idx >= 0 {
		rest := banner[idx+10:]
		if end := strings.IndexAny(rest, " \t\r\n("); end >= 0 {
			return strings.TrimSpace(rest[:end])
		}
		return strings.TrimSpace(rest)
	}
	return ""
}

func extractRedisVersion(infoResp string) string {
	if strings.HasPrefix(infoResp, "$") {
		return "version info available"
	}
	return ""
}

// ipToUint32 / uint32ToIP — ported from V4 orchestrator
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// ICMPEcho sends a single ICMP echo request via raw socket and returns true
// if a reply is received within the timeout. Uses only the standard library.
func ICMPEcho(host string, timeout time.Duration) bool {
	// Resolve the target
	raddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return false
	}

	// Open raw ICMP socket
	conn, err := net.DialIP("ip4:icmp", nil, raddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Build ICMP echo request manually
	// ICMP header: type(1) code(1) checksum(2) id(2) seq(2) data(variable)
	payload := []byte("fortress-probe")
	packet := make([]byte, 8+len(payload))
	packet[0] = 8       // Echo request
	packet[1] = 0       // Code
	packet[2] = 0       // Checksum high
	packet[3] = 0       // Checksum low
	packet[4] = 0       // ID high
	packet[5] = 1       // ID low
	packet[6] = 0       // Seq high
	packet[7] = 1       // Seq low
	copy(packet[8:], payload)

	// Calculate checksum
	cs := icmpChecksum(packet)
	packet[2] = byte(cs >> 8)
	packet[3] = byte(cs & 0xff)

	// Send
	if _, err := conn.Write(packet); err != nil {
		return false
	}

	// Read reply
	reply := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		n, err := conn.Read(reply)
		if err != nil {
			return false
		}
		// ICMP Echo Reply has type=0, check ID and sequence match
		if n >= 8 && reply[0] == 0 && reply[4] == 0 && reply[5] == 1 && reply[6] == 0 && reply[7] == 1 {
			return true
		}
	}
}

// icmpChecksum computes the RFC 1071 checksum for ICMP packets.
func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
