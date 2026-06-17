// Package offense implements offensive security tools. This file provides
// TCP port scanning and basic service fingerprinting via banner grabbing.
package offense

import (
	"bufio"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// SERVICE_MAP maps common TCP port numbers to their typical service names.
var SERVICE_MAP = map[int]string{
	7:    "Echo",
	20:   "FTP-Data",
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	69:   "TFTP",
	80:   "HTTP",
	110:  "POP3",
	111:  "RPC",
	123:  "NTP",
	135:  "MSRPC",
	139:  "NetBIOS",
	143:  "IMAP",
	161:  "SNMP",
	194:  "IRC",
	389:  "LDAP",
	443:  "HTTPS",
	445:  "SMB",
	465:  "SMTPS",
	514:  "Syslog",
	587:  "SMTP-Submission",
	636:  "LDAPS",
	873:  "Rsync",
	993:  "IMAPS",
	995:  "POP3S",
	1080: "SOCKS",
	1433: "MSSQL",
	1521: "Oracle",
	1723: "PPTP",
	2049: "NFS",
	2082: "cPanel",
	2083: "cPanel-SSL",
	3128: "Squid",
	3306: "MySQL",
	3389: "RDP",
	4444: "Metasploit",
	5060: "SIP",
	5432: "PostgreSQL",
	5900: "VNC",
	5985: "WinRM-HTTP",
	5986: "WinRM-HTTPS",
	6379: "Redis",
	6443: "Kubernetes-API",
	8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
	8888: "HTTP-Alt-2",
	9000: "PHP-FPM",
	9090: "Prometheus",
	9200: "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
}

// topPorts is the list of the top 1000 TCP ports ordered by prevalence
// (IANA assignment frequency combined with empirical scan data).
var topPorts []int

func init() {
	// Build top 1000 ports: all ports in SERVICE_MAP plus sequential ports
	// in well-known and registered ranges.
	seen := make(map[int]bool)

	// Add all known service ports first (they are the most interesting).
	for port := range SERVICE_MAP {
		seen[port] = true
		topPorts = append(topPorts, port)
	}

	// Fill well-known (1-1023) ports not already present.
	for p := 1; p <= 1023; p++ {
		if !seen[p] {
			seen[p] = true
			topPorts = append(topPorts, p)
		}
	}

	// Fill registered-range highlights (1024-49151) — add every 50th port
	// to keep the list tight while covering the range.
	for p := 1024; p <= 9000; p += 50 {
		if !seen[p] {
			topPorts = append(topPorts, p)
		}
	}

	sort.Ints(topPorts)
}

// ---------------------------------------------------------------------------
// PortScanner
// ---------------------------------------------------------------------------

// PortScanner performs TCP connect scans against remote hosts.
type PortScanner struct {
	timeout    time.Duration
	maxWorkers int
}

// NewPortScanner creates a PortScanner with the given timeout and worker
// count.
func NewPortScanner(timeout time.Duration, maxWorkers int) *PortScanner {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	if maxWorkers > 1000 {
		maxWorkers = 1000
	}
	return &PortScanner{
		timeout:    timeout,
		maxWorkers: maxWorkers,
	}
}

// ScanPort attempts a single TCP connect to host:port. Returns true if the
// connection succeeds within the scanner's timeout.
func (ps *PortScanner) ScanPort(host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, ps.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ScanRange concurrently scans every port in [startPort, endPort] inclusive
// and returns a sorted slice of open ports.
func (ps *PortScanner) ScanRange(host string, startPort, endPort int) []int {
	if startPort > endPort {
		startPort, endPort = endPort, startPort
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var openPorts []int

	// Spin up workers.
	for i := 0; i < ps.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if ps.ScanPort(host, port) {
					mu.Lock()
					openPorts = append(openPorts, port)
					mu.Unlock()
				}
			}
		}()
	}

	// Submit ports.
	for port := startPort; port <= endPort; port++ {
		jobs <- port
	}
	close(jobs)
	wg.Wait()

	sort.Ints(openPorts)
	return openPorts
}

// QuickScan scans the top 1000 most common TCP ports on the given host.
func (ps *PortScanner) QuickScan(host string) []int {
	return ps.scanPortList(host, topPorts)
}

// scanPortList scans a pre-defined slice of ports concurrently.
func (ps *PortScanner) scanPortList(host string, ports []int) []int {
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var openPorts []int

	for i := 0; i < ps.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if ps.ScanPort(host, port) {
					mu.Lock()
					openPorts = append(openPorts, port)
					mu.Unlock()
				}
			}
		}()
	}

	for _, port := range ports {
		jobs <- port
	}
	close(jobs)
	wg.Wait()

	sort.Ints(openPorts)
	return openPorts
}

// ---------------------------------------------------------------------------
// ServiceFingerprinter
// ---------------------------------------------------------------------------

// ServiceFingerprinter identifies services by connecting and reading their
// initial banner.
type ServiceFingerprinter struct {
	timeout time.Duration
}

// NewServiceFingerprinter creates a ServiceFingerprinter with a default 3 s
// timeout.
func NewServiceFingerprinter() *ServiceFingerprinter {
	return &ServiceFingerprinter{
		timeout: 3 * time.Second,
	}
}

// Fingerprint connects to host:port, reads the banner, and returns a best-
// guess service name and version string. Falls back to SERVICE_MAP when no
// banner is sent.
func (sf *ServiceFingerprinter) Fingerprint(host string, port int) (service, version string) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, sf.timeout)
	if err != nil {
		return sf.serviceByPort(port), ""
	}
	defer conn.Close()

	// Give the server a moment to send its banner.
	conn.SetReadDeadline(time.Now().Add(sf.timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		// No banner — fall back to port-based guess.
		return sf.serviceByPort(port), ""
	}

	service, version = parseBanner(banner)
	if service == "" {
		service = sf.serviceByPort(port)
	}
	return service, version
}

// serviceByPort returns the known service name for a port, or "unknown".
func (sf *ServiceFingerprinter) serviceByPort(port int) string {
	if name, ok := SERVICE_MAP[port]; ok {
		return name
	}
	return "unknown"
}

// parseBanner attempts to extract a service name and version from a raw
// banner string. It recognises common banner formats (SSH, HTTP, FTP, SMTP,
// POP3, IMAP, MySQL, PostgreSQL, etc.).
func parseBanner(banner string) (service, version string) {
	b := banner

	// SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
	if len(b) >= 4 && b[:4] == "SSH-" {
		service = "SSH"
		version = strings.TrimSpace(b)
		return
	}

	// HTTP: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n..." — we only get
	// a partial read, but we check what we have.
	if len(b) >= 4 && b[:4] == "HTTP" {
		service = "HTTP"
		return
	}

	// Check for HTTP server header in middle of banner.
	if idx := strings.Index(b, "Server:"); idx >= 0 {
		service = "HTTP"
		rest := b[idx+7:]
		if end := strings.Index(rest, "\r"); end >= 0 {
			version = strings.TrimSpace(rest[:end])
		} else {
			version = strings.TrimSpace(rest)
		}
		return
	}

	// SMTP: "220 mail.example.com ESMTP Postfix" — check before FTP because
	// FTP banners may also start with "220" (e.g. "220-ProFTPD...").
	if len(b) >= 4 && b[:4] == "220 " {
		service = "SMTP"
		version = strings.TrimSpace(b[4:])
		return
	}

	// FTP: "220-ProFTPD 1.3.5 Server ready" or "220 ProFTPD ..."
	if len(b) >= 3 && b[:3] == "220" {
		service = "FTP"
		version = strings.TrimSpace(b[3:])
		return
	}

	// POP3: "+OK POP3 server ready"
	if len(b) >= 3 && b[:3] == "+OK" {
		service = "POP3"
		version = strings.TrimSpace(b)
		return
	}

	// IMAP: "* OK IMAP4rev1 server ready"
	if len(b) >= 4 && b[:4] == "* OK" {
		service = "IMAP"
		version = strings.TrimSpace(b)
		return
	}

	// MySQL: starts with a version packet (binary, but sometimes we get a text fragment)
	if idx := strings.Index(b, "mysql_native_password"); idx >= 0 {
		service = "MySQL"
		return
	}

	// PostgreSQL: first byte is typically an error or auth packet
	if idx := strings.Index(b, "PostgreSQL"); idx >= 0 {
		service = "PostgreSQL"
		return
	}

	// Redis: "-ERR unknown command" or "+OK" etc — but any + line can be Redis
	if len(b) > 0 && b[0] == '+' {
		service = "Redis"
		version = strings.TrimSpace(b[1:])
		return
	}

	// Generic: if we have a banner but can't identify it, report "banner".
	if strings.TrimSpace(b) != "" {
		service = "banner"
		version = strings.TrimSpace(b)
	}
	return
}

