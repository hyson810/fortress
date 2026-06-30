package defense

import (
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

// HoneypotType identifies the protocol a honeypot emulates.
type HoneypotType string

const (
	SSHHoneypot   HoneypotType = "ssh"
	HTTPHoneypot  HoneypotType = "http"
	MySQLHoneypot HoneypotType = "mysql"
)

// HitRecord captures the details of a single honeypot interaction.
type HitRecord struct {
	IP        string       `json:"ip"`
	Port      int          `json:"port"`
	Type      HoneypotType `json:"type"`
	Timestamp time.Time    `json:"timestamp"`
	Data      string       `json:"data"`
}

// honeypotListener manages a single protocol listener and its connection pool.
type honeypotListener struct {
	Type      HoneypotType
	Port      int
	listener  net.Listener
	running   atomic.Bool
	wg        sync.WaitGroup
	maxConns  int
	connCount atomic.Int32
	onHit     func(HitRecord)
}

// HoneypotManager starts and stops multiple protocol honeypot listeners
// and collects interaction records.
type HoneypotManager struct {
	mu    sync.Mutex
	pots  map[HoneypotType]*honeypotListener
	hits  []HitRecord
	hitCh chan HitRecord
}

// NewHoneypotManager creates a new HoneypotManager.
func NewHoneypotManager() *HoneypotManager {
	return &HoneypotManager{
		pots:  make(map[HoneypotType]*honeypotListener),
		hits:  make([]HitRecord, 0),
		hitCh: make(chan HitRecord, 100),
	}
}

// StartSSH starts an SSH honeypot on the given port.
func (hm *HoneypotManager) StartSSH(port int) error {
	return hm.startPot(SSHHoneypot, port, handleSSH)
}

// StartHTTP starts an HTTP honeypot on the given port.
func (hm *HoneypotManager) StartHTTP(port int) error {
	return hm.startPot(HTTPHoneypot, port, handleHTTP)
}

// StartMySQL starts a MySQL honeypot on the given port.
func (hm *HoneypotManager) StartMySQL(port int) error {
	return hm.startPot(MySQLHoneypot, port, handleMySQL)
}

// startPot registers and launches a honeypot listener of the given type.
func (hm *HoneypotManager) startPot(t HoneypotType, port int, handler func(net.Conn, func(HitRecord))) error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if _, ok := hm.pots[t]; ok {
		return fmt.Errorf("honeypot %s already running", t)
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("honeypot %s port %d: %w", t, port, err)
	}

	pot := &honeypotListener{
		Type:     t,
		Port:     port,
		listener: l,
		maxConns: 1000,
		onHit: func(r HitRecord) {
			select {
			case hm.hitCh <- r:
			default:
				// hitCh full, drop hit to avoid blocking honeypot handler
			}
			hm.mu.Lock()
			hm.hits = append(hm.hits, r)
			hm.mu.Unlock()
		},
	}
	pot.running.Store(true)
	pot.wg.Add(1)
	go pot.acceptLoop(handler)

	hm.pots[t] = pot
	log.Printf("[honeypot] %s started on :%d", t, port)
	return nil
}

// acceptLoop accepts incoming connections and dispatches them to the handler.
func (p *honeypotListener) acceptLoop(handler func(net.Conn, func(HitRecord))) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[honeypot] accept loop panic: %v\nstack: %s", r, debug.Stack())
		}
	}()
	defer p.wg.Done()
	for p.running.Load() {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.running.Load() {
				log.Printf("[honeypot] accept: %v", err)
			}
			continue
		}
		if p.connCount.Load() >= int32(p.maxConns) {
			conn.Close()
			continue
		}
		p.connCount.Add(1)
		p.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[honeypot] handler panic: %v\nstack: %s", r, debug.Stack())
				}
			}()
			defer p.wg.Done()
			defer p.connCount.Add(-1)
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(60 * time.Second))
			handler(c, p.onHit)
		}(conn)
	}
}

// StopAll shuts down all honeypot listeners and waits for handlers to finish.
func (hm *HoneypotManager) StopAll() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	for t, p := range hm.pots {
		p.running.Store(false)
		p.listener.Close()
		p.wg.Wait()
		log.Printf("[honeypot] %s stopped", t)
	}
	hm.pots = make(map[HoneypotType]*honeypotListener)
}

// HitChannel returns a receive-only channel of honeypot interaction records.
func (hm *HoneypotManager) HitChannel() <-chan HitRecord {
	return hm.hitCh
}

// CheckHit reports whether the given IP has triggered any honeypot
// in the last 60 seconds.
func (hm *HoneypotManager) CheckHit(ip string) bool {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	cutoff := time.Now().Add(-60 * time.Second)
	for _, h := range hm.hits {
		if h.IP == ip && h.Timestamp.After(cutoff) {
			return true
		}
	}
	return false
}

// RecentHits returns a snapshot of all recorded honeypot interactions.
func (hm *HoneypotManager) RecentHits() []HitRecord {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	return hm.hits
}

// RecordHit injects a honeypot interaction record for the given IP without
// requiring an actual network connection. Used for testing and simulation
// scenarios where TCP localhost is unavailable.
func (hm *HoneypotManager) RecordHit(ip string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	r := HitRecord{
		IP:        ip,
		Port:      0,
		Type:      "manual",
		Timestamp: time.Now(),
		Data:      "test injection",
	}
	hm.hits = append(hm.hits, r)
	// Non-blocking send to channel.
	select {
	case hm.hitCh <- r:
	default:
	}
}

// handleSSH emulates an OpenSSH server banner and captures the client hello.
func handleSSH(conn net.Conn, onHit func(HitRecord)) {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if _, err := conn.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7\r\n")); err != nil {
		log.Printf("[honeypot/ssh] write banner: %v", err)
		conn.Close()
		return
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("[honeypot/ssh] read: %v", err)
		conn.Close()
		return
	}
	if n > 0 {
		onHit(HitRecord{
			IP: ip, Port: 2222, Type: SSHHoneypot,
			Timestamp: time.Now(), Data: sanitizeLogInput(string(buf[:n])),
		})
	}
	conn.Close()
}

// handleHTTP emulates an nginx web server and captures the request.
func handleHTTP(conn net.Conn, onHit func(HitRecord)) {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("[honeypot/http] read: %v", err)
		conn.Close()
		return
	}
	if n > 0 {
		onHit(HitRecord{
			IP: ip, Port: 8080, Type: HTTPHoneypot,
			Timestamp: time.Now(), Data: sanitizeLogInput(string(buf[:n])),
		})
	}
	if _, err := conn.Write([]byte(
		"HTTP/1.1 404 Not Found\r\n" +
			"Server: nginx/1.24.0\r\n" +
			"Content-Type: text/html\r\n" +
			"\r\n" +
			"<html><body><h1>404 Not Found</h1></body></html>\r\n",
	)); err != nil {
		log.Printf("[honeypot/http] write response: %v", err)
	}
	conn.Close()
}

// handleMySQL emulates a MySQL 8.0 server and captures the client handshake.
func handleMySQL(conn net.Conn, onHit func(HitRecord)) {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	greeting := []byte{
		0x4a, 0x00, 0x00, 0x00, 0x0a, 0x38, 0x2e, 0x30, 0x2e, 0x33, 0x36, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if _, err := conn.Write(greeting); err != nil {
		log.Printf("[honeypot/mysql] write greeting: %v", err)
		conn.Close()
		return
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("[honeypot/mysql] read: %v", err)
		conn.Close()
		return
	}
	if n > 0 {
		onHit(HitRecord{
			IP: ip, Port: 3307, Type: MySQLHoneypot,
			Timestamp: time.Now(), Data: sanitizeLogInput(string(buf[:n])),
		})
	}
	conn.Close()
}

// sanitizeLogInput sanitizes attacker-controlled data before logging.
// It truncates to max 512 bytes, replaces non-printable chars with '.',
// and removes ANSI escape sequences.
func sanitizeLogInput(s string) string {
	// Truncate to 512 bytes
	if len(s) > 512 {
		s = s[:512]
	}
	// Remove ANSI escape sequences
	var result strings.Builder
	result.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b { // ESC
			// Skip until we hit a letter (end of ANSI sequence)
			for i++; i < len(s); i++ {
				if (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') {
					break
				}
			}
			continue
		}
		r := rune(s[i])
		if unicode.IsPrint(r) {
			result.WriteByte(s[i])
		} else {
			result.WriteByte('.')
		}
	}
	return result.String()
}
