package defense

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FakeService defines the configuration for a single deceptive service.
type FakeService struct {
	Name            string `json:"name"`
	Port            int    `json:"port"`
	Protocol        string `json:"protocol"` // tcp, udp
	Banner          string `json:"banner"`
	ResponsePattern string `json:"response_pattern"` // ssh, http, mysql, generic
}

// DeceptionStat collects counters for a single fake service.
type DeceptionStat struct {
	Name        string `json:"name"`
	Port        int    `json:"port"`
	Connections int64  `json:"connections"`
	Captured    int64  `json:"captured"`
	Active      int64  `json:"active"`
}

// Deceptor manages multiple fake services that emulate real protocols
// to deceive and gather intelligence on attackers.
type Deceptor struct {
	mu          sync.Mutex
	services    map[string]*fakeServiceListener
	stats       map[string]*DeceptionStat
	listeners   map[string]net.Listener
	maxConcurrent int32
	activeConns  atomic.Int32
	running      atomic.Bool
}

type fakeServiceListener struct {
	Service  FakeService
	listener net.Listener
	wg       sync.WaitGroup
}

// NewDeceptor creates a new Deceptor instance.
func NewDeceptor(maxConcurrent int) *Deceptor {
	if maxConcurrent <= 0 {
		maxConcurrent = 1000
	}
	return &Deceptor{
		services:      make(map[string]*fakeServiceListener),
		stats:         make(map[string]*DeceptionStat),
		listeners:     make(map[string]net.Listener),
		maxConcurrent: int32(maxConcurrent),
	}
}

// AddFakeService registers and starts a new fake service listener.
func (d *Deceptor) AddFakeService(name string, port int, protocol string, banner string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.services[name]; ok {
		return fmt.Errorf("deceptor: service %q already registered", name)
	}

	svc := FakeService{
		Name:     name,
		Port:     port,
		Protocol: strings.ToLower(protocol),
		Banner:   banner,
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("deceptor: %s on :%d: %w", name, port, err)
	}

	fsl := &fakeServiceListener{
		Service:  svc,
		listener: l,
	}
	d.services[name] = fsl
	d.listeners[name] = l
	d.stats[name] = &DeceptionStat{
		Name: name,
		Port: port,
	}

	fsl.wg.Add(1)
	go d.acceptLoop(fsl)

	log.Printf("[deceptor] fake service %q started on :%d (%s)", name, port, protocol)
	return nil
}

// acceptLoop accepts connections and dispatches them to the appropriate handler.
func (d *Deceptor) acceptLoop(fsl *fakeServiceListener) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[deceptor] accept loop panic: %v\nstack: %s", r, debug.Stack())
		}
	}()
	defer fsl.wg.Done()

	for d.running.Load() || d.activeConns.Load() > 0 {
		conn, err := fsl.listener.Accept()
		if err != nil {
			if d.running.Load() {
				// Only log if we're still supposed to be running.
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
			}
			return
		}

		if d.activeConns.Load() >= d.maxConcurrent {
			conn.Close()
			continue
		}

		d.activeConns.Add(1)
		fsl.wg.Add(1)
		go d.handleConnection(fsl, conn)
	}
}

// handleConnection processes a single incoming connection for a fake service.
func (d *Deceptor) handleConnection(fsl *fakeServiceListener, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[deceptor] handler panic: %v\nstack: %s", r, debug.Stack())
		}
	}()
	defer fsl.wg.Done()
	defer d.activeConns.Add(-1)
	defer conn.Close()

	d.mu.Lock()
	stat := d.stats[fsl.Service.Name]
	d.mu.Unlock()

	if stat != nil {
		atomic.AddInt64(&stat.Connections, 1)
		atomic.AddInt64(&stat.Active, 1)
		defer atomic.AddInt64(&stat.Active, -1)
	}

	// Random delay before responding to mimic a real service.
	RandomDelay(100*time.Millisecond, 2*time.Second)

	pattern := fsl.Service.ResponsePattern
	if pattern == "" {
		pattern = "generic"
	}

	switch pattern {
	case "ssh":
		d.FakeSSH(conn, fsl.Service)
	case "http":
		d.FakeHTTP(conn)
	case "mysql":
		d.FakeMySQL(conn)
	default:
		d.spoofGeneric(conn, fsl.Service)
	}
}

// SpoofBanner sends a fake service banner to the connection.
func (d *Deceptor) SpoofBanner(conn net.Conn, svc FakeService) {
	if svc.Banner != "" {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(conn, svc.Banner+"\r\n")
	}
}

// FakeSSH emulates an OpenSSH handshake and captures any credentials sent.
func (d *Deceptor) FakeSSH(conn net.Conn, svc FakeService) {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	banner := svc.Banner
	if banner == "" {
		banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.7"
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(conn, banner+"\r\n")

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	d.mu.Lock()
	stat := d.stats[svc.Name]
	d.mu.Unlock()

	if stat != nil {
		atomic.AddInt64(&stat.Captured, 1)
	}

	log.Printf("[deceptor] SSH capture from %s (%d bytes): %s", ip, n, string(buf[:min(n, 200)]))
}

// FakeHTTP returns a fake nginx 200 response with a tracking pixel.
func (d *Deceptor) FakeHTTP(conn net.Conn) {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	conn.Read(buf)

	body := `<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
` + webBugTag() + `
</body></html>
`

	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Server: nginx/1.24.0\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n%s",
		len(body), body,
	)

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(conn, resp)

	log.Printf("[deceptor] HTTP deception served to %s", ip)
}

// FakeMySQL emulates a MySQL 8.0 greeting and captures the client handshake.
func (d *Deceptor) FakeMySQL(conn net.Conn) {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	greeting := []byte{
		0x5b, 0x00, 0x00, 0x00, 0x0a, 0x38, 0x2e, 0x30, 0x2e, 0x33, 0x36, 0x00,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	// Set server version bytes: "8.0.36"
	copy(greeting[5:11], []byte("8.0.36"))

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write(greeting)

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	d.mu.Lock()
	stat := d.stats["mysql"]
	d.mu.Unlock()

	if stat != nil {
		atomic.AddInt64(&stat.Captured, 1)
	}

	log.Printf("[deceptor] MySQL handshake captured from %s (%d bytes)", ip, n)
}

// spoofGeneric sends a generic banner and captures the first line of input.
func (d *Deceptor) spoofGeneric(conn net.Conn, svc FakeService) {
	d.SpoofBanner(conn, svc)

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, _ := conn.Read(buf)

	if n > 0 {
		d.mu.Lock()
		stat := d.stats[svc.Name]
		d.mu.Unlock()

		if stat != nil {
			atomic.AddInt64(&stat.Captured, 1)
		}
		log.Printf("[deceptor] %s captured %d bytes from %s", svc.Name, n, ip)
	}
}

// TrackDeceptions returns a snapshot of all deception statistics.
func (d *Deceptor) TrackDeceptions() []DeceptionStat {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]DeceptionStat, 0, len(d.stats))
	for _, s := range d.stats {
		out = append(out, DeceptionStat{
			Name:        s.Name,
			Port:        s.Port,
			Connections: atomic.LoadInt64(&s.Connections),
			Captured:    atomic.LoadInt64(&s.Captured),
			Active:      atomic.LoadInt64(&s.Active),
		})
	}
	return out
}

// ActiveConnections returns the current number of active deceptive connections.
func (d *Deceptor) ActiveConnections() int32 {
	return d.activeConns.Load()
}

// StopAll shuts down all fake service listeners and waits for connections
// to drain.
func (d *Deceptor) StopAll() {
	d.running.Store(false)

	d.mu.Lock()
	for name, l := range d.listeners {
		l.Close()
		log.Printf("[deceptor] fake service %q stopped", name)
	}

	// Drain wait groups.
	for _, fsl := range d.services {
		fsl.wg.Wait()
	}

	d.listeners = make(map[string]net.Listener)
	d.services = make(map[string]*fakeServiceListener)
	d.mu.Unlock()

	log.Println("[deceptor] all deception services stopped")
}

// RandomDelay pauses for a duration between min and max.
func RandomDelay(min, max time.Duration) {
	if max <= min {
		time.Sleep(min)
		return
	}
	jitter := time.Duration(rand.Int63n(int64(max - min)))
	time.Sleep(min + jitter)
}

// MaxConcurrentDeceptions returns the maximum number of concurrent
// deceptive connections allowed.
func (d *Deceptor) MaxConcurrentDeceptions() int32 {
	return atomic.LoadInt32(&d.maxConcurrent)
}

// SetMaxConcurrentDeceptions updates the max concurrent connections limit.
func (d *Deceptor) SetMaxConcurrentDeceptions(n int32) {
	atomic.StoreInt32(&d.maxConcurrent, n)
}

// webBugTag returns a 1x1 tracking pixel HTML img tag.
func webBugTag() string {
	id := fmt.Sprintf("%x", rand.Uint64())
	return fmt.Sprintf(
		`<img src="/pixel.gif?id=%s" width="1" height="1" alt="" style="display:none" />`,
		id,
	)
}

func init() {
	if runtime.GOOS != "linux" {
		log.Printf("[deceptor] non-Linux OS (%s) — deception services available in limited mode", runtime.GOOS)
	}
}
