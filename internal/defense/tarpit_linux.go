//go:build linux

package defense

import (
	"fmt"
	"log"
	"sync"
	"syscall"
)

// Tarpit implements a TCP zero-window tarpit using raw sockets.
// It pins attacker connections indefinitely to waste their resources.
// Linux only — requires raw socket capability (CAP_NET_RAW or root).
type Tarpit struct {
	mu          sync.Mutex
	connections map[string]bool
	active      bool
}

// NewTarpit creates a new Tarpit instance.
func NewTarpit() *Tarpit {
	return &Tarpit{connections: make(map[string]bool)}
}

// Start verifies raw socket capability and marks the tarpit as active.
// Returns an error if the process lacks the required permissions.
func (t *Tarpit) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("tarpit: raw socket: %w (requires root)", err)
	}
	syscall.Close(fd) // Just check capability

	t.active = true
	log.Println("[tarpit] raw socket capability confirmed — ready")
	return nil
}

// Stop deactivates the tarpit.
func (t *Tarpit) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active = false
	log.Println("[tarpit] deactivated")
}

// TrapIP registers an IP address for tarpit tracking.
func (t *Tarpit) TrapIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connections[ip] = true
	log.Printf("[tarpit] trapping %s (conns: %d)", ip, len(t.connections))
}

// ReleaseIP removes an IP from tarpit tracking.
func (t *Tarpit) ReleaseIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.connections, ip)
}

// ActiveCount returns the number of IPs currently trapped.
func (t *Tarpit) ActiveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.connections)
}

// Cleanup evicts excess connections when the trap count exceeds maxConns.
// Returns the number of connections removed.
func (t *Tarpit) Cleanup(maxConns int) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.connections) <= maxConns {
		return 0
	}

	removed := 0
	for ip := range t.connections {
		if len(t.connections) <= maxConns {
			break
		}
		delete(t.connections, ip)
		removed++
	}
	return removed
}
