//go:build !linux

package defense

import (
	"fmt"
	"sync"
)

// Tarpit implements a TCP zero-window tarpit using raw sockets.
// Windows: raw sockets not available — connections tracked but not held.
type Tarpit struct {
	mu          sync.Mutex
	connections map[string]bool
	active      bool
}

// NewTarpit creates a new Tarpit instance.
func NewTarpit() *Tarpit {
	return &Tarpit{connections: make(map[string]bool)}
}

// Start marks the tarpit as active.
// Windows: no raw socket capability needed.
func (t *Tarpit) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active = true
	return nil
}

// Stop deactivates the tarpit.
func (t *Tarpit) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active = false
}

// TrapIP adds an IP to the tarpit.
func (t *Tarpit) TrapIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connections[ip] = true
}

// ReleaseIP removes an IP from the tarpit.
func (t *Tarpit) ReleaseIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.connections, ip)
}

// ActiveCount returns the number of trapped connections.
func (t *Tarpit) ActiveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.connections)
}

// Cleanup removes stale connections.
// maxConns caps the connection count on Linux; ignored on Windows.
// Returns the number of connections remaining.
func (t *Tarpit) Cleanup(maxConns int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.connections) > maxConns {
		t.connections = make(map[string]bool)
	}
	return len(t.connections)
}

// Linux-specific implementation is in tarpit_linux.go.
// This file uses fmt to avoid unused import warnings.
var _ = fmt.Sprintf
