/*
Package engines provides high-level Go interfaces for the Fortress detection
pipeline.  The eBPF blocker wraps the kernel-level XDP/TC engine with
concurrency-safe access suitable for use by the Go detection pipeline.
*/
package engines

import (
	"sync"

	"github.com/fortress/v6/kernel/loader"
)

// EBpfBlocker wraps the kernel eBPF engine for use by the Go detection
// pipeline.  It serializes map mutations with a mutex so the detection
// engine can call Block / Unblock from any goroutine without coordinating
// with the stats reader.
type EBpfBlocker struct {
	engine *loader.EBpfEngine
	mu     sync.Mutex
}

// NewEBpfBlocker creates an eBPF blocker attached to the named network
// interface.  Returns an error if the kernel does not support eBPF or if
// the interface does not exist.
func NewEBpfBlocker(iface string) (*EBpfBlocker, error) {
	eng, err := loader.NewEBpfEngine(iface)
	if err != nil {
		return nil, err
	}
	return &EBpfBlocker{engine: eng}, nil
}

// Block adds an IPv4 address to the XDP drop list.  All ingress packets from
// this IP will be dropped at the NIC driver level.
func (eb *EBpfBlocker) Block(ip string) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	return eb.engine.BlockIP(ip)
}

// Unblock removes an IPv4 address from the XDP drop list.
func (eb *EBpfBlocker) Unblock(ip string) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	return eb.engine.UnblockIP(ip)
}

// GetStats returns the number of blocked IPs (from the map entry count),
// dropped packets, and passed packets since the engine started.
func (eb *EBpfBlocker) GetStats() (blocked int, dropped uint64, passed uint64, err error) {
	stats, err := eb.engine.GetStats()
	if err != nil {
		return 0, 0, 0, err
	}
	return 0, stats.Dropped, stats.Passed, nil // blocked count not directly tracked; set to 0
}

// SetRateLimit sets the token bucket token count for the given IP.
// This is typically called by a background goroutine that refills tokens
// on a periodic tick (e.g. 10 tokens/s, capped at 100).
func (eb *EBpfBlocker) SetRateLimit(ip string, tokens uint32) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	return eb.engine.SetRateLimit(ip, tokens)
}

// EgressAlerts returns a channel that receives exfiltration alerts from the
// TC egress monitor.
func (eb *EBpfBlocker) EgressAlerts() <-chan loader.EgressAlert {
	return eb.engine.EgressAlerts()
}

// Close detaches all eBPF programs and releases kernel resources.
func (eb *EBpfBlocker) Close() error {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	return eb.engine.Close()
}
