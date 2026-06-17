//go:build !linux
// +build !linux

/*
Package loader provides a graceful no-op fallback for platforms that do not
support eBPF (non-Linux).  All methods return descriptive errors.
*/
package loader

import "fmt"

// EBpfEngine is a no-op stub on non-Linux platforms.
type EBpfEngine struct{}

// NewEBpfEngine returns an error — eBPF requires a Linux kernel 5.4+.
func NewEBpfEngine(iface string) (*EBpfEngine, error) {
	return nil, fmt.Errorf("eBPF engine requires Linux kernel 5.4+")
}

// BlockIP is a stub.
func (e *EBpfEngine) BlockIP(ip string) error {
	return fmt.Errorf("eBPF engine requires Linux kernel 5.4+")
}

// UnblockIP is a stub.
func (e *EBpfEngine) UnblockIP(ip string) error {
	return fmt.Errorf("eBPF engine requires Linux kernel 5.4+")
}

// SetRateLimit is a stub.
func (e *EBpfEngine) SetRateLimit(ip string, tokens uint32) error {
	return fmt.Errorf("eBPF engine requires Linux kernel 5.4+")
}

// GetStats is a stub.
func (e *EBpfEngine) GetStats() (*XDPStats, error) {
	return nil, fmt.Errorf("eBPF engine requires Linux kernel 5.4+")
}

// EgressAlerts is a stub.
func (e *EBpfEngine) EgressAlerts() <-chan EgressAlert {
	ch := make(chan EgressAlert)
	close(ch)
	return ch
}

// DroppedAlerts is a stub.
func (e *EBpfEngine) DroppedAlerts() uint64 {
	return 0
}

// Close is a stub.
func (e *EBpfEngine) Close() error {
	return fmt.Errorf("eBPF engine requires Linux kernel 5.4+")
}
