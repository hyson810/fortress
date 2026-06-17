// Package loader compiles, loads, and manages eBPF programs for Fortress.
package loader

// XDPStats holds the aggregated (all-CPU) XDP filter counters.
type XDPStats struct {
	Passed      uint64
	Dropped     uint64
	RateLimited uint64
}

// EgressAlert mirrors the kernel egress_alert struct pushed via the perf
// event array from the TC egress program.
type EgressAlert struct {
	DestIP    uint32
	ByteCount uint64
	Timestamp uint64
}
