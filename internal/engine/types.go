package engine

import "time"

// Threat represents a detected security threat.
type Threat struct {
	Type   string
	IP     string
	Detail string
}

// PacketContext holds metadata about a captured network packet.
type PacketContext struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string // "TCP", "UDP", "ICMP"
	TCPFlags    string // sorted uppercase, e.g. "S", "AS", "FPU"
	PayloadSize uint16
	PayloadHash uint64
	Direction   string // "ingress" or "egress"
}
