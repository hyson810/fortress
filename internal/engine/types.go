package engine

import "time"

// Threat represents a detected packet-level threat.
type Threat struct {
	Type   string // Chinese threat category (e.g. "SYN洪水", "FIN扫描")
	IP     string // Source IP address
	Detail string // Human-readable detail (flags, port, MAC, etc.)
}

// PacketContext holds pre-parsed packet metadata extracted by the
// XDP/data-plane layer before passing into the Go inspection engine.
type PacketContext struct {
	Timestamp   time.Time // Packet arrival time
	SrcIP       string    // Source IP address
	DstIP       string    // Destination IP address
	SrcPort     uint16    // Source port (TCP/UDP only)
	DstPort     uint16    // Destination port (TCP/UDP only)
	Protocol    string    // "TCP", "UDP", or "ICMP"
	TCPFlags    string    // Sorted uppercase TCP flags (e.g. "S", "AS", "FPU")
	PayloadSize uint16    // Payload size in bytes
}
