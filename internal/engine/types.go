package engine

// Threat represents a detected packet-level threat.
type Threat struct {
	Type   string // Chinese threat category (e.g. "SYN洪水", "FIN扫描")
	IP     string // Source IP address
	Detail string // Human-readable detail (flags, port, MAC, etc.)
}

// PacketContext holds pre-parsed packet metadata extracted by the
// XDP/data-plane layer before passing into the Go inspection engine.
type PacketContext struct {
	TCPFlags string // Sorted uppercase TCP flags (e.g. "S", "AS", "FPU")
	SrcIP    string // Source IP address
	DstPort  uint16 // Destination port (TCP/UDP only)
	Protocol string // "TCP", "UDP", or "ICMP"
}
