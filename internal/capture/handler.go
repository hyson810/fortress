package capture

import (
	"sync/atomic"
	"time"
)

// CaptureHandler abstracts packet capture sources.
type CaptureHandler interface {
	Packets() <-chan *DecodedPacket
	Stats() *CaptureStats
	Close() error
}

// DecodedPacket is a zero-copy decoded packet from the capture layer.
type DecodedPacket struct {
	Raw       []byte
	Timestamp time.Time

	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8 // 6=TCP, 17=UDP, 1=ICMP
	Length   int

	// TCP-specific
	TCPFlags uint8 // SYN=2, ACK=16, FIN=1, RST=4
	TCPSeq   uint32

	// Ethernet
	SrcMAC string
	DstMAC string

	// Metadata for processing pipeline
	Meta *PacketMeta
}

// PacketMeta holds metadata for the processing pipeline.
type PacketMeta struct {
	Prefiltered bool
	MatchCount  int
}

// CaptureStats exposes capture performance counters.
type CaptureStats struct {
	PacketsReceived atomic.Uint64
	PacketsDropped  atomic.Uint64
	BytesReceived   atomic.Uint64
}

