package capture

import (
	"sync"
	"time"
)

// InjectHandler implements CaptureHandler for test/dev environments
// where AF_PACKET is unavailable. Packets are injected programmatically.
type InjectHandler struct {
	packetCh chan *DecodedPacket
	stats    *CaptureStats
	closed   bool
	mu       sync.Mutex
}

// NewInjectHandler creates a new InjectHandler with a buffered channel
// of capacity 1000.
func NewInjectHandler() *InjectHandler {
	return &InjectHandler{
		packetCh: make(chan *DecodedPacket, 1000),
		stats:    &CaptureStats{},
	}
}

// Inject pushes a raw packet into the handler for processing.
// This is the main entry point for test packets.
func (h *InjectHandler) Inject(raw []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return
	}

	pkt := decodePacket(raw, time.Now())
	if pkt == nil {
		return
	}

	// Copy raw into a new slice so the caller can reuse the original
	rawCopy := make([]byte, len(raw))
	copy(rawCopy, raw)
	pkt.Raw = rawCopy


	// Non-blocking send to packetCh; if full, increment PacketsDropped
	select {
	case h.packetCh <- pkt:
		h.stats.PacketsReceived.Add(1)
		h.stats.BytesReceived.Add(uint64(len(raw)))
	default:
		h.stats.PacketsDropped.Add(1)
	}
}

// Packets returns a read-only channel of decoded packets.
func (h *InjectHandler) Packets() <-chan *DecodedPacket {
	return h.packetCh
}

// Stats returns the capture statistics counters.
func (h *InjectHandler) Stats() *CaptureStats {
	return h.stats
}

// Close marks the handler as closed and closes the packet channel.
// Subsequent calls to Inject will be silently dropped.
func (h *InjectHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.closed {
		close(h.packetCh)
		h.closed = true
	}
	return nil
}
