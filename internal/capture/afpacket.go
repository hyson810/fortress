//go:build linux

package capture

import (
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// AFPacketConfig configures the AF_PACKET capture handler.
type AFPacketConfig struct {
	Interface    string
	BufferFrames int
	BufferSize   int
	Promisc      bool
	Fanout       bool
	Snaplen      int // max packet size to capture
}

// AFPacketHandler implements CaptureHandler using AF_PACKET raw sockets.
type AFPacketHandler struct {
	cfg      AFPacketConfig
	packetCh chan *DecodedPacket
	sock     int
	stopCh   chan struct{}
	wg       sync.WaitGroup
	stats    *CaptureStats
	ifIndex  int
	closed   bool
	mu       sync.Mutex
}

// NewAFPacketHandler creates a new AF_PACKET capture handler bound to the
// specified interface. Requires CAP_NET_RAW or root.
func NewAFPacketHandler(cfg AFPacketConfig) (*AFPacketHandler, error) {
	// Set defaults
	if cfg.Snaplen <= 0 {
		cfg.Snaplen = 65536
	}

	// Look up interface
	ifi, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("afpacket: interface lookup: %w", err)
	}

	// Create AF_PACKET socket
	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("afpacket: socket: %w", err)
	}

	// Bind to interface
	ll := &unix.SockaddrLinklayer{
		Ifindex:  ifi.Index,
		Protocol: htons(unix.ETH_P_ALL),
	}
	if err := unix.Bind(sock, ll); err != nil {
		unix.Close(sock)
		return nil, fmt.Errorf("afpacket: bind: %w", err)
	}

	h := &AFPacketHandler{
		cfg:      cfg,
		packetCh: make(chan *DecodedPacket, 1000),
		sock:     sock,
		stopCh:   make(chan struct{}),
		stats:    &CaptureStats{},
		ifIndex:  ifi.Index,
	}

	// Set promiscuous mode
	if cfg.Promisc {
		if err := setPromisc(sock, ifi.Index); err != nil {
			unix.Close(sock)
			return nil, fmt.Errorf("afpacket: promisc: %w", err)
		}
	}

	// Set fanout
	if cfg.Fanout {
		if err := setFanout(sock); err != nil {
			unix.Close(sock)
			return nil, fmt.Errorf("afpacket: fanout: %w", err)
		}
	}

	// Set receive timeout so the capture loop can check stopCh periodically
	tv := unix.Timeval{Sec: 1, Usec: 0}
	if err := unix.SetsockoptTimeval(sock, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(sock)
		return nil, fmt.Errorf("afpacket: set rcvtimeo: %w", err)
	}

	// Start capture loop
	h.wg.Add(1)
	go h.captureLoop()

	return h, nil
}

func (h *AFPacketHandler) captureLoop() {
	defer h.wg.Done()

	buf := make([]byte, h.cfg.Snaplen)

	for {
		// Check if we should stop
		select {
		case <-h.stopCh:
			return
		default:
		}

		n, _, err := unix.Recvfrom(h.sock, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			// Unexpected error — socket may be closed, exit loop
			return
		}

		if n == 0 {
			continue
		}

		// Copy raw bytes so the buffer can be reused
		raw := make([]byte, n)
		copy(raw, buf[:n])

		pkt := decodePacket(raw, time.Now())
		if pkt == nil {
			continue
		}

		select {
		case h.packetCh <- pkt:
			h.stats.PacketsReceived.Add(1)
			h.stats.BytesReceived.Add(uint64(n))
		default:
			h.stats.PacketsDropped.Add(1)
		}
	}
}

// Packets returns a read-only channel of decoded packets.
func (h *AFPacketHandler) Packets() <-chan *DecodedPacket {
	return h.packetCh
}

// Stats returns the capture statistics counters.
func (h *AFPacketHandler) Stats() *CaptureStats {
	return h.stats
}

// Close stops the capture loop and releases the socket.
func (h *AFPacketHandler) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.mu.Unlock()

	close(h.stopCh)
	h.wg.Wait()

	unix.Close(h.sock)
	return nil
}
