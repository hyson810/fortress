//go:build linux

package capture

import (
	"testing"
	"time"
)

// TestCaptureToSuricataPipeline verifies that packets flow correctly through the
// capture layer. The InjectHandler simulates packet injection as the first stage
// of the capture-to-suricata pipeline.
func TestCaptureToSuricataPipeline(t *testing.T) {
	h := NewInjectHandler()
	defer h.Close()

	// Inject a TCP SYN packet.
	rawTCP := buildTestPacket()
	h.Inject(rawTCP)

	// Inject a UDP packet.
	rawUDP := buildUDPTestPacket()
	h.Inject(rawUDP)

	// Receive both packets from the channel and validate.
	pkt1, ok1 := <-h.Packets()
	if !ok1 {
		t.Fatal("channel closed before receiving first packet")
	}
	if pkt1 == nil {
		t.Fatal("received nil TCP packet")
	}
	if pkt1.Protocol != 6 {
		t.Errorf("expected Protocol 6 (TCP), got %d", pkt1.Protocol)
	}
	if pkt1.DstPort != 80 {
		t.Errorf("expected DstPort 80, got %d", pkt1.DstPort)
	}
	if pkt1.TCPFlags != 2 {
		t.Errorf("expected TCPFlags 2 (SYN), got %d", pkt1.TCPFlags)
	}
	if pkt1.Meta == nil {
		t.Error("Meta should not be nil for TCP packet")
	}

	pkt2, ok2 := <-h.Packets()
	if !ok2 {
		t.Fatal("channel closed before receiving second packet")
	}
	if pkt2 == nil {
		t.Fatal("received nil UDP packet")
	}
	if pkt2.Protocol != 17 {
		t.Errorf("expected Protocol 17 (UDP), got %d", pkt2.Protocol)
	}
	if pkt2.SrcPort != 53 {
		t.Errorf("expected SrcPort 53, got %d", pkt2.SrcPort)
	}
	if pkt2.Meta == nil {
		t.Error("Meta should not be nil for UDP packet")
	}

	// Verify stats after pipeline processing.
	stats := h.Stats()
	if stats.PacketsReceived.Load() != 2 {
		t.Errorf("expected 2 packets received, got %d", stats.PacketsReceived.Load())
	}
	if stats.BytesReceived.Load() != uint64(len(rawTCP)+len(rawUDP)) {
		t.Errorf("expected %d bytes received, got %d", len(rawTCP)+len(rawUDP), stats.BytesReceived.Load())
	}
	if stats.PacketsDropped.Load() != 0 {
		t.Errorf("expected 0 packets dropped, got %d", stats.PacketsDropped.Load())
	}
}

// TestCaptureToSuricataPipeline_MultiplePackets stresses the capture layer
// with a burst of packets, verifying ordering and that no packets are lost
// (when channel capacity is not exceeded).
func TestCaptureToSuricataPipeline_MultiplePackets(t *testing.T) {
	h := NewInjectHandler()
	defer h.Close()

	const count = 50
	pkts := make([][]byte, count)
	for i := 0; i < count; i++ {
		if i%2 == 0 {
			pkts[i] = buildTestPacket()
		} else {
			pkts[i] = buildUDPTestPacket()
		}
		h.Inject(pkts[i])
	}

	for i := 0; i < count; i++ {
		select {
		case pkt := <-h.Packets():
			if pkt == nil {
				t.Fatalf("received nil packet at index %d", i)
			}
			if i%2 == 0 && pkt.Protocol != 6 {
				t.Errorf("at index %d: expected TCP (6), got %d", i, pkt.Protocol)
			}
			if i%2 != 0 && pkt.Protocol != 17 {
				t.Errorf("at index %d: expected UDP (17), got %d", i, pkt.Protocol)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for packet at index %d", i)
		}
	}

	// Verify all packets accounted for.
	stats := h.Stats()
	if stats.PacketsReceived.Load() != uint64(count) {
		t.Errorf("expected %d packets received, got %d", count, stats.PacketsReceived.Load())
	}
}

// TestCaptureToSuricataPipeline_Close verifies that closing the handler
// terminates the packet channel, which is how the engine detects shutdown.
func TestCaptureToSuricataPipeline_Close(t *testing.T) {
	h := NewInjectHandler()

	raw := buildTestPacket()
	h.Inject(raw)

	// Read the packet, then close.
	<-h.Packets()
	h.Close()

	// After close, the channel should be drained and closed.
	// A subsequent range over the channel should exit immediately.
	remaining := 0
	for range h.Packets() {
		remaining++
	}
	if remaining != 0 {
		t.Errorf("expected 0 packets after close, got %d", remaining)
	}

	// Inject after close should be silently dropped.
	h.Inject(raw)

	// Channel is closed, so ranging again yields nothing.
	for range h.Packets() {
		remaining++
	}
	if remaining != 0 {
		t.Errorf("expected 0 packets after close, got %d", remaining)
	}
}
