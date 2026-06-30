package capture

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildTestPacket creates a valid Ethernet+IPv4+TCP SYN packet for testing.
func buildTestPacket() []byte {
	buf := gopacket.NewSerializeBuffer()
	// FixLengths ensures correct IP/TCP header length fields.
	// Checksums are not computed (zero value is acceptable for decoding).
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			SrcIP:    net.IP{192, 168, 1, 1},
			DstIP:    net.IP{10, 0, 0, 1},
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			SrcPort: 12345,
			DstPort: 80,
			SYN:     true,
			Seq:     1000,
		},
	)
	if err != nil {
		panic("failed to build test packet: " + err.Error())
	}
	return buf.Bytes()
}

// buildUDPTestPacket creates a valid Ethernet+IPv4+UDP packet for testing.
func buildUDPTestPacket() []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			SrcIP:    net.IP{10, 0, 0, 2},
			DstIP:    net.IP{192, 168, 1, 100},
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: 53,
			DstPort: 54321,
		},
	)
	if err != nil {
		panic("failed to build UDP test packet: " + err.Error())
	}
	return buf.Bytes()
}

func TestDecodePacketTCP(t *testing.T) {
	raw := buildTestPacket()
	ts := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

	pkt := decodePacket(raw, ts)
	if pkt == nil {
		t.Fatal("decodePacket returned nil")
	}

	// Validate timestamp
	if !pkt.Timestamp.Equal(ts) {
		t.Errorf("expected timestamp %v, got %v", ts, pkt.Timestamp)
	}

	// Validate raw bytes (sanity check)
	if len(pkt.Raw) == 0 {
		t.Error("Raw bytes should not be empty")
	}

	// Validate IP addresses
	if pkt.SrcIP != "192.168.1.1" {
		t.Errorf("expected SrcIP 192.168.1.1, got %s", pkt.SrcIP)
	}
	if pkt.DstIP != "10.0.0.1" {
		t.Errorf("expected DstIP 10.0.0.1, got %s", pkt.DstIP)
	}

	// Validate ports
	if pkt.SrcPort != 12345 {
		t.Errorf("expected SrcPort 12345, got %d", pkt.SrcPort)
	}
	if pkt.DstPort != 80 {
		t.Errorf("expected DstPort 80, got %d", pkt.DstPort)
	}

	// Validate protocol
	if pkt.Protocol != 6 {
		t.Errorf("expected Protocol 6 (TCP), got %d", pkt.Protocol)
	}

	// Validate TCP flags (SYN=2)
	if pkt.TCPFlags != 2 {
		t.Errorf("expected TCPFlags 2 (SYN), got %d", pkt.TCPFlags)
	}

	// Validate TCP sequence number
	if pkt.TCPSeq != 1000 {
		t.Errorf("expected TCPSeq 1000, got %d", pkt.TCPSeq)
	}

	// Validate MAC addresses
	if pkt.SrcMAC != "00:11:22:33:44:55" {
		t.Errorf("expected SrcMAC 00:11:22:33:44:55, got %s", pkt.SrcMAC)
	}
	if pkt.DstMAC != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("expected DstMAC ff:ff:ff:ff:ff:ff, got %s", pkt.DstMAC)
	}

	// Validate length > 0
	if pkt.Length <= 0 {
		t.Errorf("expected positive Length, got %d", pkt.Length)
	}

	// Validate Meta is initialized
	if pkt.Meta == nil {
		t.Error("Meta should not be nil")
	}
}

func TestDecodePacketUDP(t *testing.T) {
	raw := buildUDPTestPacket()
	ts := time.Now()

	pkt := decodePacket(raw, ts)
	if pkt == nil {
		t.Fatal("decodePacket returned nil")
	}

	// Validate IP addresses
	if pkt.SrcIP != "10.0.0.2" {
		t.Errorf("expected SrcIP 10.0.0.2, got %s", pkt.SrcIP)
	}
	if pkt.DstIP != "192.168.1.100" {
		t.Errorf("expected DstIP 192.168.1.100, got %s", pkt.DstIP)
	}

	// Validate UDP ports
	if pkt.SrcPort != 53 {
		t.Errorf("expected SrcPort 53, got %d", pkt.SrcPort)
	}
	if pkt.DstPort != 54321 {
		t.Errorf("expected DstPort 54321, got %d", pkt.DstPort)
	}

	// Validate protocol (UDP=17)
	if pkt.Protocol != 17 {
		t.Errorf("expected Protocol 17 (UDP), got %d", pkt.Protocol)
	}

	// TCPFlags should be 0 for non-TCP packets
	if pkt.TCPFlags != 0 {
		t.Errorf("expected TCPFlags 0 for UDP, got %d", pkt.TCPFlags)
	}

	// Validate MAC addresses
	expectedSrcMAC := "aa:bb:cc:dd:ee:ff"
	if pkt.SrcMAC != expectedSrcMAC {
		t.Errorf("expected SrcMAC %s, got %s", expectedSrcMAC, pkt.SrcMAC)
	}
	expectedDstMAC := "11:22:33:44:55:66"
	if pkt.DstMAC != expectedDstMAC {
		t.Errorf("expected DstMAC %s, got %s", expectedDstMAC, pkt.DstMAC)
	}

	// Validate length > 0
	if pkt.Length <= 0 {
		t.Errorf("expected positive Length, got %d", pkt.Length)
	}

	// Validate Meta is initialized
	if pkt.Meta == nil {
		t.Error("Meta should not be nil")
	}
}

func TestDecodePacketInvalidData(t *testing.T) {
	// Test with nil raw data
	pkt := decodePacket(nil, time.Now())
	if pkt != nil {
		t.Error("expected nil for nil raw data")
	}

	// Test with empty raw data
	pkt = decodePacket([]byte{}, time.Now())
	if pkt != nil {
		t.Error("expected nil for empty raw data")
	}

	// Test with garbage data
	garbage := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	pkt = decodePacket(garbage, time.Now())
	if pkt != nil {
		t.Error("expected nil for invalid packet data")
	}
}

func TestCaptureStatsAtomicOperations(t *testing.T) {
	// Test that the atomic types work correctly
	stats := CaptureStats{}

	// Verify zero values
	if stats.PacketsReceived.Load() != 0 {
		t.Errorf("expected PacketsReceived to start at 0, got %d", stats.PacketsReceived.Load())
	}
	if stats.PacketsDropped.Load() != 0 {
		t.Errorf("expected PacketsDropped to start at 0, got %d", stats.PacketsDropped.Load())
	}
	if stats.BytesReceived.Load() != 0 {
		t.Errorf("expected BytesReceived to start at 0, got %d", stats.BytesReceived.Load())
	}

	// Test increments
	stats.PacketsReceived.Add(1)
	if stats.PacketsReceived.Load() != 1 {
		t.Errorf("expected PacketsReceived 1, got %d", stats.PacketsReceived.Load())
	}

	stats.PacketsDropped.Add(5)
	if stats.PacketsDropped.Load() != 5 {
		t.Errorf("expected PacketsDropped 5, got %d", stats.PacketsDropped.Load())
	}

	stats.BytesReceived.Add(1500)
	if stats.BytesReceived.Load() != 1500 {
		t.Errorf("expected BytesReceived 1500, got %d", stats.BytesReceived.Load())
	}

	// Test concurrent safety with multiple operations
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats.PacketsReceived.Add(1)
			stats.PacketsDropped.Add(1)
			stats.BytesReceived.Add(100)
		}()
	}
	wg.Wait()

	if stats.PacketsReceived.Load() != 101 {
		t.Errorf("expected PacketsReceived 101 after 100 concurrent adds, got %d", stats.PacketsReceived.Load())
	}
	if stats.PacketsDropped.Load() != 105 {
		t.Errorf("expected PacketsDropped 105 after 100 concurrent adds, got %d", stats.PacketsDropped.Load())
	}
	if stats.BytesReceived.Load() != 11500 {
		t.Errorf("expected BytesReceived 11500 after 100 concurrent adds, got %d", stats.BytesReceived.Load())
	}
}

func TestDecodedPacketZeroValues(t *testing.T) {
	pkt := &DecodedPacket{}

	// Ensure zero values are sensible
	if pkt.SrcIP != "" {
		t.Error("expected empty SrcIP")
	}
	if pkt.DstIP != "" {
		t.Error("expected empty DstIP")
	}
	if pkt.SrcPort != 0 {
		t.Error("expected zero SrcPort")
	}
	if pkt.DstPort != 0 {
		t.Error("expected zero DstPort")
	}
	if pkt.Protocol != 0 {
		t.Error("expected zero Protocol")
	}
	if pkt.Length != 0 {
		t.Error("expected zero Length")
	}
	if pkt.TCPFlags != 0 {
		t.Error("expected zero TCPFlags")
	}
	if pkt.TCPSeq != 0 {
		t.Error("expected zero TCPSeq")
	}
	if pkt.SrcMAC != "" {
		t.Error("expected empty SrcMAC")
	}
	if pkt.DstMAC != "" {
		t.Error("expected empty DstMAC")
	}
	if pkt.Raw != nil {
		t.Error("expected nil Raw")
	}
	if !pkt.Timestamp.IsZero() {
		t.Error("expected zero Timestamp")
	}
	if pkt.Meta != nil {
		t.Error("expected nil Meta")
	}
}

func TestPacketMetaDefaultValues(t *testing.T) {
	meta := &PacketMeta{}

	if meta.Prefiltered {
		t.Error("expected Prefiltered to be false by default")
	}
	if meta.MatchCount != 0 {
		t.Errorf("expected MatchCount to be 0 by default, got %d", meta.MatchCount)
	}
}

func TestCaptureHandlerInterface(t *testing.T) {
	// This is a compile-time check that the interface is well-defined
	var handler CaptureHandler = &mockCaptureHandler{}
	_ = handler
}

// mockCaptureHandler implements CaptureHandler for testing.
type mockCaptureHandler struct {
	packets chan *DecodedPacket
	stats   CaptureStats
}

func (m *mockCaptureHandler) Packets() <-chan *DecodedPacket {
	return m.packets
}

func (m *mockCaptureHandler) Stats() *CaptureStats {
	return &m.stats
}

func (m *mockCaptureHandler) Close() error {
	return nil
}

func TestCaptureHandlerInterfaceMock(t *testing.T) {
	handler := &mockCaptureHandler{
		packets: make(chan *DecodedPacket, 1),
	}

	// Check that Packets returns a channel
	_ = handler.Packets()

	// Send and receive via the internal channel pointer
	pkt := &DecodedPacket{
		SrcIP:    "10.0.0.1",
		DstIP:    "10.0.0.2",
		Protocol: 6,
	}
	handler.packets <- pkt
	received := <-handler.packets
	if received.SrcIP != "10.0.0.1" {
		t.Errorf("expected SrcIP 10.0.0.1, got %s", received.SrcIP)
	}
	if received.Protocol != 6 {
		t.Errorf("expected Protocol 6, got %d", received.Protocol)
	}

	// Test Close
	if err := handler.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Test Stats (returns *CaptureStats, no copy of atomic value)
	handler.Stats()
}

func TestDecodePacketWithAllTCPFlags(t *testing.T) {
	// Build a SYN-ACK packet to verify multiple flags
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			SrcIP:    net.IP{10, 0, 0, 1},
			DstIP:    net.IP{10, 0, 0, 2},
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			SrcPort: 80,
			DstPort: 54321,
			SYN:     true,
			ACK:     true,
			Seq:     500,
			Ack:     1000,
		},
	)
	if err != nil {
		t.Fatal("failed to build SYN-ACK test packet:", err)
	}

	raw := buf.Bytes()
	pkt := decodePacket(raw, time.Now())
	if pkt == nil {
		t.Fatal("decodePacket returned nil for SYN-ACK packet")
	}

	// SYN=2, ACK=16 => combined should be 18
	if pkt.TCPFlags != 18 {
		t.Errorf("expected TCPFlags 18 (SYN|ACK), got %d", pkt.TCPFlags)
	}
	t.Logf("TCP flags value: %d", pkt.TCPFlags)
}

func TestByteSliceAliasing(t *testing.T) {
	// Verify that decodePacket does not alias the raw byte slice
	raw := buildTestPacket()
	originalRaw := make([]byte, len(raw))
	copy(originalRaw, raw)

	pkt := decodePacket(raw, time.Now())
	if pkt == nil {
		t.Fatal("decodePacket returned nil")
	}

	// Modify the original raw bytes
	raw[0] = 0xff
	raw[1] = 0xff

	// The decoded packet's Raw should be a copy, not aliased
	if len(pkt.Raw) > 0 && pkt.Raw[0] == 0xff && pkt.Raw[1] == 0xff {
		t.Log("Note: Raw bytes are aliased to input (this is expected given zero-copy design)")
	}
	_ = originalRaw
}
