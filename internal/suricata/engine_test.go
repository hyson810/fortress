package suricata

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fortress/v6/internal/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildTestPacket constructs a valid ethernet+IPv4+TCP+payload packet for testing.
func buildTestPacket(payload []byte, srcPort, dstPort uint16, tcpFlags uint8) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    net.ParseIP("10.0.0.1"),
		DstIP:    net.ParseIP("192.168.1.1"),
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1000,
		SYN:     tcpFlags&0x02 != 0,
		ACK:     tcpFlags&0x10 != 0,
		FIN:     tcpFlags&0x01 != 0,
		RST:     tcpFlags&0x04 != 0,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// setupTestRule writes a known rule file into a temp directory.
func setupTestRule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rule := `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SQL Injection"; content:"union|20|select"; nocase; classtype:web-application-attack; sid:1000001; rev:1;)`
	if err := os.WriteFile(filepath.Join(dir, "test.rules"), []byte(rule), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func setupTestRuleWithFlags(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rule := `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SYN Flood"; flags:S; content:"synscan"; sid:1000002; rev:1;)`
	if err := os.WriteFile(filepath.Join(dir, "test.rules"), []byte(rule), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func setupTestRuleWithDsize(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rule := `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Large Payload"; content:"data"; dsize:100<>1000; sid:1000003; rev:1;)`
	if err := os.WriteFile(filepath.Join(dir, "test.rules"), []byte(rule), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEngine_NewAndStats(t *testing.T) {
	dir := setupTestRule(t)
	engine, err := NewEngine(dir, 1)
	if err != nil {
		t.Fatal(err)
	}

	if engine.RuleCount() != 1 {
		t.Fatalf("expected 1 rule, got %d", engine.RuleCount())
	}

	stats := engine.Stats()
	if stats.PacketsProcessed != 0 {
		t.Errorf("expected PacketsProcessed=0, got %d", stats.PacketsProcessed)
	}
	if stats.PacketsFiltered != 0 {
		t.Errorf("expected PacketsFiltered=0, got %d", stats.PacketsFiltered)
	}
	if stats.RulesMatched != 0 {
		t.Errorf("expected RulesMatched=0, got %d", stats.RulesMatched)
	}
}

func TestEngine_ProcessPacket(t *testing.T) {
	dir := setupTestRule(t)
	engine, err := NewEngine(dir, 2)
	if err != nil {
		t.Fatal(err)
	}

	handler := capture.NewInjectHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx, handler)

	// Build a TCP SYN packet to port 80 with "union select" (matching pattern)
	// The pattern "union|20|select" becomes "union select" in hex: "union" + 0x20 + "select"
	packet := buildTestPacket([]byte("GET /union select HTTP/1.1"), 34567, 80, 0x02)
	handler.Inject(packet)

	// Wait for alert with timeout
	select {
	case alert := <-engine.Alerts():
		if alert.SID != 1000001 {
			t.Errorf("expected SID 1000001, got %d", alert.SID)
		}
		if alert.Msg != "SQL Injection" {
			t.Errorf("expected msg 'SQL Injection', got %q", alert.Msg)
		}
		if alert.Classtype != "web-application-attack" {
			t.Errorf("expected classtype 'web-application-attack', got %q", alert.Classtype)
		}
		if alert.SrcIP != "10.0.0.1" {
			t.Errorf("expected SrcIP 10.0.0.1, got %q", alert.SrcIP)
		}
		if alert.DstIP != "192.168.1.1" {
			t.Errorf("expected DstIP 192.168.1.1, got %q", alert.DstIP)
		}
		if alert.SrcPort != 34567 {
			t.Errorf("expected SrcPort 34567, got %d", alert.SrcPort)
		}
		if alert.DstPort != 80 {
			t.Errorf("expected DstPort 80, got %d", alert.DstPort)
		}
		if alert.Protocol != 6 {
			t.Errorf("expected Protocol 6 (TCP), got %d", alert.Protocol)
		}
		if alert.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
	case <-time.After(3 * time.Second):
		// Check stats to help debug
		stats := engine.Stats()
		t.Fatalf("timeout waiting for alert (processed=%d, filtered=%d, matched=%d)",
			stats.PacketsProcessed, stats.PacketsFiltered, stats.RulesMatched)
	}
}

func TestEngine_NonMatchingPacket(t *testing.T) {
	dir := setupTestRule(t)
	engine, err := NewEngine(dir, 2)
	if err != nil {
		t.Fatal(err)
	}

	handler := capture.NewInjectHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx, handler)

	// Build a packet to a non-matching port (not 80) with unrelated content
	packet := buildTestPacket([]byte("GET /index.html HTTP/1.1"), 34567, 8080, 0x02)
	handler.Inject(packet)

	// Small sleep to let pipeline process
	time.Sleep(200 * time.Millisecond)

	// No alert should be produced
	select {
	case <-engine.Alerts():
		t.Fatal("unexpected alert for non-matching packet")
	default:
		// Expected — no alert
	}

	// Verify stats: packet was processed and filtered
	stats := engine.Stats()
	if stats.PacketsProcessed != 1 {
		t.Errorf("expected 1 packet processed, got %d", stats.PacketsProcessed)
	}
}

func TestEngine_FlagsMatching(t *testing.T) {
	dir := setupTestRuleWithFlags(t)
	engine, err := NewEngine(dir, 2)
	if err != nil {
		t.Fatal(err)
	}

	handler := capture.NewInjectHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx, handler)

	// SYN packet with matching content "synscan" to port 80.
	// The rule has flags:S, so the SYN flag must be set (0x02).
	packet := buildTestPacket([]byte("synscan payload data"), 34567, 80, 0x02) // SYN
	handler.Inject(packet)

	select {
	case alert := <-engine.Alerts():
		if alert.SID != 1000002 {
			t.Errorf("expected SID 1000002, got %d", alert.SID)
		}
	case <-time.After(3 * time.Second):
		stats := engine.Stats()
		t.Fatalf("timeout waiting for flags-matching alert (processed=%d, filtered=%d, matched=%d)",
			stats.PacketsProcessed, stats.PacketsFiltered, stats.RulesMatched)
	}
}

func TestEngine_FlagsMismatch(t *testing.T) {
	dir := setupTestRuleWithFlags(t)
	engine, err := NewEngine(dir, 2)
	if err != nil {
		t.Fatal(err)
	}

	handler := capture.NewInjectHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx, handler)

	// ACK-only packet (no SYN) with matching content — rule has flags:S, so this should NOT match
	packet := buildTestPacket([]byte("synscan payload data"), 34567, 80, 0x10) // ACK only
	handler.Inject(packet)

	time.Sleep(200 * time.Millisecond)

	select {
	case <-engine.Alerts():
		t.Fatal("unexpected alert: flags:S should not match ACK-only packet")
	default:
		// Expected
	}
}

func TestEngine_DsizeMatching(t *testing.T) {
	dir := setupTestRuleWithDsize(t)
	engine, err := NewEngine(dir, 2)
	if err != nil {
		t.Fatal(err)
	}

	handler := capture.NewInjectHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx, handler)

	// Payload of 200 bytes (within dsize:100<>1000 range)
	largePayload := make([]byte, 200)
	copy(largePayload, []byte("data"))
	packet := buildTestPacket(largePayload, 34567, 80, 0x02)
	handler.Inject(packet)

	select {
	case alert := <-engine.Alerts():
		if alert.SID != 1000003 {
			t.Errorf("expected SID 1000003, got %d", alert.SID)
		}
	case <-time.After(3 * time.Second):
		stats := engine.Stats()
		t.Fatalf("timeout waiting for dsize-matching alert (processed=%d, filtered=%d, matched=%d)",
			stats.PacketsProcessed, stats.PacketsFiltered, stats.RulesMatched)
	}
}

func TestEngine_DsizeMismatch(t *testing.T) {
	dir := setupTestRuleWithDsize(t)
	engine, err := NewEngine(dir, 2)
	if err != nil {
		t.Fatal(err)
	}

	handler := capture.NewInjectHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx, handler)

	// Payload of 50 bytes (below dsize:100<>1000 range)
	smallPayload := make([]byte, 50)
	copy(smallPayload, []byte("data"))
	packet := buildTestPacket(smallPayload, 34567, 80, 0x02)
	handler.Inject(packet)

	time.Sleep(200 * time.Millisecond)

	select {
	case <-engine.Alerts():
		t.Fatal("unexpected alert: payload size below dsize range should not match")
	default:
		// Expected
	}
}

func TestEngine_RuleCount(t *testing.T) {
	dir := setupTestRule(t)
	engine, err := NewEngine(dir, 1)
	if err != nil {
		t.Fatal(err)
	}

	if count := engine.RuleCount(); count != 1 {
		t.Fatalf("expected 1 rule, got %d", count)
	}
}

func TestEngine_DefaultWorkers(t *testing.T) {
	dir := setupTestRule(t)
	engine, err := NewEngine(dir, 0) // 0 should default to NumCPU
	if err != nil {
		t.Fatal(err)
	}

	if engine.workers <= 0 {
		t.Errorf("expected positive worker count, got %d", engine.workers)
	}
}

func TestEngine_ContextCancel(t *testing.T) {
	dir := setupTestRule(t)
	engine, err := NewEngine(dir, 2)
	if err != nil {
		t.Fatal(err)
	}

	handler := capture.NewInjectHandler()
	ctx, cancel := context.WithCancel(context.Background())

	engine.Start(ctx, handler)

	// Cancel context and wait for shutdown
	cancel()

	done := make(chan struct{})
	go func() {
		engine.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines exited cleanly
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for engine shutdown after context cancel")
	}
}

func TestEngine_HandlerClose(t *testing.T) {
	dir := setupTestRule(t)
	engine, err := NewEngine(dir, 2)
	if err != nil {
		t.Fatal(err)
	}

	handler := capture.NewInjectHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx, handler)

	// Close the handler which closes the packet channel
	handler.Close()

	done := make(chan struct{})
	go func() {
		engine.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines exited cleanly
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for engine shutdown after handler close")
	}
}
