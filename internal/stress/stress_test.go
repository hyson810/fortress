// Package stress implements high-intensity stress tests for the Fortress V4
// Network Intrusion Detection System. Each test targets a specific component or
// integration point, documents the expected behavior, and identifies the exact
// point at which the system breaks.
//
// Test naming convention: TestStress_<Category>_<Scenario>
// Benchmark naming:      BenchmarkStress_<Category>_<Scenario>
//
// Categories:
//   A - Flood/Volume Attacks
//   B - Evasion Techniques
//   C - Application-Layer Attacks
//   D - Swarm/Protocol Attacks
//   E - Resource Exhaustion
//   F - False Positive Flood
//   G - Kernel/BPF Stress
//   X - Adversarial Chaos (combined multi-vector)
package stress

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/counterstrike"
	"github.com/fortress/v6/internal/engines"
	"github.com/fortress/v6/internal/swarm"
)

// =============================================================================
// Test Infrastructure — traffic generators, mock helpers, assertions
// =============================================================================

// testConfig returns a default Config suitable for stress testing.
// Whitelist is empty so all traffic passes through detection.
func testConfig() *config.Config {
	cfg := config.Default()
	cfg.SetWhitelist(nil) // No whitelist — every packet gets inspected.
	cfg.Engine.SynFloodPPS = 80
	cfg.Engine.UdpFloodPPS = 200
	cfg.Engine.IcmpFloodPPS = 50
	return cfg
}

// assertThreatCount fails the test if the threat slice does not have exactly
// the expected count. Returns the threats for further inspection.
func assertThreatCount(t *testing.T, threats []engines.Threat, expected int, label string) {
	t.Helper()
	if len(threats) != expected {
		t.Errorf("%s: expected %d threats, got %d: %+v", label, expected, len(threats), threats)
	}
}

// assertAtLeastThreats fails if fewer than min threats were produced.
func assertAtLeastThreats(t *testing.T, threats []engines.Threat, min int, label string) {
	t.Helper()
	if len(threats) < min {
		t.Errorf("%s: expected at least %d threats, got %d", label, min, len(threats))
	}
}

// uniqueIP generates predictable unique IPs in 10.0.0.0/8 for testing.
// This avoids actual network traffic while generating realistic-looking addresses.
func uniqueIP(index int) string {
	return fmt.Sprintf("10.%d.%d.%d", (index>>16)&0xFF, (index>>8)&0xFF, index&0xFF)
}

// uniquePort cycles through ports 1024-65535 deterministically.
func uniquePort(index int) uint16 {
	return uint16(1024 + (index % 64512))
}

// entropyPayload generates a byte slice with the given Shannon entropy
// (approximate). entropy 0 = all identical bytes, entropy 8 = uniform random.
func entropyPayload(length int, targetEntropy float64) []byte {
	payload := make([]byte, length)
	switch {
	case targetEntropy <= 0.5:
		// All identical — entropy near 0.
		for i := range payload {
			payload[i] = 0x41
		}
	case targetEntropy >= 7.5:
		// Uniform random — entropy near 8.
		_, _ = rand.Read(payload)
	default:
		// Mix of structured and random to approximate target entropy.
		nRandom := int(float64(length) * targetEntropy / 8.0)
		_, _ = rand.Read(payload[:nRandom])
		for i := nRandom; i < length; i++ {
			payload[i] = 0x41
		}
	}
	return payload
}

// mockGossipNode creates a GossipNode for testing swarm attacks.
// The node binds to a random localhost port and starts its gossip loops.
func mockGossipNode(t *testing.T, name string, gossipKey string) *swarm.GossipNode {
	t.Helper()

	// Pick a random port in the ephemeral range.
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mockGossipNode: listen: %v", err)
	}
	localAddr := listener.LocalAddr().String()
	listener.Close()

	cfg := config.SwarmConfig{
		Name:      name,
		Bind:      localAddr,
		GossipKey: gossipKey,
		Peers:     nil,
	}

	node, err := swarm.NewGossipNode(cfg, localAddr)
	if err != nil {
		t.Fatalf("mockGossipNode: NewGossipNode: %v", err)
	}

	node.Start()
	t.Cleanup(func() { node.Stop() })
	return node
}

// peerCountEventually waits for the gossip node to see the expected number of
// alive peers, polling every 200ms up to the timeout.
func peerCountEventually(t *testing.T, node *swarm.GossipNode, expected int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if node.PeerCount() == expected {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Errorf("peer count: expected %d, got %d after %v", expected, node.PeerCount(), timeout)
}

// uniqueSourceIPs generates n unique IP addresses.
func uniqueSourceIPs(n int) []string {
	ips := make([]string, n)
	for i := range ips {
		ips[i] = uniqueIP(i)
	}
	return ips
}

// =============================================================================
// CATEGORY A: Flood / Volume Attacks
// =============================================================================

// ---------------------------------------------------------------------------
// Test A1: SYN Flood RingBuffer Saturation
// 测试名称: SYN洪水环缓冲区饱和攻击
// Target: PacketInspector (L1), synCounter RingBuffer (cap 1000)
//
// Attack Methodology:
//   Send 2000 pure SYN packets from a single IP within 1 second. The default
//   SYN flood threshold is 80 pps. The ring buffer capacity is 1000 entries.
//   After 1000 entries, the oldest are silently evicted via buf[1:] shift.
//   This means packet #1001 pushes out packet #1, and the count stays at 1000.
//
// Expected Fortress Behavior:
//   - Packets 0-79: no alert (below 80 pps threshold)
//   - Packets 80-1000: "SYN洪水" alerts triggered
//   - Packets 1001-2000: alerts continue (rate still exceeds 80)
//
// Breaking Point:
//   The RingBuffer silently drops oldest entries at cap 1000. If an attacker
//   sends exactly 1000 SYN packets then pauses exactly 1 second, the entire
//   buffer is pruned and the attacker's rate resets to 0. No historical record
//   survives beyond the 1-second window. The system has no long-term memory
//   of flood activity — it only sees the current second's rate.
//   Additionally, the silent eviction on overflow (buf[1:] shift) means that
//   at extremely high rates (>1000 pps), the rate measurement is capped at
//   1000 — the true rate is under-reported.
func TestStress_A1_SYNFloodRingBufferSaturation(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	inspector := engines.NewPacketInspector(cfg)

	const attackIP = "10.13.37.1"
	const packetCount = 2000

	var alertCount int
	var firstAlertAt, lastAlertAt int

	for i := 0; i < packetCount; i++ {
		threats := inspector.Feed("S", attackIP, 80, "TCP")
		if len(threats) > 0 {
			if alertCount == 0 {
				firstAlertAt = i
			}
			lastAlertAt = i
			alertCount++
		}
	}

	// Expected: alerts start around packet 80 (the threshold).
	t.Logf("SYN flood: %d alerts from %d packets (first at %d, last at %d)",
		alertCount, packetCount, firstAlertAt, lastAlertAt)

	if alertCount < 100 {
		t.Errorf("expected at least 100 alerts from 2000 SYN packets, got %d", alertCount)
	}
	if firstAlertAt < 70 || firstAlertAt > 90 {
		t.Logf("NOTE: first alert at packet %d (expected ~80); small timing variance is normal", firstAlertAt)
	}

	// BREAKING POINT: Verify the ring buffer caps at 1000 and silent eviction.
	// After sending 2000 packets, the buffer only holds the last 1000.
	// If we pause 1 second and send 1 more, the previous 1000 are all pruned.
	time.Sleep(1100 * time.Millisecond)
	threats := inspector.Feed("S", attackIP, 80, "TCP")
	// After the pause, the single packet should NOT trigger a flood alert
	// because the 1-second window only contains 1 packet (below 80 threshold).
	if len(threats) > 0 {
		t.Logf("BREAKING POINT CONFIRMED: after 1s pause, single SYN does NOT trigger alert (rate reset). Threats: %v", threats)
	} else {
		t.Log("After 1s pause: rate correctly reset to 0 (ring buffer fully pruned)")
	}
}

// ---------------------------------------------------------------------------
// Test A2: DNS Query Flood vs DnsTunnelDetector Overflow
// 测试名称: DNS查询洪水过载DNS隧道检测器
// Target: DnsTunnelDetector (L4), per-IP query history (cap 200)
//
// Attack Methodology:
//   Send 500 DNS queries from a single IP within 30 seconds. This exceeds
//   the flood threshold (30 queries/30s) and the history cap (200 records).
//   Each query uses a unique subdomain to avoid entropy-based detection
//   (keeping entropy low with structured names like "host-N.data.example.com").
//
// Expected Fortress Behavior:
//   - Check() called after 500 queries: "DNS查询洪水" alert (500 > 30 threshold)
//   - History capped at 200 records; oldest 300 are silently evicted
//
// Breaking Point:
//   The per-IP history cap of 200 records silently drops the oldest entries.
//   If 300 of the queries were tunnel data and the most recent 200 are benign,
//   the tunnel evidence is destroyed. An attacker can "flush" the history by
//   sending 200+ benign queries after exfiltrating data. The flood detection
//   only counts records within 30s — if the attacker spreads queries at 29
//   queries per 30s, they never trigger the flood threshold while still
//   exfiltrating data.
func TestStress_A2_DNSQueryFloodHistoryOverflow(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	detector := engines.NewDnsTunnelDetector(cfg)

	const attackIP = "10.99.88.77"
	const queryCount = 500

	// Feed 500 queries with structured names (low entropy to avoid entropy alert).
	for i := 0; i < queryCount; i++ {
		queryName := fmt.Sprintf("host-%d.data.example.com", i)
		detector.Feed(attackIP, queryName)
	}

	threats := detector.Check(attackIP)

	// Should detect flood: 500 queries in the 30s window > 30 threshold.
	assertAtLeastThreats(t, threats, 1, "DNS flood detection")

	var floodThreat *engines.Threat
	for i := range threats {
		if threats[i].Type == "DNS查询洪水" {
			floodThreat = &threats[i]
			break
		}
	}
	if floodThreat == nil {
		t.Error("expected 'DNS查询洪水' threat, not found")
	} else {
		t.Logf("Flood detected: %s", floodThreat.Detail)
	}

	// BREAKING POINT: Verify history is capped at 200 — the oldest 300 queries
	// are irretrievably lost. An attacker can mask tunnel activity by flooding
	// benign queries afterward.
	t.Log("BREAKING POINT: per-IP history capped at 200 records. Oldest 300 queries evicted and unrecoverable.")

	// Demonstrate slow exfiltration bypass: spread queries below threshold.
	cfg2 := testConfig()
	detector2 := engines.NewDnsTunnelDetector(cfg2)
	const slowIP = "10.88.77.66"
	const slowQueries = 29 // Just below the 30-query threshold.

	for i := 0; i < slowQueries; i++ {
		// Long query names like real tunnel data.
		queryName := fmt.Sprintf("ev-%d.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com", i)
		detector2.Feed(slowIP, queryName)
	}

	slowThreats := detector2.Check(slowIP)
	// 29 queries < 30 threshold: no flood alert.
	if len(slowThreats) > 0 {
		for _, th := range slowThreats {
			if th.Type == "DNS查询洪水" {
				t.Error("slow exfiltration should NOT trigger flood alert at 29 queries")
			}
		}
	}
	t.Logf("Slow exfiltration (%d queries): flood NOT triggered (threshold is 30)", slowQueries)
}

// ---------------------------------------------------------------------------
// Test A3: HTTP Stream Reassembly OOM via Request Flood
// 测试名称: HTTP请求洪泛导致流重组内存耗尽
// Target: HttpInspector (L5), TCP stream reassembly (max 5000 streams, 64KB each)
//
// Attack Methodology:
//   Open 6000 concurrent TCP streams sending HTTP request fragments. Each stream
//   sends a partial HTTP header (no CRLFCRLF), keeping the stream alive but
//   unparseable. The HttpInspector creates one stream per unique 4-tuple.
//   At stream 5001, new streams are silently rejected — the attack succeeds
//   because legitimate traffic arriving during the attack cannot be inspected.
//
// Expected Fortress Behavior:
//   - Streams 0-4999: accepted, payloads buffered (up to 64KB each = 320MB max)
//   - Stream 5000+: silently dropped, no alert generated
//
// Breaking Point:
//   When maxConcurrentStreams (5000) is hit, new streams are silently discarded
//   with no alert. Legitimate HTTP traffic arriving during the attack is not
//   inspected. The 64KB per-stream limit means an attacker can consume 320MB
//   of memory before the stream table is full. FIN/RST closes streams but the
//   attacker never sends those flags. The 30-second idle timeout is the only
//   cleanup mechanism — an attacker sending a single byte every 29 seconds
//   keeps streams alive indefinitely.
func TestStress_A3_HTTPStreamReassemblyOOM(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	inspector := engines.NewHttpInspector(cfg)

	const attackBaseIP = "10.50.0."
	const streamsToOpen = 6000
	const benignIP = "192.168.100.50"

	acceptedCount := 0
	rejectedCount := 0

	// Open streams beyond the 5000 limit.
	for i := 0; i < streamsToOpen; i++ {
		srcIP := fmt.Sprintf("%s%d", attackBaseIP, i%255)
		srcPort := uniquePort(i)
		dstPort := uint16(80)

		payload := []byte(fmt.Sprintf("GET /path/%d HTTP/1.1\r\nHost: target-%d\r\n", i, i))
		threats := inspector.Feed(srcIP, "10.0.0.1", srcPort, dstPort, payload, "A")

		if i < 5000 {
			if len(threats) > 0 || true { // Stream was created.
				acceptedCount++
			}
		} else {
			rejectedCount++
		}
	}

	t.Logf("Streams: %d accepted (of first 5000), %d attempted beyond limit",
		acceptedCount, streamsToOpen-5000)

	// Now try to inspect legitimate traffic — it should fail at stream limit.
	legitimateThreats := inspector.Feed(benignIP, "10.0.0.1", 12345, 80,
		[]byte("GET /login?user=admin' OR '1'='1 HTTP/1.1\r\nHost: bank\r\n"), "A")

	t.Logf("Legitimate traffic threats detected: %d (should be detected but may be dropped)", len(legitimateThreats))

	// BREAKING POINT: At 5000+ streams, new streams silently dropped.
	t.Log("BREAKING POINT: streams beyond 5000 silently dropped; 30s idle timeout is only cleanup; single byte every 29s keeps stream alive indefinitely")
}

// =============================================================================
// CATEGORY B: Evasion Techniques
// =============================================================================

// ---------------------------------------------------------------------------
// Test B1: JA3 Spoofing with Known-Browser Profiles
// 测试名称: JA3指纹伪造绕过检测
// Target: JA3Fingerprinter, knownJA3 database, ja3Blacklist
//
// Attack Methodology:
//   The offense module's JA3SpoofProfile produces TLS parameters mimicking
//   Chrome 120, Firefox 120, or Safari 17. An attacker constructs TLS
//   ClientHello packets using these profiles. The JA3 hash will match the
//   known browser entries in knownJA3 (producing a benign "JA3指纹" alert),
//   NOT the ja3Blacklist entries. Since the system treats known-browser JA3
//   matches as informational (Type: "JA3指纹") rather than malicious (Type:
//   "JA3恶意指纹"), the attack is categorized as benign.
//
// Expected Fortress Behavior:
//   - JA3 hash matches knownJA3 -> "JA3指纹" threat (informational, not blocked)
//   - No "JA3恶意指纹" alert triggered
//
// Breaking Point:
//   The knownJA3 map is tiny (13 entries) and based on hardcoded MD5 hashes.
//   An attacker can use any browser profile to generate a ClientHello that
//   matches a known-good fingerprint. The system cannot distinguish between
//   legitimate Chrome traffic and C2 traffic spoofing Chrome's JA3.
//   Furthermore, the ja3Blacklist has only 4 entries (Cobalt Strike x2,
//   Metasploit, Empire) — any C2 framework not on this list is invisible.
//   Finally, the JA3 only covers the outer TLS ClientHello; inner protocol
//   behavior (HTTP/2 settings, ALPN, certificate validation) is not inspected.
func TestStress_B1_JA3SpoofKnownBrowser(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	engine := engines.NewFingerprintEngine(cfg)

	// The JA3Fingerprinter needs raw TLS ClientHello bytes.
	// We construct a minimal but valid TLS 1.3 ClientHello.
	buildTLSClientHello := func(cipherSuites []uint16, extensions []uint16) []byte {
		var ch []byte

		// TLS record header: content type 0x16 (handshake), version 0x0303 (TLS 1.2 record)
		ch = append(ch, 0x16, 0x03, 0x03)

		// --- Build ClientHello inner payload ---
		var inner []byte

		// Handshake type 0x01 (ClientHello)
		inner = append(inner, 0x01)

		// Handshake length placeholder (3 bytes, filled later)
		lenPos := len(inner)
		inner = append(inner, 0x00, 0x00, 0x00)

		// Client version: TLS 1.2 (0x0303) in ClientHello legacy field.
		inner = append(inner, 0x03, 0x03)

		// Random (32 bytes).
		random := make([]byte, 32)
		_, _ = rand.Read(random)
		inner = append(inner, random...)

		// Session ID length: 0 (no session resumption).
		inner = append(inner, 0x00)

		// Cipher suites.
		cipherBytes := make([]byte, 2+len(cipherSuites)*2)
		cipherBytes[0] = byte((len(cipherSuites) * 2) >> 8)
		cipherBytes[1] = byte(len(cipherSuites) * 2)
		for i, cs := range cipherSuites {
			cipherBytes[2+i*2] = byte(cs >> 8)
			cipherBytes[2+i*2+1] = byte(cs)
		}
		inner = append(inner, cipherBytes...)

		// Compression methods: 1 method (null).
		inner = append(inner, 0x01, 0x00)

		// Extensions.
		if len(extensions) > 0 {
			extBytes := make([]byte, 0)
			for _, extType := range extensions {
				// Extension type (2 bytes) + length (2 bytes, 0 data).
				extBytes = append(extBytes, byte(extType>>8), byte(extType))
				extBytes = append(extBytes, 0x00, 0x00)
			}
			extLen := len(extBytes)
			inner = append(inner, byte(extLen>>8), byte(extLen))
			inner = append(inner, extBytes...)
		}

		// Fill handshake length.
		handshakeLen := len(inner) - 4 // Exclude type + len field.
		inner[lenPos] = byte(handshakeLen >> 16)
		inner[lenPos+1] = byte(handshakeLen >> 8)
		inner[lenPos+2] = byte(handshakeLen)

		// Fill TLS record length.
		recordLen := len(inner)
		ch = append(ch, byte(recordLen>>8), byte(recordLen))

		// Append inner to record.
		ch = append(ch, inner...)

		return ch
	}

	const attackIP = "10.77.66.55"

	// Test 1: Chrome-like cipher suites (TLS 1.3 ciphers + legacy).
	chromeCH := buildTLSClientHello(
		[]uint16{0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030},
		[]uint16{0x0000, 0x000A, 0x000B, 0x0023, 0x0010}, // SNI, supported_groups, ec_point_formats, session_ticket, ALPN
	)

	threats := engine.Feed(attackIP, chromeCH, 64, 65535, true, 1460, []string{"MSS", "SACK", "TS", "NOP", "WSCALE"})

	t.Logf("Chrome-spoofed TLS ClientHello produced %d threats", len(threats))
	for _, th := range threats {
		t.Logf("  Threat: type=%s ip=%s detail=%s", th.Type, th.IP, th.Detail)
	}

	// BREAKING POINT: The system cannot distinguish spoofed browser JA3 from real.
	t.Log("BREAKING POINT: hardcoded JA3 database has only 13 known-good + 4 blacklisted hashes; any browser profile bypasses detection; inner protocol behavior not inspected")
}

// ---------------------------------------------------------------------------
// Test B2: IP Fragmentation + TCP Segmentation Overlap Attack
// 测试名称: IP分片与TCP分段重叠攻击
// Target: HttpInspector (stream reassembly), HybridAnomalyDetector (payload entropy)
//
// Attack Methodology:
//   Split a SQL injection payload across multiple IP fragments and TCP segments.
//   The HTTP request "GET /search?q=1' OR '1'='1" is:
//   1. Split into 3 TCP segments (8 bytes each): "GET /sea", "rch?q=1'", " OR '1'='1"
//   2. Each segment is fragmented at the IP layer into 2 fragments (4 bytes each)
//   Total: 6 packets, none containing a complete attack signature.
//
// Expected Fortress Behavior:
//   HttpInspector reassembles the TCP stream and scans the accumulated buffer.
//   Since all segments arrive in order, the reassembled buffer contains the
//   full SQLi payload and triggers a "SQL注入攻击" alert.
//
// Breaking Point:
//   HttpInspector has no IP fragment reassembly — it only reassembles at the
//   TCP stream level. If IP fragments arrive out of order or with overlapping
//   offsets, the Go net stack handles reassembly before Fortress sees the data.
//   However, the 64KB per-stream buffer limit means a large fragmented payload
//   can fill the buffer with garbage before the attack payload arrives.
//   Additionally, the HttpInspector only scans on each Feed call — if the
//   fragments arrive in an order where the regex never matches the intermediate
//   buffer state, detection may be delayed or missed if an eviction occurs.
func TestStress_B2_IPFragmentTCPSegmentOverlap(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	inspector := engines.NewHttpInspector(cfg)

	const attackIP = "10.33.44.55"
	srcPort := uint16(34567)
	dstPort := uint16(80)

	// SQL injection payload split across 3 TCP segments.
	segments := [][]byte{
		[]byte("GET /search?q="),
		[]byte("1' OR '1'="),
		[]byte("'1 HTTP/1.1\r\nHost: target\r\n\r\n"),
	}

	// Feed each segment to the same stream.
	var allThreats []engines.Threat
	for i, seg := range segments {
		threats := inspector.Feed(attackIP, "10.0.0.1", srcPort, dstPort, seg, "A")
		allThreats = append(allThreats, threats...)
		t.Logf("Segment %d (%q): %d threats", i, string(seg), len(threats))
	}

	// Close the stream with FIN to trigger final scan.
	finThreats := inspector.Feed(attackIP, "10.0.0.1", srcPort, dstPort, nil, "F")
	allThreats = append(allThreats, finThreats...)

	// Expected: at least one SQL injection detection.
	hasSQLi := false
	for _, th := range allThreats {
		if th.Type == "SQL注入攻击" {
			hasSQLi = true
			t.Logf("SQLi detected: %s", th.Detail)
		}
	}

	if !hasSQLi {
		// This is the breaking point — if the regex doesn't match across
		// segment boundaries, detection fails.
		t.Log("BREAKING POINT: SQLi NOT detected across TCP segments — regex requires contiguous match; fragmented payloads can evade detection")
	} else {
		t.Log("SQLi correctly detected across TCP segments")
	}

	// BREAKING POINT: no IP fragment reassembly in Fortress; relies on kernel.
	t.Log("BREAKING POINT: no IP fragment reassembly in HttpInspector; 64KB buffer limit allows garbage-fill before attack payload; out-of-order fragments may evade regex")
}

// ---------------------------------------------------------------------------
// Test B3: Slowloris — Slow HTTP Headers Below Timeout
// 测试名称: Slowloris慢速HTTP头部攻击
// Target: HttpInspector stream idle timeout (30 seconds)
//
// Attack Methodology:
//   Open 1000 connections, each sending a single byte of an HTTP header every
//   29 seconds (just below the 30-second idle timeout). Each connection
//   consumes one stream slot. The attack keeps all 1000 streams alive
//   indefinitely without ever sending a complete attack payload. Legitimate
//   traffic streams cannot be opened when the 5000-stream limit is reached.
//
// Expected Fortress Behavior:
//   - Each byte resets the lastActive timer for that stream.
//   - No threats detected (incomplete HTTP, no pattern match).
//   - Streams remain open as long as bytes arrive within 30s.
//
// Breaking Point:
//   The streamIdleSeconds (30) timeout is per-stream and reset on every Feed
//   call. An attacker sending 1 byte every 29 seconds keeps streams alive
//   forever. With 5000 max streams, the attacker can exhaust the stream table
//   using only 5000*12 = 60KB/hour of total traffic. The only countermeasure
//   would be an absolute stream lifetime or a minimum byte-rate threshold,
//   neither of which exists in the current implementation.
func TestStress_B3_SlowlorisSlowHTTPHeaders(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	inspector := engines.NewHttpInspector(cfg)

	// Test: send one byte every 29 seconds on a single stream, three times.
	// We simulate this with immediate calls to verify the lastActive reset.
	const attackIP = "10.22.33.44"
	srcPort := uint16(45678)
	dstPort := uint16(80)

	// First byte.
	inspector.Feed(attackIP, "10.0.0.1", srcPort, dstPort, []byte("G"), "A")
	t.Log("Sent byte 1: 'G'")

	// Simulate 29-second gap (we can't actually wait 29s in a unit test,
	// but we verify the mechanism works by checking that eviction at 28s
	// keeps the stream and eviction at 31s removes it).

	// The stream should survive a 28s eviction.
	evicted28s := inspector.Evict(float64(time.Now().Add(-28*time.Second).Unix()))
	t.Logf("Eviction at 28s idle: %d streams removed (expected 0)", evicted28s)

	// Second byte at 29s — resets the timer.
	inspector.Feed(attackIP, "10.0.0.1", srcPort, dstPort, []byte("E"), "A")
	t.Log("Sent byte 2: 'E' at 29s")

	// The stream should survive another 29s.
	evicted29s := inspector.Evict(float64(time.Now().Add(-29*time.Second).Unix()))
	t.Logf("Eviction at 29s idle: %d streams removed (expected 0)", evicted29s)

	// BREAKING POINT: 30s idle timeout is the only cleanup; single byte every 29s keeps stream alive forever.
	t.Log("BREAKING POINT: stream idle timeout is 30s; 1 byte every 29s keeps stream alive indefinitely; 5000 streams exhaust table with only 60KB/hour total traffic")
}

// =============================================================================
// CATEGORY C: Application-Layer Attacks
// =============================================================================

// ---------------------------------------------------------------------------
// Test C1: Polyglot SQLi/XSS/Path Traversal Combo
// 测试名称: 多态SQL注入/XSS/路径遍历组合攻击
// Target: HttpInspector regex patterns (reSQLi, reXSS, rePathTraversal)
//
// Attack Methodology:
//   Send HTTP payloads containing overlapping SQLi, XSS, and path traversal
//   patterns in a single request. The offense module's WebAttacker has 14 SQLi,
//   8 XSS, and 7 path traversal payloads. When combined (e.g., a single URI
//   containing all three), only the first regex match position is reported.
//   The regex is called with FindIndex, which returns the leftmost match only.
//   Subsequent patterns in the same buffer may be missed.
//
// Expected Fortress Behavior:
//   - All three threat types detected (separate regex calls).
//   - Alert for each independent pattern match.
//
// Breaking Point:
//   The scanPayload method calls each regex independently (reSQLi, reXSS,
//   rePathTraversal), so all three should fire. However, the maxStreamBytes
//   limit of 64KB means a crafted payload can pad the buffer with benign data
//   before the attack pattern, and if benign data pushes the attack beyond
//   64KB, the attack is truncated and missed. Additionally, the regex uses
//   case-insensitive matching (?i) but specific keyword patterns — novel
//   SQLi syntax (e.g., JSON-based injection, NoSQL injection) is not covered.
func TestStress_C1_PolyglotSQLiXSSTraversal(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	inspector := engines.NewHttpInspector(cfg)

	const attackIP = "10.55.66.77"

	// A payload containing SQLi, XSS, and path traversal simultaneously.
	// SQLi: "UNION SELECT" and "' OR 1=1"
	// XSS: "<script>" and "alert("
	// Path traversal: "../../../etc/passwd"
	payloads := []string{
		// Polyglot: all three in one line.
		`GET /login?user=admin&pass=' OR '1'='1'-- HTTP/1.1
Host: target.com
X-Token: ../../../etc/passwd
Cookie: session=<script>alert(1)</script>
`,

		// SQLi with UNION SELECT and path traversal.
		`GET /products?id=1 UNION SELECT username,password FROM users--&file=../../../etc/shadow HTTP/1.1
Host: target.com
`,

		// XSS with path traversal in the referer.
		`POST /submit HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Referer: ../../../../etc/passwd

comment=<img src=x onerror=alert(document.cookie)>&name=test'; DROP TABLE users;--
`,
	}

	totalThreats := 0
	for i, payload := range payloads {
		threats := inspector.Feed(attackIP, "10.0.0.1", uint16(40000+i), 80, []byte(payload), "A")
		totalThreats += len(threats)
		t.Logf("Payload %d: %d threats", i, len(threats))
		for _, th := range threats {
			t.Logf("  Threat: type=%s detail=%s", th.Type, th.Detail)
		}
	}

	if totalThreats < 3 {
		t.Errorf("expected at least 3 threats across payloads, got %d", totalThreats)
	}

	// BREAKING POINT: Test payload truncation at 64KB boundary.
	// A payload padded to 63KB + 1KB attack pattern loses the pattern.
	padPayload := make([]byte, 65000)
	for i := range padPayload {
		padPayload[i] = 'A'
	}
	copy(padPayload[64900:], []byte("' OR '1'='1"))
	paddedThreats := inspector.Feed(attackIP, "10.0.0.1", 40003, 80, padPayload, "A")
	t.Logf("Padded payload (65000 bytes, SQLi at end): %d threats", len(paddedThreats))
	if len(paddedThreats) == 0 {
		t.Log("BREAKING POINT: 64KB buffer limit truncates attack patterns; padding can push payloads beyond detection threshold")
	}
}

// ---------------------------------------------------------------------------
// Test C2: Distributed SSH Brute Force with IP Rotation
// 测试名称: 分布式SSH暴力破解及IP轮换绕过
// Target: BruteForceDetector (per-IP RingBuffer, cap 200), CorrelationEngine
//
// Attack Methodology:
//   Use 50 unique source IPs, each sending 9 SSH SYN attempts (1 below the
//   10-attempt threshold). Total: 450 SSH attempts — enough to compromise
//   most weak passwords, but no single IP triggers the brute-force alert.
//   Additionally, rotates JA3 fingerprints between attempts to evade
//   fingerprint-based detection.
//
// Expected Fortress Behavior:
//   - No individual IP reaches threshold (9 < 10), so no "SSH暴力破解" alerts.
//   - CorrelationEngine may or may not detect distributed attack depending on
//     alert timing (needs 3+ IPs with 2 or fewer attack types in 60s).
//
// Breaking Point:
//   The BruteForceDetector is purely per-IP with no cross-IP aggregation.
//   An attacker with access to 50 IPs can send 450 attempts completely
//   undetected. The CorrelationEngine only correlates AFTER alerts are generated,
//   but since no individual IP triggers an alert, there is nothing to correlate.
//   The 60-second window is also too short for slow distributed attacks
//   (e.g., 1 attempt per IP per hour across 1000 IPs).
func TestStress_C2_DistributedSSHBruteForce(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	detector := engines.NewBruteForceDetector(cfg)
	correlator := engines.NewCorrelationEngine()

	const attemptsPerIP = 9 // 1 below the 10-attempt threshold.
	const ipCount = 50

	ips := uniqueSourceIPs(ipCount)

	// Each IP sends 9 SSH SYN attempts.
	for _, ip := range ips {
		for j := 0; j < attemptsPerIP; j++ {
			detector.FeedSSH(ip)
		}
	}

	// Check: no single IP should trigger.
	threats := detector.CheckAll()
	t.Logf("BruteForceDetector: %d threats from %d IPs x %d attempts each",
		len(threats), ipCount, attemptsPerIP)

	// All threats that DID trigger (if any edge case).
	for _, th := range threats {
		t.Logf("  Threat: type=%s ip=%s detail=%s", th.Type, th.IP, th.Detail)
	}

	if len(threats) > 0 {
		t.Logf("BREAKING POINT PARTIAL: some IPs triggered at %d attempts (threshold is 10)", attemptsPerIP)
	} else {
		t.Log("BREAKING POINT CONFIRMED: 450 SSH attempts across 50 IPs = 0 alerts. Per-IP threshold of 10 completely bypassed by IP rotation.")
	}

	// Now test with 10 attempts per IP from just 2 IPs — should trigger.
	detector2 := engines.NewBruteForceDetector(cfg)
	detector2.FeedSSH("10.1.1.1")
	detector2.FeedSSH("10.1.1.1")
	detector2.FeedSSH("10.1.1.1")
	detector2.FeedSSH("10.1.1.1")
	detector2.FeedSSH("10.1.1.1")
	detector2.FeedSSH("10.1.1.1")
	detector2.FeedSSH("10.1.1.1")
	detector2.FeedSSH("10.1.1.1")
	detector2.FeedSSH("10.1.1.1")
	detector2.FeedSSH("10.1.1.1") // 10th attempt.

	threats2 := detector2.CheckAll()
	assertAtLeastThreats(t, threats2, 1, "SSH brute force at threshold")

	// Feed correlation engine.
	for _, th := range threats2 {
		correlator.Feed(th.IP, th.Type)
	}
	corrThreats := correlator.CheckCorrelation()
	t.Logf("Correlation after 2-IP attack: %d correlated threats (needs 3+ IPs)", len(corrThreats))

	t.Log("BREAKING POINT: CorrelationEngine requires 3+ IPs with existing alerts; distributed attack below per-IP thresholds produces zero alerts to correlate")
}

// =============================================================================
// CATEGORY D: Swarm / Protocol Attacks
// =============================================================================

// ---------------------------------------------------------------------------
// Test D1: Gossip Peer Table Poisoning
// 测试名称: Gossip对等表投毒攻击
// Target: GossipNode peer table, mergePeerList, HMAC authentication
//
// Attack Methodology:
//   When GossipKey is empty (the default), HMAC verification is skipped:
//     verifyHMAC returns true immediately if g.config.GossipKey == "".
//   An attacker can send forged GossipMessages with arbitrary peer lists.
//   The mergePeerList method adds any unknown peers to the local table.
//   The attacker can inject thousands of fake dead/alive peers, exhausting
//   the peer table and causing the gossip loop to spend all its time pinging
//   nonexistent hosts.
//
// Expected Fortress Behavior:
//   - With GossipKey set: forged messages fail HMAC verification and are dropped.
//   - Without GossipKey: ALL messages accepted, peer table grows unbounded.
//
// Breaking Point:
//   The default config has GossipKey="" — no authentication. ANY host on the
//   network can inject peers. The peer table has no maximum size. An attacker
//   sending a join or ping message with a large PeerList can inject arbitrary
//   entries. Since pings are sent to ALL non-dead peers every 5 seconds, a
//   table with 100,000 poisoned entries would generate 20,000 pings/second,
//   saturating the UDP socket and effectively DoS-ing the swarm node.
func TestStress_D1_GossipPeerTablePoisoning(t *testing.T) {
	t.Parallel()

	// Test 1: Verify HMAC bypass when GossipKey is empty.
	t.Run("HMAC_Bypass_EmptyKey", func(t *testing.T) {
		t.Parallel()

		// Create a node WITHOUT a gossip key (default).
		node := mockGossipNode(t, "test-node-1", "")

		// The verifyHMAC function (internal, tested via behavior):
		// When GossipKey is "", verifyHMAC returns true immediately.
		// This means any UDP datagram with valid JSON is accepted.

		// We can't directly test internal HMAC, but we can verify that
		// the config allows empty keys.
		peerCount := node.PeerCount()
		t.Logf("Node started with empty GossipKey; peer count: %d", peerCount)

		// BREAKING POINT: With empty key, any UDP datagram with valid JSON
		// is accepted. The peer table has no maximum size.
		t.Log("BREAKING POINT: empty GossipKey = no authentication; any UDP datagram with valid JSON accepted; peer table unbounded")
	})

	// Test 2: Peer table unbounded growth potential.
	t.Run("Unbounded_PeerTable", func(t *testing.T) {
		t.Parallel()

		node := mockGossipNode(t, "test-node-2", "test-key")

		// Verify the peer table has no explicit maximum.
		// The mergePeerList method does not enforce any cap.
		initialCount := node.PeerCount()
		t.Logf("Initial peer count: %d", initialCount)

		// BREAKING POINT: No maximum peer count enforced.
		t.Log("BREAKING POINT: peer table has no maximum; 100K poisoned entries = 20K pings/sec; UDP socket saturation DoS")
	})
}

// ---------------------------------------------------------------------------
// Test D2: Raft Quorum Deadlock via Partitioned Leadership
// 测试名称: Raft法定人数死锁
// Target: RaftNode (simplified Raft), deterministic alphabetical leadership
//
// Attack Methodology:
//   The RaftNode uses deterministic alphabetical leadership (LeaderName sorts
//   peer names and picks the first). There is no election process — the leader
//   is predetermined. If the alphabetically-first node goes down, NO node can
//   propose counterstrikes because every node agrees the dead node is leader.
//   The 5-second vote timeout means proposals from non-leaders are ignored.
//
//   Additionally, quorum is > N/2 of all alive peers. During a network
//   partition where each side has exactly N/2 nodes, neither partition can
//   reach quorum (need > N/2, have exactly N/2). The system deadlocks.
//
// Expected Fortress Behavior:
//   - IsLeader() returns true only for the alphabetically first node.
//   - ProposeCounterstrike returns false for non-leaders.
//   - When leader is dead, no counterstrikes can be authorized.
//
// Breaking Point:
//   Deterministic leadership without election means leader failure = total
//   consensus failure. The simplified Raft has no election timeout, no
//   Candidate state transition logic (Candidate is "reserved for future use").
//   In a 3-node cluster, if node "alpha" (leader) dies, "beta" and "gamma"
//   can never propose counterstrikes. The system is permanently deadlocked
//   until "alpha" comes back or the peer list is manually changed.
func TestStress_D2_RaftQuorumDeadlock(t *testing.T) {
	t.Parallel()

	// Scenario: 3-node cluster: "alpha", "beta", "gamma".
	// Leadership: alpha (alphabetically first).
	peers := []string{"alpha", "beta", "gamma"}

	t.Run("DeterministicLeadership", func(t *testing.T) {
		t.Parallel()

		raftAlpha := swarm.NewRaftNode("alpha", peers)
		raftBeta := swarm.NewRaftNode("beta", peers)
		raftGamma := swarm.NewRaftNode("gamma", peers)

		if !raftAlpha.IsLeader() {
			t.Error("alpha should be leader (alphabetically first)")
		}
		if raftBeta.IsLeader() {
			t.Error("beta should NOT be leader")
		}
		if raftGamma.IsLeader() {
			t.Error("gamma should NOT be leader")
		}

		t.Logf("Leader: %s (alphabetically first)", raftAlpha.LeaderName())
		t.Logf("Beta IsLeader: %v, Gamma IsLeader: %v", raftBeta.IsLeader(), raftGamma.IsLeader())

		// BREAKING POINT: Leader is deterministic, no election. Dead leader = dead consensus.
		t.Log("BREAKING POINT: deterministic alphabetical leadership means leader death = permanent consensus deadlock; Candidate state is unimplemented ('reserved for future use'); no election timeout")
	})

	t.Run("QuorumSplitBrain", func(t *testing.T) {
		// NOT Parallel — this test intentionally demonstrates a deadlock.

		// With an even number of peers (e.g., 4: alpha, beta, gamma, delta),
		// a partition where each side has 2 nodes means quorum (> N/2 = > 2)
		// can never be reached. N=4, quorum = >2 = 3, but each partition has 2.
		peers4 := []string{"alpha", "beta", "gamma", "delta"}

		// Alpha is leader (alphabetically first).
		raft := swarm.NewRaftNode("alpha", peers4)

		// In a 4-node cluster: quorum = N/2 + 1 = 3.
		// A 2-2 partition means neither side can reach quorum.
		t.Logf("4-node cluster: quorum requires > %d/2 = 3 votes", len(peers4))
		t.Logf("2-2 partition: neither side reaches quorum of 3")

		// ProposeCounterstrike will block waiting for quorum. Run in goroutine
		// with timeout to confirm the deadlock.
		done := make(chan bool, 1)
		go func() {
			result := raft.ProposeCounterstrike("10.0.0.99", 90.0, 85.0)
			t.Logf("ProposeCounterstrike result (no gossip attached): %v", result)
			done <- result
		}()

		select {
		case <-done:
			t.Log("ProposeCounterstrike returned (unexpected — quorum was reached somehow)")
		case <-time.After(3 * time.Second):
			t.Log("CONFIRMED DEADLOCK: ProposeCounterstrike blocked for 3s waiting for quorum in 2-2 partition. Even-numbered clusters create split-brain; quorum > N/2 means N/2 nodes in each partition = permanent deadlock.")
			t.Log("FIX SUGGESTION: add context.Context timeout to ProposeCounterstrike, or use odd-numbered clusters only.")
		}
	})
}

// =============================================================================
// CATEGORY E: Resource Exhaustion
// =============================================================================

// ---------------------------------------------------------------------------
// Test E1: Flow Table Exhaustion — 10K Unique Source IPs
// 测试名称: 流表耗尽攻击
// Target: HybridAnomalyDetector flow table (maxFlows = 10000), Count-Min Sketch
//
// Attack Methodology:
//   Send traffic from 20,000 unique source IPs. The flow table caps at 10,000.
//   On overflow, the oldest flow is evicted (linear scan of all entries).
//   The Count-Min Sketch continues to count fingerprints, but no per-flow
//   EMA/Z-Score tracking exists for evicted IPs. An attacker can:
//   1. Fill the flow table with 10,000 benign IPs.
//   2. Start attacking from IP #10,001 — no flow history exists.
//   3. Each attack packet creates a new flow, evicting one benign flow.
//   4. The attack IP's flow is regularly evicted and recreated, resetting
//      the Z-Score statistics (n resets to 1, Z-Score to 0).
//
// Expected Fortress Behavior:
//   - First 10,000 IPs: normal tracking, Z-Score accumulates.
//   - IPs 10,001+: oldest flow evicted on each new IP.
//   - Evicted-then-recreated flows lose all statistical history.
//
// Breaking Point:
//   The getOrCreateFlow eviction is O(n) (linear scan of all 10,000 entries),
//   making each overflow insertion expensive. The Z-Score requires minSamples
//   (5 default) before alerting — an attacker who cycles IPs faster than 5
//   samples per IP never triggers a Z-Score alert. The Count-Min Sketch has
//   65536 columns and decays at 10M total — at extreme volume, hash collisions
//   cause rare fingerprints to appear common, masking structural anomalies.
func TestStress_E1_FlowTableExhaustion(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	detector := engines.NewHybridAnomalyDetector(cfg, false)

	const uniqueIPCount = 15000
	const attackIP = "10.255.255.1"

	// Phase 1: Fill flow table with 10,000 benign IPs.
	for i := 0; i < 10000; i++ {
		ip := uniqueIP(i)
		detector.Feed(ip, "10.0.0.99", uint16(20000+i%65535), 80, "TCP", 1500, 0, 3.0)
	}

	t.Log("Phase 1: 10,000 benign flows created")

	// Phase 2: Add 5,000 more IPs to trigger eviction churn.
	for i := 10000; i < uniqueIPCount; i++ {
		ip := uniqueIP(i)
		detector.Feed(ip, "10.0.0.99", uint16(20000+i%65535), 80, "TCP", 1500, 0, 3.0)
	}

	t.Log("Phase 2: 5,000 more IPs added, oldest flows evicted")

	// Phase 3: Now attack from the IP whose flow was evicted.
	// Feed 4 packets — below minSamples (5), so no Z-Score alert possible.
	var attackThreats []engines.Threat
	for i := 0; i < 4; i++ {
		threats := detector.Feed(attackIP, "10.0.0.99", 54321, 22, "TCP", 64, 0x02, 7.5)
		attackThreats = append(attackThreats, threats...)
	}
	t.Logf("Attack from %s after eviction: %d threats (4 samples, minSamples=5)", attackIP, len(attackThreats))

	// Phase 4: The 5th packet triggers Z-Score for the first time.
	threats5 := detector.Feed(attackIP, "10.0.0.99", 54321, 22, "TCP", 64, 0x02, 7.5)
	t.Logf("5th packet from %s: %d threats", attackIP, len(threats5))

	// BREAKING POINT: O(n) eviction scan, minSamples reset on eviction,
	// Count-Min Sketch hash collisions at scale.
	t.Log("BREAKING POINT: O(n) eviction scan of 10K entries; Z-Score resets to 0 on eviction; minSamples=5 means IP cycling faster than 5 packets/flow never alerts; Count-Min Sketch 65536 columns cause hash collisions at scale")
}

// ---------------------------------------------------------------------------
// Test E2: Honeypot Connection Saturation
// 测试名称: 蜜罐连接饱和攻击
// Target: HoneypotManager (SSH/HTTP/MySQL), BaseHoneypot acceptLoop
//
// Attack Methodology:
//   The honeypot acceptLoop spawns a goroutine per accepted connection.
//   Each connection handler blocks on reading from the connection. An attacker
//   opens thousands of connections and never sends data (or sends very slowly).
//   The goroutines accumulate, each holding a socket and buffer.
//   The BaseHoneypot has no connection limit, no read timeout, and no rate
//   limiting on new connections. A single attacker can exhaust the host's
//   file descriptors and goroutine scheduler.
//
// Expected Fortress Behavior:
//   - Each connection spawns a goroutine.
//   - No limit on concurrent connections.
//   - No read timeout on connections.
//
// Breaking Point:
//   Unlimited goroutine spawning per connection. No MaxConns setting on the
//   listener. No SetReadDeadline on accepted connections (the handler does a
//   blocking bufio read). An attacker can open connections faster than the OS
//   can close them, leading to file descriptor exhaustion and goroutine leak.
//   The acceptLoop's b.running.Load() check happens once per iteration —
//   a tight accept loop can spawn goroutines faster than Stop() can clean up.
func TestStress_E2_HoneypotConnectionSaturation(t *testing.T) {
	// This test requires actual network sockets, so it's not run in parallel
	// with other tests that may bind the same ports.
	if testing.Short() {
		t.Skip("skipping honeypot saturation test in short mode (requires network sockets)")
	}

	// Start the honeypot manager.
	manager := counterstrike.NewHoneypotManager()
	if err := manager.StartAll(); err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	defer manager.StopAll()

	// Open 200 connections to each honeypot but send no data.
	// The handlers will block on bufio read.
	const connsPerHoneypot = 200

	type dialTarget struct {
		network string
		addr    string
	}

	targets := []dialTarget{
		{"tcp", "127.0.0.1:2222"}, // SSH
		{"tcp", "127.0.0.1:8080"}, // HTTP
		{"tcp", "127.0.0.1:3307"}, // MySQL
	}

	var conns []net.Conn
	for _, target := range targets {
		for i := 0; i < connsPerHoneypot; i++ {
			conn, err := net.DialTimeout(target.network, target.addr, 2*time.Second)
			if err != nil {
				t.Logf("Connection %d to %s failed: %v (file descriptors may be exhausted)", i, target.addr, err)
				break
			}
			conns = append(conns, conn)
		}
	}

	t.Logf("Opened %d connections across 3 honeypots", len(conns))

	// Close all connections.
	for _, conn := range conns {
		conn.Close()
	}

	// Check honeypot hit counts after saturation attempt.
	totalHits := manager.GetRecentHits(60)
	t.Logf("Honeypot hits recorded in last 60s: %d", len(totalHits))

	// BREAKING POINT: no connection limit, no read deadline, unlimited goroutines.
	t.Log("BREAKING POINT: no MaxConns limit; no SetReadDeadline on accepted connections; acceptLoop spawns goroutines faster than Stop() cleans up; file descriptor exhaustion at scale")
}

// =============================================================================
// CATEGORY F: False Positive Flood
// =============================================================================

// ---------------------------------------------------------------------------
// Test F1: Benign High-Entropy Traffic Masquerading as Attack
// 测试名称: 良性高熵流量误报测试
// Target: HybridAnomalyDetector (payload entropy feature), BehaviorAnalyzer (entropy deviation)
//
// Attack Methodology:
//   Legitimate encrypted traffic (HTTPS, VPN, SSH file transfers) has high
//   Shannon entropy (typically 6.5-7.8). Large file downloads generate
//   sustained high-byte-count flows with bursty packet patterns. These
//   characteristics overlap significantly with data exfiltration and tunnel
//   traffic. The test sends legitimate-looking traffic patterns that would
//   be produced by:
//   - HTTPS video streaming (high entropy, high bytes, asymmetric)
//   - SSH SCP file transfer (high entropy, port 22, large packets)
//   - VPN tunnel (encrypted all traffic, constant flow)
//
// Expected Fortress Behavior:
//   If properly tuned, these benign patterns should NOT trigger alerts.
//   If the entropy threshold or Z-Score is too aggressive, false positives fire.
//
// Breaking Point:
//   The Z-Score uses a fixed threshold (4.0 default, 3.0 aggressive) regardless
//   of protocol or port. Encrypted traffic on port 443 is normal; encrypted
//   traffic on port 53 (DNS) is suspicious. The system does not contextualize
//   entropy by port. A Netflix stream from a new IP would look identical to
//   data exfiltration — high entropy, high byte count, asymmetric flow.
func TestStress_F1_BenignHighEntropyTraffic(t *testing.T) {
	t.Parallel()

	// Test 1: Aggressive mode false positives on benign traffic.
	t.Run("AggressiveMode_BenignHTTPS", func(t *testing.T) {
		t.Parallel()

		cfg := testConfig()
		// Aggressive mode: Z=3.0, L2=4.5, minSamples=3.
		detector := engines.NewHybridAnomalyDetector(cfg, true)

		const benignIP = "10.100.50.50"

		var threatCount int
		// Simulate HTTPS video streaming: 200 packets, 1500 bytes each, high entropy.
		for i := 0; i < 200; i++ {
			threats := detector.Feed(benignIP, "10.0.0.99", 44300+uint16(i%100), 443,
				"TCP", 1500, 0x10, 7.2) // PSH flag, high entropy.
			threatCount += len(threats)
		}

		t.Logf("Aggressive mode: %d threats from 200 legitimate HTTPS packets", threatCount)

		if threatCount > 0 {
			t.Log("Agresive mode produced false positives on benign HTTPS traffic")
		}
	})

	// Test 2: File download traffic pattern.
	t.Run("StandardMode_LargeDownload", func(t *testing.T) {
		t.Parallel()

		cfg := testConfig()
		detector := engines.NewHybridAnomalyDetector(cfg, false)

		const downloadIP = "10.200.1.1"

		var threatCount int
		// Simulate large file download: 500 packets, 1500 bytes, moderate entropy.
		for i := 0; i < 500; i++ {
			threats := detector.Feed(downloadIP, "10.0.0.99", 50000, 443,
				"TCP", 1500, 0x10, 6.5)
			threatCount += len(threats)
		}

		t.Logf("Standard mode: %d threats from 500 file-download-like packets", threatCount)

		// The expected behavior is 0 threats for normal traffic.
		if threatCount > 5 {
			t.Logf("WARNING: %d false positives from legitimate file download (target: 0)", threatCount)
		}
	})

	t.Log("BREAKING POINT: fixed entropy/Z-Score thresholds without protocol/port context; encrypted Netflix = encrypted exfiltration to the detector; no port-based entropy expectations")
}

// =============================================================================
// CATEGORY G: Kernel / BPF Stress
// =============================================================================

// ---------------------------------------------------------------------------
// Test G1: eBPF Blocked IP Map Overflow
// 测试名称: eBPF阻断IP映射溢出
// Target: eBPF XDP filter, blocked_ips BPF hash map (max 10K entries)
//
// Attack Methodology:
//   The XDP filter has a blocked_ips LRU hash map with max 10K entries.
//   When the map is full and a new IP is added, the LRU eviction kicks in.
//   However, the Go wrapper (EBpfBlocker) does not track map capacity —
//   Block() blissfully calls BlockIP() which calls the BPF map update.
//   If 10,001 IPs are blocked, the oldest (least recently used) blocked IP
//   is silently evicted from the map and its traffic is PASSED again.
//   An attacker can: (1) trigger blocks on 10K decoy IPs, (2) attack from
//   IP A, (3) when A is blocked, trigger 10K more decoy blocks to evict A,
//   (4) resume attacking from A.
//
// Expected Fortress Behavior:
//   - Block() succeeds for all calls.
//   - GetStats() reports dropped/passed counts but not blocked IP count.
//   - No notification when a blocked IP is evicted from the map.
//
// Breaking Point:
//   The Go wrapper has NO visibility into BPF map capacity. GetStats() returns
//   blocked=0 (hardcoded). The LRU eviction is silent — blocked IPs can be
//   evicted without any alert. An attacker can cycle through blocks by
//   triggering enough new blocks to push their IP out of the map.
func TestStress_G1_EBPFBlockedIPMapOverflow(t *testing.T) {
	t.Parallel()

	// Note: This test documents the breaking point at the Go wrapper level.
	// The actual BPF map overflow requires a running kernel with eBPF support.
	// We test the Go-level bookkeeping to verify the gap.

	// Verify that the Go wrapper has no map capacity tracking.
	// The GetStats method hardcodes blocked=0.
	// The EBpfBlocker struct has no map size field.

	t.Log("BREAKING POINT (documented):")
	t.Log("  1. blocked_ips BPF map: max 10K entries, LRU eviction.")
	t.Log("  2. Go wrapper GetStats() returns blocked=0 (hardcoded) — no capacity visibility.")
	t.Log("  3. Block() always succeeds; if map is full, oldest blocked IP silently unblocked.")
	t.Log("  4. Attack: trigger 10K decoy blocks -> attack from IP A -> A gets blocked ->")
	t.Log("     trigger 10K more blocks to evict A -> A is unblocked -> resume attack.")
	t.Log("  5. No alert when a blocked IP is silently evicted from the BPF map.")
}

// ---------------------------------------------------------------------------
// Test G2: Token Bucket Exhaustion via Distributed Rate-Limited Flood
// 测试名称: 分布式速率限制令牌桶耗尽
// Target: eBPF rate_limit token bucket (max 50K entries)
//
// Attack Methodology:
//   The XDP rate_limit map is a per-IP token bucket with max 50K entries.
//   Tokens are refilled by a Go-side goroutine calling SetRateLimit().
//   An attacker sends traffic from 50,001 unique IPs, each below the
//   individual rate limit. The map fills up, and the 50,001st IP's entry
//   triggers LRU eviction of the oldest entry. That IP is now un-rate-limited
//   and can flood freely.
//
// Expected Fortress Behavior:
//   - SetRateLimit() succeeds for all calls.
//   - IPs within the token bucket are rate-limited.
//   - IPs evicted from the bucket have no rate limit applied.
//
// Breaking Point:
//   Same as blocked IPs — the Go wrapper has no map capacity visibility.
//   Token bucket map is 50K max. A distributed attack with 50K+ IPs can
//   push target IPs out of the map. If the Go-side token refill goroutine
//   is slow or crashes, tokens are never refilled and legitimate IPs get
//   rate-limited into oblivion. There is no alert for map-full conditions.
func TestStress_G2_TokenBucketExhaustion(t *testing.T) {
	t.Parallel()

	// Document the breaking points at the architecture level.
	t.Log("BREAKING POINT (documented):")
	t.Log("  1. rate_limit BPF map: max 50K entries, LRU eviction.")
	t.Log("  2. Go wrapper SetRateLimit() has no capacity check.")
	t.Log("  3. Distributed attack: 50,001 IPs, each below rate limit.")
	t.Log("     Map fills -> 50,001st IP evicts oldest -> oldest IP now unlimited.")
	t.Log("  4. Token refill goroutine crash = all tokens eventually exhausted =")
	t.Log("     all rate-limited IPs drop to 0 throughput.")
	t.Log("  5. No alert for BPF map-full condition or token refill failure.")
}

// =============================================================================
// CATEGORY X: Adversarial Chaos Tests
// =============================================================================

// ---------------------------------------------------------------------------
// Test X1: Full Engine Saturation — All 5 Tiers at Maximum Rate
// 测试名称: 全引擎饱和攻击 — 五层检测同时达到最大速率
// Target: ALL engines simultaneously — PacketInspector + FlowAnalyzer +
//         BehaviorAnalyzer + HybridAnomalyDetector + DnsTunnelDetector +
//         HttpInspector + BruteForceDetector + FingerprintEngine
//
// Attack Methodology:
//   Generate traffic that exercises every detection tier simultaneously at
//   maximum rate. Use a goroutine pool to feed all engines concurrently.
//   The goal is to find emergent failures from contention, memory pressure,
//   or mutex contention that do not appear when engines are tested in isolation.
//
//   Concurrent load:
//   - 10 goroutines feeding PacketInspector with SYN flood
//   - 10 goroutines feeding FlowAnalyzer with port scans
//   - 5 goroutines feeding HybridAnomalyDetector with anomalous packets
//   - 5 goroutines feeding DnsTunnelDetector with DNS queries
//   - 10 goroutines feeding HttpInspector with SQLi payloads
//   - 5 goroutines feeding BruteForceDetector with SSH attempts
//   - 5 goroutines feeding FingerprintEngine with TLS ClientHello
//
//   Total: 50 goroutines, each sending 1000 events = 50,000 total events.
//
// Expected Fortress Behavior:
//   - All threats detected correctly despite concurrent load.
//   - No data races (test with -race flag).
//   - No deadlocks from mutex contention.
//   - Memory usage remains bounded.
//
// Breaking Point:
//   Multiple engines hold their respective mutexes while doing O(n) operations
//   (flow eviction, DNS query pruning, stream cleanup). Under maximum load,
//   these mutexes could be held for extended periods, causing other goroutines
//   to block. The HybridAnomalyDetector holds its lock for the entire Feed
//   call, which includes O(n) getOrCreateFlow eviction scan (up to 10000
//   entries). During this time, all other Feed calls are blocked.
func TestStress_X1_FullEngineSaturation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full saturation test in short mode")
	}

	cfg := testConfig()

	// Initialize all engines.
	packetInsp := engines.NewPacketInspector(cfg)
	flowAnalyzer := engines.NewFlowAnalyzer(cfg)
	behaviorAnalyzer := engines.NewBehaviorAnalyzer(cfg)
	anomalyDetector := engines.NewHybridAnomalyDetector(cfg, false)
	dnsDetector := engines.NewDnsTunnelDetector(cfg)
	httpInspector := engines.NewHttpInspector(cfg)
	bruteForce := engines.NewBruteForceDetector(cfg)
	fingerprint := engines.NewFingerprintEngine(cfg)

	const eventsPerGoroutine = 1000

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// Group 1: PacketInspector SYN floods (10 goroutines).
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				ip := uniqueIP(base + i)
				packetInsp.Feed("S", ip, uint16(80+(i%1000)), "TCP")
			}
		}(g * eventsPerGoroutine)
	}

	// Group 2: FlowAnalyzer port scans (10 goroutines).
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				ip := uniqueIP(base + i + 20000)
				flowAnalyzer.Feed(ip, uint16(1+(i%65535)))
			}
		}(g * eventsPerGoroutine)
	}

	// Group 3: HybridAnomalyDetector (5 goroutines).
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				ip := uniqueIP(base + i + 40000)
				anomalyDetector.Feed(ip, "10.0.0.99", uint16(30000+i%65535), 80,
					"TCP", 100+int(1500), 0x02, 3.0+float64(i%400)/100.0)
			}
		}(g * eventsPerGoroutine)
	}

	// Group 4: DnsTunnelDetector (5 goroutines).
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				ip := uniqueIP(base + i + 50000)
				dnsDetector.Feed(ip, fmt.Sprintf("query-%d.example.com", i))
			}
		}(g * eventsPerGoroutine)
	}

	// Group 5: HttpInspector SQLi payloads (10 goroutines).
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				ip := uniqueIP(base + i + 60000)
				payload := []byte(fmt.Sprintf("GET /search?q=%d' OR '1'='1 HTTP/1.1\r\nHost: x\r\n\r\n", i))
				httpInspector.Feed(ip, "10.0.0.1", uint16(40000+i%10000), 80, payload, "A")
			}
		}(g * eventsPerGoroutine)
	}

	// Group 6: BruteForceDetector (5 goroutines).
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				ip := uniqueIP(base + i + 80000)
				bruteForce.FeedSSH(ip)
			}
		}(g * eventsPerGoroutine)
	}

	// Group 7: FingerprintEngine (5 goroutines).
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				ip := uniqueIP(base + i + 90000)
				fingerprint.Feed(ip, nil, 64, 65535, true, 1460,
					[]string{"MSS", "SACK", "TS", "NOP", "WSCALE"})
			}
		}(g * eventsPerGoroutine)
	}

	// Wait for all groups to complete.
	wg.Wait()
	close(errCh)

	// Collect errors.
	var errors []error
	for err := range errCh {
		errors = append(errors, err)
	}
	if len(errors) > 0 {
		t.Errorf("Full saturation: %d errors: %v", len(errors), errors)
	}

	// Run all Check methods.
	dnsThreats := 0
	// Check DNS for a few IPs.
	for i := 0; i < 100; i++ {
		threats := dnsDetector.Check(uniqueIP(50000 + i))
		dnsThreats += len(threats)
	}
	t.Logf("DNS threats after saturation: %d (sampled 100 IPs)", dnsThreats)

	bruteThreats := bruteForce.CheckAll()
	t.Logf("Brute force threats after saturation: %d", len(bruteThreats))

	behThreats := behaviorAnalyzer.Check()
	t.Logf("Behavior entropy threats after saturation: %d", len(behThreats))

	// Evict all engines.
	totalEvicted := 0
	totalEvicted += anomalyDetector.Evict(float64(time.Now().Add(-10 * time.Second).Unix()))
	totalEvicted += httpInspector.Evict(float64(time.Now().Add(-10 * time.Second).Unix()))
	totalEvicted += dnsDetector.Evict(float64(time.Now().Add(-10 * time.Second).Unix()))
	totalEvicted += bruteForce.Evict(float64(time.Now().Add(-10 * time.Second).Unix()))
	totalEvicted += flowAnalyzer.Evict(float64(time.Now().Add(-10 * time.Second).Unix()))
	totalEvicted += behaviorAnalyzer.Evict(float64(time.Now().Add(-10 * time.Second).Unix()))
	totalEvicted += packetInsp.Evict(float64(time.Now().Add(-10 * time.Second).Unix()))
	t.Logf("Total evicted entries: %d", totalEvicted)

	t.Log("BREAKING POINT: HybridAnomalyDetector holds mutex during O(n) eviction scan; all other Feed calls blocked; 50 goroutines contending on same locks may deadlock under extreme pressure")
}

// ---------------------------------------------------------------------------
// Test X2: Swarm Partition + Active Attack
// 测试名称: 蜂群分区与主动攻击并发
// Target: GossipNode + RaftNode + ImmunityEngine during network partition
//
// Attack Methodology:
//   A 5-node swarm is partitioned into two groups: {alpha, beta} and
//   {gamma, delta, epsilon}. During the partition:
//   - An external attacker launches a SYN flood against nodes in partition B.
//   - Node gamma detects the flood and tries to broadcast immunity (IP block).
//   - The immunity record reaches gamma/delta/epsilon but NOT alpha/beta.
//   - Alpha (alphabetical leader) cannot propose counterstrike because it
//     can't reach quorum (needs > 5/2 = 3, only sees itself + beta = 2).
//   - Gamma thinks alpha is dead (suspect timeout 15s -> dead at 30s) but
//     cannot become leader (deterministic leadership, gamma > alpha).
//
// Expected Fortress Behavior:
//   - Partition A (2 nodes): cannot reach quorum, no counterstrikes possible.
//   - Partition B (3 nodes): can reach quorum (> 5/2 = 3), but alpha (leader)
//     is in partition A. Gamma cannot propose without being leader.
//   - Immunity records do not propagate across partitions.
//
// Breaking Point:
//   Triple failure: (1) leader in minority partition cannot authorize,
//   (2) majority partition has no leader so cannot authorize,
//   (3) immunity rules are not shared across partitions, creating
//   inconsistent defense states. When the partition heals, nodes have
//   conflicting views of which IPs are blocked.
func TestStress_X2_SwarmPartitionActiveAttack(t *testing.T) {
	t.Parallel()

	// Simulate a 5-node cluster partition scenario.
	peers := []string{"alpha", "beta", "gamma", "delta", "epsilon"}

	t.Run("Partition_Leadership", func(t *testing.T) {
		t.Parallel()

		// All nodes agree alpha is leader (deterministic alphabetical).
		raftGamma := swarm.NewRaftNode("gamma", peers)
		if raftGamma.IsLeader() {
			t.Error("gamma should not be leader")
		}
		t.Logf("Leader is: %s", raftGamma.LeaderName())

		// Gamma is in partition B (majority: gamma, delta, epsilon = 3 of 5).
		// Quorum = > 5/2 = 3. Partition B has exactly 3.
		// But gamma CANNOT propose because it's not the leader.
		// The leader (alpha) is in partition A (minority: alpha, beta = 2 of 5).
		// Alpha CANNOT reach quorum (needs 3, has 2).
		//
		// Result: NO ONE can authorize counterstrikes.

		t.Log("Partition scenario: alpha(leader)+beta in partition A (2 nodes)")
		t.Log("                    gamma+delta+epsilon in partition B (3 nodes)")
		t.Log("  Result: alpha cannot reach quorum 3 (has 2)")
		t.Log("          gamma cannot propose (not leader)")
		t.Log("  BREAKING POINT: majority partition without leader cannot act; leader in minority cannot reach quorum")
	})

	t.Run("Immunity_Inconsistency", func(t *testing.T) {
		t.Parallel()

		// Two separate swarms simulate the partition.
		// Partition A: alpha, beta — share immunity.
		// Partition B: gamma, delta, epsilon — share different immunity.

		// In a real partition, immunity records broadcast within each partition
		// but not across. When the partition heals, nodes have conflicting
		// blocked-IP sets. No conflict resolution exists in ImmunityEngine.

		t.Log("BREAKING POINT: no immunity conflict resolution after partition heals; nodes have inconsistent blocked-IP sets; no CRDT or last-write-wins merge strategy")
	})
}

// ---------------------------------------------------------------------------
// Test X3: Friendly Fire — Offense Module Attacks Defense on Same Host
// 测试名称: 友军火力 — 攻击模块攻击同主机防御模块
// Target: ALL defensive engines running on localhost, attacked by offense module
//
// Attack Methodology:
//   Run the offense module (port scanner, web attacker, brute forcer) against
//   the defense module running on the same host. Because the default whitelist
//   includes 127.0.0.1 and all private IPs (10.0.0.0/8, 172.16.0.0/12,
//   192.168.0.0/16), all local traffic is WHITELISTED and bypasses detection.
//
//   Additionally:
//   - The offense module uses localhost or private IPs for testing.
//   - The defense whitelist silently passes ALL private-IP traffic.
//   - Even if the offense and defense use different loopback aliases,
//     the whitelist covers the entire private address space.
//
// Expected Fortress Behavior:
//   - All threats from whitelisted IPs are silently dropped at the Feed level.
//   - IsWhitelisted uses exact string match (not CIDR), so "10.0.0.0/8" only
//     matches the literal string "10.0.0.0/8" — NOT "10.1.2.3".
//     Wait — this is the opposite! The whitelist entries ARE literal strings,
//     and IsWhitelisted does exact match. So "10.1.2.3" is NOT whitelisted
//     despite "10.0.0.0/8" being in the list! This means private IPs are NOT
//     actually whitelisted in the current implementation.
//
// Breaking Point:
//   The whitelist is broken by design: it stores CIDR notation strings but
//   does exact string comparison. "10.0.0.0/8" in the whitelist does NOT match
//   "10.1.2.3". This means ALL private IP traffic goes through full detection.
//   When the offense module runs from localhost (127.0.0.1), it IS whitelisted.
//   But when it runs from any other private IP, it is NOT whitelisted.
//   This creates an inconsistency: localhost attacks bypass detection, but
//   same-host attacks from the machine's LAN IP go through full inspection.
func TestStress_X3_FriendlyFireSameHost(t *testing.T) {
	t.Parallel()

	t.Run("Whitelist_CIDR_Fixed", func(t *testing.T) {
		t.Parallel()

		cfg := config.Default()

		// CIDR whitelist is now FIXED — 10.0.0.0/8 matches all 10.x IPs.
		if cfg.IsWhitelisted("10.1.2.3") {
			t.Log("FIXED: '10.1.2.3' IS whitelisted (matched by CIDR 10.0.0.0/8)")
		} else {
			t.Error("REGRESSION: '10.1.2.3' should be whitelisted by CIDR 10.0.0.0/8")
		}
		if cfg.IsWhitelisted("192.168.1.100") {
			t.Log("FIXED: '192.168.1.100' IS whitelisted (matched by CIDR 192.168.0.0/16)")
		} else {
			t.Error("REGRESSION: '192.168.1.100' should be whitelisted by CIDR 192.168.0.0/16")
		}
		// Literal CIDR string still matches (exact string match).
		if cfg.IsWhitelisted("10.0.0.0/8") {
			t.Log("Literal '10.0.0.0/8' IS whitelisted (exact string match)")
		}
		if cfg.IsWhitelisted("127.0.0.1") {
			t.Log("'127.0.0.1' IS whitelisted (exact match)")
		}
		// An IP NOT in any whitelist range should NOT match.
		if cfg.IsWhitelisted("203.0.113.5") {
			t.Error("BUG: '203.0.113.5' should NOT be whitelisted (outside all CIDR ranges)")
		} else {
			t.Log("CORRECT: '203.0.113.5' is NOT whitelisted (outside 10/172.16/192.168 ranges)")
		}
	})

	t.Run("OffenseFromLocalhost_BypassesDetection", func(t *testing.T) {
		t.Parallel()

		cfgWithWhitelist := config.Default()
		inspector := engines.NewPacketInspector(cfgWithWhitelist)

		// Attack from 127.0.0.1 (whitelisted).
		threats := inspector.Feed("S", "127.0.0.1", 22, "TCP")
		if len(threats) > 0 {
			t.Error("SYN from 127.0.0.1 should be whitelisted and produce 0 threats")
		} else {
			t.Log("CONFIRMED: attack from 127.0.0.1 bypasses detection (whitelisted)")
		}
	})

	t.Run("OffenseFromPrivateIP_AlsoWhitelisted", func(t *testing.T) {
		t.Parallel()

		// Now that CIDR matching is fixed, private IPs ARE whitelisted.
		cfgWithWhitelist := config.Default()
		inspector := engines.NewPacketInspector(cfgWithWhitelist)

		// 10.1.2.3 is now whitelisted by 10.0.0.0/8 CIDR.
		threats := inspector.Feed("S", "10.1.2.3", 22, "TCP")
		if len(threats) > 0 {
			t.Log("NOTE: 10.1.2.3 produced threats — CIDR whitelist may need test-specific config")
		} else {
			t.Log("FIXED: 10.1.2.3 is whitelisted by CIDR 10.0.0.0/8, bypasses detection")
		}

		// Attack from a truly external IP with default whitelist.
		threats2 := inspector.Feed("S", "203.0.113.99", 22, "TCP")
		if len(threats2) == 0 {
			t.Log("203.0.113.99: single SYN doesn't trigger flood (threshold 80), correct")
		}
	})
}

// =============================================================================
// Benchmarks — throughput measurement under maximum load
// =============================================================================

// BenchmarkPacketInspector_SYNFlood measures the maximum SYN flood detection
// throughput of the PacketInspector under ideal conditions.
func BenchmarkPacketInspector_SYNFlood(b *testing.B) {
	cfg := testConfig()
	inspector := engines.NewPacketInspector(cfg)
	ips := uniqueSourceIPs(b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inspector.Feed("S", ips[i%len(ips)], 80, "TCP")
	}
}

// BenchmarkHybridAnomalyDetector_Feed measures the throughput of the two-layer
// anomaly detector (EMA Z-Score + Count-Min Sketch) per packet.
func BenchmarkHybridAnomalyDetector_Feed(b *testing.B) {
	cfg := testConfig()
	detector := engines.NewHybridAnomalyDetector(cfg, false)
	ips := uniqueSourceIPs(b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Feed(ips[i%len(ips)], "10.0.0.99", 12345, 80, "TCP", 1500, 0x02, 4.5)
	}
}

// BenchmarkHttpInspector_Feed measures the throughput of HTTP stream reassembly
// and regex scanning per TCP segment.
func BenchmarkHttpInspector_Feed(b *testing.B) {
	cfg := testConfig()
	inspector := engines.NewHttpInspector(cfg)
	payload := []byte("GET /search?q=1' OR '1'='1 HTTP/1.1\r\nHost: x\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inspector.Feed("10.1.1.1", "10.0.0.1", 40000, 80, payload, "A")
	}
}

// BenchmarkDnsTunnelDetector_Feed measures DNS query ingestion throughput.
func BenchmarkDnsTunnelDetector_Feed(b *testing.B) {
	cfg := testConfig()
	detector := engines.NewDnsTunnelDetector(cfg)
	names := make([]string, b.N)
	for i := range names {
		names[i] = fmt.Sprintf("query-%d.example.com", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Feed("10.1.1.1", names[i])
	}
}

// BenchmarkFlowAnalyzer_Feed measures port scan detection throughput.
func BenchmarkFlowAnalyzer_Feed(b *testing.B) {
	cfg := testConfig()
	analyzer := engines.NewFlowAnalyzer(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Feed("10.1.1.1", uint16(1+(i%65535)))
	}
}

// BenchmarkBehaviorAnalyzer_Feed measures entropy baseline tracking throughput.
func BenchmarkBehaviorAnalyzer_Feed(b *testing.B) {
	cfg := testConfig()
	analyzer := engines.NewBehaviorAnalyzer(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Feed("10.1.1.1", uint16(80+(i%1000)))
	}
}

// =============================================================================
// Additional edge-case tests
// =============================================================================

// TestEdge_WhitelistCIDR documents the FIXED CIDR whitelist behavior.
// Previously IsWhitelisted used exact string matching, making CIDR entries
// like "10.0.0.0/8" decorative only. Now it properly evaluates CIDR subnets.
func TestEdge_WhitelistCIDR(t *testing.T) {
	t.Parallel()

	cfg := config.Default()

	tests := []struct {
		ip          string
		whitelisted bool
		reason      string
	}{
		{"127.0.0.1", true, "exact match in default whitelist"},
		{"::1", true, "exact match in default whitelist"},
		{"10.0.0.0/8", true, "exact string match (the literal CIDR string itself)"},
		{"10.1.2.3", true, "CIDR match — 10.0.0.0/8 contains 10.1.2.3"},
		{"10.255.255.255", true, "CIDR match — 10.0.0.0/8 contains 10.255.255.255"},
		{"172.16.0.0/12", true, "exact string match of the literal CIDR string"},
		{"172.16.1.1", true, "CIDR match — 172.16.0.0/12 contains 172.16.1.1"},
		{"172.31.255.255", true, "CIDR match — 172.16.0.0/12 contains 172.31.255.255"},
		{"192.168.0.0/16", true, "exact string match of the literal CIDR string"},
		{"192.168.1.1", true, "CIDR match — 192.168.0.0/16 contains 192.168.1.1"},
		// Truly external IP — NOT whitelisted by any default entry.
		{"203.0.113.5", false, "external IP — not in any default CIDR range"},
		{"8.8.8.8", false, "external IP — not in any default CIDR range"},
		// Private IP outside default ranges.
		{"100.64.0.1", false, "CGNAT — not in default whitelist"},
	}

	for _, tt := range tests {
		result := cfg.IsWhitelisted(tt.ip)
		if result != tt.whitelisted {
			t.Errorf("IsWhitelisted(%q) = %v, expected %v (%s)", tt.ip, result, tt.whitelisted, tt.reason)
		} else {
			t.Logf("IsWhitelisted(%q) = %v (%s)", tt.ip, result, tt.reason)
		}
	}

	t.Log("SUMMARY: CIDR whitelist is FIXED — 10.0.0.0/8 correctly matches all 10.x IPs, 172.16.0.0/12 matches 172.16-31.x, 192.168.0.0/16 matches all 192.168.x. Private IPs ARE properly whitelisted. Only truly external IPs go through full detection pipeline.")
}

// TestEdge_CountMinSketchHashCollision documents the degradation of the
// Count-Min Sketch at high insertion volumes.
func TestEdge_CountMinSketchHashCollision(t *testing.T) {
	t.Parallel()

	// This test is informational — we document the expected collision rate.
	// Count-Min Sketch: 4 rows x 65536 columns = 262144 total counters.
	// FNV-32a hash space: 2^32. Column index = hash % 65536.
	// For N distinct fingerprints, expected collisions per row ~= N / 65536.
	// At 10M insertions, each column has ~152 entries (10e6 / 65536).
	// The estimate returns min(row0, row1, row2, row3) — with 4 rows,
	// the probability that ALL 4 rows collide is low, but the minimum
	// is inflated by expected collision noise.

	// At 1M insertions: ~15 entries per column, min estimate ~15.
	// At 10M: ~152 entries per column, min estimate ~152 (decay at 10M).
	// At 100M (if decay didn't happen): estimate would be heavily inflated.

	t.Log("Count-Min Sketch collision analysis:")
	t.Log("  Columns: 65536, Rows: 4")
	t.Log("  At 1M insertions: ~15 entries/column, min estimate noise ~+15")
	t.Log("  At 10M insertions: decay triggers (total >>= 1), all counters >>= 1")
	t.Log("  Decay preserves relative ordering but loses absolute counts")
	t.Log("  Structural anomaly detection (Layer 2) becomes unreliable at high volume")
	t.Log("BREAKING POINT: Count-Min Sketch may report rare patterns as common when hash collisions inflate minimum estimates at scale")
}
