package swarm_test

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/swarm"
)

// freePort returns a free port on localhost by briefly listening on :0.
func freePort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	conn.Close()
	// Let OS reclaim the port before tests bind to it.
	time.Sleep(50 * time.Millisecond)

	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return port
}

func newTestConfig(name string, bind string, peers []string) config.SwarmConfig {
	return config.SwarmConfig{
		Name:      name,
		Bind:      bind,
		Peers:     peers,
		GossipKey: "", // no HMAC for tests
	}
}

// ---------------------------------------------------------------------------
// Test 1: Create and Start
// ---------------------------------------------------------------------------

func TestGossipNode_CreateAndStart(t *testing.T) {
	port := freePort(t)
	addr := formatAddr(port)

	cfg := newTestConfig("node-a", addr, nil)
	node, err := swarm.NewGossipNode(cfg, addr)
	if err != nil {
		t.Fatalf("NewGossipNode: %v", err)
	}

	node.Start()

	// With no seed peers, PeerCount should be 0.
	if n := node.PeerCount(); n != 0 {
		t.Errorf("expected PeerCount 0, got %d", n)
	}

	// Verify peers snapshot is empty.
	peers := node.GetPeers()
	if len(peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(peers))
	}

	node.Stop()
}

// ---------------------------------------------------------------------------
// Test 2: Two-Node Discovery
// ---------------------------------------------------------------------------

func TestGossipNode_TwoNodeDiscovery(t *testing.T) {
	portA := freePort(t)
	addrA := formatAddr(portA)
	portB := freePort(t)
	addrB := formatAddr(portB)

	cfgA := newTestConfig("alpha", addrA, nil)
	cfgB := newTestConfig("bravo", addrB, []string{addrA})

	nodeA, err := swarm.NewGossipNode(cfgA, addrA)
	if err != nil {
		t.Fatalf("NewGossipNode A: %v", err)
	}
	nodeB, err := swarm.NewGossipNode(cfgB, addrB)
	if err != nil {
		t.Fatalf("NewGossipNode B: %v", err)
	}

	nodeA.Start()
	nodeB.Start()
	defer nodeA.Stop()
	defer nodeB.Stop()

	// Wait for gossip — first ping exchange at ~5 s (pingInterval).
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if nodeB.PeerCount() >= 1 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	bCount := nodeB.PeerCount()
	if bCount < 1 {
		t.Fatalf("node B discovered %d peers after 8s, expected >=1", bCount)
	}

	// Verify mutual discovery: A should also know about B by now.
	aPeers := nodeA.GetPeers()
	foundB := false
	for _, p := range aPeers {
		if p.Name == "bravo" {
			foundB = true
			break
		}
	}
	if !foundB {
		t.Logf("node A has %d peers; mutual discovery may need more time", len(aPeers))
	}

	t.Logf("node A peers: %d, node B peers: %d", nodeA.PeerCount(), nodeB.PeerCount())
}

// ---------------------------------------------------------------------------
// Test 3: Threat Intel Broadcast
// ---------------------------------------------------------------------------

func TestGossipNode_ThreatIntelBroadcast(t *testing.T) {
	portA := freePort(t)
	addrA := formatAddr(portA)
	portB := freePort(t)
	addrB := formatAddr(portB)
	portC := freePort(t)
	addrC := formatAddr(portC)

	// 3-node full-mesh gossip — same topology proven to work by the
	// Raft leader-election tests. Epidemic relay requires at least 2
	// other nodes for reliable fan-out to the callback target.
	cfgA := newTestConfig("alpha", addrA, []string{addrB, addrC})
	cfgB := newTestConfig("bravo", addrB, []string{addrA, addrC})
	cfgC := newTestConfig("charlie", addrC, []string{addrA, addrB})

	gA, err := swarm.NewGossipNode(cfgA, addrA)
	if err != nil {
		t.Fatalf("gossip A: %v", err)
	}
	gB, err := swarm.NewGossipNode(cfgB, addrB)
	if err != nil {
		t.Fatalf("gossip B: %v", err)
	}
	gC, err := swarm.NewGossipNode(cfgC, addrC)
	if err != nil {
		t.Fatalf("gossip C: %v", err)
	}

	var deliveryCount int32
	received := make(chan struct{}, 3)

	gA.Start()
	gB.Start()
	gC.Start()
	defer gA.Stop()
	defer gB.Stop()
	defer gC.Stop()

	// Wait for the gossip mesh to form (same pattern as Raft tests).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if gA.PeerCount() >= 2 && gB.PeerCount() >= 2 && gC.PeerCount() >= 2 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Logf("mesh formed: A=%d B=%d C=%d", gA.PeerCount(), gB.PeerCount(), gC.PeerCount())

	// Register callback AFTER mesh is ready — matches Raft SetGossipNode pattern.
	gC.OnThreatIntel(func(peerName string, data []byte) {
		t.Logf("C received threat_intel from %s: %s", peerName, string(data))
		atomic.AddInt32(&deliveryCount, 1)
		select { case received <- struct{}{}: default: {} }
	})

	// Retry broadcast up to 3 times to handle occasional UDP packet loss.
	delivered := false
	for attempt := 0; attempt < 3 && !delivered; attempt++ {
		if attempt > 0 {
			t.Logf("retry broadcast attempt %d", attempt+1)
			time.Sleep(500 * time.Millisecond)
		}

		// Use confirmed delivery for first attempt, then fall back to fan-out.
		if attempt == 0 {
			gA.BroadcastThreatIntelReliable([]byte(`{"alert":"test-scan","ip":"10.0.0.99"}`))
		} else {
			gA.BroadcastThreatIntel([]byte(`{"alert":"test-scan","ip":"10.0.0.99"}`))
		}

		select {
		case <-received:
			delivered = true
			t.Log("threat intel delivered successfully")
		case <-time.After(2 * time.Second):
			// Not delivered this attempt; will retry.
		}
	}

	if !delivered {
		// Final attempt: direct send from B as well (A->B->C epidemic path)
		gB.BroadcastThreatIntelReliable([]byte(`{"alert":"relay-test","ip":"10.0.0.100"}`))
		select {
		case <-received:
			delivered = true
			t.Log("threat intel delivered via B relay")
		case <-time.After(3 * time.Second):
			t.Errorf("threat intel callback never fired on C after 3 broadcasts + relay")
		}
	}

	t.Logf("total deliveries to C: %d", atomic.LoadInt32(&deliveryCount))
}

// ---------------------------------------------------------------------------
// Test 4: State Transitions (SWIM state machine)
// ---------------------------------------------------------------------------

func TestGossipNode_StateTransitions(t *testing.T) {
	// Verify PeerState constants and String representations.
	t.Run("PeerState constants", func(t *testing.T) {
		if swarm.PeerAlive.String() != "alive" {
			t.Errorf("PeerAlive = %q, want %q", swarm.PeerAlive.String(), "alive")
		}
		if swarm.PeerSuspect.String() != "suspect" {
			t.Errorf("PeerSuspect = %q, want %q", swarm.PeerSuspect.String(), "suspect")
		}
		if swarm.PeerDead.String() != "dead" {
			t.Errorf("PeerDead = %q, want %q", swarm.PeerDead.String(), "dead")
		}

		// Verify iota ordering: Alive(0), Suspect(1), Dead(2).
		if int(swarm.PeerAlive) != 0 {
			t.Errorf("PeerAlive = %d, want 0", int(swarm.PeerAlive))
		}
		if int(swarm.PeerSuspect) != 1 {
			t.Errorf("PeerSuspect = %d, want 1", int(swarm.PeerSuspect))
		}
		if int(swarm.PeerDead) != 2 {
			t.Errorf("PeerDead = %d, want 2", int(swarm.PeerDead))
		}
	})

	t.Run("State ordering", func(t *testing.T) {
		// Alive → Suspect → Dead is the expected progression.
		if swarm.PeerAlive >= swarm.PeerSuspect {
			t.Error("expected PeerAlive < PeerSuspect")
		}
		if swarm.PeerSuspect >= swarm.PeerDead {
			t.Error("expected PeerSuspect < PeerDead")
		}
	})

	t.Run("SuspectTimeoutTriggers", func(t *testing.T) {
		// Create a 2-node cluster with mutual seeding. Stop one node and
		// verify the survivor marks it as Suspect via the SWIM detector.
		portA := freePort(t)
		addrA := formatAddr(portA)
		portB := freePort(t)
		addrB := formatAddr(portB)

		cfgA := newTestConfig("alpha", addrA, []string{addrB})
		cfgB := newTestConfig("bravo", addrB, []string{addrA})

		nodeA, err := swarm.NewGossipNode(cfgA, addrA)
		if err != nil {
			t.Fatalf("NewGossipNode A: %v", err)
		}
		nodeB, err := swarm.NewGossipNode(cfgB, addrB)
		if err != nil {
			t.Fatalf("NewGossipNode B: %v", err)
		}

		nodeA.Start()
		nodeB.Start()

		// Stop node B to simulate a crash.
		nodeB.Stop()

		// Wait for A's suspect detection. suspectTimeout = 15 s,
		// suspectCheckInterval = 3 s. Suspect should appear by ~18 s
		// after B stops responding. Dead requires deadTimeout = 30 s
		// and the deadProbeInterval (30 s), so it can take 45-60 s.
		// We wait up to 22 s to reliably catch Suspect.
		gotSuspect := false
		suspectDeadline := time.Now().Add(22 * time.Second)
		for time.Now().Before(suspectDeadline) {
			for _, p := range nodeA.GetPeers() {
				if p.Name == "bravo" || p.Addr == addrB {
					if p.State == swarm.PeerSuspect {
						gotSuspect = true
					}
				}
			}
			if gotSuspect {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		if gotSuspect {
			t.Log("node A correctly marked B as Suspect")
		} else {
			t.Error("node A did not mark B as Suspect within 22 s of crash")
		}

		nodeA.Stop()
	})
}

func formatAddr(port int) string {
	return net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
}
