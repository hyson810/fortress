package swarm_test

import (
	"testing"
	"time"

	"github.com/fortress/v6/internal/swarm"
)

// ---------------------------------------------------------------------------
// Test 5: New Node Is Follower
// ---------------------------------------------------------------------------

func TestRaftNode_NewNodeIsFollower(t *testing.T) {
	rn := swarm.NewRaftNode("hydra-1", []string{"hydra-1", "hydra-2", "hydra-3"})
	defer rn.Stop()

	// A freshly created node must start as a follower, not auto-leader.
	if rn.IsLeader() {
		t.Fatal("new RaftNode must NOT be leader; got leader immediately")
	}

	// LeaderName should default to self when no leader is known.
	if name := rn.LeaderName(); name != "hydra-1" {
		t.Errorf("LeaderName = %q, want %q (defaults to self when unknown)", name, "hydra-1")
	}
}

// ---------------------------------------------------------------------------
// Test 6: Leader Election (3 nodes)
// ---------------------------------------------------------------------------

func TestRaftNode_LeaderElection(t *testing.T) {
	portA := freePort(t)
	addrA := formatAddr(portA)
	portB := freePort(t)
	addrB := formatAddr(portB)
	portC := freePort(t)
	addrC := formatAddr(portC)

	// Full-mesh gossip seeding so all nodes know each other's addresses
	// before Raft elections begin. Without this, nodes that start with
	// an empty seed list cannot send to peers they haven't discovered yet.
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

	gA.Start()
	gB.Start()
	gC.Start()
	defer gA.Stop()
	defer gB.Stop()
	defer gC.Stop()

	// Wait for the gossip mesh to form — pings fire every 5 s.
	// All nodes should have at least 1 peer before we start Raft.
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if gA.PeerCount() >= 2 && gB.PeerCount() >= 2 && gC.PeerCount() >= 2 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("gossip ready: A=%d B=%d C=%d", gA.PeerCount(), gB.PeerCount(), gC.PeerCount())

	// Now create RaftNodes — elections will start with a working mesh.
	allPeers := []string{"alpha", "bravo", "charlie"}
	rA := swarm.NewRaftNode("alpha", allPeers)
	rB := swarm.NewRaftNode("bravo", allPeers)
	rC := swarm.NewRaftNode("charlie", allPeers)
	defer rA.Stop()
	defer rB.Stop()
	defer rC.Stop()

	// Moderate timeouts: fast enough for tests, slow enough that
	// RequestVote round-trips can complete before the next election.
	rA.SetElectionTimeoutRange(300*time.Millisecond, 800*time.Millisecond)
	rB.SetElectionTimeoutRange(300*time.Millisecond, 800*time.Millisecond)
	rC.SetElectionTimeoutRange(300*time.Millisecond, 800*time.Millisecond)

	rA.SetGossipNode(gA)
	rB.SetGossipNode(gB)
	rC.SetGossipNode(gC)

	// Wait for leader election — up to 15 seconds.
	electionDeadline := time.Now().Add(15 * time.Second)
	var leaderA, leaderB, leaderC string
	converged := false
	for time.Now().Before(electionDeadline) {
		leaderA = rA.LeaderName()
		leaderB = rB.LeaderName()
		leaderC = rC.LeaderName()

		if leaderA == leaderB && leaderB == leaderC && leaderA != "" {
			converged = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	t.Logf("leaders: A=%q B=%q C=%q", leaderA, leaderB, leaderC)

	if !converged {
		t.Fatalf("leader election did not converge: A=%q B=%q C=%q", leaderA, leaderB, leaderC)
	}

	// Exactly one node should be the leader.
	leaders := 0
	if rA.IsLeader() {
		leaders++
		t.Log("A is leader")
	}
	if rB.IsLeader() {
		leaders++
		t.Log("B is leader")
	}
	if rC.IsLeader() {
		leaders++
		t.Log("C is leader")
	}

	if leaders != 1 {
		t.Errorf("expected exactly 1 leader, got %d", leaders)
	}
}

// ---------------------------------------------------------------------------
// Test 7: Quorum Calculation
// ---------------------------------------------------------------------------

func TestRaftNode_QuorumCalculation(t *testing.T) {
	tests := []struct {
		name       string
		peers      []string
		wantQuorum int
	}{
		{"1 node",  []string{"n1"},                           1},
		{"2 nodes", []string{"n1", "n2"},                     2}, // floor(2/2)+1 = 2
		{"3 nodes", []string{"n1", "n2", "n3"},               2}, // floor(3/2)+1 = 2
		{"5 nodes", []string{"n1", "n2", "n3", "n4", "n5"},   3}, // floor(5/2)+1 = 3
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rn := swarm.NewRaftNode(tt.peers[0], tt.peers)
			defer rn.Stop()

			got := rn.QuorumSize()
			if got != tt.wantQuorum {
				t.Errorf("QuorumSize() = %d, want %d (peers=%v)", got, tt.wantQuorum, tt.peers)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 8: Propose Counterstrike
// ---------------------------------------------------------------------------

func TestRaftNode_ProposeCounterstrike(t *testing.T) {
	portA := freePort(t)
	addrA := formatAddr(portA)
	portB := freePort(t)
	addrB := formatAddr(portB)
	portC := freePort(t)
	addrC := formatAddr(portC)

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

	gA.Start()
	gB.Start()
	gC.Start()
	defer gA.Stop()
	defer gB.Stop()
	defer gC.Stop()

	// Wait for gossip mesh.
	meshDeadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(meshDeadline) {
		if gA.PeerCount() >= 2 && gB.PeerCount() >= 2 && gC.PeerCount() >= 2 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	allPeers := []string{"alpha", "bravo", "charlie"}
	rA := swarm.NewRaftNode("alpha", allPeers)
	rB := swarm.NewRaftNode("bravo", allPeers)
	rC := swarm.NewRaftNode("charlie", allPeers)
	defer rA.Stop()
	defer rB.Stop()
	defer rC.Stop()

	rA.SetElectionTimeoutRange(300*time.Millisecond, 800*time.Millisecond)
	rB.SetElectionTimeoutRange(300*time.Millisecond, 800*time.Millisecond)
	rC.SetElectionTimeoutRange(300*time.Millisecond, 800*time.Millisecond)

	rA.SetGossipNode(gA)
	rB.SetGossipNode(gB)
	rC.SetGossipNode(gC)

	// Wait for leader election.
	electionDeadline := time.Now().Add(15 * time.Second)
	leaderFound := false
	for time.Now().Before(electionDeadline) {
		la, lb, lc := rA.LeaderName(), rB.LeaderName(), rC.LeaderName()
		if la == lb && lb == lc && la != "" {
			leaderFound = true
			t.Logf("leader elected: %s (term: A=%d B=%d C=%d)", la, rA.CurrentTerm(), rB.CurrentTerm(), rC.CurrentTerm())
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !leaderFound {
		t.Fatal("leader election did not converge")
	}

	// Find the leader node.
	var leader *swarm.RaftNode
	for _, r := range []*swarm.RaftNode{rA, rB, rC} {
		if r.IsLeader() {
			leader = r
			break
		}
	}
	if leader == nil {
		t.Fatal("no node believes it is leader")
	}

	// The leader proposes a counterstrike with score >= threshold so
	// followers auto-approve when they relay the proposal.
	approved := leader.ProposeCounterstrike("10.99.0.1", 95.0, 80.0)
	if !approved {
		t.Error("ProposeCounterstrike was not approved; expected quorum consensus")
	}

	// A non-leader must not be allowed to propose.
	for _, r := range []*swarm.RaftNode{rA, rB, rC} {
		if !r.IsLeader() {
			if r.ProposeCounterstrike("10.99.0.2", 90.0, 80.0) {
				t.Error("non-leader should not be able to propose a counterstrike")
			}
			break
		}
	}
}

// ---------------------------------------------------------------------------
// Test 9: Term Monotonic
// ---------------------------------------------------------------------------

func TestRaftNode_TermMonotonic(t *testing.T) {
	// In a single-node cluster without gossip, the RaftNode repeatedly
	// starts elections (no vote responses arrive, so it never wins).
	// Each election increments the term. The key invariant: term must
	// never decrease.
	rn := swarm.NewRaftNode("solo", []string{"solo"})
	defer rn.Stop()

	// Short timeouts so we observe multiple elections quickly.
	rn.SetElectionTimeoutRange(30*time.Millisecond, 60*time.Millisecond)

	initialTerm := rn.CurrentTerm()
	t.Logf("initial term: %d", initialTerm)

	prevTerm := initialTerm
	// Sample term over ~3 seconds — with 30-60ms timeouts we expect
	// multiple election cycles.
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		current := rn.CurrentTerm()
		if current < prevTerm {
			t.Errorf("term decreased: %d → %d (iteration %d)", prevTerm, current, i)
		}
		if current > prevTerm {
			t.Logf("term advanced: %d → %d", prevTerm, current)
		}
		prevTerm = current
	}

	finalTerm := rn.CurrentTerm()
	t.Logf("final term: %d", finalTerm)

	if finalTerm < initialTerm {
		t.Errorf("term decreased over test: %d → %d", initialTerm, finalTerm)
	}
}
