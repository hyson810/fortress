// Package swarm implements the Fortress distributed protocol for peer
// discovery, threat intel sharing, and consensus-based counterstrikes.
//
// consensus.go provides a simplified Raft consensus engine used to approve
// autonomous counterstrike decisions across the swarm (D阶 authorization).
package swarm

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// RaftState
// ---------------------------------------------------------------------------

// RaftState represents the node's role in the simplified Raft protocol.
type RaftState int

const (
	Follower  RaftState = iota
	Candidate            // reserved for future election support
	Leader
)

func (s RaftState) String() string {
	switch s {
	case Follower:
		return "follower"
	case Candidate:
		return "candidate"
	case Leader:
		return "leader"
	default:
		return "unknown"
	}
}

// Raft protocol constants.
const (
	voteTimeout = 5 * time.Second
)

// ---------------------------------------------------------------------------
// RaftVote
// ---------------------------------------------------------------------------

// RaftVote is the wire format for a single vote in a counterstrike proposal.
// Vote messages are broadcast through the gossip threat_intel channel with
// JSON-marshalled RaftVote. The Type field discriminates raft_vote payloads
// from other threat-intel traffic.
type RaftVote struct {
	Type       string  `json:"type"`
	ProposalID string  `json:"proposal_id"`
	IP         string  `json:"ip"`
	Score      float64 `json:"score"`
	Threshold  float64 `json:"threshold"`
	Voter      string  `json:"voter"`
	Approve    bool    `json:"approve"`
	Timestamp  int64   `json:"ts"`
}

// ---------------------------------------------------------------------------
// proposalRecord
// ---------------------------------------------------------------------------

// proposalRecord tracks the in-flight state of a single counterstrike proposal.
type proposalRecord struct {
	ID        string
	IP        string
	Score     float64
	Threshold float64
	StartTime time.Time
	Votes     map[string]bool // voter -> approve
	Result    chan bool
	Resolved  bool
}

// ---------------------------------------------------------------------------
// RaftNode
// ---------------------------------------------------------------------------

// RaftNode participates in simplified Raft consensus for counterstrike
// authorization. It uses deterministic leadership (alphabetically first
// peer name) and broadcasts vote messages through an attached GossipNode.
//
// All exported methods are safe for concurrent use.
type RaftNode struct {
	mu          sync.RWMutex
	name        string
	peers       []string
	state       RaftState
	gossip      *GossipNode
	proposals   map[string]*proposalRecord
	voteTimeout time.Duration
	stopCh      chan struct{}
}

// NewRaftNode creates a RaftNode with the given node name and initial peer
// list. The peer list is used in leadership determination and quorum
// calculation until a GossipNode is attached via SetGossipNode.
// Leadership is deterministic: the alphabetically first peer name wins.
func NewRaftNode(name string, peers []string) *RaftNode {
	rn := &RaftNode{
		name:        name,
		peers:       append([]string(nil), peers...),
		state:       Follower,
		proposals:   make(map[string]*proposalRecord),
		voteTimeout: voteTimeout,
		stopCh:      make(chan struct{}),
	}

	// Deterministic leadership by alphabetical order.
	sorted := make([]string, len(peers)+1)
	copy(sorted, peers)
	sorted[len(peers)] = name
	sort.Strings(sorted)
	if sorted[0] == name {
		rn.state = Leader
		log.Printf("[raft] %s is leader (alphabetical)", name)
	}
	return rn
}

// SetGossipNode attaches a GossipNode for vote-message broadcasting and
// dynamic peer discovery. It registers a threat-intel callback to receive
// incoming raft_vote messages. Call before proposing counterstrikes.
func (r *RaftNode) SetGossipNode(g *GossipNode) {
	r.mu.Lock()
	r.gossip = g
	r.mu.Unlock()

	g.OnThreatIntel(func(peerName string, data []byte) {
		var vote RaftVote
		if err := json.Unmarshal(data, &vote); err != nil {
			return
		}
		if vote.Type != "raft_vote" || vote.ProposalID == "" {
			return
		}
		r.recordVote(vote)
	})
}

// IsLeader returns true if this node is the current leader.
func (r *RaftNode) IsLeader() bool {
	return r.LeaderName() == r.name
}

// LeaderName returns the name of the current leader. The leader is
// deterministically the alphabetically first name among all known peers.
// If the gossip node is attached, only alive peers are considered.
func (r *RaftNode) LeaderName() string {
	r.mu.RLock()
	gossip := r.gossip
	r.mu.RUnlock()

	candidates := r.peerNames(gossip)
	if len(candidates) == 0 {
		return r.name
	}

	sort.Strings(candidates)
	return candidates[0]
}

// ProposeCounterstrike initiates a consensus round for a counterstrike
// against the given IP. Only the leader may propose. Returns true if
// consensus is reached (> N/2 approvals including self) within the vote
// timeout window.
func (r *RaftNode) ProposeCounterstrike(ip string, score float64, threshold float64) bool {
	r.mu.Lock()
	if r.state != Leader {
		r.mu.Unlock()
		log.Printf("[raft] not leader, cannot propose counterstrike for %s", ip)
		return false
	}

	pid := fmt.Sprintf("%s-%s-%d", r.name, ip, time.Now().UnixNano())
	prop := &proposalRecord{
		ID:        pid,
		IP:        ip,
		Score:     score,
		Threshold: threshold,
		StartTime: time.Now(),
		Votes:     make(map[string]bool),
		Result:    make(chan bool, 1),
	}
	// Leader auto-votes yes.
	prop.Votes[r.name] = true
	r.proposals[pid] = prop

	// Capture gossip reference under lock to avoid data race.
	gossip := r.gossip
	r.mu.Unlock()

	// Broadcast proposal via gossip.
	if gossip != nil {
		vote := RaftVote{
			Type:       "raft_vote",
			ProposalID: pid,
			IP:         ip,
			Score:      score,
			Threshold:  threshold,
			Voter:      r.name,
			Approve:    true,
			Timestamp:  time.Now().Unix(),
		}
		data, err := json.Marshal(vote)
		if err == nil {
			gossip.BroadcastThreatIntel(data)
		}
	}

	log.Printf("[raft] %s proposed counterstrike %s (score=%.1f threshold=%.1f)",
		r.name, pid, score, threshold)

	// Wait for quorum with timeout.
	quorum := len(r.peers)/2 + 1
	timer := time.NewTimer(r.voteTimeout)
	defer timer.Stop()

	for {
		r.mu.RLock()
		yesVotes := 0
		totalVotes := 0
		for _, v := range prop.Votes {
			totalVotes++
			if v {
				yesVotes++
			}
		}
		resolved := prop.Resolved
		r.mu.RUnlock()

		if resolved || yesVotes >= quorum {
			log.Printf("[raft] counterstrike approved for %s (%d/%d votes)", ip, yesVotes, totalVotes)
			r.mu.Lock()
			delete(r.proposals, pid)
			r.mu.Unlock()
			return true
		}

		select {
		case <-timer.C:
			r.mu.Lock()
			delete(r.proposals, pid)
			r.mu.Unlock()
			log.Printf("[raft] counterstrike TIMEOUT for %s (got %d yes votes, need %d)", ip, yesVotes, quorum)
			return false
		case result := <-prop.Result:
			return result
		case <-time.After(100 * time.Millisecond):
			// Re-check vote count on next iteration.
		}
	}
}

// QuorumSize returns the number of votes needed for consensus (> N/2).
func (r *RaftNode) QuorumSize() int {
	return len(r.peers)/2 + 1
}

// Stop signals the RaftNode to shut down background goroutines.
func (r *RaftNode) Stop() {
	close(r.stopCh)
}

// ---------------------------------------------------------------------------
// internal: vote recording & proposal evaluation
// ---------------------------------------------------------------------------

func (r *RaftNode) recordVote(vote RaftVote) {
	r.mu.Lock()
	defer r.mu.Unlock()

	prop, ok := r.proposals[vote.ProposalID]
	if !ok {
		// Ignore votes for proposals that have already timed out.
		if time.Now().Unix() > vote.Timestamp+int64(voteTimeout.Seconds()) {
			return
		}

		// Create a tracker for proposals we didn't originate (as a follower).
		prop = &proposalRecord{
			ID:        vote.ProposalID,
			IP:        vote.IP,
			Score:     vote.Score,
			Threshold: vote.Threshold,
			StartTime: time.Now(),
			Votes:     make(map[string]bool),
			Result:    make(chan bool, 1),
		}
		r.proposals[vote.ProposalID] = prop

		// Auto-vote yes if score exceeds threshold.
		autoApprove := vote.Score >= vote.Threshold
		prop.Votes[r.name] = autoApprove

		log.Printf("[raft] received proposal %s from %s (score=%.1f threshold=%.1f)",
			vote.ProposalID, vote.Voter, vote.Score, vote.Threshold)

		// Re-broadcast the proposal via gossip (epidemic relay).
		gossip := r.gossip
		if gossip != nil {
			selfVote := RaftVote{
				Type:       "raft_vote",
				ProposalID: vote.ProposalID,
				IP:         vote.IP,
				Score:      vote.Score,
				Threshold:  vote.Threshold,
				Voter:      r.name,
				Approve:    autoApprove,
				Timestamp:  time.Now().Unix(),
			}
			data, err := json.Marshal(selfVote)
			if err == nil {
				go func() {
					gossip.BroadcastThreatIntel(data)
				}()
			}
		}
	}

	// Record the incoming vote (dedup by voter name).
	if _, exists := prop.Votes[vote.Voter]; !exists {
		prop.Votes[vote.Voter] = vote.Approve
		log.Printf("[raft] vote on %s: %s=%v", vote.ProposalID, vote.Voter, vote.Approve)
	}

	// Check if we have enough votes to decide now.
	r.evaluateProposalLocked(prop)
}

// evaluateProposalLocked checks whether the proposal has reached a decision
// and signals Result if so. Caller must hold r.mu.
func (r *RaftNode) evaluateProposalLocked(prop *proposalRecord) {
	if prop.Resolved {
		return
	}

	quorum := r.quorumSizeLocked()

	yesVotes := 0
	totalVotes := 0
	for _, approve := range prop.Votes {
		totalVotes++
		if approve {
			yesVotes++
		}
	}

	// Decide when we have all possible votes or enough yes votes for approval.
	allVoted := totalVotes >= quorum
	approved := yesVotes >= quorum
	rejected := (totalVotes - yesVotes) > quorum/2

	if allVoted || approved || rejected {
		prop.Resolved = true
		log.Printf("[raft] proposal %s result: %d yes / %d total (quorum=%d) => approved=%v",
			prop.ID, yesVotes, totalVotes, quorum, approved)

		select {
		case prop.Result <- approved:
		default:
		}
	}
}

// quorumSizeLocked returns the number of voting peers. Caller must hold r.mu.
func (r *RaftNode) quorumSizeLocked() int {
	return len(r.peerNames(r.gossip))
}

// peerNames returns the set of known peer names. If a gossip node is
// attached, only alive peers are included and self is always present.
func (r *RaftNode) peerNames(gossip *GossipNode) []string {
	if gossip == nil {
		// Fall back to the static peer list.
		names := append([]string(nil), r.peers...)
		for _, n := range names {
			if n == r.name {
				return names
			}
		}
		return append(names, r.name)
	}

	gossipPeers := gossip.GetPeers()
	names := make([]string, 0, len(gossipPeers)+1)
	names = append(names, r.name)
	for _, p := range gossipPeers {
		if p.State == PeerAlive && p.Name != "" && p.Name != r.name {
			names = append(names, p.Name)
		}
	}
	return names
}
