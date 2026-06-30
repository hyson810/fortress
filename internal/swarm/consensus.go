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
	"math/rand"
	"runtime/debug"
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
	Candidate            // actively seeking election
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

	// Default election timeouts are randomized per node to avoid split votes.
		// Wider range (500-1500ms) prevents simultaneous candidate transitions
		// that cause split-vote deadlock in gossip-based propagation.
	defaultElectionTimeoutMin = 500 * time.Millisecond
	defaultElectionTimeoutMax = 1500 * time.Millisecond

	// Heartbeat interval must be shorter than the election timeout so
	// followers do not time out while the leader is alive.
	heartbeatInterval = 100 * time.Millisecond
)

// ---------------------------------------------------------------------------
// RaftVote (counterstrike proposal votes — unchanged wire format)
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
// RaftRPCMessage (leader-election protocol messages)
// ---------------------------------------------------------------------------

// RaftRPCMessage is the wire format for Raft leader-election RPCs. These
// are broadcast through the same gossip threat_intel channel that carries
// RaftVote messages and ImmunityRecords. The Type field discriminates:
//
//	"raft_request_vote"       — Candidate soliciting votes
//	"raft_request_vote_resp"  — Follower response to a vote request
//	"raft_heartbeat"          — Leader AppendEntries heartbeat
type RaftRPCMessage struct {
	Type string `json:"type"` // one of the three values above
	Term uint64 `json:"term"`
	From string `json:"from"`

	// RequestVote fields
	CandidateID string `json:"candidate_id,omitempty"`

	// RequestVoteResponse fields
	VoteGranted bool `json:"vote_granted,omitempty"`

	// Heartbeat (AppendEntries) fields
	LeaderID string `json:"leader_id,omitempty"`
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
// authorization. It uses randomized election timeouts (150–300 ms) to elect
// a leader — no alphabetical tie-breaking. Leader-election RPCs
// (RequestVote, heartbeat) and counterstrike proposal votes both flow
// through the attached GossipNode's threat_intel epidemic channel.
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

	// ---- Raft leader-election fields ----
	currentTerm uint64
	votedFor    string // peer we voted for in currentTerm ("" if none)
	leaderID    string // peer we believe is the current leader

	// electionTimer fires after a randomized duration; reset on every
	// heartbeat from a valid leader.
	electionTimer *time.Timer

	// electionVotes tracks votes received during the current election.
	// Only accessed while state == Candidate and holding mu.
	electionVotes map[string]bool // voter -> granted

	// heartbeatStop is closed when the node stops being leader, causing
	// the heartbeat goroutine to exit.
	heartbeatStop chan struct{}

	// electionTimeoutMin/Max are the per-instance election timeout bounds.
	// They default to defaultElectionTimeoutMin/Max but may be tightened
	// via SetElectionTimeoutRange for tests.
	electionTimeoutMin time.Duration
	electionTimeoutMax time.Duration
}

// NewRaftNode creates a RaftNode with the given node name and initial peer
// list. The peer list seeds quorum calculation until a GossipNode is
// attached via SetGossipNode.
//
// Every node starts as a Follower with a randomized election timeout.
// Leadership is acquired through a proper Raft election, not alphabetical
// ordering.
func NewRaftNode(name string, peers []string) *RaftNode {
	rn := &RaftNode{
		name:              name,
		peers:             append([]string(nil), peers...),
		state:             Follower,
		proposals:         make(map[string]*proposalRecord),
		voteTimeout:       voteTimeout,
		stopCh:            make(chan struct{}),
		currentTerm:       0,
		votedFor:          "",
		leaderID:          "",
		electionVotes:     make(map[string]bool),
		heartbeatStop:     make(chan struct{}),
		electionTimeoutMin: defaultElectionTimeoutMin,
		electionTimeoutMax: defaultElectionTimeoutMax,
	}

	// Start the randomized election timer.
	rn.resetElectionTimerLocked()

	// Background goroutine: handles election timeouts and heartbeats.
	go rn.runElectionLoop()

	log.Printf("[raft] %s started as follower (term=%d)", name, rn.currentTerm)
	return rn
}

// ---------------------------------------------------------------------------
// Gossip integration
// ---------------------------------------------------------------------------

// SetGossipNode attaches a GossipNode for vote-message broadcasting and
// dynamic peer discovery. It registers two threat-intel callbacks:
//   1. Raft leader-election RPCs (RequestVote / heartbeat)
//   2. Counterstrike proposal votes (raft_vote — backward compatible)
//
// Call before proposing counterstrikes.
func (r *RaftNode) SetGossipNode(g *GossipNode) {
	r.mu.Lock()
	r.gossip = g
	r.mu.Unlock()

	// Callback 1: leader-election protocol messages.
	g.OnThreatIntel(func(peerName string, data []byte) {
		var msg RaftRPCMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		switch msg.Type {
		case "raft_request_vote":
			r.handleRequestVote(msg)
		case "raft_request_vote_resp":
			r.handleRequestVoteResponse(msg)
		case "raft_heartbeat":
			r.handleHeartbeat(msg)
		}
	})

	// Callback 2: counterstrike proposal votes (existing raft_vote path).
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

// ---------------------------------------------------------------------------
// Exported state queries
// ---------------------------------------------------------------------------

// IsLeader returns true if this node is the current leader (by election,
// not by alphabetical ordering).
func (r *RaftNode) IsLeader() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.state == Leader
}

// LeaderName returns the ID of the current leader as determined by the
// last heartbeat received. If no leader is known, returns the local name.
func (r *RaftNode) LeaderName() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.leaderID != "" {
		return r.leaderID
	}
	return r.name
}

// CurrentTerm returns the node's current Raft term number (diagnostic).
func (r *RaftNode) CurrentTerm() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.currentTerm
}

// SetElectionTimeoutRange overrides the default election timeout bounds for
// this node. Call before SetGossipNode or before any election activity starts.
// Tests can use this to shorten timeouts (e.g. 50-100ms) for fast convergence.
// Both min and max must be positive and min < max, otherwise the call is
// silently ignored.
func (r *RaftNode) SetElectionTimeoutRange(min, max time.Duration) {
	if min <= 0 || max <= min {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.electionTimeoutMin = min
	r.electionTimeoutMax = max
	r.resetElectionTimerLocked()
}

// ---------------------------------------------------------------------------
// Counterstrike proposal (unchanged semantics — only Leader can propose)
// ---------------------------------------------------------------------------

// ProposeCounterstrike initiates a consensus round for a counterstrike
// against the given IP. Only the current elected leader may propose.
// Returns true if consensus is reached within the vote timeout window.
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
	quorum := r.dynamicQuorum()
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
			log.Printf("[raft] counterstrike approved for %s (%d/%d votes, quorum=%d)", ip, yesVotes, totalVotes, quorum)
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

// QuorumSize returns the number of votes needed for consensus.
// Uses alive-peer-aware calculation to avoid deadlock in small clusters.
func (r *RaftNode) QuorumSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.dynamicQuorumLocked()
}

// Stop signals the RaftNode to shut down background goroutines (election
// loop, heartbeat loop). Safe to call multiple times.
func (r *RaftNode) Stop() {
	r.mu.Lock()
	select {
	case <-r.stopCh:
		// Already stopped.
		r.mu.Unlock()
		return
	default:
	}
	close(r.stopCh)

	// Stop heartbeat goroutine if running.
	if r.heartbeatStop != nil {
		select {
		case <-r.heartbeatStop:
		default:
			close(r.heartbeatStop)
		}
	}
	r.mu.Unlock()
}

// ---------------------------------------------------------------------------
// internal: leader election
// ---------------------------------------------------------------------------

// runElectionLoop is the single background goroutine that manages both the
// election timeout (when follower/candidate) and heartbeat broadcasts
// (when leader).
func (r *RaftNode) runElectionLoop() {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[raft] election loop panic: %v\nstack: %s", rec, debug.Stack())
		}
	}()

	heartbeatTick := time.NewTicker(heartbeatInterval)
	defer heartbeatTick.Stop()

	for {
		select {
		case <-r.stopCh:
			return

		case <-r.electionTimer.C:
			// Election timeout fired — start an election if not leader.
			r.mu.Lock()
			if r.state != Leader {
				r.mu.Unlock()
				r.startElection()
			} else {
				r.mu.Unlock()
			}

		case <-heartbeatTick.C:
			// If we are leader, broadcast a heartbeat.
			r.mu.RLock()
			isLeader := r.state == Leader
			gossip := r.gossip
			term := r.currentTerm
			name := r.name
			r.mu.RUnlock()

			if isLeader && gossip != nil {
				msg := RaftRPCMessage{
					Type:     "raft_heartbeat",
					Term:     term,
					From:     name,
					LeaderID: name,
				}
				data, err := json.Marshal(msg)
				if err == nil {
					gossip.BroadcastThreatIntel(data)
				}
			}
		}
	}
}

// startElection transitions this node to Candidate, increments the term,
// votes for itself, and broadcasts RequestVote RPCs. Caller must NOT hold
// r.mu (this method acquires it).
func (r *RaftNode) startElection() {
	r.mu.Lock()

	// Double-check we are not already leader (race with heartbeat).
	if r.state == Leader {
		r.mu.Unlock()
		return
	}

	r.currentTerm++
	r.state = Candidate
	r.votedFor = r.name
	r.leaderID = ""
	r.electionVotes = map[string]bool{r.name: true} // vote for self

	term := r.currentTerm
	gossip := r.gossip
	r.mu.Unlock()

	log.Printf("[raft] %s starting election for term %d", r.name, term)

	// Broadcast RequestVote via gossip epidemic relay.
	if gossip != nil {
		msg := RaftRPCMessage{
			Type:        "raft_request_vote",
			Term:        term,
			From:        r.name,
			CandidateID: r.name,
		}
		data, err := json.Marshal(msg)
		if err == nil {
			gossip.BroadcastThreatIntel(data)
		}
	}

	// Reset election timeout in case we do not win.
	r.mu.Lock()
	r.resetElectionTimerLocked()
	r.mu.Unlock()
}

// becomeLeaderLocked transitions this node to Leader and starts heartbeats.
// Caller must hold r.mu.
func (r *RaftNode) becomeLeaderLocked() {
	if r.state == Leader {
		return
	}
	r.state = Leader
	r.leaderID = r.name
	r.electionVotes = make(map[string]bool) // clear election state

	log.Printf("[raft] %s became leader for term %d", r.name, r.currentTerm)

	// Reset heartbeat stop channel.
	select {
	case <-r.heartbeatStop:
	default:
		close(r.heartbeatStop)
	}
	r.heartbeatStop = make(chan struct{})
}

// stepDownLocked reverts this node to Follower, adopting a newer term.
// If the node was leader, the heartbeat goroutine is stopped.
// Caller must hold r.mu.
func (r *RaftNode) stepDownLocked(newTerm uint64) {
	if newTerm > r.currentTerm {
		r.currentTerm = newTerm
	}
	if r.state == Leader {
		select {
		case <-r.heartbeatStop:
		default:
			close(r.heartbeatStop)
		}
	}
	r.state = Follower
	r.votedFor = ""
	r.leaderID = ""
	r.electionVotes = make(map[string]bool)
	r.resetElectionTimerLocked()

	log.Printf("[raft] %s stepped down to follower (term=%d)", r.name, r.currentTerm)
}

// ---------------------------------------------------------------------------
// internal: Raft RPC handlers
// ---------------------------------------------------------------------------

// handleRequestVote processes an incoming RequestVote RPC. If the
// candidate's term is >= our term and we have not yet voted this term, we
// grant the vote and reset our election timer.
func (r *RaftNode) handleRequestVote(msg RaftRPCMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if msg.Term < r.currentTerm {
		// Stale term — ignore (in a full impl we would send a rejection).
		return
	}

	if msg.Term > r.currentTerm {
		r.stepDownLocked(msg.Term)
	}

	// Tie-breaking: if both nodes are Candidates in the same term,
	// the one with the lexicographically smaller name wins to avoid
	// perpetual split votes.
	if msg.Term == r.currentTerm && r.state == Candidate && r.votedFor == r.name {
		if msg.CandidateID < r.name {
			// Other candidate has smaller name — step down and vote for them.
			r.state = Follower
			r.votedFor = ""
		}
		// If msg.CandidateID > r.name, we keep our vote for ourselves
		// and the other candidate should step down for us.
	}
	// Grant vote if we have not voted for anyone else this term.
	// Re-delivery (via epidemic fan-out) is acknowledged without a
	// duplicate log or timer reset, to prevent infinite echo loops.
	granted := false
	newVote := false
	if r.votedFor == "" {
		r.votedFor = msg.CandidateID
		granted = true
		newVote = true
		r.resetElectionTimerLocked()
	} else if r.votedFor == msg.CandidateID {
		granted = true // acknowledge re-delivery, no timer reset
	}

	// Send response via gossip.
	gossip := r.gossip
	if gossip != nil {
		resp := RaftRPCMessage{
			Type:        "raft_request_vote_resp",
			Term:        r.currentTerm,
			From:        r.name,
			CandidateID: msg.CandidateID,
			VoteGranted: granted,
		}
		data, err := json.Marshal(resp)
		if err == nil {
			go func() {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("[raft] vote resp relay panic: %v", rec)
					}
				}()
				gossip.BroadcastThreatIntel(data)
			}()
		}
	}

	if newVote {
		log.Printf("[raft] %s voted for %s in term %d", r.name, msg.CandidateID, r.currentTerm)
	}
}

// handleRequestVoteResponse processes an incoming vote response. Only the
// Candidate that initiated the election tallies these votes.
func (r *RaftNode) handleRequestVoteResponse(msg RaftRPCMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Ignore if we are not a candidate, the response is for a
	// different term, or the vote was cast for a different candidate.
	if r.state != Candidate || msg.Term != r.currentTerm || msg.CandidateID != r.name {
		return
	}

	if msg.VoteGranted {
		r.electionVotes[msg.From] = true
	}

	// Check if we have majority.
	if r.hasElectionMajorityLocked() {
		r.becomeLeaderLocked()
	}
}

// handleHeartbeat processes an incoming leader heartbeat (AppendEntries).
// If the leader's term >= our term, we acknowledge them as leader, reset
// our election timer, and step down if we were leader/candidate.
func (r *RaftNode) handleHeartbeat(msg RaftRPCMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if msg.Term < r.currentTerm {
		// Stale heartbeat — ignore.
		return
	}

	if msg.Term > r.currentTerm {
		r.stepDownLocked(msg.Term)
	}

	// Accept the new leader.
	r.leaderID = msg.LeaderID
	r.state = Follower
	// votedFor is per-term — only cleared when stepping down to a higher
	// term via stepDownLocked, never on same-term heartbeats (Raft §5.2).
	r.resetElectionTimerLocked()
}

// ---------------------------------------------------------------------------
// internal: election helpers
// ---------------------------------------------------------------------------

// randomElectionTimeout returns a duration in [min, max) using this node's
// per-instance timeout bounds (which default to the package-level constants
// but may be tightened via SetElectionTimeoutRange for tests).
func (r *RaftNode) randomElectionTimeout() time.Duration {
	return r.electionTimeoutMin + time.Duration(rand.Int63n(int64(r.electionTimeoutMax-r.electionTimeoutMin)))
}

// resetElectionTimerLocked (re)creates the election timer with a fresh
// randomized duration. Caller must hold r.mu.
func (r *RaftNode) resetElectionTimerLocked() {
	d := r.randomElectionTimeout()
	if r.electionTimer == nil {
		r.electionTimer = time.NewTimer(d)
	} else {
		if !r.electionTimer.Stop() {
			select {
			case <-r.electionTimer.C:
			default:
			}
		}
		r.electionTimer.Reset(d)
	}
}

// hasElectionMajorityLocked returns true if the candidate has received
// votes from a majority of the cluster. Caller must hold r.mu.
func (r *RaftNode) hasElectionMajorityLocked() bool {
	peers := r.peerNamesLocked()
	clusterSize := len(peers)
	votes := 0
	for _, granted := range r.electionVotes {
		if granted {
			votes++
		}
	}
	// Majority: strictly more than half of the cluster.
	return votes > clusterSize/2
}

// ---------------------------------------------------------------------------
// internal: dynamic quorum (counterstrike proposals)
// ---------------------------------------------------------------------------

// dynamicQuorum returns the number of yes votes required for a
// counterstrike proposal. It uses the current alive peer set (when gossip
// is attached) to avoid deadlock in small / degraded clusters.
//
// Standard formula: majority = floor(N/2) + 1
// Degraded safeguard: if there are fewer alive peers than the standard
// quorum would require, allow a single node to act (logged as WARNING).
func (r *RaftNode) dynamicQuorum() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.dynamicQuorumLocked()
}

func (r *RaftNode) dynamicQuorumLocked() int {
	alive := len(r.peerNamesLocked())
	stdQuorum := alive/2 + 1 // majority

	// In a degraded 1-node or 2-node cluster where the standard
	// majority is unachievable, allow the sole remaining node to act.
	if stdQuorum > alive && alive > 0 {
		log.Printf("[raft] WARNING: quorum %d > alive peers %d; operating in degraded mode",
			stdQuorum, alive)
		return 1
	}
	return stdQuorum
}

// ---------------------------------------------------------------------------
// internal: vote recording & proposal evaluation (unchanged logic)
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
					defer func() {
						if r := recover(); r != nil {
							log.Printf("[raft] vote relay panic: %v\nstack: %s", r, debug.Stack())
						}
					}()
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

	quorum := r.dynamicQuorumLocked()

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
// Deprecated internal helper — prefer dynamicQuorumLocked.
func (r *RaftNode) quorumSizeLocked() int {
	return r.dynamicQuorumLocked()
}

// ---------------------------------------------------------------------------
// internal: peer name helpers
// ---------------------------------------------------------------------------

// peerNames returns the set of known peer names. If a gossip node is
// attached, only alive peers are included and self is always present.
func (r *RaftNode) peerNames(gossip *GossipNode) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.peerNamesWithGossipLocked(gossip)
}

// peerNamesLocked is the same as peerNames but caller must hold r.mu.
func (r *RaftNode) peerNamesLocked() []string {
	return r.peerNamesWithGossipLocked(r.gossip)
}

func (r *RaftNode) peerNamesWithGossipLocked(gossip *GossipNode) []string {
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
