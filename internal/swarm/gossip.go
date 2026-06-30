// Package swarm implements the Fortress distributed protocol for peer
// discovery, threat intel sharing, and consensus-based counterstrikes.
//
// gossip.go provides UDP-based epidemic gossip with failure detection,
// peer-list exchange, and HMAC-authenticated message passing.
package swarm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fortress/v6/internal/config"
)

// ---------------------------------------------------------------------------
// PeerState
// ---------------------------------------------------------------------------

// PeerState is the SWIM-inspired liveness state of a swarm peer.
type PeerState int

const (
	PeerAlive   PeerState = iota // actively responding
	PeerSuspect                  // unacked, indirect-ping in progress
	PeerDead                     // confirmed silent
)

func (s PeerState) String() string {
	switch s {
	case PeerAlive:
		return "alive"
	case PeerSuspect:
		return "suspect"
	case PeerDead:
		return "dead"
	default:
		return "unknown"
	}
}

// protocol timing constants
const (
	pingInterval       = 5 * time.Second
	deadProbeInterval  = 30 * time.Second
	suspectTimeout     = 15 * time.Second
	deadTimeout        = 30 * time.Second
	suspectCheckInterval = 3 * time.Second
	indirectPingFanout = 3
	threatIntelFanout  = 3
	udpBufSize         = 8192
)

// ---------------------------------------------------------------------------
// Peer / PeerInfo
// ---------------------------------------------------------------------------

// Peer is the local bookkeeping record for a known swarm node.
type Peer struct {
	Name     string
	Addr     string
	State    PeerState
	LastSeen time.Time
	Score    float64
}

// PeerInfo is the wire-format snapshot of a peer included in gossip messages.
type PeerInfo struct {
	Name  string `json:"name"`
	Addr  string `json:"addr"`
	State string `json:"state"`
	Score float64 `json:"score"`
}

// ---------------------------------------------------------------------------
// GossipMessage
// ---------------------------------------------------------------------------

// GossipMessage is the JSON envelope for all gossip UDP datagrams.
type GossipMessage struct {
	Type       string          `json:"type"` // ping, ack, indirect_ping, threat_intel, join, leave
	NodeName   string          `json:"node"`
	Addr       string          `json:"addr"`
	Peers      []PeerInfo      `json:"peers,omitempty"`
	ThreatData json.RawMessage `json:"threat_data,omitempty"`
	Timestamp  int64           `json:"ts"`
	HMAC       string          `json:"hmac,omitempty"`
}

// ---------------------------------------------------------------------------
// GossipNode
// ---------------------------------------------------------------------------

// GossipNode is a single participant in the swarm gossip mesh. It:
//   - Periodically pings all known peers with its local peer list
//   - Replies to pings with an ack + merged peer list
//   - Marks unresponsive peers Suspect and probes them indirectly
//   - Broadcasts threat-intel messages using epidemic fan-out
//
// All exported methods are safe for concurrent use.
type GossipNode struct {
	mu              sync.RWMutex
	config          config.SwarmConfig
	peers           map[string]*Peer // keyed by "name/addr"
	localAddr       string
	conn            *net.UDPConn
	stopCh          chan struct{}
	onThreatIntelCBs []func(peerName string, data []byte)
	stats           GossipStats // atomics for monitoring
}

// GossipStats tracks messaging performance and health of the gossip node.
type GossipStats struct {
	MessagesSent     int64 `json:"messages_sent"`
	MessagesReceived int64 `json:"messages_received"`
	ThreatsSent      int64 `json:"threats_sent"`
	ThreatsReceived  int64 `json:"threats_received"`
	PeersDiscovered  int64 `json:"peers_discovered"`
	PingTimeouts     int64 `json:"ping_timeouts"`
	SuspectEvents    int64 `json:"suspect_events"`
	DeadEvents       int64 `json:"dead_events"`
}

// GetStats returns a snapshot of gossip performance counters.
func (g *GossipNode) GetStats() GossipStats {
	var s GossipStats
	s.MessagesSent = atomic.LoadInt64(&g.stats.MessagesSent)
	s.MessagesReceived = atomic.LoadInt64(&g.stats.MessagesReceived)
	s.ThreatsSent = atomic.LoadInt64(&g.stats.ThreatsSent)
	s.ThreatsReceived = atomic.LoadInt64(&g.stats.ThreatsReceived)
	s.PeersDiscovered = atomic.LoadInt64(&g.stats.PeersDiscovered)
	s.PingTimeouts = atomic.LoadInt64(&g.stats.PingTimeouts)
	s.SuspectEvents = atomic.LoadInt64(&g.stats.SuspectEvents)
	s.DeadEvents = atomic.LoadInt64(&g.stats.DeadEvents)
	return s
}

// incStats atomically increments a stats counter by 1.
func (g *GossipNode) incStats(field *int64) {
		atomic.AddInt64(field, 1)
}

// NewGossipNode creates a UDP socket bound to cfg.Bind, seeds the peer table
// with cfg.Peers, and returns a ready-to-start GossipNode. localAddr is the
// publicly reachable address this node advertises (e.g. "192.168.1.10:9700").
func NewGossipNode(cfg config.SwarmConfig, localAddr string) (*GossipNode, error) {
	addr, err := net.ResolveUDPAddr("udp", cfg.Bind)
	if err != nil {
		return nil, fmt.Errorf("swarm: resolve bind %q: %w", cfg.Bind, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("swarm: listen udp %q: %w", cfg.Bind, err)
	}

	g := &GossipNode{
		config:    cfg,
		localAddr: localAddr,
		conn:      conn,
		stopCh:    make(chan struct{}),
		peers:     make(map[string]*Peer),
	}

	// Seed initial peers as alive — we will learn their true state on first ping.
	now := time.Now()
	for _, p := range cfg.Peers {
		key := peerKey("", p)
		g.peers[key] = &Peer{
			Name:     "", // unknown until first message
			Addr:     p,
			State:    PeerAlive,
			LastSeen: now,
		}
	}

	return g, nil
}

// Start launches the gossip loop. It reads incoming datagrams on the UDP
// socket and periodically sends pings. Safe to call once.
func (g *GossipNode) Start() {
	go g.recvLoop()
	go g.gossipLoop()
	log.Printf("[swarm] %s started on %s with %d seed peers", g.config.Name, g.localAddr, len(g.config.Peers))
}

// Stop sends a leave message to every known peer, closes the UDP socket, and
// signals background goroutines to exit. Returns after cleanup.
func (g *GossipNode) Stop() {
	close(g.stopCh)

	g.mu.RLock()
	msg := GossipMessage{
		Type:      "leave",
		NodeName:  g.config.Name,
		Addr:      g.localAddr,
		Timestamp: time.Now().Unix(),
	}
	for _, p := range g.peers {
		if p.State == PeerDead {
			continue
		}
		g.sendTo(p.Addr, msg)
	}
	g.mu.RUnlock()

	g.conn.Close()
	log.Printf("[swarm] %s stopped", g.config.Name)
}

// BroadcastThreatIntel pushes threat intelligence data to all alive peers
// via threat_intel messages. Returns the number of peers the message was
// successfully sent to. Unlike fire-and-forget, this sends to every alive
// peer (not a random subset) for maximum reliability.
func (g *GossipNode) BroadcastThreatIntel(data []byte) int {
	msg := GossipMessage{
		Type:       "threat_intel",
		NodeName:   g.config.Name,
		Addr:       g.localAddr,
		ThreatData: data,
		Timestamp:  time.Now().Unix(),
	}

	return g.broadcastToAll(msg)
}

// BroadcastThreatIntelReliable sends threat intel with delivery confirmation.
// Blocks until at least one peer ACKs or all peers fail.
// Returns true if at least one peer confirmed receipt.
func (g *GossipNode) BroadcastThreatIntelReliable(data []byte) bool {
	msg := GossipMessage{
		Type:       "threat_intel_ack",
		NodeName:   g.config.Name,
		Addr:       g.localAddr,
		ThreatData: data,
		Timestamp:  time.Now().Unix(),
	}

	g.mu.RLock()
	var targets []*Peer
	for _, p := range g.peers {
		if p.State == PeerAlive {
			targets = append(targets, p)
		}
	}
	g.mu.RUnlock()

	if len(targets) == 0 {
		return false
	}

	// Try confirmed delivery to each peer via sendAndWait.
	// Return on first ACK.
	for _, p := range targets {
		reply, err := g.sendAndWait(p.Addr, msg, 500*time.Millisecond)
		if err == nil && reply != nil {
			return true
		}
	}

	// Fall back to fire-and-forget broadcast to all alive peers.
	g.broadcastToAll(msg)
	return false
}

// broadcastToAll sends a message to every alive peer. Returns success count.
func (g *GossipNode) broadcastToAll(msg GossipMessage) int {
	g.mu.RLock()
	var targets []*Peer
	for _, p := range g.peers {
		if p.State == PeerAlive {
			targets = append(targets, p)
		}
	}
	g.mu.RUnlock()

	for _, p := range targets {
		g.sendTo(p.Addr, msg)
	}
	return len(targets)
}

// OnThreatIntel registers a callback invoked when a threat_intel message is
// received from another peer. Multiple callbacks can coexist — each is
// invoked in order.
func (g *GossipNode) OnThreatIntel(fn func(peerName string, data []byte)) {
	g.mu.Lock()
	g.onThreatIntelCBs = append(g.onThreatIntelCBs, fn)
	g.mu.Unlock()
}

// GetPeers returns a snapshot of the current peer list.
func (g *GossipNode) GetPeers() []Peer {
	g.mu.RLock()
	defer g.mu.RUnlock()

	out := make([]Peer, 0, len(g.peers))
	for _, p := range g.peers {
		out = append(out, *p)
	}
	return out
}

// PeerCount returns the number of peers currently in the Alive state.
func (g *GossipNode) PeerCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	n := 0
	for _, p := range g.peers {
		if p.State == PeerAlive {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// internal: receive loop
// ---------------------------------------------------------------------------

func (g *GossipNode) recvLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[swarm] recv loop panic: %v\nstack: %s", r, debug.Stack())
		}
	}()
	buf := make([]byte, udpBufSize)
	for {
		select {
		case <-g.stopCh:
			return
		default:
		}

		g.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remote, err := g.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Socket closed during shutdown.
			select {
			case <-g.stopCh:
				return
			default:
			}
			log.Printf("[swarm] recv error: %v", err)
			continue
		}

		var msg GossipMessage
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			log.Printf("[swarm] bad message from %v: %v", remote, err)
			continue
		}

		if !g.verifyHMAC(msg) {
			log.Printf("[swarm] hmac verification failed from %v", remote)
			continue
		}

		g.handleMessage(msg, remote)
		atomic.AddInt64(&g.stats.MessagesReceived, 1)
	}
}

// ---------------------------------------------------------------------------
// internal: gossip (send) loop
// ---------------------------------------------------------------------------

func (g *GossipNode) gossipLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[swarm] gossip loop panic: %v\nstack: %s", r, debug.Stack())
		}
	}()
	pingTick := time.NewTicker(pingInterval)
	deadTick := time.NewTicker(deadProbeInterval)
	suspectTick := time.NewTicker(suspectCheckInterval)
	defer pingTick.Stop()
	defer deadTick.Stop()
	defer suspectTick.Stop()

	for {
		select {
		case <-g.stopCh:
			return
		case <-pingTick.C:
			g.pingAll()
		case <-suspectTick.C:
			g.detectSuspects()
		case <-deadTick.C:
			g.probeDead()
		}
	}
}

func (g *GossipNode) pingAll() {
	g.mu.RLock()
	peers := g.peerList()
	msg := GossipMessage{
		Type:      "ping",
		NodeName:  g.config.Name,
		Addr:      g.localAddr,
		Peers:     peers,
		Timestamp: time.Now().Unix(),
	}
	targets := make([]*Peer, 0, len(g.peers))
	for _, p := range g.peers {
		if p.State == PeerDead {
			continue
		}
		targets = append(targets, p)
	}
	g.mu.RUnlock()

	for _, p := range targets {
		g.sendTo(p.Addr, msg)
	}
}

func (g *GossipNode) detectSuspects() {
	g.mu.Lock()
	now := time.Now()
	var newSuspects []*Peer
	for _, p := range g.peers {
		if p.State == PeerAlive && now.Sub(p.LastSeen) > suspectTimeout {
			p.State = PeerSuspect
			newSuspects = append(newSuspects, p)
			log.Printf("[swarm] peer %s (%s) marked suspect (last seen %v ago)", p.Name, p.Addr, now.Sub(p.LastSeen))
		}
	}
	g.mu.Unlock()

	// For each newly suspect peer, ask 3 random alive peers to ping it indirectly.
	for _, suspect := range newSuspects {
		g.mu.RLock()
		proxies := g.pickRandomAlive(indirectPingFanout)
		g.mu.RUnlock()

		indirectMsg := GossipMessage{
			Type:      "indirect_ping",
			NodeName:  g.config.Name,
			Addr:      suspect.Addr,
			Timestamp: time.Now().Unix(),
		}
		for _, proxy := range proxies {
			if proxy.Addr == suspect.Addr {
				continue
			}
			g.sendTo(proxy.Addr, indirectMsg)
		}
	}
}

func (g *GossipNode) probeDead() {
	g.mu.Lock()
	now := time.Now()
	for _, p := range g.peers {
		if p.State == PeerSuspect && now.Sub(p.LastSeen) > deadTimeout {
			p.State = PeerDead
			log.Printf("[swarm] peer %s (%s) marked dead", p.Name, p.Addr)
		}
	}
	g.mu.Unlock()
}

// ---------------------------------------------------------------------------
// internal: message dispatch
// ---------------------------------------------------------------------------

func (g *GossipNode) handleMessage(msg GossipMessage, remote *net.UDPAddr) {
	switch msg.Type {
	case "ping":
		g.handlePing(msg, remote)
	case "ack":
		g.handleAck(msg, remote)
	case "indirect_ping":
		g.handleIndirectPing(msg, remote)
	case "threat_intel", "threat_intel_ack":
		g.handleThreatIntel(msg, remote)
	case "join":
		g.handleJoin(msg)
	case "leave":
		g.handleLeave(msg)
	default:
		log.Printf("[swarm] unknown message type %q from %v", msg.Type, remote)
	}
}

func (g *GossipNode) handlePing(msg GossipMessage, remote *net.UDPAddr) {
	peerName := msg.NodeName
	peerAddr := remote.String()

	g.mu.Lock()
	g.upsertPeer(peerName, peerAddr, PeerAlive)
	g.mergePeerList(msg.Peers)
	ack := GossipMessage{
		Type:      "ack",
		NodeName:  g.config.Name,
		Addr:      g.localAddr,
		Peers:     g.peerList(),
		Timestamp: time.Now().Unix(),
	}
	g.mu.Unlock()

	g.sendTo(peerAddr, ack)
}

func (g *GossipNode) handleAck(msg GossipMessage, remote *net.UDPAddr) {
	g.mu.Lock()
	// Try name-qualified key first, then addr-only for seed peers that
	// were added without a known name.
	key := peerKey(msg.NodeName, remote.String())
	p, ok := g.peers[key]
	if !ok {
		key = peerKey("", remote.String())
		p, ok = g.peers[key]
	}
	if ok {
		p.State = PeerAlive
		p.LastSeen = time.Now()
		if msg.NodeName != "" {
			p.Name = msg.NodeName
		}
	}
	g.mergePeerList(msg.Peers)
	g.mu.Unlock()
}

func (g *GossipNode) handleIndirectPing(msg GossipMessage, remote *net.UDPAddr) {
	// A third party is asking us to ping the target on their behalf.
	// The target address is embedded in the message addr field (the suspect).
	targetAddr := msg.Addr
	if targetAddr == "" {
		return
	}

	indirectMsg := GossipMessage{
		Type:      "ping",
		NodeName:  g.config.Name,
		Addr:      g.localAddr,
		Peers:     nil, // minimal payload
		Timestamp: time.Now().Unix(),
	}
	resp, err := g.sendAndWait(targetAddr, indirectMsg, 2*time.Second)
	if err != nil {
		log.Printf("[swarm] indirect ping to %s failed: %v", targetAddr, err)
	}

	g.mu.Lock()
	if resp != nil && resp.Type == "ack" {
		key := peerKey(msg.NodeName, targetAddr)
		if p, ok := g.peers[key]; ok && p.State == PeerSuspect {
			p.State = PeerAlive
			p.LastSeen = time.Now()
		}
	}
	g.mu.Unlock()

	// Relay our finding back to the original requester via ack.
	if resp != nil && resp.Type == "ack" {
		ack := GossipMessage{
			Type:      "ack",
			NodeName:  msg.NodeName,
			Addr:      targetAddr,
			Timestamp: time.Now().Unix(),
		}
		g.sendTo(remote.String(), ack)
	}
}

func (g *GossipNode) handleThreatIntel(msg GossipMessage, remote *net.UDPAddr) {
	// If an ACK was requested (threat_intel_ack type), send confirmation.
	if msg.Type == "threat_intel_ack" && remote != nil {
		ack := GossipMessage{
			Type:       "threat_intel_ack_resp",
			NodeName:   g.config.Name,
			Addr:       g.localAddr,
			Timestamp:  time.Now().Unix(),
		}
		g.sendRaw(remote, ack)
	}

	g.mu.RLock()
	cbs := g.onThreatIntelCBs
	g.mu.RUnlock()

	if len(msg.ThreatData) > 0 {
		for _, cb := range cbs {
			cb(msg.NodeName, msg.ThreatData)
		}
	}

	// Epidemic fan-out: forward to all alive peers (excluding originator).
	g.mu.RLock()
	var targets []*Peer
	for _, p := range g.peers {
		if p.State == PeerAlive && p.Addr != msg.Addr {
			targets = append(targets, p)
		}
	}
	g.mu.RUnlock()

	for _, p := range targets {
		g.sendTo(p.Addr, msg)
	}
}

func (g *GossipNode) handleJoin(msg GossipMessage) {
	g.mu.Lock()
	g.upsertPeer(msg.NodeName, msg.Addr, PeerAlive)
	g.mu.Unlock()
	log.Printf("[swarm] peer %s (%s) joined", msg.NodeName, msg.Addr)
}

func (g *GossipNode) handleLeave(msg GossipMessage) {
	g.mu.Lock()
	key := peerKey(msg.NodeName, msg.Addr)
	delete(g.peers, key)
	g.mu.Unlock()
	log.Printf("[swarm] peer %s (%s) left", msg.NodeName, msg.Addr)
}

// ---------------------------------------------------------------------------
// internal: peer management
// ---------------------------------------------------------------------------

func peerKey(name, addr string) string {
	if name != "" {
		return name + "/" + addr
	}
	return addr
}

func (g *GossipNode) upsertPeer(name, addr string, state PeerState) {
	key := peerKey(name, addr)
	if existing, ok := g.peers[key]; ok {
		existing.State = state
		existing.LastSeen = time.Now()
		if name != "" {
			existing.Name = name
		}
		return
	}
	g.peers[key] = &Peer{
		Name:     name,
		Addr:     addr,
		State:    state,
		LastSeen: time.Now(),
	}
}

func (g *GossipNode) mergePeerList(incoming []PeerInfo) {
	for _, pi := range incoming {
		key := peerKey(pi.Name, pi.Addr)
		if existing, ok := g.peers[key]; ok {
			if pi.Score > existing.Score {
				existing.Score = pi.Score
			}
			if pi.Name != "" && existing.Name == "" {
				existing.Name = pi.Name
			}
		} else {
			state := PeerAlive
			switch pi.State {
			case "suspect":
				state = PeerSuspect
			case "dead":
				state = PeerDead
			}
			g.peers[key] = &Peer{
				Name:     pi.Name,
				Addr:     pi.Addr,
				State:    state,
				Score:    pi.Score,
				LastSeen: time.Now(),
			}
		}
	}
}

func (g *GossipNode) peerList() []PeerInfo {
	list := make([]PeerInfo, 0, len(g.peers))
	for _, p := range g.peers {
		list = append(list, PeerInfo{
			Name:  p.Name,
			Addr:  p.Addr,
			State: p.State.String(),
			Score: p.Score,
		})
	}
	return list
}

func (g *GossipNode) pickRandomAlive(n int) []*Peer {
	alive := make([]*Peer, 0, len(g.peers))
	for _, p := range g.peers {
		if p.State == PeerAlive {
			alive = append(alive, p)
		}
	}
	if len(alive) <= n {
		return alive
	}
	rand.Shuffle(len(alive), func(i, j int) {
		alive[i], alive[j] = alive[j], alive[i]
	})
	return alive[:n]
}

// ---------------------------------------------------------------------------
// internal: message sending / auth
// ---------------------------------------------------------------------------

// sendRaw marshals, signs, and writes a message to the given UDP address.
// Shared by sendTo and sendAndWait to avoid duplicated marshal-and-send logic.
func (g *GossipNode) sendRaw(addr *net.UDPAddr, msg GossipMessage) error {
	g.signMessage(&msg)

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if _, err := g.conn.WriteToUDP(data, addr); err != nil {
		return fmt.Errorf("write to %s: %w", addr, err)
	}
		atomic.AddInt64(&g.stats.MessagesSent, 1)
	return nil
}

func (g *GossipNode) sendTo(peerAddr string, msg GossipMessage) {
	udpAddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		log.Printf("[swarm] resolve peer %q: %v", peerAddr, err)
		return
	}

	if err := g.sendRaw(udpAddr, msg); err != nil {
		log.Printf("[swarm] send to %s: %v", peerAddr, err)
	}
}

// sendAndWait sends a message and blocks for a single response datagram.
// Returns (nil, error) on any failure including marshal, network write,
// read timeout, unmarshal, or HMAC verification.
func (g *GossipNode) sendAndWait(addr string, msg GossipMessage, timeout time.Duration) (*GossipMessage, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", addr, err)
	}

	if err := g.sendRaw(udpAddr, msg); err != nil {
		return nil, err
	}

	buf := make([]byte, udpBufSize)
	g.conn.SetReadDeadline(time.Now().Add(timeout))
	n, _, err := g.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var resp GossipMessage
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	if !g.verifyHMAC(resp) {
		return nil, fmt.Errorf("hmac mismatch from %s", addr)
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// internal: HMAC authentication
// ---------------------------------------------------------------------------

func (g *GossipNode) signMessage(msg *GossipMessage) {
	msg.HMAC = "" // clear before computing
	if g.config.GossipKey == "" {
		return
	}
	msg.HMAC = computeHMAC(msg, g.config.GossipKey)
}

func (g *GossipNode) verifyHMAC(msg GossipMessage) bool {
	if g.config.GossipKey == "" {
		return true
	}
	received := msg.HMAC
	msg.HMAC = ""
	expected := computeHMAC(&msg, g.config.GossipKey)
	return hmac.Equal([]byte(received), []byte(expected))
}

func computeHMAC(msg *GossipMessage, key string) string {
	data, err := json.Marshal(msg)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	return base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
}
