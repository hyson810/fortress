package swarm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
)

// PeerState represents the SWIM lifecycle state of a peer.
type PeerState int

const (
	PeerAlive PeerState = iota
	PeerSuspect
	PeerDead
)

// Peer represents a known node in the swarm.
type Peer struct {
	Name   string    `json:"name"`
	Addr   string    `json:"addr"`
	State  PeerState `json:"state"`
	LastOK time.Time `json:"last_ok"`
}

// GossipMessage is the wire format for all swarm protocol messages.
type GossipMessage struct {
	Type string          `json:"type"` // ping, ack, threat_intel, immunity
	From string          `json:"from"`
	Data json.RawMessage `json:"data"`
	HMAC string          `json:"hmac"`
}

// ThreatIntelMsg carries a scored threat between swarm peers.
type ThreatIntelMsg struct {
	IP        string  `json:"ip"`
	Score     float64 `json:"score"`
	Level     int     `json:"level"`
	Timestamp int64   `json:"ts"`
}

// ImmunityRecord propagates a whitelist/immunity entry across the swarm.
type ImmunityRecord struct {
	IP        string `json:"ip"`
	Rule      string `json:"rule"`
	PublicKey string `json:"pubkey"`
	Signature string `json:"sig"`
	TTL       int64  `json:"ttl"`
}

// GossipNode is a single SWIM participant.
type GossipNode struct {
	mu               sync.RWMutex
	name             string
	addr             string
	peers            map[string]*Peer
	conn             *net.UDPConn
	gossipKey        string
	onThreatIntelCBs []func(string, []byte)
	immuneRecords    map[string]ImmunityRecord
	stopCh           chan struct{}
}

// NewGossipNode creates and starts a SWIM gossip node.
func NewGossipNode(cfg config.SwarmConfig) (*GossipNode, error) {
	addr, err := net.ResolveUDPAddr("udp", cfg.Bind)
	if err != nil {
		return nil, fmt.Errorf("gossip: resolve %s: %w", cfg.Bind, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("gossip: listen %s: %w", cfg.Bind, err)
	}

	gn := &GossipNode{
		name:          cfg.Name,
		addr:          cfg.Bind,
		peers:         make(map[string]*Peer),
		conn:          conn,
		gossipKey:     cfg.GossipKey,
		immuneRecords: make(map[string]ImmunityRecord),
		stopCh:        make(chan struct{}),
	}

	for _, p := range cfg.Peers {
		gn.peers[p] = &Peer{Name: p, State: PeerAlive, LastOK: time.Now()}
	}

	go gn.listen()
	go gn.pingLoop()

	log.Printf("[swarm] %s started on %s with %d seed peers", cfg.Name, cfg.Bind, len(cfg.Peers))
	return gn, nil
}

func (g *GossipNode) listen() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-g.stopCh:
			return
		default:
			g.conn.SetReadDeadline(time.Now().Add(time.Second))
			n, remote, err := g.conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			var msg GossipMessage
			if err := json.Unmarshal(buf[:n], &msg); err != nil {
				continue
			}
			if !g.verifyHMAC(msg) {
				continue
			}
			g.handle(msg, remote)
		}
	}
}

func (g *GossipNode) pingLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-g.stopCh:
			return
		case <-ticker.C:
			g.mu.RLock()
			for _, p := range g.peers {
				if p.State == PeerAlive {
					go g.pingPeer(p)
				}
			}
			g.mu.RUnlock()
		}
	}
}

func (g *GossipNode) pingPeer(p *Peer) {
	msg := GossipMessage{Type: "ping", From: g.name}
	data, _ := json.Marshal(msg)
	g.signMessage(&msg, data)
	addr, _ := net.ResolveUDPAddr("udp", p.Addr)
	g.conn.WriteToUDP(data, addr)
}

func (g *GossipNode) handle(msg GossipMessage, remote *net.UDPAddr) {
	switch msg.Type {
	case "ping":
		ack := GossipMessage{Type: "ack", From: g.name}
		ackData, _ := json.Marshal(ack)
		g.signMessage(&ack, ackData)
		g.conn.WriteToUDP(ackData, remote)
	case "ack":
		g.mu.Lock()
		for _, p := range g.peers {
			if p.Addr == remote.String() {
				p.LastOK = time.Now()
				p.State = PeerAlive
			}
		}
		g.mu.Unlock()
	case "threat_intel":
		var ti ThreatIntelMsg
		if err := json.Unmarshal(msg.Data, &ti); err == nil {
			for _, cb := range g.onThreatIntelCBs {
				cb(msg.From, msg.Data)
			}
		}
	case "immunity":
		var ir ImmunityRecord
		if err := json.Unmarshal(msg.Data, &ir); err == nil {
			g.mu.Lock()
			if _, ok := g.immuneRecords[ir.IP]; !ok {
				g.immuneRecords[ir.IP] = ir
				log.Printf("[swarm] immunity: %s blocked via %s (from %s, ttl=%ds)", ir.IP, ir.Rule, msg.From, ir.TTL)
			}
			g.mu.Unlock()
		}
	}
}

// OnThreatIntel registers a callback invoked for every threat_intel message.
func (g *GossipNode) OnThreatIntel(cb func(string, []byte)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.onThreatIntelCBs = append(g.onThreatIntelCBs, cb)
}

// BroadcastThreatIntel fans out a scored threat to all alive peers.
func (g *GossipNode) BroadcastThreatIntel(ip string, score float64, level int) error {
	ti := ThreatIntelMsg{IP: ip, Score: score, Level: level, Timestamp: time.Now().Unix()}
	data, _ := json.Marshal(ti)
	msg := GossipMessage{Type: "threat_intel", From: g.name, Data: data}
	msgData, _ := json.Marshal(msg)
	g.signMessage(&msg, msgData)
	return g.broadcast(msgData)
}

// BroadcastImmunity fans out an immunity record to all alive peers.
func (g *GossipNode) BroadcastImmunity(ir ImmunityRecord) error {
	data, _ := json.Marshal(ir)
	msg := GossipMessage{Type: "immunity", From: g.name, Data: data}
	msgData, _ := json.Marshal(msg)
	g.signMessage(&msg, msgData)
	return g.broadcast(msgData)
}

func (g *GossipNode) broadcast(data []byte) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, p := range g.peers {
		if p.State == PeerAlive {
			addr, _ := net.ResolveUDPAddr("udp", p.Addr)
			g.conn.WriteToUDP(data, addr)
		}
	}
	return nil
}

func (g *GossipNode) signMessage(msg *GossipMessage, raw []byte) {
	if g.gossipKey == "" {
		return
	}
	mac := hmac.New(sha256.New, []byte(g.gossipKey))
	mac.Write(raw)
	msg.HMAC = fmt.Sprintf("%x", mac.Sum(nil))
}

func (g *GossipNode) verifyHMAC(msg GossipMessage) bool {
	if g.gossipKey == "" {
		return true
	}
	saved := msg.HMAC
	msg.HMAC = ""
	data, _ := json.Marshal(msg)
	mac := hmac.New(sha256.New, []byte(g.gossipKey))
	mac.Write(data)
	return hmac.Equal([]byte(saved), []byte(fmt.Sprintf("%x", mac.Sum(nil))))
}

// PeerCount returns the number of known peers regardless of state.
func (g *GossipNode) PeerCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.peers)
}

// Stop gracefully shuts down the gossip node.
func (g *GossipNode) Stop() {
	close(g.stopCh)
	g.conn.Close()
	log.Printf("[swarm] %s stopped", g.name)
}
