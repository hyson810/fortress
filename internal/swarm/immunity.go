// Package swarm implements the Fortress distributed protocol for peer
// discovery, threat intel sharing, and consensus-based counterstrikes.
//
// immunity.go provides swarm-wide adaptive immunity: when one node detects
// a new threat, it broadcasts the rule to all peers via gossip. Receiving
// nodes inject the rule directly into their local kernel (eBPF / iptables).
package swarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// ImmunityRecord — wire format for a swarm immunity rule
// ---------------------------------------------------------------------------

// ImmunityRecord is a serializable eBPF / firewall rule that can be
// broadcast through the gossip mesh. Every record carries an Ed25519
// signature so receivers can verify the originating node's identity.
type ImmunityRecord struct {
	ID         string `json:"id"`          // unique ID: {node}-{timestamp}
	OriginNode string `json:"origin"`      // node that discovered the threat
	TargetIP   string `json:"target_ip"`   // IP to block ("" for subnet / pattern)
	Subnet     string `json:"subnet"`      // CIDR subnet to block
	Pattern    string `json:"pattern"`     // JA3 hash or byte pattern
	RuleType   string `json:"type"`        // "ip_block", "subnet_block", "ja3_block", "rate_limit"
	TTL        int64  `json:"ttl"`         // unix timestamp when rule expires (0 = never)
	Timestamp  int64  `json:"ts"`
	PublicKey  []byte `json:"pubkey"`      // Ed25519 public key of the origin node
	Signature  []byte `json:"sig"`         // Ed25519 signature over all fields above
}

// Sign computes and attaches an Ed25519 signature to the record. The caller
// must set ID, OriginNode, TargetIP, Subnet, Pattern, RuleType, TTL,
// Timestamp, and PublicKey before calling Sign. Signature covers all of
// those fields (in the order they appear in the struct).
func (r *ImmunityRecord) Sign(privateKey ed25519.PrivateKey) error {
	r.Signature = nil
	payload, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("immunity: marshal for signing: %w", err)
	}
	r.Signature = ed25519.Sign(privateKey, payload)
	return nil
}

// Verify checks the Ed25519 signature against the embedded public key.
func (r *ImmunityRecord) Verify() bool {
	sig := r.Signature
	if len(sig) == 0 || len(r.PublicKey) == 0 {
		return false
	}
	r.Signature = nil
	payload, err := json.Marshal(r)
	r.Signature = sig
	if err != nil {
		return false
	}
	return ed25519.Verify(r.PublicKey, payload, sig)
}

// Expired returns true if the rule's TTL has passed (nonzero TTL only).
func (r *ImmunityRecord) Expired() bool {
	if r.TTL == 0 {
		return false
	}
	return time.Now().Unix() > r.TTL
}

// ---------------------------------------------------------------------------
// ImmunityEngine — manages swarm-wide immunity rules
// ---------------------------------------------------------------------------

// ImmunityEngine manages the lifecycle of swarm immunity rules: publishing
// locally discovered threats, receiving remote rules via gossip, applying
// them via a user-supplied callback, and cleaning up expired entries.
//
// All exported methods are safe for concurrent use.
type ImmunityEngine struct {
	mu       sync.RWMutex
	gossip   *GossipNode
	rules    map[string]*ImmunityRecord // ID → record
	pubKey   ed25519.PublicKey
	privKey  ed25519.PrivateKey
	applyFn  func(record *ImmunityRecord) error // callback to apply rule locally
}

// NewImmunityEngine creates an ImmunityEngine attached to the given
// GossipNode, generates a fresh Ed25519 key pair for origin authentication,
// and registers itself as the threat-intel callback so incoming immunity
// records are processed automatically.
func NewImmunityEngine(gossip *GossipNode) (*ImmunityEngine, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("immunity: generate key pair: %w", err)
	}

	ie := &ImmunityEngine{
		gossip:  gossip,
		rules:   make(map[string]*ImmunityRecord),
		pubKey:  pub,
		privKey: priv,
	}

	// Register as threat-intel callback. The GossipNode already handles
	// epidemic fan-out in its handleThreatIntel, so we only need to
	// verify, deduplicate, and apply locally.
	gossip.OnThreatIntel(func(peerName string, data []byte) {
		if err := ie.ReceiveImmunity(data); err != nil {
			log.Printf("[immunity] receive from %s: %v", peerName, err)
		}
	})

	return ie, nil
}

// SetApplyFunc registers the local rule-application callback (e.g., inject
// an eBPF filter, add an iptables rule, or update an XDP blacklist).
func (ie *ImmunityEngine) SetApplyFunc(fn func(*ImmunityRecord) error) {
	ie.mu.Lock()
	ie.applyFn = fn
	ie.mu.Unlock()
}

// PublishImmunity signs the record, stores it locally, and broadcasts it to
// the swarm via the attached GossipNode.
func (ie *ImmunityEngine) PublishImmunity(record *ImmunityRecord) error {
	if record == nil {
		return fmt.Errorf("immunity: nil record")
	}

	// Fill in origin metadata.
	ie.mu.RLock()
	pubKey := ie.pubKey
	privKey := ie.privKey
	ie.mu.RUnlock()

	record.PublicKey = pubKey
	if record.Timestamp == 0 {
		record.Timestamp = time.Now().Unix()
	}

	if err := record.Sign(privKey); err != nil {
		return fmt.Errorf("immunity: sign: %w", err)
	}

	// Store locally first so we recognise our own rule on echo.
	ie.mu.Lock()
	ie.rules[record.ID] = record
	ie.mu.Unlock()

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("immunity: marshal: %w", err)
	}

	ie.gossip.BroadcastThreatIntel(data)
	log.Printf("[immunity] published rule %s type=%s", record.ID, record.RuleType)
	return nil
}

// ReceiveImmunity deserializes an incoming immunity record, verifies its
// signature, deduplicates, applies the rule locally via the registered
// apply callback, and stores it. The GossipNode automatically fans out
// the raw threat-intel payload to 3 peers, so we do not re-broadcast here.
func (ie *ImmunityEngine) ReceiveImmunity(data []byte) error {
	var record ImmunityRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	if record.ID == "" {
		return fmt.Errorf("missing id")
	}

	// Verify Ed25519 signature.
	if !record.Verify() {
		return fmt.Errorf("signature verification failed for %s", record.ID)
	}

	// Deduplicate.
	ie.mu.Lock()
	if _, exists := ie.rules[record.ID]; exists {
		ie.mu.Unlock()
		return nil // already known
	}

	// Reject expired rules on arrival.
	if record.Expired() {
		ie.mu.Unlock()
		return nil
	}

	ie.rules[record.ID] = &record
	applyFn := ie.applyFn
	ie.mu.Unlock()

	// Apply locally.
	if applyFn != nil {
		if err := applyFn(&record); err != nil {
			log.Printf("[immunity] apply rule %s: %v", record.ID, err)
			// Keep the rule — a later retry or manual intervention may succeed.
		}
	}

	log.Printf("[immunity] accepted rule %s type=%s from %s", record.ID, record.RuleType, record.OriginNode)
	return nil
}

// GetRules returns a snapshot of all active (non-expired) immunity rules.
func (ie *ImmunityEngine) GetRules() []*ImmunityRecord {
	ie.mu.RLock()
	defer ie.mu.RUnlock()

	out := make([]*ImmunityRecord, 0, len(ie.rules))
	for _, r := range ie.rules {
		if !r.Expired() {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out
}

// Cleanup removes every rule whose TTL has passed. It should be called
// periodically (e.g., every 30 seconds) from a background goroutine.
func (ie *ImmunityEngine) Cleanup() {
	ie.mu.Lock()
	defer ie.mu.Unlock()

	for id, r := range ie.rules {
		if r.Expired() {
			delete(ie.rules, id)
			log.Printf("[immunity] expired rule %s removed", id)
		}
	}
}
