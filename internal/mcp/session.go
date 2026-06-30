package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

// Session represents an authenticated MCP client session.
type Session struct {
	ID         string            `json:"id"`
	CreatedAt  time.Time         `json:"created_at"`
	LastActive time.Time         `json:"last_active"`
	AuthLevel  int               `json:"auth_level"`
	ClientInfo map[string]string `json:"client_info"`
}

// Expired reports whether the session has been idle longer than the given timeout.
func (s *Session) Expired(timeout time.Duration) bool {
	return time.Since(s.LastActive) > timeout
}

// Touch updates the LastActive timestamp to the current time.
func (s *Session) Touch() {
	s.LastActive = time.Now()
}

// SessionInfo provides a snapshot of session manager state for status reporting.
type SessionInfo struct {
	ActiveSessions int         `json:"active_sessions"`
	MaxSessions    int         `json:"max_sessions"`
	SessionsByAuth map[int]int `json:"sessions_by_auth"`
}

// SessionManager handles MCP session lifecycle: creation, validation, expiry.
type SessionManager struct {
	mu             sync.RWMutex
	sessions       map[string]*Session
	maxSessions    int
	sessionTimeout time.Duration
	stopCleanup    chan struct{}
}

// NewSessionManager creates a new SessionManager with default limits.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:       make(map[string]*Session),
		maxSessions:    10,
		sessionTimeout: 30 * time.Minute,
		stopCleanup:    make(chan struct{}),
	}
}

// SetMaxSessions configures the maximum concurrent sessions allowed.
func (sm *SessionManager) SetMaxSessions(n int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.maxSessions = n
}

// SetSessionTimeout configures the idle timeout after which sessions expire.
func (sm *SessionManager) SetSessionTimeout(d time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessionTimeout = d
}

// CreateSession creates a new session with the given auth level and client metadata.
// Returns an error if the maximum number of concurrent sessions has been reached.
func (sm *SessionManager) CreateSession(authLevel int, clientInfo map[string]string) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.sessions) >= sm.maxSessions {
		return nil, fmt.Errorf("session: max sessions (%d) reached", sm.maxSessions)
	}

	id, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("session: id generation: %w", err)
	}

	session := &Session{
		ID:         id,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		AuthLevel:  authLevel,
		ClientInfo: copyStringMap(clientInfo),
	}
	sm.sessions[id] = session

	log.Printf("[session] created %s (auth=%d, total=%d)", id, authLevel, len(sm.sessions))
	return session, nil
}

// CloseSession removes and closes a session by ID.
func (sm *SessionManager) CloseSession(id string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, ok := sm.sessions[id]; !ok {
		return fmt.Errorf("session: not found: %s", id)
	}
	delete(sm.sessions, id)
	log.Printf("[session] closed %s (remaining=%d)", id, len(sm.sessions))
	return nil
}

// ValidateSession checks that a session exists and has not expired.
// Updates LastActive on successful validation.
func (sm *SessionManager) ValidateSession(id string) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session: invalid: %s", id)
	}

	timeout := sm.sessionTimeout
	if session.Expired(timeout) {
		delete(sm.sessions, id)
		log.Printf("[session] expired %s (idle=%v)", id, time.Since(session.LastActive))
		return nil, fmt.Errorf("session: expired: %s", id)
	}

	session.Touch()
	// Return a copy to prevent mutation of shared state
	copied := *session
	copied.ClientInfo = copyStringMap(session.ClientInfo)
	return &copied, nil
}

// SessionList returns a copy of all active sessions.
func (sm *SessionManager) SessionList() []Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make([]Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		copied := *s
		copied.ClientInfo = copyStringMap(s.ClientInfo)
		result = append(result, copied)
	}
	return result
}

// SessionCount returns the number of active sessions.
func (sm *SessionManager) SessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// ActiveSessionsByAuth returns the count of sessions at a given auth level.
func (sm *SessionManager) ActiveSessionsByAuth(authLevel int) int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	for _, s := range sm.sessions {
		if s.AuthLevel == authLevel {
			count++
		}
	}
	return count
}

// Info returns a snapshot of current session manager state.
func (sm *SessionManager) Info() SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	byAuth := map[int]int{
		0: 0,
		1: 0,
		2: 0,
	}
	for _, s := range sm.sessions {
		byAuth[s.AuthLevel]++
	}
	return SessionInfo{
		ActiveSessions: len(sm.sessions),
		MaxSessions:    sm.maxSessions,
		SessionsByAuth: byAuth,
	}
}

// StartCleanup launches a background goroutine that periodically removes
// expired sessions. Call StopCleanup to terminate the goroutine.
func (sm *SessionManager) StartCleanup(interval time.Duration) {
	if interval <= 0 {
		interval = 1 * time.Minute
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[session] cleanup panic: %v\nstack: %s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		log.Printf("[session] cleanup goroutine started (interval=%v)", interval)
		for {
			select {
			case <-sm.stopCleanup:
				log.Println("[session] cleanup goroutine stopped")
				return
			case <-ticker.C:
				sm.removeExpired()
			}
		}
	}()
}

// StopCleanup signals the cleanup goroutine to terminate.
func (sm *SessionManager) StopCleanup() {
	select {
	case sm.stopCleanup <- struct{}{}:
	default:
	}
}

// removeExpired drops all sessions that have exceeded the idle timeout.
func (sm *SessionManager) removeExpired() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	timeout := sm.sessionTimeout
	expired := make([]string, 0)
	for id, s := range sm.sessions {
		if s.Expired(timeout) {
			expired = append(expired, id)
		}
	}
	for _, id := range expired {
		delete(sm.sessions, id)
	}
	if len(expired) > 0 {
		log.Printf("[session] removed %d expired sessions (remaining=%d)", len(expired), len(sm.sessions))
	}
}

// generateSessionID produces a hex-encoded random session identifier.
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: rand read: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// copyStringMap returns a shallow copy of a string map (immutable pattern).
func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
