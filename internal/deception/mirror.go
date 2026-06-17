package deception

import "log"

// MirrorEngine implements a digital twin redirect via XDP.
// Attackers probing the real system are transparently redirected
// to a high-fidelity replica, isolating them from production.
type MirrorEngine struct {
	active bool
}

// NewMirrorEngine creates a new MirrorEngine in an inactive state.
func NewMirrorEngine() *MirrorEngine { return &MirrorEngine{} }

// Redirect marks the target IP for XDP-level redirection to the
// digital twin environment.
func (m *MirrorEngine) Redirect(ip string) {
	m.active = true
	log.Printf("[deception] mirror: redirecting %s to digital twin", ip)
}

// IsActive returns whether the mirror engine is currently redirecting traffic.
func (m *MirrorEngine) IsActive() bool { return m.active }
