// Package engines — Adaptive Slow Attack Hunter
//
// Detects low-and-slow scanning that traditional fixed-window detectors miss.
// Uses dynamic window scaling: if no alerts fire in a window, shrink the
// window (faster detection). If alerts fire too often, grow the window
// (reduce false positives).
//
// Hot technique 2025-2026: slow stealth attacks that bypass all fixed-threshold
// IDS/IPS by staying just below the threshold indefinitely.
package engines

import (
	"math"
	"sync"
	"time"
)

// AdaptiveHunterConfig tunes the slow-attack detection.
type AdaptiveHunterConfig struct {
	// Initial window size in seconds
	InitialWindow float64
	// Minimum window size (fastest detection)
	MinWindow float64
	// Maximum window size (most patient)
	MaxWindow float64
	// Port threshold per window
	PortThreshold int
	// Window shrink factor when idle (0-1)
	ShrinkFactor float64
	// Window grow factor when alerting (0-1)
	GrowFactor float64
	// Cooldown between window adjustments
	AdjustCooldown time.Duration
}

// DefaultAdaptiveConfig returns sensible defaults for slow-attack hunting.
func DefaultAdaptiveConfig() AdaptiveHunterConfig {
	return AdaptiveHunterConfig{
		InitialWindow:  30.0,
		MinWindow:      5.0,
		MaxWindow:      300.0,
		PortThreshold:  10,
		ShrinkFactor:   0.9,
		GrowFactor:     1.5,
		AdjustCooldown: 30 * time.Second,
	}
}

// AdaptiveSlowHunter tracks per-IP scan rates with adaptive windows.
type AdaptiveSlowHunter struct {
	mu      sync.Mutex
	tracker map[string]*hunterState
	config  AdaptiveHunterConfig
}

type hunterState struct {
	window       float64          // current adaptive window in seconds
	ports        map[int]struct{} // unique ports seen
	lastAdjust   time.Time
	lastPortTime time.Time
	alerted      bool
	resetAt      time.Time // when this state was created
}

// NewAdaptiveSlowHunter creates a slow-attack hunter.
func NewAdaptiveSlowHunter(cfg AdaptiveHunterConfig) *AdaptiveSlowHunter {
	return &AdaptiveSlowHunter{
		tracker: make(map[string]*hunterState),
		config:  cfg,
	}
}

// Feed records a port probe from an IP. Returns true if the IP's scan rate
// exceeds the adaptive threshold (i.e., a slow scan was detected).
func (h *AdaptiveSlowHunter) Feed(ip string, port int) (detected bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	state, ok := h.tracker[ip]
	if !ok {
		state = &hunterState{
			window:       h.config.InitialWindow,
			ports:        make(map[int]struct{}),
			lastAdjust:   now,
			lastPortTime: now,
			resetAt:      now,
		}
		h.tracker[ip] = state
	}

	// Record port
	state.ports[port] = struct{}{}
	state.lastPortTime = now

	// Calculate time window elapsed
	windowDur := time.Duration(state.window * float64(time.Second))


	// Count unique ports in window (simple: total seen since reset or in window)
	portCount := len(state.ports)

	// Adaptive window adjustment
	if now.Sub(state.lastAdjust) >= h.config.AdjustCooldown {
		if portCount < h.config.PortThreshold && state.window > h.config.MinWindow {
			// Not enough activity — shrink window for faster detection
			state.window = math.Max(state.window*h.config.ShrinkFactor, h.config.MinWindow)
		} else if portCount >= h.config.PortThreshold && state.window < h.config.MaxWindow {
			// Alerting too much — grow window for patience
			state.window = math.Min(state.window*h.config.GrowFactor, h.config.MaxWindow)
		}
		state.lastAdjust = now

		// If window elapsed, reset port counter
		if state.resetAt.Add(windowDur).Before(now) {
			state.ports = make(map[int]struct{})
			state.ports[port] = struct{}{}
			state.resetAt = now
		}
	}

	// Detection: unique ports >= threshold in current adaptive window
	if portCount >= h.config.PortThreshold && !state.alerted {
		state.alerted = true
		return true
	}

	// Reset alert flag when window resets
	if state.resetAt.Add(windowDur).Before(now) {
		state.alerted = false
	}

	return false
}

// Stats returns current hunter state for diagnostics.
func (h *AdaptiveSlowHunter) Stats() map[string]interface{} {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats := map[string]interface{}{
		"total_tracked": len(h.tracker),
	}
	return stats
}

// Evict removes stale entries.
func (h *AdaptiveSlowHunter) Evict(deadlineUnix float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(h.config.MaxWindow) * time.Second)
	for ip, state := range h.tracker {
		if state.lastPortTime.Before(cutoff) {
			delete(h.tracker, ip)
		}
	}
	_ = deadlineUnix
}
