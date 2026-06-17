// Package offense implements offensive security tools. This file provides
// traffic shaping, IP fragmentation, TCP segmentation, TLS fingerprint
// spoofing, and adaptive evasion strategies that react to defender behavior.
package offense

import (
	"crypto/rand"
	"math"
	"math/big"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Traffic shaping utilities
// ---------------------------------------------------------------------------

// JitterDelay returns a random duration uniformly distributed in
// [baseMs - varianceMs, baseMs + varianceMs], clamped to a minimum of 0.
func JitterDelay(baseMs, varianceMs float64) time.Duration {
	delta := varianceMs
	if delta < 0 {
		delta = -delta
	}

	// Use crypto/rand for a uniform jitter in [-variance, +variance].
	n, err := rand.Int(rand.Reader, big.NewInt(int64(delta*2*1000)))
	var offset float64
	if err == nil {
		offset = float64(n.Int64())/1000.0 - delta
	} else {
		// Fallback to deterministic centre on crypto/rand failure (extremely
		// unlikely).
		offset = 0
	}

	ms := baseMs + offset
	if ms < 0 {
		ms = 0
	}
	return time.Duration(ms * float64(time.Millisecond))
}

// FragmentIP splits a payload into IP-layer fragments. Each fragment
// (except the last) has size fragSize and carries the MF (More Fragments)
// flag semantics. Returns a slice of byte slices representing individual
// fragments.
//
// This models the data that would be placed in IP fragment payloads; the
// caller is responsible for constructing actual IP headers.
func FragmentIP(payload []byte, fragSize int) [][]byte {
	if fragSize < 8 {
		fragSize = 8 // minimum IP fragment size (8-byte boundary)
	}
	if len(payload) == 0 {
		return nil
	}

	var fragments [][]byte
	for offset := 0; offset < len(payload); offset += fragSize {
		end := offset + fragSize
		if end > len(payload) {
			end = len(payload)
		}
		frag := make([]byte, end-offset)
		copy(frag, payload[offset:end])
		fragments = append(fragments, frag)
	}
	return fragments
}

// SegmentTCP splits a payload into TCP segments of at most segSize bytes.
// Returns a slice of byte slices representing individual segments.
func SegmentTCP(payload []byte, segSize int) [][]byte {
	if segSize < 1 {
		segSize = 1
	}
	if len(payload) == 0 {
		return nil
	}

	var segments [][]byte
	for offset := 0; offset < len(payload); offset += segSize {
		end := offset + segSize
		if end > len(payload) {
			end = len(payload)
		}
		seg := make([]byte, end-offset)
		copy(seg, payload[offset:end])
		segments = append(segments, seg)
	}
	return segments
}

// JA3SpoofProfile returns a map of TLS client parameters that mimic a
// known browser's JA3 fingerprint. Supported browsers: "chrome", "firefox",
// "safari". Returns nil for unrecognised values.
func JA3SpoofProfile(browser string) map[string]interface{} {
	switch browser {
	case "chrome":
		return map[string]interface{}{
			"version":             "Chrome 120",
			"tls_version":         "TLS 1.3",
			"ciphers":             []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
			"extensions":          []string{"server_name", "supported_groups", "ec_point_formats", "session_ticket", "application_layer_protocol_negotiation"},
			"elliptic_curves":     []string{"X25519", "P-256", "P-384"},
			"ec_point_formats":    []string{"uncompressed"},
			"alpn":                []string{"h2", "http/1.1"},
			"signature_algorithms": []string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384"},
		}
	case "firefox":
		return map[string]interface{}{
			"version":             "Firefox 120",
			"tls_version":         "TLS 1.3",
			"ciphers":             []string{"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384"},
			"extensions":          []string{"server_name", "supported_groups", "ec_point_formats", "session_ticket", "application_layer_protocol_negotiation"},
			"elliptic_curves":     []string{"X25519", "P-256", "P-384", "P-521"},
			"ec_point_formats":    []string{"uncompressed"},
			"alpn":                []string{"h2", "http/1.1"},
			"signature_algorithms": []string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"},
		}
	case "safari":
		return map[string]interface{}{
			"version":             "Safari 17",
			"tls_version":         "TLS 1.3",
			"ciphers":             []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
			"extensions":          []string{"server_name", "supported_groups", "ec_point_formats", "session_ticket", "application_layer_protocol_negotiation"},
			"elliptic_curves":     []string{"X25519", "P-256", "P-384"},
			"ec_point_formats":    []string{"uncompressed"},
			"alpn":                []string{"h2", "http/1.1"},
			"signature_algorithms": []string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"},
		}
	default:
		return nil
	}
}

// ---------------------------------------------------------------------------
// AdaptiveEvader
// ---------------------------------------------------------------------------

// AdaptiveEvader tracks success/failure signals and rotates through evasion
// strategies when defenders are suspected to be filtering or rate-limiting.
type AdaptiveEvader struct {
	mu                 sync.Mutex
	consecutiveFailures int
	consecutiveSuccesses int
	strategyIndex       int

	// Strategies is the ordered list of evasion strategies to rotate through.
	// Exported so callers can customise the list.
	Strategies []string
}

// defaultStrategies used by NewAdaptiveEvader.
var defaultStrategies = []string{
	"direct",
	"fragmented",
	"slow_scan",
	"distributed",
	"tls_spoof",
}

// NewAdaptiveEvader returns an AdaptiveEvader initialised with the default
// five-strategy rotation.
func NewAdaptiveEvader() *AdaptiveEvader {
	return &AdaptiveEvader{
		Strategies: append([]string{}, defaultStrategies...),
	}
}

// RecordSuccess increments the success counter and resets the failure counter.
func (ae *AdaptiveEvader) RecordSuccess() {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	ae.consecutiveSuccesses++
	ae.consecutiveFailures = 0
}

// RecordFailure increments the failure counter and resets the success counter.
func (ae *AdaptiveEvader) RecordFailure() {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	ae.consecutiveFailures++
	ae.consecutiveSuccesses = 0
}

// ShouldBackoff returns true when the evader has seen 3 or more consecutive
// failures, indicating the target may be rate-limiting or blocking.
func (ae *AdaptiveEvader) ShouldBackoff() bool {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	return ae.consecutiveFailures >= 3
}

// ShouldRotateStrategy returns true when the evader has seen 5 or more
// consecutive failures, indicating the current strategy is likely detected.
func (ae *AdaptiveEvader) ShouldRotateStrategy() bool {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	return ae.consecutiveFailures >= 5
}

// NextStrategy advances to the next evasion strategy and returns its name.
// If no strategies are configured it returns "direct".
func (ae *AdaptiveEvader) NextStrategy() string {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	if len(ae.Strategies) == 0 {
		return "direct"
	}
	ae.strategyIndex = (ae.strategyIndex + 1) % len(ae.Strategies)
	return ae.Strategies[ae.strategyIndex]
}

// ExponentialBackoff computes a backoff duration using the formula
// 2^failures * 500 ms, capped at 60 seconds. Returns 0 when there have been
// no failures.
func (ae *AdaptiveEvader) ExponentialBackoff() time.Duration {
	ae.mu.Lock()
	failures := ae.consecutiveFailures
	ae.mu.Unlock()

	if failures <= 0 {
		return 0
	}
	ms := math.Pow(2, float64(failures)) * 500
	if ms > 60000 {
		ms = 60000
	}
	return time.Duration(ms * float64(time.Millisecond))
}

// DetectRateLimit returns true when the response time exceeds twice the
// baseline, which is a heuristic indicator that the server is artificially
// delaying responses (rate-limiting).
func (ae *AdaptiveEvader) DetectRateLimit(responseTime, baseline time.Duration) bool {
	if baseline <= 0 {
		return false
	}
	return responseTime > baseline*2
}
