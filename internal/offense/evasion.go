package offense

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	mathrand "math/rand"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Evasion — traffic shaping, IP frag, TCP seg, JA3 spoof, adaptive evader
// ---------------------------------------------------------------------------

// JitterDelay returns a random duration in [base-variance, base+variance].
// Uses crypto/rand for unpredictability.
func JitterDelay(baseMs, varianceMs float64) time.Duration {
	if varianceMs <= 0 {
		return time.Duration(baseMs * float64(time.Millisecond))
	}
	n := make([]byte, 8)
	rand.Read(n)
	delta := float64(int64(binary.LittleEndian.Uint64(n))%int64(varianceMs*2*1000+1)) / 1000.0 - varianceMs
	ms := baseMs + delta
	if ms < 0 {
		ms = 0
	}
	return time.Duration(ms * float64(time.Millisecond))
}

// FragmentIP splits payload into IP fragments of at most fragSize bytes.
func FragmentIP(payload []byte, fragSize int) [][]byte {
	if fragSize < 8 {
		fragSize = 8
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

// SegmentTCP splits payload into TCP segments of at most segSize bytes.
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

// JA3SpoofProfile returns a map of TLS client parameters that mimic a known
// browser. Browsers: "chrome", "firefox", "safari", "edge", "opera".
func JA3SpoofProfile(browser string) map[string]interface{} {
	switch browser {
	case "chrome":
		return map[string]interface{}{
			"browser":            "Chrome 120",
			"tls_version":        "TLS 1.3",
			"ciphers":            []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
			"extensions":         []string{"server_name", "supported_groups", "ec_point_formats", "session_ticket", "application_layer_protocol_negotiation", "key_share", "extended_master_secret"},
			"elliptic_curves":    []string{"X25519", "P-256", "P-384"},
			"ec_point_formats":   []string{"uncompressed"},
			"alpn":               []string{"h2", "http/1.1"},
			"signature_algorithms": []string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384"},
		}
	case "firefox":
		return map[string]interface{}{
			"browser":            "Firefox 120",
			"tls_version":        "TLS 1.3",
			"ciphers":            []string{"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
			"extensions":         []string{"server_name", "supported_groups", "ec_point_formats", "session_ticket", "application_layer_protocol_negotiation", "key_share", "extended_master_secret"},
			"elliptic_curves":    []string{"X25519", "P-256", "P-384", "P-521"},
			"ec_point_formats":   []string{"uncompressed"},
			"alpn":               []string{"h2", "http/1.1"},
			"signature_algorithms": []string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384"},
		}
	case "safari":
		return map[string]interface{}{
			"browser":            "Safari 17",
			"tls_version":        "TLS 1.3",
			"ciphers":            []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
			"extensions":         []string{"server_name", "supported_groups", "ec_point_formats", "session_ticket", "application_layer_protocol_negotiation", "key_share"},
			"elliptic_curves":    []string{"X25519", "P-256", "P-384"},
			"ec_point_formats":   []string{"uncompressed"},
			"alpn":               []string{"h2", "http/1.1"},
			"signature_algorithms": []string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"},
		}
	case "edge":
		return map[string]interface{}{
			"browser":            "Edge 120",
			"tls_version":        "TLS 1.3",
			"ciphers":            []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
			"extensions":         []string{"server_name", "supported_groups", "ec_point_formats", "session_ticket", "application_layer_protocol_negotiation", "key_share"},
			"elliptic_curves":    []string{"X25519", "P-256", "P-384"},
			"ec_point_formats":   []string{"uncompressed"},
			"alpn":               []string{"h2", "http/1.1"},
			"signature_algorithms": []string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"},
		}
	default:
		return nil
	}
}

// RandomTTL returns a TTL that mimics a common OS value ± small jitter.
func RandomTTL() int {
	profiles := []int{64, 128, 255}
	return profiles[mathrand.Intn(len(profiles))]
}

// ---------------------------------------------------------------------------
// AdaptiveEvader — strategy rotation with backoff
// ---------------------------------------------------------------------------

// AdaptiveEvader tracks success/failure and rotates through evasion
// strategies when defenders are suspected to be filtering or rate-limiting.
type AdaptiveEvader struct {
	mu                   sync.Mutex
	consecutiveFailures  int
	consecutiveSuccesses int
	strategyIndex        int

	// Strategies is the ordered list of evasion strategies.
	Strategies []string
}

var defaultStrategies = []string{
	"direct",
	"jitter",
	"fragmented",
	"slow_scan",
	"distributed",
	"tls_spoof",
	"http2",
}

// NewAdaptiveEvader returns an evader with default 7-strategy rotation.
func NewAdaptiveEvader() *AdaptiveEvader {
	s := make([]string, len(defaultStrategies))
	copy(s, defaultStrategies)
	return &AdaptiveEvader{Strategies: s}
}

func (ae *AdaptiveEvader) RecordSuccess() {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	ae.consecutiveSuccesses++
	ae.consecutiveFailures = 0
}

func (ae *AdaptiveEvader) RecordFailure() {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	ae.consecutiveFailures++
	ae.consecutiveSuccesses = 0
}

// ShouldBackoff returns true when failures >= 3.
func (ae *AdaptiveEvader) ShouldBackoff() bool {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	return ae.consecutiveFailures >= 3
}

// ShouldRotate returns true when failures >= 5.
func (ae *AdaptiveEvader) ShouldRotate() bool {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	return ae.consecutiveFailures >= 5
}

// NextStrategy advances to the next strategy and returns its name.
func (ae *AdaptiveEvader) NextStrategy() string {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	if len(ae.Strategies) == 0 {
		return "direct"
	}
	ae.strategyIndex = (ae.strategyIndex + 1) % len(ae.Strategies)
	return ae.Strategies[ae.strategyIndex]
}

// Backoff computes exponential backoff: 2^failures * 500ms, cap 60s.
func (ae *AdaptiveEvader) Backoff() time.Duration {
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

// DetectRateLimit returns true if response time > 2x baseline.
func (ae *AdaptiveEvader) DetectRateLimit(responseTime, baseline time.Duration) bool {
	if baseline <= 0 {
		return false
	}
	return responseTime > baseline*2
}
