package engine

import (
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/pkg/ringbuf"
)

const (
	sshBruteThresh  = 10
	sshBruteWindow  = 60 * time.Second
	httpBruteThresh = 15
	httpBruteWindow = 60 * time.Second
)

// BruteForceDetector tracks per-IP login attempts for SSH and HTTP
// services and generates threats when thresholds are exceeded within
// the configured time windows.
type BruteForceDetector struct {
	mu          sync.Mutex
	sshAttempts map[string]*ringbuf.RingBuffer
	httpErrors  map[string]*ringbuf.RingBuffer
}

// NewBruteForceDetector creates a BruteForceDetector with the given
// configuration.
func NewBruteForceDetector(cfg *config.Config) *BruteForceDetector {
	return &BruteForceDetector{
		sshAttempts: make(map[string]*ringbuf.RingBuffer),
		httpErrors:  make(map[string]*ringbuf.RingBuffer),
	}
}

// FeedSSH records an SSH login attempt from srcIP.
func (bf *BruteForceDetector) FeedSSH(srcIP string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	rb, ok := bf.sshAttempts[srcIP]
	if !ok {
		rb = ringbuf.New(200)
		bf.sshAttempts[srcIP] = rb
	}
	rb.Push(time.Now())
	rb.PruneBefore(time.Now().Add(-sshBruteWindow))
}

// FeedHTTPError records an HTTP authentication error from srcIP.
func (bf *BruteForceDetector) FeedHTTPError(srcIP string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	rb, ok := bf.httpErrors[srcIP]
	if !ok {
		rb = ringbuf.New(200)
		bf.httpErrors[srcIP] = rb
	}
	rb.Push(time.Now())
	rb.PruneBefore(time.Now().Add(-httpBruteWindow))
}

// Check evaluates all tracked IPs against their thresholds and returns
// any detected brute-force threats.
func (bf *BruteForceDetector) Check() []Threat {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	var threats []Threat
	for ip, rb := range bf.sshAttempts {
		if rb.Len() >= sshBruteThresh {
			threats = append(threats, Threat{Type: "SSH爆破", IP: ip, Detail: "尝试次数过多"})
		}
	}
	for ip, rb := range bf.httpErrors {
		if rb.Len() >= httpBruteThresh {
			threats = append(threats, Threat{Type: "HTTP爆破", IP: ip, Detail: "错误次数过多"})
		}
	}
	return threats
}
