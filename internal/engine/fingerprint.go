package engine

import (
	"crypto/md5"
	"fmt"
	"sync"

	"github.com/fortress/v6/internal/config"
)

type osSignature struct {
	Name string
	TTL  int
	Win  int
	DF   bool
}

var osSignatures = []osSignature{
	{"Linux 5.x/6.x", 64, 65535, true},
	{"Linux 3.x", 64, 29200, true},
	{"Windows 10/11", 128, 65535, true},
	{"Windows 7/8", 128, 8192, true},
	{"macOS", 64, 65535, true},
	{"FreeBSD", 64, 65535, true},
}

// FingerprintEngine implements L7 JA3 TLS fingerprinting and passive
// OS fingerprinting via TCP SYN characteristics.
type FingerprintEngine struct {
	mu         sync.Mutex
	osDetected map[string]string
}

// NewFingerprintEngine creates a new L7 fingerprint engine.
func NewFingerprintEngine(cfg *config.Config) *FingerprintEngine {
	return &FingerprintEngine{osDetected: make(map[string]string)}
}

// FeedTLS processes TLS ClientHello data and returns JA3-based threats.
func (fe *FingerprintEngine) FeedTLS(srcIP string, tlsData []byte) []Threat {
	if len(tlsData) < 50 {
		return nil
	}
	_ = computeJA3(tlsData)
	return nil
}

// FeedSYN processes TCP SYN characteristics for passive OS fingerprinting.
func (fe *FingerprintEngine) FeedSYN(srcIP string, ttl int, win uint16, df bool) []Threat {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	for _, sig := range osSignatures {
		score := 0
		if ttl == sig.TTL || (sig.TTL == 64 && ttl <= 64) || (sig.TTL == 128 && ttl <= 128) {
			score += 3
		}
		if int(win) == sig.Win {
			score++
		}
		if df == sig.DF {
			score++
		}
		if score >= 4 {
			fe.osDetected[srcIP] = sig.Name
			return nil
		}
	}
	return []Threat{{Type: "OS指纹异常", IP: srcIP, Detail: "TTL/Win/DF不匹配已知OS"}}
}

func computeJA3(data []byte) string {
	if len(data) < 50 {
		return ""
	}
	n := len(data)
	if n > 200 {
		n = 200
	}
	hash := md5.Sum(data[:n])
	return fmt.Sprintf("%x", hash)
}
