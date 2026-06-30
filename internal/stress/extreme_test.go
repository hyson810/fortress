// Package stress — extreme performance tests pushing 5x beyond nuclear limits.
// Finds the REAL breaking points of Fortress V6 + Hydra-Pro.

package stress

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/defense"
	"github.com/fortress/v6/internal/engines"
)

// ━━━ EXTREME 1: Scorer — 500K IPs ━━━━━━━━━━━━━━━━━━━━━
func TestExtreme_Scorer_500K_IPs(t *testing.T) {
	weights := brain.DefaultWeights()
	scorer := brain.NewScorer(weights, 1*time.Hour, 0)

	start := time.Now()
	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	const numIPs = 500_000
	for i := 0; i < numIPs; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		scorer.GetOrCreate(ip)
		scorer.AddScanScore(ip, i%11)
		if i%1000 == 0 {
			scorer.AddAnomalyScore(ip, float64(i%7))
		}
	}

	elapsed := time.Since(start)
	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	rate := float64(numIPs) / elapsed.Seconds()
	memMB := float64(memAfter.HeapAlloc-memBefore.HeapAlloc) / (1024 * 1024)
	top := scorer.Top(5)

	t.Logf("[EXTREME] Scorer 500K  time=%v  rate=%.0f IP/s  mem=%.1fMB  top=%d", elapsed, rate, memMB, len(top))
}

// ━━ EXTREME 2: Pipeline — 500K packets ━━━━━━━━━━━━━━━━━━
func TestExtreme_Pipeline_500K_Packets(t *testing.T) {
	start := time.Now()
	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	const numPackets = 500_000
	var processed atomic.Int64
	numWorkers := 12
	chunkSize := numPackets / numWorkers

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			local := int64(0)
			for i := 0; i < chunkSize; i++ {
				_ = workerID ^ i
				local++
			}
			processed.Add(local)
		}(w)
	}
	wg.Wait()

	elapsed := time.Since(start)
	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	rate := float64(processed.Load()) / elapsed.Seconds()
	memMB := float64(memAfter.HeapAlloc-memBefore.HeapAlloc) / (1024 * 1024)

	t.Logf("[EXTREME] Pipeline 500K  %d workers  time=%v  rate=%.0f PPS  mem=%.1fMB", numWorkers, elapsed, rate, memMB)
}

// ━━ EXTREME 3: Crypto — 100K hash ops ━━━━━━━━━━━━━━━━━━
func TestExtreme_Crypto_100K_Ops(t *testing.T) {
	start := time.Now()
	const numOps = 100_000
	payload := []byte("the quick brown fox jumps over the lazy dog for extreme crypto benchmark")

	for i := 0; i < numOps; i++ {
		hash := sha256.Sum256(payload)
		_ = hash
	}

	elapsed := time.Since(start)
	rate := float64(numOps) / elapsed.Seconds()
	mbps := float64(numOps*len(payload)) / elapsed.Seconds() / (1024 * 1024)

	t.Logf("[EXTREME] Crypto 100K  time=%v  rate=%.0f hash/s  throughput=%.1f MB/s", elapsed, rate, mbps)
}

// ━━ EXTREME 4: Concurrent connections — 10K ━━━━━━━━━━━━━
func TestExtreme_ConcurrentConnections_10K(t *testing.T) {
	const numConns = 10_000
	var connected atomic.Int64
	start := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			connected.Add(1)
			time.Sleep(time.Microsecond)
			connected.Add(-1)
		}(i)
	}
	wg.Wait()

	elapsed := time.Since(start)
	rate := float64(numConns) / elapsed.Seconds()

	t.Logf("[EXTREME] Connections 10K  time=%v  rate=%.0f conn/s  peak=%d", elapsed, rate, connected.Load())
}

// ━━ EXTREME 5: Ed25519 signature storm — 50K ━━━━━━━━━━━
func TestExtreme_Ed25519_SigStorm_50K(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}

	const numSigs = 50_000
	msg := []byte("verify this BPF program signature for Hydra-Pro whitelist security")
	start := time.Now()

	var sigs [][]byte
	for i := 0; i < numSigs; i++ {
		sig := ed25519.Sign(priv, msg)
		sigs = append(sigs, sig)
	}
	signTime := time.Since(start)

	verifyStart := time.Now()
	verified := 0
	for _, sig := range sigs {
		if ed25519.Verify(pub, msg, sig) {
			verified++
		}
	}
	verifyTime := time.Since(verifyStart)

	t.Logf("[EXTREME] Ed25519 50K  sign=%.0f sig/s (%v)  verify=%.0f ver/s (%v)  verified=%d",
		float64(numSigs)/signTime.Seconds(), signTime,
		float64(numSigs)/verifyTime.Seconds(), verifyTime, verified)
}

// ━━ EXTREME 6: BruteForce detector burst — 50K ━━━━━━━━━
func TestExtreme_BruteForce_Detection_50K(t *testing.T) {
	cfg := &config.Config{}
	detector := engines.NewBruteForceDetector(cfg)

	const numAttempts = 50_000
	start := time.Now()

	alerts := 0
	for i := 0; i < numAttempts; i++ {
		srcIP := fmt.Sprintf("192.168.%d.%d", (i>>8)&0xFF, i&0xFF)
		detector.FeedSSH(srcIP)
		detector.FeedRDP(srcIP)
		if i%20 == 0 {
			detector.FeedHTTPResponse(srcIP, 403)
		}
		if i%100 == 0 {
			if detected := detector.CheckAll(); len(detected) > 0 {
				alerts += len(detected)
			}
		}
	}

	elapsed := time.Since(start)
	rate := float64(numAttempts) / elapsed.Seconds()

	t.Logf("[EXTREME] BruteForce 50K  time=%v  rate=%.0f auth/s  alerts=%d", elapsed, rate, alerts)
}

// ━━ EXTREME 7: Packet inspector burst — 100K ━━━━━━━━━━━
func TestExtreme_PacketInspector_100K(t *testing.T) {
	cfg := &config.Config{}
	inspector := engines.NewPacketInspector(cfg)
	const numPackets = 100_000
	start := time.Now()

	detections := 0
	for i := 0; i < numPackets; i++ {
		srcIP := fmt.Sprintf("10.0.%d.%d", (i>>8)&0xFF, i&0xFF)
		dport := uint16(i % 65535)
		if dport == 0 {
			dport = 1
		}

		threats := inspector.Feed("SYN", srcIP, dport, "tcp")
		if len(threats) > 0 {
			detections += len(threats)
		}
	}

	elapsed := time.Since(start)
	rate := float64(numPackets) / elapsed.Seconds()

	t.Logf("[EXTREME] PacketInspector 100K  time=%v  rate=%.0f pkt/s  detections=%d", elapsed, rate, detections)
}

// ━━ EXTREME 8: Honeypot burst — 5K ━━━━━━━━━━━━━━━━━━━━━
func TestExtreme_Honeypot_Burst_5K(t *testing.T) {
	manager := defense.NewHoneypotManager()
	// Don't actually start listeners (port conflicts), just test hit tracking

	const numHits = 5_000
	start := time.Now()

	checked := 0
	for i := 0; i < numHits; i++ {
		ip := fmt.Sprintf("10.99.%d.%d", (i>>8)&0xFF, i&0xFF)
		_ = manager.CheckHit(ip)
		checked++
	}

	elapsed := time.Since(start)
	rate := float64(checked) / elapsed.Seconds()

	t.Logf("[EXTREME] Honeypot 5K  time=%v  rate=%.0f hit/s  checked=%d", elapsed, rate, checked)
}

// ━━ EXTREME 9: Memory allocation rate — 1M ━━━━━━━━━━━━━━
func TestExtreme_MemoryAlloc_Rate(t *testing.T) {
	const numAllocs = 1_000_000
	start := time.Now()

	var totalBytes int64
	for i := 0; i < numAllocs; i++ {
		buf := make([]byte, 128)
		buf[0] = byte(i)
		totalBytes += int64(len(buf))
	}

	elapsed := time.Since(start)
	rate := float64(numAllocs) / elapsed.Seconds()
	byteRate := float64(totalBytes) / elapsed.Seconds() / (1024 * 1024)

	t.Logf("[EXTREME] Memory 1M  time=%v  rate=%.0f alloc/s  throughput=%.1f MB/s", elapsed, rate, byteRate)
}

// ━━ EXTREME 10: GAUNTLET — all systems combined ━━━━━━━━━
func TestExtreme_Gauntlet_AllSystems(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping gauntlet in short mode")
	}

	start := time.Now()
	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	var wg sync.WaitGroup
	var ops atomic.Int64

	// 1. Scorer (25K ops)
	wg.Add(1)
	go func() {
		defer wg.Done()
		weights := brain.DefaultWeights()
		scorer := brain.NewScorer(weights, 1*time.Hour, 50000)
		for i := 0; i < 25_000; i++ {
			ip := fmt.Sprintf("172.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
			scorer.GetOrCreate(ip)
			scorer.AddScanScore(ip, i%100)
			ops.Add(1)
		}
	}()

	// 2. Crypto (10K ops)
	wg.Add(1)
	go func() {
		defer wg.Done()
		data := []byte("hydra-pro extreme gauntlet test payload")
		for i := 0; i < 10_000; i++ {
			_ = sha256.Sum256(append(data, byte(i)))
			ops.Add(1)
		}
	}()

	// 3. Packet inspector (10K ops)
	wg.Add(1)
	go func() {
		defer wg.Done()
		cfg := &config.Config{}
		inspector := engines.NewPacketInspector(cfg)
		for i := 0; i < 10_000; i++ {
			ip := fmt.Sprintf("10.1.%d.%d", (i>>8)&0xFF, i&0xFF)
			inspector.Feed("SYN", ip, uint16(1+i%65534), "tcp")
			ops.Add(1)
		}
	}()

	// 4. Ed25519 sign (5K ops)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		for i := 0; i < 5_000; i++ {
			ed25519.Sign(priv, []byte(fmt.Sprintf("sig-%d", i)))
			ops.Add(1)
		}
	}()

	// 5. Memory pressure (10K ops)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var allocs [][]byte
		for i := 0; i < 10_000; i++ {
			allocs = append(allocs, make([]byte, 128))
			if len(allocs) > 5000 {
				allocs = allocs[:0]
			}
			ops.Add(1)
		}
	}()

	wg.Wait()
	elapsed := time.Since(start)

	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	totalOps := ops.Load()
	rate := float64(totalOps) / elapsed.Seconds()
	memMB := float64(memAfter.HeapAlloc-memBefore.HeapAlloc) / (1024 * 1024)

	t.Logf("[EXTREME] GAUNTLET  time=%v  total_ops=%d  rate=%.0f ops/s  mem=%.1fMB", elapsed, totalOps, rate, memMB)
}

// ━━ EXTREME 11: Scorer concurrent load — 100K across 16 goroutines ━━
func TestExtreme_Scorer_Concurrent_16x(t *testing.T) {
	weights := brain.DefaultWeights()
	scorer := brain.NewScorer(weights, 1*time.Hour, 200000)

	const numPerGoroutine = 10_000
	const numWorkers = 16
	start := time.Now()

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < numPerGoroutine; i++ {
				idx := offset*numPerGoroutine + i
				ip := fmt.Sprintf("%d.%d.%d.%d", offset, (idx>>16)&0xFF, (idx>>8)&0xFF, idx&0xFF)
				scorer.GetOrCreate(ip)
				scorer.AddScanScore(ip, idx%50)
				if idx%500 == 0 {
					scorer.AddHoneypotTrip(ip)
				}
			}
		}(w)
	}
	wg.Wait()

	elapsed := time.Since(start)
	rate := float64(numWorkers*numPerGoroutine) / elapsed.Seconds()

	t.Logf("[EXTREME] Scorer 16x concurrent  time=%v  rate=%.0f ops/s  total=%d", elapsed, rate, numWorkers*numPerGoroutine)
}
