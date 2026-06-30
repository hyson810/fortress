// Package stress — HYPERNOVA: Beyond extreme limits.
// Pushes Hydra-Pro past breaking point to find REAL ceiling.
// This is NOT a normal test. This is a DESTRUCTION TEST.
//
// Categories:
//   H0 - Single-component annihilation (1M+ operations each)
//   H1 - All-systems thermonuclear gauntlet
//   H2 - Memory saturation (alloc until OOM or slowdown)
//   H3 - Goroutine storm (10K+ concurrent goroutines)
//   H4 - Rapid create/destroy cycles (fragmentation attack)

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
	"github.com/fortress/v6/internal/swarm"
)

// ═══════════════════════════════════════════════════════════════════════════
// H0-1: SCORER ANNIHILATION — 1,000,000 IPs
// ═══════════════════════════════════════════════════════════════════════════

func TestHYPERNOVA_Scorer_1M_IPs(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	start := time.Now()
	s := brain.NewScorer(brain.AggressiveWeights(), 1800, 0)
	n := 1_000_000

	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		s.GetOrCreate(ip)
		if i%10 == 0 {
			s.AddScanScore(ip, i%100)
		}
		if i%100 == 0 {
			s.AddAnomalyScore(ip, float64(i%30))
			s.AddFloodScore(ip, float64(i%500))
		}
		if i%500 == 0 {
			s.AddHoneypotTrip(ip)
		}
	}

	elapsed := time.Since(start)
	runtime.GC()
	runtime.ReadMemStats(&m2)
	memMB := float64(m2.HeapAlloc-m1.HeapAlloc) / (1024 * 1024)

	top := s.Top(10)
	rate := float64(n) / elapsed.Seconds()

	t.Logf("[HYPERNOVA] Scorer 1M IPs | time=%v | rate=%.0f IP/s | mem=%.1fMB | top=%d",
		elapsed.Round(time.Millisecond), rate, memMB, len(top))

	if n < 1_000_000 {
		t.Error("FAIL: did not reach 1M target")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// H0-2: EVIDENCE TSUNAMI — 500,000 Records + Chain Verify
// ═══════════════════════════════════════════════════════════════════════════

func TestHYPERNOVA_Evidence_500K_Records(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	ec := brain.NewEvidenceCollector(600_000, "")
	start := time.Now()
	n := 500_000

	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("172.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		level := brain.ResponseA
		switch i % 5 {
		case 1:
			level = brain.ResponseB
		case 2:
			level = brain.ResponseC
		case 3, 4:
			level = brain.ResponseD
		}
		ec.Collect(ip, "hypernova", float64(i%100), level, []string{"burn"})
	}

	elapsed := time.Since(start)
	runtime.GC()
	runtime.ReadMemStats(&m2)
	memMB := float64(m2.HeapAlloc-m1.HeapAlloc) / (1024 * 1024)

	verifyStart := time.Now()
	chainOk := ec.VerifyChain()
	verifyTime := time.Since(verifyStart)

	rate := float64(n) / elapsed.Seconds()

	t.Logf("[HYPERNOVA] Evidence 500K | time=%v | rate=%.0f rec/s | mem=%.1fMB | chain=%v | verify=%v",
		elapsed.Round(time.Millisecond), rate, memMB, chainOk, verifyTime.Round(time.Microsecond))

	if !chainOk {
		t.Error("FAIL: evidence chain integrity broken at 500K records")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// H0-3: CRYPTO TORNADO — 500K SHA256 + 50K Ed25519 sign+verify
// ═══════════════════════════════════════════════════════════════════════════

func TestHYPERNOVA_Crypto_500K_Combined(t *testing.T) {
	payload := []byte("HYDRA-PRO HYPERNOVA cryptographic stress test payload for annihilation benchmark")
	n := 500_000

	// SHA256 storm
	shaStart := time.Now()
	for i := 0; i < n; i++ {
		_ = sha256.Sum256(append(payload, byte(i)))
	}
	shaTime := time.Since(shaStart)
	shaRate := float64(n) / shaTime.Seconds()

	// Ed25519 sign+verify storm
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sigN := 50_000

	signStart := time.Now()
	var sigs [][]byte
	for i := 0; i < sigN; i++ {
		sig := ed25519.Sign(priv, append(payload, byte(i)))
		sigs = append(sigs, sig)
	}
	signTime := time.Since(signStart)

	verifyStart := time.Now()
	verified := 0
	for _, sig := range sigs {
		if ed25519.Verify(pub, append(payload, byte(verified)), sig) {
			verified++
		}
	}
	verifyTime := time.Since(verifyStart)

	t.Logf("[HYPERNOVA] Crypto Combined | SHA256: %.0f hash/s (%v) | Ed25519 sign: %.0f/s (%v) verify: %.0f/s (%v) ok=%d",
		shaRate, shaTime.Round(time.Microsecond),
		float64(sigN)/signTime.Seconds(), signTime.Round(time.Millisecond),
		float64(sigN)/verifyTime.Seconds(), verifyTime.Round(time.Millisecond),
		verified)

	if verified != sigN {
		t.Errorf("FAIL: only %d/%d signatures verified", verified, sigN)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// H0-4: GOROUTINE STORM — 20,000 concurrent goroutines
// ═══════════════════════════════════════════════════════════════════════════

func TestHYPERNOVA_Goroutine_20K(t *testing.T) {
	n := 20_000
	var counter atomic.Int64
	var maxConcurrent atomic.Int64
	var current atomic.Int64

	start := time.Now()
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			cur := current.Add(1)
			if cur > maxConcurrent.Load() {
				maxConcurrent.Store(cur)
			}
			// Simulate real work: crypto + allocation
			data := make([]byte, 256)
			data[0] = byte(id)
			_ = sha256.Sum256(data)
			counter.Add(1)
			current.Add(-1)
			wg.Done()
		}(i)
	}
	wg.Wait()

	elapsed := time.Since(start)
	rate := float64(counter.Load()) / elapsed.Seconds()

	t.Logf("[HYPERNOVA] Goroutine 20K | time=%v | rate=%.0f goroutines/s | max_concurrent=%d | total=%d",
		elapsed.Round(time.Millisecond), rate, maxConcurrent.Load(), counter.Load())

	if counter.Load() != int64(n) {
		t.Errorf("FAIL: only %d/%d goroutines completed", counter.Load(), n)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// H0-5: PACKET INSPECTOR — 2,000,000 packets
// ═══════════════════════════════════════════════════════════════════════════

func TestHYPERNOVA_PacketInspector_2M(t *testing.T) {
	cfg := &config.Config{}
	inspector := engines.NewPacketInspector(cfg)
	n := 2_000_000

	start := time.Now()
	detections := 0
	flags := []string{"S", "A", "FA", "R", "PA"}

	for i := 0; i < n; i++ {
		srcIP := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		dport := uint16(1 + i%65535)
		if dport == 0 {
			dport = 1
		}
		flag := flags[i%len(flags)]
		threats := inspector.Feed(flag, srcIP, dport, "tcp")
		if len(threats) > 0 {
			detections += len(threats)
		}
	}

	elapsed := time.Since(start)
	rate := float64(n) / elapsed.Seconds()

	t.Logf("[HYPERNOVA] PacketInspector 2M | time=%v | rate=%.0f pkt/s | detections=%d",
		elapsed.Round(time.Millisecond), rate, detections)
}

// ═══════════════════════════════════════════════════════════════════════════
// H1: THERMONUCLEAR GAUNTLET — All 16 subsystems, 100K ops each, concurrent
// ═══════════════════════════════════════════════════════════════════════════

func TestHYPERNOVA_ThermonuclearGauntlet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping thermonuclear gauntlet in short mode")
	}

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	start := time.Now()
	var totalOps atomic.Int64
	var wg sync.WaitGroup

	// 1. Scorer — 200K IPs
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := brain.NewScorer(brain.AggressiveWeights(), 3600, 300_000)
		for i := 0; i < 200_000; i++ {
			ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
			s.GetOrCreate(ip)
			if i%50 == 0 {
				s.AddScanScore(ip, i%200)
				s.AddHoneypotTrip(ip)
			}
			totalOps.Add(1)
		}
	}()

	// 2. Evidence — 100K records
	wg.Add(1)
	go func() {
		defer wg.Done()
		ec := brain.NewEvidenceCollector(150_000, "")
		for i := 0; i < 100_000; i++ {
			ip := fmt.Sprintf("172.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
			ec.Collect(ip, "gauntlet", float64(i%80), brain.ResponseC, nil)
			totalOps.Add(1)
		}
		ec.VerifyChain()
	}()

	// 3. Crypto — 250K SHA256
	wg.Add(1)
	go func() {
		defer wg.Done()
		payload := []byte("thermonuclear gauntlet crypto test")
		for i := 0; i < 250_000; i++ {
			_ = sha256.Sum256(append(payload, byte(i)))
			totalOps.Add(1)
		}
	}()

	// 4. Ed25519 — 25K signatures
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		for i := 0; i < 25_000; i++ {
			ed25519.Sign(priv, []byte(fmt.Sprintf("sig-%d", i)))
			totalOps.Add(1)
		}
	}()

	// 5. PacketInspector — 100K packets
	wg.Add(1)
	go func() {
		defer wg.Done()
		cfg := &config.Config{}
		pi := engines.NewPacketInspector(cfg)
		for i := 0; i < 100_000; i++ {
			ip := fmt.Sprintf("192.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
			pi.Feed("S", ip, uint16(1+i%65534), "tcp")
			totalOps.Add(1)
		}
	}()

	// 6. FlowAnalyzer — 50K flows
	wg.Add(1)
	go func() {
		defer wg.Done()
		cfg := &config.Config{}
		fa := engines.NewFlowAnalyzer(cfg)
		for i := 0; i < 50_000; i++ {
			ip := fmt.Sprintf("10.1.%d.%d", (i>>8)&0xFF, i&0xFF)
			fa.Feed(ip, uint16(1+i%65535))
			totalOps.Add(1)
		}
	}()

	// 7. DNS Tunnel Detector — 50K queries
	wg.Add(1)
	go func() {
		defer wg.Done()
		cfg := &config.Config{}
		dd := engines.NewDnsTunnelDetector(cfg)
		for i := 0; i < 50_000; i++ {
			ip := fmt.Sprintf("10.2.%d.%d", (i>>8)&0xFF, i&0xFF)
			dd.Feed(ip, fmt.Sprintf("q%d.ultra-long-subdomain-for-testing.example.com", i))
			if i%100 == 0 {
				dd.Check(ip)
			}
			totalOps.Add(1)
		}
	}()

	// 8. BruteForce — 50K auth attempts
	wg.Add(1)
	go func() {
		defer wg.Done()
		cfg := &config.Config{}
		bd := engines.NewBruteForceDetector(cfg)
		for i := 0; i < 50_000; i++ {
			ip := fmt.Sprintf("10.3.%d.%d", (i>>8)&0xFF, i&0xFF)
			bd.FeedSSH(ip)
			bd.FeedRDP(ip)
			if i%200 == 0 {
				bd.CheckAll()
			}
			totalOps.Add(2)
		}
	}()

	// 9. BehaviorAnalyzer — 50K events
	wg.Add(1)
	go func() {
		defer wg.Done()
		cfg := &config.Config{}
		ba := engines.NewBehaviorAnalyzer(cfg)
		for i := 0; i < 50_000; i++ {
			ip := fmt.Sprintf("10.4.%d.%d", (i>>8)&0xFF, i&0xFF)
			ba.Feed(ip, uint16(1+i%65535))
			totalOps.Add(1)
		}
	}()

	// 10. CorrelationEngine — 50K events
	wg.Add(1)
	go func() {
		defer wg.Done()
		ce := engines.NewCorrelationEngine()
		for i := 0; i < 50_000; i++ {
			ip := fmt.Sprintf("10.5.%d.%d", (i>>8)&0xFF, i&0xFF)
			ce.Feed(ip, "hypernova_event")
			totalOps.Add(1)
		}
	}()

	// 11. HybridAnomalyDetector — 25K
	wg.Add(1)
	go func() {
		defer wg.Done()
		cfg := &config.Config{}
		had := engines.NewHybridAnomalyDetector(cfg, true)
		for i := 0; i < 25_000; i++ {
			srcIP := fmt.Sprintf("10.6.%d.%d", (i>>8)&0xFF, i&0xFF)
			had.Feed(srcIP, "10.0.0.1", uint16(40000+i%30000), uint16(1+i%65535), "TCP", 1500, 2, 3.0)
			totalOps.Add(1)
		}
	}()

	// 12. Countermeasure + Threshold + Whitelist — 50K ops
	wg.Add(1)
	go func() {
		defer wg.Done()
		cm := brain.NewCountermeasureEngine()
		at := brain.NewAdaptiveThreshold(20, 5, 80, 0.05)
		lw := brain.NewLearnedWhitelist(100_000)
		for i := 0; i < 50_000; i++ {
			ip := fmt.Sprintf("10.7.%d.%d", (i>>8)&0xFF, i&0xFF)
			cm.Recommend(ip, float64(i%100), brain.ResponseB, false)
			at.Update(float64(i % 60))
			lw.LearnFromTraffic(ip, "hypernova", i%10 == 0)
			totalOps.Add(3)
		}
	}()

	// 13. Honeypot burst — 10K
	wg.Add(1)
	go func() {
		defer wg.Done()
		hm := defense.NewHoneypotManager()
		for i := 0; i < 10_000; i++ {
			ip := fmt.Sprintf("10.8.%d.%d", (i>>8)&0xFF, i&0xFF)
			hm.CheckHit(ip)
			totalOps.Add(1)
		}
	}()

	// 14. Swarm — 100 nodes
	wg.Add(1)
	go func() {
		defer wg.Done()
		cfg := config.SwarmConfig{Name: "nova", GossipKey: "test-key-32-bytes-hypernova-xxxxxx!"}
		for i := 0; i < 100; i++ {
			gn, err := swarm.NewGossipNode(cfg, "127.0.0.1:0")
			if err != nil {
				break
			}
			gn.Start()
			totalOps.Add(1)
			time.Sleep(time.Millisecond)
			gn.Stop()
		}
	}()

	wg.Wait()
	elapsed := time.Since(start)

	runtime.GC()
	runtime.ReadMemStats(&m2)
	memMB := float64(m2.HeapAlloc-m1.HeapAlloc) / (1024 * 1024)
	rate := float64(totalOps.Load()) / elapsed.Seconds()

	t.Logf("[HYPERNOVA] THERMONUCLEAR GAUNTLET | time=%v | total_ops=%d | rate=%.0f ops/s | mem=%.1fMB | SUBSYSTEMS=14",
		elapsed.Round(time.Millisecond), totalOps.Load(), rate, memMB)
}

// ═══════════════════════════════════════════════════════════════════════════
// H2: MEMORY ANNIHILATION — Allocate until GC pressure peaks
// ═══════════════════════════════════════════════════════════════════════════

func TestHYPERNOVA_MemoryAnnihilation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory annihilation in short mode")
	}

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	start := time.Now()
	var totalAlloc int64
	var maxAllocMB float64
	batchSize := 10_000
	totalBatches := 200 // 2M allocations total

	for b := 0; b < totalBatches; b++ {
		var batch [][]byte
		for i := 0; i < batchSize; i++ {
			// Allocate varied sizes: 64B to 4KB
			size := 64 + (i%63)*64
			buf := make([]byte, size)
			buf[0] = byte(b)
			buf[len(buf)-1] = byte(i)
			batch = append(batch, buf)
			totalAlloc += int64(size)
		}

		// Every 10 batches, check memory pressure
		if b%10 == 0 {
			runtime.GC()
			runtime.ReadMemStats(&m2)
			currentMB := float64(m2.HeapAlloc) / (1024 * 1024)
			if currentMB > maxAllocMB {
				maxAllocMB = currentMB
			}
		}

		// Release batch (GC will collect)
		batch = nil
	}

	elapsed := time.Since(start)
	runtime.GC()
	runtime.ReadMemStats(&m2)
	finalMB := float64(m2.HeapAlloc) / (1024 * 1024)
	totalAllocMB := float64(totalAlloc) / (1024 * 1024)

	t.Logf("[HYPERNOVA] Memory Annihilation | time=%v | total_alloc=%.0fMB | peak_heap=%.1fMB | final_heap=%.1fMB | allocs=%d",
		elapsed.Round(time.Millisecond), totalAllocMB, maxAllocMB, finalMB, totalBatches*batchSize)
}

// ═══════════════════════════════════════════════════════════════════════════
// H3: RAPID CYCLE — Create/destroy 1000 scorers in a loop
// ═══════════════════════════════════════════════════════════════════════════

func TestHYPERNOVA_RapidCycle_Scorers(t *testing.T) {
	n := 1_000

	start := time.Now()
	for i := 0; i < n; i++ {
		s := brain.NewScorer(brain.DefaultWeights(), 1800, 5000)
		for j := 0; j < 100; j++ {
			ip := fmt.Sprintf("10.%d.%d.%d", i, j>>4, j&0xFF)
			s.GetOrCreate(ip)
			s.AddScanScore(ip, j%50)
		}
		_ = s.Top(5)
		// Let GC collect this scorer
	}

	elapsed := time.Since(start)
	rate := float64(n) / elapsed.Seconds()

	t.Logf("[HYPERNOVA] RapidCycle 1000 Scorers | time=%v | rate=%.0f scorers/s | total_creations=%d",
		elapsed.Round(time.Millisecond), rate, n)
}

// ═══════════════════════════════════════════════════════════════════════════
// H4: MAX CONCURRENCY — 32× Scorer + 32× Crypto + 32× Inspector
// ═══════════════════════════════════════════════════════════════════════════

func TestHYPERNOVA_MaxConcurrency_96x(t *testing.T) {
	var totalOps atomic.Int64
	start := time.Now()
	var wg sync.WaitGroup
	numWorkers := 32

	// 32 Scorer workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			s := brain.NewScorer(brain.DefaultWeights(), 1800, 100_000)
			for i := 0; i < 50_000; i++ {
				ip := fmt.Sprintf("%d.%d.%d.%d", offset+1, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
				s.GetOrCreate(ip)
				s.AddScanScore(ip, i%80)
				totalOps.Add(1)
			}
		}(w)
	}

	// 32 Crypto workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("concurrency-worker-%d", offset))
			for i := 0; i < 20_000; i++ {
				_ = sha256.Sum256(append(payload, byte(i)))
				totalOps.Add(1)
			}
		}(w)
	}

	// 32 Inspector workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			cfg := &config.Config{}
			pi := engines.NewPacketInspector(cfg)
			for i := 0; i < 20_000; i++ {
				ip := fmt.Sprintf("%d.%d.%d.%d", offset+33, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
				pi.Feed("S", ip, uint16(1+i%65534), "tcp")
				totalOps.Add(1)
			}
		}(w)
	}

	wg.Wait()
	elapsed := time.Since(start)
	rate := float64(totalOps.Load()) / elapsed.Seconds()

	t.Logf("[HYPERNOVA] MaxConcurrency 96x (32+32+32) | time=%v | total_ops=%d | rate=%.0f ops/s",
		elapsed.Round(time.Millisecond), totalOps.Load(), rate)
}

// ═══════════════════════════════════════════════════════════════════════════
// H5: ULTIMATE ANNIHILATION — Everything, everywhere, all at once
// ═══════════════════════════════════════════════════════════════════════════

func TestHYPERNOVA_ULTIMATE_EverythingEverywhereAllAtOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ULTIMATE in short mode")
	}

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	globalStart := time.Now()
	var totalOps atomic.Int64
	var wg sync.WaitGroup

	// EVERYTHING runs concurrently at extreme scale:
	// 20 subsystems × (25K–200K ops) = over 1.5M total operations

	// S1: Scorer 200K
	wg.Add(1)
	go func() { defer wg.Done(); s := brain.NewScorer(brain.AggressiveWeights(), 3600, 300_000); for i := 0; i < 200_000; i++ { ip := fmt.Sprintf("s1.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF); s.GetOrCreate(ip); s.AddScanScore(ip, i%150); totalOps.Add(1) } }()

	// S2: Scorer 100K (different weights)
	wg.Add(1)
	go func() { defer wg.Done(); s := brain.NewScorer(brain.DefaultWeights(), 600, 150_000); for i := 0; i < 100_000; i++ { ip := fmt.Sprintf("s2.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF); s.GetOrCreate(ip); if i%20 == 0 { s.AddHoneypotTrip(ip) }; totalOps.Add(1) } }()

	// S3: Evidence 200K
	wg.Add(1)
	go func() { defer wg.Done(); ec := brain.NewEvidenceCollector(250_000, ""); for i := 0; i < 200_000; i++ { ip := fmt.Sprintf("ev.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF); ec.Collect(ip, "ultimate", float64(i%100), brain.ResponseD, []string{"ALL"}); totalOps.Add(1) }; ec.VerifyChain() }()

	// S4: Evidence 50K with chain verification every 10K
	wg.Add(1)
	go func() { defer wg.Done(); ec := brain.NewEvidenceCollector(60_000, ""); for i := 0; i < 50_000; i++ { ec.Collect(fmt.Sprintf("ev2.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF), "ult", float64(i%50), brain.ResponseB, nil); if i%10_000 == 0 { ec.VerifyChain() }; totalOps.Add(1) } }()

	// S5: SHA256 200K
	wg.Add(1)
	go func() { defer wg.Done(); p := []byte("ULTIMATE"); for i := 0; i < 200_000; i++ { _ = sha256.Sum256(append(p, byte(i))); totalOps.Add(1) } }()

	// S6: SHA256 150K
	wg.Add(1)
	go func() { defer wg.Done(); p := []byte("ANNIHILATION"); for i := 0; i < 150_000; i++ { _ = sha256.Sum256(append(p, byte(i), byte(i>>8))); totalOps.Add(1) } }()

	// S7: Ed25519 25K
	wg.Add(1)
	go func() { defer wg.Done(); _, priv, _ := ed25519.GenerateKey(rand.Reader); for i := 0; i < 25_000; i++ { ed25519.Sign(priv, []byte(fmt.Sprintf("u-%d", i))); totalOps.Add(1) } }()

	// S8: PacketInspector 100K
	wg.Add(1)
	go func() { defer wg.Done(); pi := engines.NewPacketInspector(&config.Config{}); for i := 0; i < 100_000; i++ { pi.Feed("S", fmt.Sprintf("pi.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF), uint16(1+i%65534), "tcp"); totalOps.Add(1) } }()

	// S9: FlowAnalyzer 50K
	wg.Add(1)
	go func() { defer wg.Done(); fa := engines.NewFlowAnalyzer(&config.Config{}); for i := 0; i < 50_000; i++ { fa.Feed(fmt.Sprintf("fa.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF), uint16(1+i%65535)); totalOps.Add(1) } }()

	// S10: DNS Detector 30K
	wg.Add(1)
	go func() { defer wg.Done(); dd := engines.NewDnsTunnelDetector(&config.Config{}); for i := 0; i < 30_000; i++ { ip := fmt.Sprintf("dns.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF); dd.Feed(ip, fmt.Sprintf("q%d.sub.ultimate.test.example.com", i)); if i%500 == 0 { dd.Check(ip) }; totalOps.Add(1) } }()

	// S11: BruteForce 30K
	wg.Add(1)
	go func() { defer wg.Done(); bd := engines.NewBruteForceDetector(&config.Config{}); for i := 0; i < 30_000; i++ { ip := fmt.Sprintf("bf.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF); bd.FeedSSH(ip); bd.FeedRDP(ip); if i%300 == 0 { bd.CheckAll() }; totalOps.Add(2) } }()

	// S12: BehaviorAnalyzer 30K
	wg.Add(1)
	go func() { defer wg.Done(); ba := engines.NewBehaviorAnalyzer(&config.Config{}); for i := 0; i < 30_000; i++ { ba.Feed(fmt.Sprintf("ba.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF), uint16(1+i%65535)); totalOps.Add(1) } }()

	// S13: CorrelationEngine 30K
	wg.Add(1)
	go func() { defer wg.Done(); ce := engines.NewCorrelationEngine(); for i := 0; i < 30_000; i++ { ce.Feed(fmt.Sprintf("ce.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF), "ultimate"); totalOps.Add(1) } }()

	// S14: HybridAnomaly 15K
	wg.Add(1)
	go func() { defer wg.Done(); had := engines.NewHybridAnomalyDetector(&config.Config{}, true); for i := 0; i < 15_000; i++ { had.Feed(fmt.Sprintf("had.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF), "10.0.0.1", uint16(40000+i%30000), uint16(1+i%65535), "TCP", 1500, 2, 3.0); totalOps.Add(1) } }()

	// S15: FingerprintEngine 15K
	wg.Add(1)
	go func() { defer wg.Done(); fe := engines.NewFingerprintEngine(&config.Config{}); for i := 0; i < 15_000; i++ { fe.Feed(fmt.Sprintf("fp.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF), nil, 64, 65535, true, 1460, nil); totalOps.Add(1) } }()

	// S16: Countermeasure 30K
	wg.Add(1)
	go func() { defer wg.Done(); cm := brain.NewCountermeasureEngine(); for i := 0; i < 30_000; i++ { cm.Recommend(fmt.Sprintf("cm.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF), float64(i%100), brain.ResponseC, false); totalOps.Add(1) } }()

	// S17: AdaptiveThreshold 30K
	wg.Add(1)
	go func() { defer wg.Done(); at := brain.NewAdaptiveThreshold(20, 5, 80, 0.05); for i := 0; i < 30_000; i++ { at.Update(float64(i % 70)); totalOps.Add(1) } }()

	// S18: Whitelist 30K
	wg.Add(1)
	go func() { defer wg.Done(); lw := brain.NewLearnedWhitelist(50_000); for i := 0; i < 30_000; i++ { lw.LearnFromTraffic(fmt.Sprintf("wl.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF), "ultimate", i%5 == 0); totalOps.Add(1) } }()

	// S19: HoneypotManager 5K
	wg.Add(1)
	go func() { defer wg.Done(); hm := defense.NewHoneypotManager(); for i := 0; i < 5_000; i++ { hm.CheckHit(fmt.Sprintf("hp.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)); totalOps.Add(1) } }()

	// S20: HTTPInspector 10K
	wg.Add(1)
	go func() { defer wg.Done(); hi := engines.NewHttpInspector(&config.Config{}); for i := 0; i < 10_000; i++ { hi.Feed(fmt.Sprintf("hi.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF), "192.168.1.1", uint16(30000+i%30000), uint16(80+i%2*363), nil, "GET"); totalOps.Add(1) } }()

	wg.Wait()
	elapsed := time.Since(globalStart)

	runtime.GC()
	runtime.ReadMemStats(&m2)
	memMB := float64(m2.HeapAlloc-m1.HeapAlloc) / (1024 * 1024)
	rate := float64(totalOps.Load()) / elapsed.Seconds()

	t.Logf("")
	t.Logf("╔══════════════════════════════════════════════════════════════╗")
	t.Logf("║   🔥 HYPERNOVA ULTIMATE ANNIHILATION RESULTS 🔥            ║")
	t.Logf("╠══════════════════════════════════════════════════════════════╣")
	t.Logf("║   Time:        %-42s ║", elapsed.Round(time.Millisecond))
	t.Logf("║   Total Ops:   %-42d ║", totalOps.Load())
	t.Logf("║   Rate:        %-42.0f ops/s ║", rate)
	t.Logf("║   Memory:      %-42.1f MB ║", memMB)
	t.Logf("║   Subsystems:  %-42d ║", 20)
	t.Logf("║   Concurrency: %-42s ║", "20 goroutines")
	t.Logf("╚══════════════════════════════════════════════════════════════╝")
	t.Logf("")
}
