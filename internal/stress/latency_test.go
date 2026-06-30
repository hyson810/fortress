package stress

import (
	"fmt"
	"testing"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/engines"
)

// ═══════════════════════════════════════════════════════════════════
// LATENCY: End-to-end decision speed — from packet → score → counterstrike
// ═══════════════════════════════════════════════════════════════════

func TestLatency_PacketToScore(t *testing.T) {
	cfg := &config.Config{}
	pi := engines.NewPacketInspector(cfg)
	fa := engines.NewFlowAnalyzer(cfg)
	bd := engines.NewBruteForceDetector(cfg)
	had := engines.NewHybridAnomalyDetector(cfg, true)
	dd := engines.NewDnsTunnelDetector(cfg)
	s := brain.NewScorer(brain.AggressiveWeights(), 1800, 10000)
	cm := brain.NewCountermeasureEngine()
	at := brain.NewAdaptiveThreshold(20, 5, 80, 0.05)

	n := 50000
	var totalLatency time.Duration
	var maxLatency time.Duration
	var minLatency = time.Hour

	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		dport := uint16(1 + i%65535)
		if dport == 0 { dport = 1 }

		start := time.Now()

		// Full L1-L7 pipeline
		pi.Feed("S", ip, dport, "tcp")
		fa.Feed(ip, dport)
		if dport == 53 { dd.Feed(ip, fmt.Sprintf("q%d.test.io", i)) }
		if dport == 22 { bd.FeedSSH(ip) }
		had.Feed(ip, "10.0.0.1", uint16(40000+i%30000), dport, "TCP", 1500, 2, 2.5)

		// Brain scoring + decision
		s.GetOrCreate(ip)
		s.AddScanScore(ip, i%100)
		score, level := s.GetScore(ip)
		cm.Recommend(ip, score, level, false)
		at.Update(score)

		lat := time.Since(start)
		totalLatency += lat
		if lat > maxLatency { maxLatency = lat }
		if lat < minLatency { minLatency = lat }
	}

	avg := totalLatency / time.Duration(n)

	t.Logf("[LATENCY] Packet→Score→Decision E2E  n=%d", n)
	t.Logf("  Avg:  %v  (%.0f µs)", avg.Round(time.Nanosecond), float64(avg.Nanoseconds())/1000.0)
	t.Logf("  Min:  %v  (%.0f µs)", minLatency.Round(time.Nanosecond), float64(minLatency.Nanoseconds())/1000.0)
	t.Logf("  Max:  %v  (%.0f µs)", maxLatency.Round(time.Nanosecond), float64(maxLatency.Nanoseconds())/1000.0)
	t.Logf("  Rate: %.0f decisions/s", float64(n)/totalLatency.Seconds())
}

func TestLatency_CounterstrikeDecision(t *testing.T) {
	s := brain.NewScorer(brain.AggressiveWeights(), 1800, 50000)

	n := 10000
	var totalLatency time.Duration

	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", (i>>8)&0xFF, i&0xFF)

		start := time.Now()

		s.GetOrCreate(ip)
		// Simulate building up threat
		s.AddScanScore(ip, 80)       // high port count
		s.AddFloodScore(ip, 500.0)   // high PPS
		s.AddAnomalyScore(ip, 5.0)   // significant anomaly
		s.AddHoneypotTrip(ip)        // attacker hit honeypot
		s.AddIntelMatch(ip, "OSINT") // threat intel match

		shouldStrike := s.ShouldCounterstrike(ip, 75.0)

		lat := time.Since(start)
		totalLatency += lat
		_ = shouldStrike
	}

	avg := totalLatency / time.Duration(n)

	t.Logf("[LATENCY] Counterstrike Decision  n=%d", n)
	t.Logf("  Avg:  %v  (%.0f ns)", avg.Round(time.Nanosecond), float64(avg.Nanoseconds()))
	t.Logf("  Rate: %.0f decisions/s", float64(n)/totalLatency.Seconds())
}

func TestLatency_SubsystemMicrobenchmark(t *testing.T) {
	iterations := 100000

	// PacketInspector
	pi := engines.NewPacketInspector(&config.Config{})
	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		pi.Feed("S", "10.0.0.1", 443, "tcp")
	}
	d0 := time.Since(t0)

	// Scorer
	s := brain.NewScorer(brain.DefaultWeights(), 1800, 100000)
	t1 := time.Now()
	for i := 0; i < iterations; i++ {
		s.GetOrCreate(fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&0xFF, i&0xFF))
	}
	d1 := time.Since(t1)

	// DNS Detector
	dd := engines.NewDnsTunnelDetector(&config.Config{})
	t2 := time.Now()
	for i := 0; i < iterations; i++ {
		dd.Feed("10.0.0.1", fmt.Sprintf("q%d.example.com", i))
	}
	d2 := time.Since(t2)

	// BruteForce
	bd := engines.NewBruteForceDetector(&config.Config{})
	t3 := time.Now()
	for i := 0; i < iterations/10; i++ {
		bd.FeedSSH(fmt.Sprintf("10.0.%d.%d", i>>8, i&0xFF))
	}
	d3 := time.Since(t3)

	// Honeypot
	hits := 0
	t4 := time.Now()
	for i := 0; i < iterations; i++ {
		if i%100 == 0 { hits++ }
	}
	d4 := time.Since(t4)

	t.Logf("[LATENCY] Subsystem Micro-benchmarks (n=%d):", iterations)
	t.Logf("  PacketInspector:    %v/op  (%d ns/op)", d0/time.Duration(iterations), d0.Nanoseconds()/int64(iterations))
	t.Logf("  Scorer(insert):     %v/op  (%d ns/op)", d1/time.Duration(iterations), d1.Nanoseconds()/int64(iterations))
	t.Logf("  DNS Detector:       %v/op  (%d ns/op)", d2/time.Duration(iterations), d2.Nanoseconds()/int64(iterations))
	t.Logf("  BruteForce(feed):   %v/op  (%d ns/op)", d3/time.Duration(iterations/10), d3.Nanoseconds()/int64(iterations/10))
	t.Logf("  CheckHit(sim):      %v/op  (%d ns/op)", d4/time.Duration(iterations), d4.Nanoseconds()/int64(iterations))
}

func TestLatency_EndToEnd_DefensePipeline(t *testing.T) {
	// Simulate a complete attack: SYN scan → port discovered → brute force → honeypot trip → counterstrike
	cfg := &config.Config{}
	pi := engines.NewPacketInspector(cfg)
	fa := engines.NewFlowAnalyzer(cfg)
	bd := engines.NewBruteForceDetector(cfg)
	had := engines.NewHybridAnomalyDetector(cfg, false)
	ce := engines.NewCorrelationEngine()
	s := brain.NewScorer(brain.AggressiveWeights(), 1800, 10000)

	attackerIP := "203.0.113.42"
	var pipelineTimes []time.Duration

	// Phase 1: SYN scan detected (50 ports)
	for port := 1; port <= 50; port++ {
		start := time.Now()
		pi.Feed("S", attackerIP, uint16(port), "tcp")
		fa.Feed(attackerIP, uint16(port))
		had.Feed(attackerIP, "192.168.1.1", uint16(40000+port), uint16(port), "TCP", 64, 1, 1.5)
		s.GetOrCreate(attackerIP)
		s.AddScanScore(attackerIP, port)
		pipelineTimes = append(pipelineTimes, time.Since(start))
	}

	// Phase 2: Brute force on discovered SSH
	for i := 0; i < 30; i++ {
		start := time.Now()
		bd.FeedSSH(attackerIP)
		t := bd.CheckAll()
		ce.Feed(attackerIP, "ssh_bruteforce")
		s.GetOrCreate(attackerIP)
		s.AddFloodScore(attackerIP, 100.0)
		if len(t) > 0 {
			s.AddAnomalyScore(attackerIP, 3.0)
		}
		pipelineTimes = append(pipelineTimes, time.Since(start))
	}

	// Phase 3: Honeypot tripped
	start := time.Now()
	s.AddHoneypotTrip(attackerIP)
	s.AddIntelMatch(attackerIP, "known-malicious")
	ce.Feed(attackerIP, "honeypot_trip")

	// Final decision
	score, level := s.GetScore(attackerIP)
	shouldStrike := s.ShouldCounterstrike(attackerIP, 75.0)
	decisionTime := time.Since(start)

	// Calculate stats
	var sum time.Duration
	var max time.Duration
	min := time.Hour
	for _, pt := range pipelineTimes {
		sum += pt
		if pt > max { max = pt }
		if pt < min { min = pt }
	}
	avgPipeline := sum / time.Duration(len(pipelineTimes))

	t.Logf("")
	t.Logf("╔══════════════════════════════════════════════════════╗")
	t.Logf("║  ⚡ E2E DEFENSE DECISION LATENCY ⚡                  ║")
	t.Logf("╠══════════════════════════════════════════════════════╣")
	t.Logf("║  Pipeline avg:    %8v  (%4.0f µs)            ║", avgPipeline.Round(time.Nanosecond), float64(avgPipeline.Nanoseconds())/1000.0)
	t.Logf("║  Pipeline min:    %8v  (%4.0f µs)            ║", min.Round(time.Nanosecond), float64(min.Nanoseconds())/1000.0)
	t.Logf("║  Pipeline max:    %8v  (%4.0f µs)            ║", max.Round(time.Nanosecond), float64(max.Nanoseconds())/1000.0)
	t.Logf("║  Final Decision:  %8v  (%4.0f µs)            ║", decisionTime.Round(time.Nanosecond), float64(decisionTime.Nanoseconds())/1000.0)
	t.Logf("╠══════════════════════════════════════════════════════╣")
	t.Logf("║  Attacker IP:     %-32s ║", attackerIP)
	t.Logf("║  Threat Score:    %-32.1f ║", score)
	t.Logf("║  Threat Level:    %-32s ║", level)
	t.Logf("║  Counterstrike:   %-32v ║", shouldStrike)
	t.Logf("╚══════════════════════════════════════════════════════╝")
	t.Logf("")
}
