package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/defense"
	"github.com/fortress/v6/internal/engines"
)

// ---------------------------------------------------------------------------
// Test 1: Defense Pipeline Initialization
// ---------------------------------------------------------------------------

func TestDefensePipeline_Initialization(t *testing.T) {
	cfg := config.Default()

	// 1. Create all 9 detection engines.
	pi := engines.NewPacketInspector(cfg)
	fa := engines.NewFlowAnalyzer(cfg)
	dnsDetector := engines.NewDnsTunnelDetector(cfg)
	httpInspector := engines.NewHttpInspector(cfg)
	bruteDetector := engines.NewBruteForceDetector(cfg)
	hybridDetector := engines.NewHybridAnomalyDetector(cfg, false)
	behaviorAnalyzer := engines.NewBehaviorAnalyzer(cfg)
	correlationEngine := engines.NewCorrelationEngine()
	fingerprintEngine := engines.NewFingerprintEngine(cfg)

	// 2. Create Scorer with default weights.
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)

	// 3. Create HoneypotManager.
	honeypotMgr := defense.NewHoneypotManager()

	// 4. Verify all are non-nil.
	type component struct {
		name string
		ptr  any
	}
	components := []component{
		{"PacketInspector", pi},
		{"FlowAnalyzer", fa},
		{"DnsTunnelDetector", dnsDetector},
		{"HttpInspector", httpInspector},
		{"BruteForceDetector", bruteDetector},
		{"HybridAnomalyDetector", hybridDetector},
		{"BehaviorAnalyzer", behaviorAnalyzer},
		{"CorrelationEngine", correlationEngine},
		{"FingerprintEngine", fingerprintEngine},
		{"Scorer", scorer},
		{"HoneypotManager", honeypotMgr},
	}

	for _, c := range components {
		if c.ptr == nil {
			t.Fatalf("%s is nil", c.name)
		}
	}

	t.Logf("All %d defense pipeline components initialized successfully", len(components))
}

// ---------------------------------------------------------------------------
// Test 2: Defense Pipeline Simulation Tick
// ---------------------------------------------------------------------------

func TestDefensePipeline_SimulationTick(t *testing.T) {
	cfg := config.Default()

	// Create all 9 detection engines.
	pi := engines.NewPacketInspector(cfg)
	fa := engines.NewFlowAnalyzer(cfg)
	dnsDetector := engines.NewDnsTunnelDetector(cfg)
	httpInspector := engines.NewHttpInspector(cfg)
	bruteDetector := engines.NewBruteForceDetector(cfg)
	hybridDetector := engines.NewHybridAnomalyDetector(cfg, false)
	behaviorAnalyzer := engines.NewBehaviorAnalyzer(cfg)
	correlationEngine := engines.NewCorrelationEngine()
	fingerprintEngine := engines.NewFingerprintEngine(cfg)

	// Create Scorer.
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)

	stopSim := make(chan struct{})
	panicCh := make(chan any, 1)

	// Run 20 ticks simulating the main.go defense loop.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicCh <- fmt.Errorf("panic in simulation goroutine: %v", r)
			} else {
				close(panicCh)
			}
		}()

		// Simulated "normal" traffic sources (same as runDefense).
		normalIPs := []string{"10.0.0.5", "10.0.0.10", "192.168.1.100"}
		normalPorts := []uint16{80, 443, 53, 22, 8080}

		for idx := 0; idx < 20; idx++ {
			select {
			case <-stopSim:
				return
			default:
			}

			srcIP := normalIPs[idx%len(normalIPs)]
			dstPort := normalPorts[idx%len(normalPorts)]

			// Feed PacketInspector — simulate normal TCP SYN.
			threats := pi.Feed("S", srcIP, dstPort, "TCP")
			for _, th := range threats {
				scorer.GetOrCreate(th.IP)
				scorer.AddScanScore(th.IP, 1)
			}

			// Feed FlowAnalyzer — track port diversity.
			faThreats := fa.Feed(srcIP, dstPort)
			for _, th := range faThreats {
				scorer.GetOrCreate(th.IP)
				scorer.AddScanScore(th.IP, 5)
			}

			// Feed DNS detector — a normal query.
			dnsDetector.Feed(srcIP, "api.example.com")

			// Feed BehaviorAnalyzer.
			behaviorAnalyzer.Feed(srcIP, dstPort)

			// Feed HybridAnomalyDetector — normal single-packet flow.
			hybridThreats := hybridDetector.Feed(
				srcIP, "10.0.0.1", 54321, dstPort, "TCP", 64, 2, 3.5,
			)
			for _, th := range hybridThreats {
				scorer.GetOrCreate(th.IP)
				scorer.AddAnomalyScore(th.IP, 5.0)
			}

			// Check BruteForce periodically (every 5 ticks).
			if idx%5 == 0 {
				bfThreats := bruteDetector.CheckAll()
				for _, th := range bfThreats {
					scorer.GetOrCreate(th.IP)
					scorer.AddScanScore(th.IP, 3)
				}
			}

			// Check DNS tunnel periodically (every 3 ticks).
			if idx%3 == 0 {
				for _, ip := range normalIPs {
					dnsThreats := dnsDetector.Check(ip)
					for _, th := range dnsThreats {
						scorer.GetOrCreate(th.IP)
						scorer.AddAnomalyScore(th.IP, 3.0)
					}
				}
			}

			// Feed CorrelationEngine.
			correlationEngine.Feed(srcIP, "normal_traffic")
			if idx%10 == 0 {
				correlationEngine.CheckCorrelation()
			}

			// Check BehaviorAnalyzer periodically (every 10 ticks).
			if idx%10 == 0 {
				behaviorAnalyzer.Check()
			}

			// Feed fingerprint engine with minimal data.
			_ = fingerprintEngine.Feed(srcIP, nil, 64, 65535, true, 1460,
				[]string{"MSS", "SACK", "TS"})

			// Evict stale entries periodically (every 5 ticks).
			if idx%5 == 0 {
				deadline := float64(time.Now().Add(-60 * time.Second).Unix())
				pi.Evict(deadline)
				fa.Evict(deadline)
				dnsDetector.Evict(deadline)
				httpInspector.Evict(deadline)
				bruteDetector.Evict(deadline)
				hybridDetector.Evict(deadline)
				behaviorAnalyzer.Evict(deadline)
				correlationEngine.Evict(deadline)
				fingerprintEngine.Evict(deadline)
			}

			// Brief sleep to allow goroutine scheduling and give realistic
			// inter-packet timing.
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Wait for simulation to finish or timeout after 5 seconds.
	select {
	case r, ok := <-panicCh:
		if ok && r != nil {
			t.Fatalf("simulation tick panic: %v", r)
		}
		// Completed without panic.
		t.Log("Simulation tick completed 20 iterations without panic")
	case <-time.After(5 * time.Second):
		close(stopSim)
		// Drain any remaining panic report.
		select {
		case r, ok := <-panicCh:
			if ok && r != nil {
				t.Fatalf("simulation tick panic after stop: %v", r)
			}
		case <-time.After(time.Second):
		}
		t.Fatal("simulation tick timed out after 5 seconds")
	}
}

// ---------------------------------------------------------------------------
// Test 3: Threat Detection — SYN scan and honeypot trip
// ---------------------------------------------------------------------------

func TestDefensePipeline_ThreatDetection(t *testing.T) {
	cfg := config.Default()

	pi := engines.NewPacketInspector(cfg)
	fa := engines.NewFlowAnalyzer(cfg)
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)

	attackerIP := "203.0.113.5"

	// -------------------------------------------------------------
	// Phase A: Simulate SYN scan — 100 SYN packets from same IP to
	// different destination ports.
	// -------------------------------------------------------------
	for port := uint16(1); port <= 100; port++ {
		// Feed PacketInspector.
		threats := pi.Feed("S", attackerIP, port, "TCP")
		for _, th := range threats {
			scorer.GetOrCreate(th.IP)
			scorer.AddScanScore(th.IP, 1)
		}

		// Feed FlowAnalyzer — track port scan across time windows.
		faThreats := fa.Feed(attackerIP, port)
		for _, th := range faThreats {
			scorer.GetOrCreate(th.IP)
			scorer.AddScanScore(th.IP, 5)
		}
	}

	record := scorer.GetOrCreate(attackerIP)
	if record.TotalScore <= 0 {
		t.Errorf("expected non-zero threat score for %s after 100-port SYN scan, got %.1f",
			attackerIP, record.TotalScore)
	}
	t.Logf("SYN scan: attacker %s score=%.1f level=%s",
		attackerIP, record.TotalScore, record.Level)

	// -------------------------------------------------------------
	// Phase B: Simulate honeypot trip and verify score increases.
	// -------------------------------------------------------------
	scoreBefore := record.TotalScore
	scorer.AddHoneypotTrip(attackerIP)

	record = scorer.GetOrCreate(attackerIP)
	if record.TotalScore <= scoreBefore {
		t.Errorf("expected score to increase after honeypot trip: before=%.1f after=%.1f",
			scoreBefore, record.TotalScore)
	}
	if !record.HoneypotTripped {
		t.Error("expected HoneypotTripped flag to be true after AddHoneypotTrip")
	}
	t.Logf("Honeypot trip: score %.1f → %.1f (honeypot tripped=%v)",
		scoreBefore, record.TotalScore, record.HoneypotTripped)
}

// ---------------------------------------------------------------------------
// Test 4: Honeypot Hit Check
// ---------------------------------------------------------------------------

func TestDefensePipeline_HoneypotHit(t *testing.T) {
	// 1. CheckHit returns false for unknown IP.
	hm := defense.NewHoneypotManager()
	if hm.CheckHit("10.0.0.99") {
		t.Error("CheckHit should return false for unknown IP")
	}

	// Verify RecentHits starts empty.
	hits := hm.RecentHits()
	if len(hits) != 0 {
		t.Errorf("expected 0 recent hits, got %d", len(hits))
	}

	// 2. Create a second HoneypotManager, inject a hit entry via RecordHit,
	//    and verify CheckHit returns true.
	hm2 := defense.NewHoneypotManager()

	attackerIP := "198.51.100.7"
	hm2.RecordHit(attackerIP)

	// CheckHit should now return true for the recorded IP.
	if !hm2.CheckHit(attackerIP) {
		t.Error("CheckHit should return true after RecordHit injection for", attackerIP)
	}

	// RecentHits should reflect the recorded hit.
	hits2 := hm2.RecentHits()
	if len(hits2) != 1 {
		t.Fatalf("expected 1 recent hit, got %d", len(hits2))
	}
	if hits2[0].IP != attackerIP {
		t.Errorf("expected hit IP=%s, got %s", attackerIP, hits2[0].IP)
	}

	// CheckHit should still return false for a different unknown IP.
	if hm2.CheckHit("10.0.0.99") {
		t.Error("CheckHit should return false for a different unknown IP")
	}

	t.Logf("Honeypot hit correctly detected: IP=%s, timestamp=%s",
		hits2[0].IP, hits2[0].Timestamp.Format(time.RFC3339))
}
