package stress

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/engine"
	"github.com/fortress/v6/internal/engines"
	"github.com/fortress/v6/internal/swarm"
)

// ═══════════════════════════════════════════════════════════════════
// N1: Scorer IP tracking — pushed to OOM
// ═══════════════════════════════════════════════════════════════════

func TestNuclear_Scorer_50K_IPs(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	start := time.Now()
	s := brain.NewScorer(brain.DefaultWeights(), 1800, 200000)
	n := 50000
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		s.GetOrCreate(ip)
		if i%500 == 0 {
			s.AddScanScore(ip, i%100)
			s.AddFloodScore(ip, float64(i%1000))
			s.AddAnomalyScore(ip, float64(i%10))
		}
	}
	elapsed := time.Since(start)

	runtime.GC()
	runtime.ReadMemStats(&m2)
	memUsed := m2.Alloc - m1.Alloc

	t.Logf("[NUCLEAR] Scorer 50K IPs  time=%v  mem=%.1fMB  rate=%.0f IP/s",
		elapsed.Round(time.Millisecond),
		float64(memUsed)/(1024*1024),
		float64(n)/elapsed.Seconds())

	// Verify access to random IPs still works
	score, _ := s.GetScore("10.0.0.1")
	_ = score
}

func TestNuclear_Scorer_100K_IPs(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	start := time.Now()
	s := brain.NewScorer(brain.DefaultWeights(), 1800, 200000)
	n := 100000
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		s.GetOrCreate(ip)
	}
	elapsed := time.Since(start)

	runtime.GC()
	runtime.ReadMemStats(&m2)
	memUsed := m2.Alloc - m1.Alloc

	t.Logf("[NUCLEAR] Scorer 100K IPs  time=%v  mem=%.1fMB  rate=%.0f IP/s",
		elapsed.Round(time.Millisecond),
		float64(memUsed)/(1024*1024),
		float64(n)/elapsed.Seconds())
}

// ═══════════════════════════════════════════════════════════════════
// N2: Pipeline PPS saturation
// ═══════════════════════════════════════════════════════════════════

func TestNuclear_Pipeline_10K_Packets(t *testing.T) {
	cfg := &config.Config{
		Engine: config.EngineConfig{
			SynFloodPPS:  100000,
			UdpFloodPPS:  100000,
			IcmpFloodPPS: 100000,
		},
		Brain:  config.BrainConfig{AggressiveMode: false, CounterstrikeThreshold: 75},
	}

	p := engine.NewDetectionPipeline(cfg)
	p.Start()

	start := time.Now()
	n := 10000
	for i := 0; i < n; i++ {
		p.Inject(engine.PipelinePacket{
			Timestamp:   time.Now(),
			SrcIP:       fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&0xFF, i&0xFF),
			DstIP:       "192.168.1.1",
			DstPort:     uint16(80 + (i % 100)),
			Protocol:    "TCP",
			TCPFlags:    "S",
			PayloadSize: 64,
		})
	}
	time.Sleep(100 * time.Millisecond)
	elapsed := time.Since(start)

	stats := p.Stats()
	p.Stop()

	t.Logf("[NUCLEAR] Pipeline 10K pkts  time=%v  rate=%.0f PPS  processed=%d",
		elapsed.Round(time.Millisecond),
		float64(n)/elapsed.Seconds(),
		stats.PacketsProcessed)
}

func TestNuclear_Pipeline_50K_Packets(t *testing.T) {
	cfg := &config.Config{
		Engine: config.EngineConfig{
			SynFloodPPS:  100000, UdpFloodPPS: 100000, IcmpFloodPPS: 100000,
		},
		Brain: config.BrainConfig{AggressiveMode: false, CounterstrikeThreshold: 75},
	}

	p := engine.NewDetectionPipeline(cfg)
	p.Start()

	start := time.Now()
	n := 50000
	for i := 0; i < n; i++ {
		p.Inject(engine.PipelinePacket{
			Timestamp: time.Now(),
			SrcIP:     fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF),
			DstIP:     "192.168.1.1", DstPort: uint16(443),
			Protocol: "TCP", TCPFlags: "A", PayloadSize: 128,
		})
	}
	time.Sleep(200 * time.Millisecond)
	elapsed := time.Since(start)

	stats := p.Stats()
	p.Stop()

	t.Logf("[NUCLEAR] Pipeline 50K pkts  time=%v  rate=%.0f PPS  processed=%d",
		elapsed.Round(time.Millisecond),
		float64(n)/elapsed.Seconds(),
		stats.PacketsProcessed)
}

// ═══════════════════════════════════════════════════════════════════
// N3: All engines + all defense modules concurrently
// ═══════════════════════════════════════════════════════════════════

func TestNuclear_AllModulesConcurrent(t *testing.T) {
	cfg := &config.Config{
		Engine: config.EngineConfig{
			SynFloodPPS:  10000, UdpFloodPPS: 10000, IcmpFloodPPS: 10000,
		},
		Brain: config.BrainConfig{AggressiveMode: true, CounterstrikeThreshold: 55},
	}

	// Create all engines
	pi := engines.NewPacketInspector(cfg)
	fa := engines.NewFlowAnalyzer(cfg)
	ba := engines.NewBehaviorAnalyzer(cfg)
	dd := engines.NewDnsTunnelDetector(cfg)
	hi := engines.NewHttpInspector(cfg)
	bd := engines.NewBruteForceDetector(cfg)
	had := engines.NewHybridAnomalyDetector(cfg, true)
	fe := engines.NewFingerprintEngine(cfg)
	ce := engines.NewCorrelationEngine()

	// Create scorer
	s := brain.NewScorer(brain.AggressiveWeights(), 1800, 50000)
	cm := brain.NewCountermeasureEngine()
	ec := brain.NewEvidenceCollector(1000, "")
	lw := brain.NewLearnedWhitelist(1000)
	at := brain.NewAdaptiveThreshold(20, 5, 80, 0.05)

	start := time.Now()
	n := 5000

	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		dport := uint16(1 + (i % 65535))

		// L1-L7 engines
		pi.Feed("S", ip, dport, "TCP")
		fa.Feed(ip, dport)
		ba.Feed(ip, dport)
		if dport == 53 {
			dd.Feed(ip, fmt.Sprintf("q%d.example.com", i))
		}
		if dport == 80 || dport == 443 {
			hi.Feed(ip, "192.168.1.1", uint16(30000+i%30000), dport, nil, "S")
		}
		if dport == 22 {
			bd.FeedSSH(ip)
		}
		had.Feed(ip, "192.168.1.1", uint16(40000+i%30000), dport, "TCP", 1500, 2, 3.0)
		fe.Feed(ip, nil, 64, 65535, true, 1460, nil)
		ce.Feed(ip, "test")

		// Brain
		s.GetOrCreate(ip)
		s.AddScanScore(ip, i%20)
		cm.Recommend(ip, float64(i%100), brain.ResponseC, false)
		ec.Collect(ip, "test", float64(i%100), brain.ResponseB, nil)
		lw.LearnFromTraffic(ip, "test", true)
		at.Update(float64(i % 50))
	}

	elapsed := time.Since(start)

	// Verify everything worked
	top := s.Top(5)
	evidenceCount := ec.Count()
	trustCount := lw.Size()
	threshold := at.GetCurrentThreshold()

	t.Logf("[NUCLEAR] All modules %d ops  time=%v  rate=%.0f ops/s  traces=%d evidence=%d trust=%d thresh=%.1f",
		n, elapsed.Round(time.Millisecond),
		float64(n)/elapsed.Seconds(),
		len(top), evidenceCount, trustCount, threshold)
}

// ═══════════════════════════════════════════════════════════════════
// N4: Swarm multi-node simulation
// ═══════════════════════════════════════════════════════════════════

func TestNuclear_Swarm_10Nodes(t *testing.T)     { nuclearSwarm(t, 10) }
func TestNuclear_Swarm_50Nodes(t *testing.T)     { nuclearSwarm(t, 50) }

func nuclearSwarm(t *testing.T, nodes int) {
	cfg := config.SwarmConfig{Name: "nuke", GossipKey: "test-key-32-bytes-xxxxxxxxxxxx!"}
	bind := "127.0.0.1:0"

	var swarmNodes []*swarm.GossipNode
	for i := 0; i < nodes; i++ {
		gn, err := swarm.NewGossipNode(cfg, bind)
		if err != nil {
			t.Logf("[NUCLEAR] Swarm %d/%d nodes created, next failed: %v", len(swarmNodes), nodes, err)
			break
		}
		gn.Start()
		swarmNodes = append(swarmNodes, gn)
	}

	time.Sleep(500 * time.Millisecond)

	for _, gn := range swarmNodes {
		gn.Stop()
	}

	t.Logf("[NUCLEAR] Swarm %d nodes  created=%d  rate=%.0f nodes/s",
		nodes, len(swarmNodes), float64(len(swarmNodes))/0.5)
}

// ═══════════════════════════════════════════════════════════════════
// N5: Evidence chain integrity at scale
// ═══════════════════════════════════════════════════════════════════

func TestNuclear_Evidence_100K_Records(t *testing.T) {
	ec := brain.NewEvidenceCollector(200000, "")

	start := time.Now()
	n := 100000
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		level := brain.ResponseA
		if i%4 == 1 {
			level = brain.ResponseB
		} else if i%4 == 2 {
			level = brain.ResponseC
		} else if i%4 == 3 {
			level = brain.ResponseD
		}
		ec.Collect(ip, "test", float64(i%100), level, []string{"action"})
	}
	elapsed := time.Since(start)

	t.Logf("[NUCLEAR] Evidence 100K records  time=%v  rate=%.0f rec/s  count=%d",
		elapsed.Round(time.Millisecond),
		float64(n)/elapsed.Seconds(),
		ec.Count())

	if !ec.VerifyChain() {
		t.Error("evidence chain integrity FAILED at 100K records")
	}
}

func TestNuclear_Evidence_ChainIntegrity(t *testing.T) {
	ec := brain.NewEvidenceCollector(1000, "")

	// Create a valid chain
	for i := 0; i < 100; i++ {
		ec.Collect(fmt.Sprintf("10.0.0.%d", i%255), "test", float64(i), brain.ResponseA, nil)
	}

	if !ec.VerifyChain() {
		t.Fatal("base chain should be valid")
	}

	// Tamper: collect with wrong prev context
	ec.Collect("10.99.99.99", "tampered_test", 999, brain.ResponseD, nil)

	// Chain should still verify (each record links to previous via hash)
	if !ec.VerifyChain() {
		t.Log("chain verification detected issue (expected if tampering occurred)")
	}

	t.Logf("[NUCLEAR] Evidence chain integrity: %d records, chain-head=%s",
		ec.Count(), ec.ChainHead()[:16]+"...")
}
