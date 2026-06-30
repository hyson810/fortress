package stress

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/engines"
)

// ---------------------------------------------------------------------------
// IP Count Scaling
// ---------------------------------------------------------------------------

func TestScaling_Scorer_100IPs(t *testing.T)  { scaleScorer(t, 100) }
func TestScaling_Scorer_1KIPs(t *testing.T)   { scaleScorer(t, 1000) }
func TestScaling_Scorer_10KIPs(t *testing.T)  { scaleScorer(t, 10000) }
func TestScaling_Scorer_50KIPs(t *testing.T)  { scaleScorer(t, 50000) }

func scaleScorer(t *testing.T, n int) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	start := time.Now()
	s := brain.NewScorer(brain.DefaultWeights(), 1800, n*2)
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		s.GetOrCreate(ip)
		if i%100 == 0 {
			s.AddScanScore(ip, 10)
		}
	}
	elapsed := time.Since(start)

	runtime.GC()
	runtime.ReadMemStats(&m2)

	memUsed := m2.Alloc - m1.Alloc
	if memUsed < m1.Alloc {
		memUsed = m2.Alloc
	}

	t.Logf("[SCALING] N=%-6d time=%v  mem=%.1fMB  allocs=%d",
		n, elapsed.Round(time.Microsecond),
		float64(memUsed)/(1024*1024), m2.Mallocs-m1.Mallocs)
}

// ---------------------------------------------------------------------------
// PPS Throughput Scaling
// ---------------------------------------------------------------------------

func TestScaling_PacketInspector_1KPPS(t *testing.T)  { scalePPS(t, 1000) }
func TestScaling_PacketInspector_10KPPS(t *testing.T) { scalePPS(t, 10000) }
func TestScaling_PacketInspector_50KPPS(t *testing.T) { scalePPS(t, 50000) }
func TestScaling_PacketInspector_100KPPS(t *testing.T) { scalePPS(t, 100000) }

func scalePPS(t *testing.T, pps int) {
	cfg := &config.Config{
		Engine: config.EngineConfig{
			SynFloodPPS:  pps * 2,
			UdpFloodPPS:  pps * 2,
			IcmpFloodPPS: pps,
		},
		Whitelist: []string{},
	}

	pi := engines.NewPacketInspector(cfg)
	ip := "203.0.113.100"

	start := time.Now()
	for i := 0; i < pps; i++ {
		pi.Feed("S", ip, uint16(80+(i%100)), "TCP")
	}
	elapsed := time.Since(start)

	actualPPS := float64(pps) / elapsed.Seconds()
	t.Logf("[SCALING] Target=%-7d PPS  actual=%-8.0f PPS  time=%v",
		pps, actualPPS, elapsed.Round(time.Microsecond))
}

// ---------------------------------------------------------------------------
// HybridAnomalyDetector Throughput
// ---------------------------------------------------------------------------

func TestScaling_HybridAnomaly_1KFlows(t *testing.T)  { scaleAnomaly(t, 1000) }
func TestScaling_HybridAnomaly_10KFlows(t *testing.T) { scaleAnomaly(t, 10000) }

func scaleAnomaly(t *testing.T, flows int) {
	cfg := &config.Config{Whitelist: []string{}}
	had := engines.NewHybridAnomalyDetector(cfg, false)

	start := time.Now()
	for i := 0; i < flows; i++ {
		srcIP := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		had.Feed(srcIP, "192.168.1.1", uint16(10000+i%50000), 80, "TCP", 1500, 2, 3.5)
	}
	elapsed := time.Since(start)

	flowsPerSec := float64(flows) / elapsed.Seconds()
	t.Logf("[SCALING] Flows=%-6d  rate=%-8.0f flows/s  time=%v",
		flows, flowsPerSec, elapsed.Round(time.Microsecond))
}

// ---------------------------------------------------------------------------
// Memory tracking helper
// ---------------------------------------------------------------------------

func BenchmarkScorer_Insert(b *testing.B) {
	s := brain.NewScorer(brain.DefaultWeights(), 1800, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&0xFF, i&0xFF)
		s.GetOrCreate(ip)
	}
}

func BenchmarkPacketInspector_Feed(b *testing.B) {
	cfg := &config.Config{
		Engine: config.EngineConfig{
			SynFloodPPS:  b.N,
			UdpFloodPPS:  b.N,
			IcmpFloodPPS: b.N,
		},
	}
	pi := engines.NewPacketInspector(cfg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pi.Feed("S", "10.0.0.1", 80, "TCP")
	}
}
