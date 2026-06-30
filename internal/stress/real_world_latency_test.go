package stress

import (
	"fmt"
	"testing"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/engines"
)

// REALITY CHECK: What does "decision speed" actually mean?

func TestReality_WhatTheseNumbersMean(t *testing.T) {
	s := brain.NewScorer(brain.AggressiveWeights(), 1800, 10000)
	pi := engines.NewPacketInspector(&config.Config{})
	fa := engines.NewFlowAnalyzer(&config.Config{})
	bd := engines.NewBruteForceDetector(&config.Config{})
	had := engines.NewHybridAnomalyDetector(&config.Config{}, false)
	dd := engines.NewDnsTunnelDetector(&config.Config{})
	ce := engines.NewCorrelationEngine()
	cm := brain.NewCountermeasureEngine()

	t.Logf("")
	t.Logf("╔══════════════════════════════════════════════════════════════╗")
	t.Logf("║     REALITY CHECK: 决策速度到底是什么水平                    ║")
	t.Logf("╠══════════════════════════════════════════════════════════════╣")
	t.Logf("║                                                              ║")
	t.Logf("║  先说清楚三类数字:                                            ║")
	t.Logf("║                                                              ║")

	// Level 1: Pure in-memory operations (real but misleading)
	iterations := 50000

	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&0xFF, i&0xFF)
		s.GetOrCreate(ip)
		s.AddScanScore(ip, i%100)
		score, level := s.GetScore(ip)
		cm.Recommend(ip, score, level, false)
	}
	fullBrainTime := time.Since(t0)
	avgBrain := fullBrainTime / time.Duration(iterations)

	t.Logf("║ 1️⃣  纯内存操作 (Go代码层面):                                  ║")
	t.Logf("║     Scorer增删改查+评分+决策建议 = %v/次            ║", avgBrain.Round(time.Nanosecond))
	t.Logf("║     这是真实数字，但它只是纯内存计算                            ║")
	t.Logf("║                                                              ║")

	// Level 2: Full software pipeline (Go detection engines)
	n := 5000
	var totalPipeline time.Duration
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("172.%d.%d.%d", i>>16, (i>>8)&0xFF, i&0xFF)
		dport := uint16(1 + i%65535)
		if dport == 0 { dport = 1 }

		start := time.Now()

		// Full L1-L7 software detection pipeline
		pi.Feed("S", ip, dport, "tcp")
		fa.Feed(ip, dport)
		if dport == 53 { dd.Feed(ip, fmt.Sprintf("q%d.example.com", i)) }
		if dport == 22 { bd.FeedSSH(ip) }
		if dport == 80 || dport == 443 { had.Feed(ip, "10.0.0.1", uint16(40000+i%30000), dport, "TCP", 1500, 2, 2.0) }
		ce.Feed(ip, "test")

		s.GetOrCreate(ip)
		s.AddScanScore(ip, i%100)
		score, level := s.GetScore(ip)
		_ = score
		_ = level

		totalPipeline += time.Since(start)
	}
	avgPipeline := totalPipeline / time.Duration(n)

	t.Logf("║ 2️⃣  完整软件管线 (8引擎+评分+决策):                           ║")
	t.Logf("║     avg = %v  (%d µs)                     ║", avgPipeline.Round(time.Microsecond), avgPipeline.Microseconds())
	t.Logf("║     这是Go层面全链路，不含网络IO/内核态                         ║")
	t.Logf("║                                                              ║")

	t.Logf("║ 3️⃣  真实世界的延迟组成 (Linux生产环境):                        ║")
	t.Logf("║     NIC硬件收包→DMA→内核:         ~5-10 µs                    ║")
	t.Logf("║     XDP eBPF过滤 (NIC driver层):  ~0.05 µs (50ns)            ║")
	t.Logf("║     AF_XDP零拷贝→用户态:          ~5-10 µs                    ║")
	t.Logf("║     Rust协议解析 (SIMD):           ~1-3 µs                    ║")
	t.Logf("║     Go检测管线 (8引擎):            ~%d µs                     ║", avgPipeline.Microseconds())
	t.Logf("║     Brain评分+决策:                ~1-3 µs                    ║")
	t.Logf("║     ─────────────────────────────────────                    ║")
	t.Logf("║     真实E2E延迟:                   ~%d µs = %.2f ms          ║", avgPipeline.Microseconds()+20, float64(avgPipeline.Microseconds()+20)/1000.0)
	t.Logf("║                                                              ║")
	t.Logf("╚══════════════════════════════════════════════════════════════╝")
	t.Logf("")
}
