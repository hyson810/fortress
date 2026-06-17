package engine_test

import (
	"testing"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/engine"
)

func TestFullPipeline(t *testing.T) {
	cfg := config.Default()
	cfg.Engine.SynFloodPPS = 10

	pi := engine.NewPacketInspector(cfg)
	fa := engine.NewFlowAnalyzer(cfg)
	ba := engine.NewBehaviorAnalyzer(cfg)
	hi := engine.NewHttpInspector(cfg)
	ha := engine.NewHybridAnomalyDetector(cfg)
	fe := engine.NewFingerprintEngine(cfg)

	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)

	attackIP := "203.0.113.99"

	// Multi-vector attack: SYN flood + port scan + SQLi + OS anomaly
	for i := 0; i < 50; i++ {
		for _, th := range pi.Feed("S", attackIP, uint16(100+i), "TCP") {
			scorer.AddThreat(th)
		}
		for _, th := range fa.Feed(attackIP, uint16(100+i)) {
			scorer.AddThreat(th)
		}
		ba.Feed(attackIP, uint16(100+i))
	}

	for _, th := range hi.Feed(attackIP, "192.168.1.1", 12345, 80,
		[]byte("GET /?q=1' OR '1'='1 HTTP/1.1\r\n\r\n")) {
		scorer.AddThreat(th)
	}

	for _, th := range fe.FeedSYN(attackIP, 32, 1234, false) {
		if th.Type == "OS指纹异常" {
			t.Log("OS anomaly detected")
		}
	}

	pkt := engine.PacketContext{
		Timestamp:   time.Now(),
		SrcIP:       attackIP,
		DstIP:       "10.0.0.1",
		SrcPort:     12345,
		DstPort:     443,
		Protocol:    "TCP",
		TCPFlags:    "S",
		PayloadSize: 1500,
	}
	for i := 0; i < 20; i++ {
		ha.Feed(pkt)
	}

	score, level := scorer.GetScore(attackIP)
	t.Logf("Attack IP %s: score=%.1f level=%d", attackIP, score, level)

	if score < 30 {
		t.Errorf("expected score >= 30 for multi-vector attack, got %.1f", score)
	}

	_, name, _ := brain.DetermineResponse(score, false)
	t.Logf("Response level: %s", name)
	if name == "A·静默" {
		t.Error("multi-vector attack should trigger at least B·侦查")
	}
}
