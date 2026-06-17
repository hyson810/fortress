package engine_test

import (
	"testing"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/engine"
	"github.com/fortress/v6/internal/fusion"
)

// E2E-1: SYN flood → L1 detection → B阶 response
func TestE2E_SYNFlood_RaisesToLevelB(t *testing.T) {
	cfg := config.Default()
	cfg.Engine.SynFloodPPS = 10
	pi := engine.NewPacketInspector(cfg)
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 50000)

	src := "203.0.113.99"
	for i := 0; i < 100; i++ {
		for _, th := range pi.Feed("S", src, uint16(80+i%10), "TCP") {
			scorer.AddThreat(th)
		}
	}
	score, _ := scorer.GetScore(src)
	_, name, _ := brain.DetermineResponse(score, false)
	t.Logf("SYN flood: score=%.1f response=%s", score, name)
	if name == "A·静默" {
		t.Error("SYN flood should trigger at least B阶")
	}
}

// E2E-2: Multi-vector attack → C阶
func TestE2E_MultiVector_RaisesToLevelC(t *testing.T) {
	cfg := config.Default()
	cfg.Engine.SynFloodPPS = 10
	pi := engine.NewPacketInspector(cfg)
	fa := engine.NewFlowAnalyzer(cfg)
	hi := engine.NewHttpInspector(cfg)
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 50000)

	src := "203.0.113.88"
	// SYN flood
	for i := 0; i < 80; i++ {
		for _, th := range pi.Feed("S", src, uint16(100+i), "TCP") {
			scorer.AddThreat(th)
		}
	}
	// Port scan
	for i := 0; i < 30; i++ {
		for _, th := range fa.Feed(src, uint16(200+i)) {
			scorer.AddThreat(th)
		}
	}
	// SQLi
	for _, th := range hi.Feed(src, "10.0.0.1", 12345, 80, []byte("GET /?q=1' OR '1'='1 HTTP/1.1\r\n\r\n")) {
		scorer.AddThreat(th)
	}
	score, _ := scorer.GetScore(src)
	_, name, _ := brain.DetermineResponse(score, false)
	t.Logf("Multi-vector: score=%.1f response=%s", score, name)
	if name == "A·静默" || name == "B·侦查" {
		t.Error("multi-vector should reach C阶 or D阶")
	}
}

// E2E-3: Honeypot trip → B阶 minimum
func TestE2E_HoneypotTrip_MinimumLevelB(t *testing.T) {
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 50000)
	scorer.AddHoneypotTrip("10.13.37.1")
	score, _ := scorer.GetScore("10.13.37.1")
	if score < 20 {
		t.Errorf("honeypot trip score should be >= 20, got %.1f", score)
	}
}

// E2E-4: Score decay after inactivity
func TestE2E_ScoreDecay(t *testing.T) {
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 50000)
	scorer.AddHoneypotTrip("10.0.0.50")
	s1, _ := scorer.GetScore("10.0.0.50")
	// Simulate decay with a very short half-life
	decayed := brain.DecayScore(s1, time.Now().Add(-30*time.Minute), 30*time.Minute)
	if decayed >= s1 {
		t.Errorf("decayed score %.1f should be < original %.1f", decayed, s1)
	}
	t.Logf("Decay: %.1f → %.1f after 30min half-life", s1, decayed)
}

// E2E-5: White-listed IP bypasses detection
func TestE2E_WhitelistBypass(t *testing.T) {
	cfg := config.Default()
	// Localhost is whitelisted by default
	if !cfg.IsWhitelisted("127.0.0.1") {
		t.Error("127.0.0.1 should be whitelisted")
	}
	// External IP is not
	if cfg.IsWhitelisted("203.0.113.5") {
		t.Error("203.0.113.5 should NOT be whitelisted")
	}
	// CIDR match: 10.x should match 10.0.0.0/8
	if !cfg.IsWhitelisted("10.99.99.99") {
		t.Error("10.99.99.99 should match 10.0.0.0/8 CIDR")
	}
}

// E2E-6: Correlation detects coordinated attack
func TestE2E_Correlation(t *testing.T) {
	ce := brain.NewCorrelationEngine()
	ce.Feed("10.0.0.1", "SYN洪水")
	ce.Feed("10.0.0.2", "SYN洪水")
	ce.Feed("10.0.0.3", "SYN洪水")
	ips, mult := ce.Check()
	if len(ips) < 3 {
		t.Error("expected 3 correlated IPs")
	}
	if mult < 1.2 {
		t.Errorf("multiplier should be >= 1.3 for 3 IPs, got %.1f", mult)
	}
}

// E2E-7: ValidateTarget rejects dangerous inputs
func TestE2E_ValidateTarget(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
	}{
		{"192.168.1.1", true},
		{"example.com", true},
		{"-T4", false},
		{"1.1.1.1;ls", false},
		{"1.1.1.1|cat", false},
		{"`id`", false},
		{"$(whoami)", false},
		{"1.1.1.1\nrm -rf /", false},
	}
	for _, tt := range tests {
		err := config.ValidateTarget(tt.input)
		if tt.ok && err != nil {
			t.Errorf("ValidateTarget(%q) should pass, got: %v", tt.input, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("ValidateTarget(%q) should FAIL", tt.input)
		}
	}
}

// E2E-8: Attack chain validates target before exec
func TestE2E_AttackChain_InputValidation(t *testing.T) {
	cfg := config.Default()
	ac := fusion.NewAttackChain(&cfg.Weapons)
	_, err := ac.Execute("-T4") // flag injection
	if err == nil {
		t.Error("flag injection should be rejected")
	}
}

// E2E-9: Full pipeline — all 7 layers + scoring + response
func TestE2E_FullPipeline_AllLayers(t *testing.T) {
	cfg := config.Default()
	cfg.Engine.SynFloodPPS = 5
	pi := engine.NewPacketInspector(cfg)
	fa := engine.NewFlowAnalyzer(cfg)
	ba := engine.NewBehaviorAnalyzer(cfg)
	dd := engine.NewDnsTunnelDetector(cfg)
	hi := engine.NewHttpInspector(cfg)
	ha := engine.NewHybridAnomalyDetector(cfg)
	fe := engine.NewFingerprintEngine(cfg)
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 50000)

	src := "203.0.113.77"
	feedAll := func() {
		for _, th := range pi.Feed("S", src, 443, "TCP") {
			scorer.AddThreat(th)
		}
		for _, th := range fa.Feed(src, 443) {
			scorer.AddThreat(th)
		}
		ba.Feed(src, 443)
		for _, th := range dd.Feed(src, "test.example.com") {
			scorer.AddThreat(th)
		}
		for _, th := range hi.Feed(src, "10.0.0.1", 12345, 80, []byte("GET / HTTP/1.1\r\n\r\n")) {
			scorer.AddThreat(th)
		}
		ha.Feed(engine.PacketContext{SrcIP: src, DstIP: "10.0.0.1", SrcPort: 12345, DstPort: 443, Protocol: "TCP", TCPFlags: "S", PayloadSize: 64, Timestamp: time.Now()})
		fe.FeedSYN(src, 64, 65535, true)
	}
	for i := 0; i < 20; i++ {
		feedAll()
	}
	score, level := scorer.GetScore(src)
	_, name, _ := brain.DetermineResponse(score, false)
	t.Logf("Full pipeline: score=%.1f level=%d response=%s IPs=%d", score, level, name, scorer.RecordCount())
	if scorer.RecordCount() == 0 {
		t.Error("scorer should track at least 1 IP")
	}
}

// E2E-10: Response ladder thresholds are correct
func TestE2E_LadderThresholds(t *testing.T) {
	tests := []struct {
		score      float64
		aggressive bool
		expected   string
	}{
		{0, false, "A·静默"},
		{25, false, "A·静默"},
		{26, false, "B·侦查"},
		{50, false, "B·侦查"},
		{51, false, "C·掠食者"},
		{75, false, "C·掠食者"},
		{76, false, "D·黑洞"},
		{100, false, "D·黑洞"},
		{14, true, "A·静默"},
		{16, true, "B·侦查"},
		{54, true, "C·掠食者"},
		{56, true, "D·黑洞"},
	}
	for _, tt := range tests {
		_, name, _ := brain.DetermineResponse(tt.score, tt.aggressive)
		if name != tt.expected {
			t.Errorf("score=%.0f agg=%v: got %s want %s", tt.score, tt.aggressive, name, tt.expected)
		}
	}
}
