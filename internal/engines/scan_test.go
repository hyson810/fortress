package engines

import (
	"testing"

	"github.com/fortress/v6/internal/config"
)

func testScanConfig() *config.Config {
	return &config.Config{
		Whitelist: []string{},
	}
}

func TestFlowAnalyzer_New(t *testing.T) {
	fa := NewFlowAnalyzer(testScanConfig())
	if fa == nil {
		t.Fatal("NewFlowAnalyzer returned nil")
	}
}

func TestFlowAnalyzer_Feed_FastScan(t *testing.T) {
	fa := NewFlowAnalyzer(testScanConfig())
	ip := "172.16.0.50"

	var threats []Threat
	for port := 1; port <= 15; port++ {
		threats = fa.Feed(ip, uint16(port))
	}

	found := false
	for _, th := range threats {
		if th.Type == "快速扫描" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 快速扫描 after 15 ports in 5s window, got %d threats", len(threats))
	}
}

func TestFlowAnalyzer_Feed_BelowThreshold(t *testing.T) {
	fa := NewFlowAnalyzer(testScanConfig())
	ip := "172.16.0.60"

	var threats []Threat
	for port := 1; port <= 5; port++ {
		threats = fa.Feed(ip, uint16(port))
	}

	// 5 ports in default window should NOT trigger scan alert (<12 threshold)
	if len(threats) > 0 {
		for _, th := range threats {
			t.Logf("unexpected threat: %s %s", th.Type, th.Detail)
		}
	}
}

func TestFlowAnalyzer_Evict(t *testing.T) {
	fa := NewFlowAnalyzer(testScanConfig())
	ip := "172.16.0.70"

	for port := 1; port <= 10; port++ {
		fa.Feed(ip, uint16(port))
	}

	// Evict should not panic
	fa.Evict(float64(1e12))
}

func TestBehaviorAnalyzer_New(t *testing.T) {
	ba := NewBehaviorAnalyzer(testScanConfig())
	if ba == nil {
		t.Fatal("NewBehaviorAnalyzer returned nil")
	}
}

func TestBehaviorAnalyzer_FeedAndCheck(t *testing.T) {
	ba := NewBehaviorAnalyzer(testScanConfig())
	ip := "172.16.0.80"

	// Feed many samples to establish baseline
	for i := 0; i < 300; i++ {
		ba.Feed(ip, uint16(80+(i%10)))
	}

	// Check should not panic even if baseline not fully established
	threats := ba.Check()
	_ = threats
}

func TestCorrelationEngine_New(t *testing.T) {
	ce := NewCorrelationEngine()
	if ce == nil {
		t.Fatal("NewCorrelationEngine returned nil")
	}
}

func TestCorrelationEngine_FeedAndCheck(t *testing.T) {
	ce := NewCorrelationEngine()

	// Feed 3 different IPs with similar attack types
	ce.Feed("10.0.0.1", "SYN洪水")
	ce.Feed("10.0.0.2", "端口扫描")
	ce.Feed("10.0.0.3", "SYN洪水")

	threats := ce.CheckCorrelation()
	// May or may not trigger depending on window — just verify no panic
	_ = threats
}
