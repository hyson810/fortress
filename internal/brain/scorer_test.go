package brain

import (
	"testing"
	"time"

	"github.com/fortress/v6/internal/engine"
)

func TestSYNFloodScoring(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 10000)
	for i := 0; i < 100; i++ {
		s.AddThreat(engine.Threat{Type: "SYN洪水", IP: "203.0.113.99"})
	}
	score, level := s.GetScore("203.0.113.99")
	t.Logf("Score: %.1f, Level: %d", score, level)
	if score < 50 {
		t.Error("expected score >= 50 for 100 SYN flood threats")
	}
}

func TestResponseLadder(t *testing.T) {
	tests := []struct {
		score float64
		agg   bool
		name  string
	}{
		{10, false, "A·静默"},
		{35, false, "B·侦查"},
		{60, false, "C·掠食者"},
		{85, false, "D·黑洞"},
		{10, true, "A·静默"},
		{20, true, "B·侦查"},
		{45, true, "C·掠食者"},
		{80, true, "D·黑洞"},
	}
	for _, tt := range tests {
		_, name, _ := DetermineResponse(tt.score, tt.agg)
		if name != tt.name {
			t.Errorf("score=%.0f agg=%v: got %s, want %s", tt.score, tt.agg, name, tt.name)
		}
	}
}

func TestHoneypotTrip(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 10000)
	s.AddHoneypotTrip("10.0.0.99")
	score, _ := s.GetScore("10.0.0.99")
	if score < 20 {
		t.Error("honeypot trip should push score above 20")
	}
}

func TestCorrelation(t *testing.T) {
	ce := NewCorrelationEngine()
	ce.Feed("10.0.0.1", "SYN洪水")
	ce.Feed("10.0.0.2", "SYN洪水")
	ce.Feed("10.0.0.3", "SYN洪水")
	ips, mult := ce.Check()
	if len(ips) < 3 {
		t.Error("expected 3 correlated IPs")
	}
	t.Logf("Correlated IPs: %v, multiplier: %.1f", ips, mult)
}

func TestDecay(t *testing.T) {
	score := DecayScore(100, time.Now().Add(-30*time.Minute), 30*time.Minute)
	if score > 55 || score < 45 {
		t.Errorf("expected ~50 after one half-life, got %.1f", score)
	}
}
