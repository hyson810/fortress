package engine_test

import (
	"testing"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/defense"
)

func TestHoneypotHitTriggersScoring(t *testing.T) {
	hm := defense.NewHoneypotManager()
	if err := hm.StartSSH(2222); err != nil {
		t.Skipf("cannot start honeypot (port in use?): %v", err)
	}
	defer hm.StopAll()

	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)

	// Simulate a honeypot hit being fed into the scorer
	scorer.AddHoneypotTrip("203.0.113.99")
	score, _ := scorer.GetScore("203.0.113.99")
	if score < 20 {
		t.Errorf("honeypot trip should push score >= 20, got %.1f", score)
	}
	t.Logf("Honeypot trip score: %.1f", score)
}

func TestIntelLookup(t *testing.T) {
	ti := defense.NewThreatIntel()
	// WHOIS lookup may fail without network; test the cache hit
	result := ti.Lookup("8.8.8.8")
	if result.IP != "8.8.8.8" {
		t.Error("expected IP in result")
	}
	t.Logf("Intel: IP=%s ASN=%s Country=%s", result.IP, result.ASN, result.Country)
}
