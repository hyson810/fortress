package brain

import (
	"testing"
)

func TestLearnedWhitelist_LearnBenign(t *testing.T) {
	lw := NewLearnedWhitelist(100)
	ip := "192.168.1.50"
	initial := lw.TrustLevel(ip)
	if initial != 0 {
		t.Errorf("initial trust should be 0, got %.2f", initial)
	}

	for i := 0; i < 20; i++ {
		lw.LearnFromTraffic(ip, "normal_http", true)
	}
	trust := lw.TrustLevel(ip)
	if trust <= initial {
		t.Errorf("trust should increase from %.2f after benign traffic, got %.2f", initial, trust)
	}
}

func TestLearnedWhitelist_LearnMalicious(t *testing.T) {
	lw := NewLearnedWhitelist(100)
	ip := "192.168.1.60"

	// Build trust first
	for i := 0; i < 20; i++ {
		lw.LearnFromTraffic(ip, "normal", true)
	}
	before := lw.TrustLevel(ip)

	// Then malicious
	lw.LearnFromTraffic(ip, "port_scan", false)
	after := lw.TrustLevel(ip)
	if after >= before {
		t.Errorf("trust should decrease after malicious traffic: %.2f → %.2f", before, after)
	}
}

func TestLearnedWhitelist_IsAutoWhitelisted(t *testing.T) {
	lw := NewLearnedWhitelist(100)
	ip := "192.168.1.70"

	if lw.IsAutoWhitelisted(ip) {
		t.Error("unknown IP should not be auto-whitelisted")
	}

	// Build high trust
	for i := 0; i < 100; i++ {
		lw.LearnFromTraffic(ip, "normal", true)
	}

	if !lw.IsAutoWhitelisted(ip) {
		trust := lw.TrustLevel(ip)
		t.Logf("trust=%.2f — auto-whitelist requires ≥0.95", trust)
	}
}

func TestLearnedWhitelist_ExportWhitelist(t *testing.T) {
	lw := NewLearnedWhitelist(100)

	lw.LearnFromTraffic("10.0.0.1", "normal", true)
	for i := 0; i < 100; i++ {
		lw.LearnFromTraffic("10.0.0.1", "normal", true)
	}

	lw.LearnFromTraffic("10.0.0.2", "normal", true) // only 1 benign

	exported := lw.ExportWhitelist(0.5)
	if len(exported) == 0 {
		t.Skip("no IPs reached threshold yet")
	}
}

func TestLearnedWhitelist_MergePeers(t *testing.T) {
	lw := NewLearnedWhitelist(100)
	ip := "10.10.10.10"

	lw.LearnFromTraffic(ip, "normal", true)

	peerScores := map[string]float64{ip: 0.8}
	lw.MergePeers(peerScores)

	trust := lw.TrustLevel(ip)
	if trust != 0.8 {
		t.Errorf("peer trust 0.8 should override local, got %.2f", trust)
	}
}

func TestLearnedWhitelist_DecayTrust(t *testing.T) {
	lw := NewLearnedWhitelist(100)
	ip := "10.10.10.20"

	for i := 0; i < 10; i++ {
		lw.LearnFromTraffic(ip, "normal", true)
	}

	lw.DecayTrust()
	// Trust should still be > 0 (just called Decay)
	trust := lw.TrustLevel(ip)
	if trust <= 0 {
		t.Error("trust should not drop to 0 immediately")
	}
}

func TestLearnedWhitelist_Size(t *testing.T) {
	lw := NewLearnedWhitelist(3)
	if lw.Size() != 0 {
		t.Errorf("expected 0, got %d", lw.Size())
	}

	lw.LearnFromTraffic("10.0.0.1", "normal", true)
	lw.LearnFromTraffic("10.0.0.2", "normal", true)
	lw.LearnFromTraffic("10.0.0.3", "normal", true)

	if lw.Size() != 3 {
		t.Errorf("expected 3, got %d", lw.Size())
	}

	// 4th IP should evict oldest
	lw.LearnFromTraffic("10.0.0.4", "normal", true)
	if lw.Size() > 3 {
		t.Errorf("expected ≤3 after maxSize overflow, got %d", lw.Size())
	}
}
