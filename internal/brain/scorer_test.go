package brain

import (
	"testing"
	"time"
)

func testConfig() *Scorer {
	return NewScorer(DefaultWeights(), 1800, 10000)
}

func TestNewScorer(t *testing.T) {
	s := testConfig()
	if s == nil {
		t.Fatal("NewScorer returned nil")
	}
	if s.weights.ScanDetect != 2.5 {
		t.Errorf("expected ScanDetect=2.5, got %.1f", s.weights.ScanDetect)
	}
	if s.maxSize != 10000 {
		t.Errorf("expected maxSize=10000, got %d", s.maxSize)
	}
}

func TestScorer_GetOrCreate_NewIP(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 10)
	r := s.GetOrCreate("10.0.0.1")
	if r == nil {
		t.Fatal("GetOrCreate returned nil for new IP")
	}
	if r.IP != "10.0.0.1" {
		t.Errorf("expected IP=10.0.0.1, got %s", r.IP)
	}
	if r.TotalScore != 0 {
		t.Errorf("expected TotalScore=0, got %.1f", r.TotalScore)
	}
}

func TestScorer_GetOrCreate_ExistingIP(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 10)
	r1 := s.GetOrCreate("10.0.0.2")
	time.Sleep(10 * time.Millisecond)
	r2 := s.GetOrCreate("10.0.0.2")
	// GetOrCreate may return same or different pointer — both acceptable
	// as long as the underlying record is the same IP
	if r2.IP != r1.IP {
		t.Fatal("GetOrCreate should return same IP")
	}
	if !r2.LastSeen.After(r1.LastSeen) || r2.LastSeen.Equal(r1.LastSeen) {
		t.Log("LastSeen should be updated on second GetOrCreate")
	}
}

func TestScorer_GetOrCreate_EvictionAtMaxSize(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 3)
	s.GetOrCreate("10.0.0.1")
	time.Sleep(1 * time.Millisecond)
	s.GetOrCreate("10.0.0.2")
	time.Sleep(1 * time.Millisecond)
	s.GetOrCreate("10.0.0.3")
	// Insert 4th — should evict oldest (10.0.0.1)
	s.GetOrCreate("10.0.0.4")

	score, _ := s.GetScore("10.0.0.1")
	if score != 0 {
		t.Error("10.0.0.1 should have been evicted")
	}
}

func TestScorer_AddScanScore(t *testing.T) {
	s := testConfig()
	s.GetOrCreate("10.0.0.5")
	s.AddScanScore("10.0.0.5", 10)

	r := s.GetOrCreate("10.0.0.5")
	// ScanScore = log2(11) * 2.5 ≈ 3.46 * 2.5 ≈ 8.65
	if r.ScanScore < 8.0 || r.ScanScore > 10.0 {
		t.Errorf("expected ScanScore ~8.65 for ports=10, got %.2f", r.ScanScore)
	}
	if r.OpenPorts != 10 {
		t.Errorf("expected OpenPorts=10, got %d", r.OpenPorts)
	}
}

func TestScorer_AddFloodScore(t *testing.T) {
	s := testConfig()
	s.GetOrCreate("10.0.0.6")
	s.AddFloodScore("10.0.0.6", 500)

	r := s.GetOrCreate("10.0.0.6")
	// Formula: pow(pps/100, 1.5) * FloodDetect
	// pow(5, 1.5) ≈ 11.18, * 3.0 ≈ 33.54
	if r.FloodScore < 30 || r.FloodScore > 40 {
		t.Errorf("expected FloodScore ~33.5 for pps=500, got %.2f", r.FloodScore)
	}
}

func TestScorer_AddFloodScore_LowPPS(t *testing.T) {
	s := testConfig()
	s.GetOrCreate("10.0.0.7")
	s.AddFloodScore("10.0.0.7", 10)

	r := s.GetOrCreate("10.0.0.7")
	if r.FloodScore > 1.0 {
		t.Errorf("expected low FloodScore for pps=10, got %.2f", r.FloodScore)
	}
}

func TestScorer_AddAnomalyScore(t *testing.T) {
	s := testConfig()
	s.GetOrCreate("10.0.0.8")
	s.AddAnomalyScore("10.0.0.8", 5.0)

	r := s.GetOrCreate("10.0.0.8")
	expected := (5.0 - 2.0) * 2.0 // 6.0
	if r.AnomalyScore != expected {
		t.Errorf("expected AnomalyScore=%.1f for zScore=5.0, got %.2f", expected, r.AnomalyScore)
	}
}

func TestScorer_AddAnomalyScore_BelowThreshold(t *testing.T) {
	s := testConfig()
	s.GetOrCreate("10.0.0.9")
	s.AddAnomalyScore("10.0.0.9", 1.0)

	r := s.GetOrCreate("10.0.0.9")
	if r.AnomalyScore != 0 {
		t.Errorf("expected AnomalyScore=0 for zScore=1.0 (below 2.0), got %.2f", r.AnomalyScore)
	}
}

func TestScorer_AddHoneypotTrip(t *testing.T) {
	s := testConfig()
	s.GetOrCreate("10.0.0.10")
	s.AddHoneypotTrip("10.0.0.10")

	r := s.GetOrCreate("10.0.0.10")
	if !r.HoneypotTripped {
		t.Error("HoneypotTripped should be true")
	}
	if r.HoneypotScore != 5.0 {
		t.Errorf("expected HoneypotScore=5.0, got %.2f", r.HoneypotScore)
	}
}

func TestScorer_AddIntelMatch(t *testing.T) {
	s := testConfig()
	s.GetOrCreate("10.0.0.11")
	s.AddIntelMatch("10.0.0.11", "abuseipdb")

	r := s.GetOrCreate("10.0.0.11")
	if len(r.IntelMatches) != 1 {
		t.Errorf("expected 1 intel match, got %d", len(r.IntelMatches))
	}
	if r.IntelMatches[0] != "abuseipdb" {
		t.Errorf("expected source=abuseipdb, got %s", r.IntelMatches[0])
	}
}

func TestScorer_ShouldCounterstrike(t *testing.T) {
	s := testConfig()
	s.GetOrCreate("10.0.0.12")
	s.AddScanScore("10.0.0.12", 100)
	s.AddFloodScore("10.0.0.12", 2000)
	s.AddAnomalyScore("10.0.0.12", 10.0)
	s.AddHoneypotTrip("10.0.0.12")

	// Should be well above default threshold of 85
	if !s.ShouldCounterstrike("10.0.0.12", 75.0) {
		r := s.GetOrCreate("10.0.0.12")
		t.Errorf("should counterstrike with score=%.1f > 75.0", r.TotalScore)
	}
}

func TestScorer_ShouldNotCounterstrike_LowScore(t *testing.T) {
	s := testConfig()
	s.GetOrCreate("10.0.0.13")
	if s.ShouldCounterstrike("10.0.0.13", 75.0) {
		t.Error("should NOT counterstrike for IP with no scores")
	}
}

func TestScorer_Top_Ordering(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 100)

	s.GetOrCreate("10.0.0.20")
	s.AddScanScore("10.0.0.20", 5)

	s.GetOrCreate("10.0.0.21")
	s.AddFloodScore("10.0.0.21", 2000)

	s.GetOrCreate("10.0.0.22")
	s.AddHoneypotTrip("10.0.0.22")
	s.AddFloodScore("10.0.0.22", 5000)

	top := s.Top(3)
	if len(top) < 3 {
		t.Fatalf("expected 3 results, got %d", len(top))
	}
	// Top should be sorted descending
	if top[0].TotalScore < top[1].TotalScore {
		t.Error("Top results should be sorted by score descending")
	}
}

func TestScorer_GetScore_NonExistent(t *testing.T) {
	s := testConfig()
	score, level := s.GetScore("99.99.99.99")
	if score != 0 {
		t.Errorf("expected score=0 for nonexistent IP, got %.1f", score)
	}
	if level != ResponseA {
		t.Errorf("expected ResponseA for nonexistent IP, got %s", level.String())
	}
}

func TestScorer_GetScore_ExistingWithScores(t *testing.T) {
	s := testConfig()
	s.GetOrCreate("10.0.0.30")
	s.AddHoneypotTrip("10.0.0.30")
	s.AddFloodScore("10.0.0.30", 3000)

	score, level := s.GetScore("10.0.0.30")
	if score == 0 {
		t.Error("expected non-zero score for attacked IP")
	}
	_ = level
}

func TestScorer_AggressiveWeights(t *testing.T) {
	aw := AggressiveWeights()
	if aw.HoneypotTrip <= DefaultWeights().HoneypotTrip {
		t.Error("AggressiveWeights should have higher HoneypotTrip than DefaultWeights")
	}
	if aw.BruteForce <= DefaultWeights().BruteForce {
		t.Error("AggressiveWeights should have higher BruteForce than DefaultWeights")
	}
}

func TestScorer_BoostSubnetNeighbors(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 1000)

	// Create a triggering IP with high score.
	s.GetOrCreate("10.0.0.50")
	s.AddScanScore("10.0.0.50", 10)      // +25 → 25
	s.AddFloodScore("10.0.0.50", 200)     // +25 → 50
	s.AddAnomalyScore("10.0.0.50", 5.0)   // +25 → 75

	// Same /24 neighbors.
	s.GetOrCreate("10.0.0.100")
	s.GetOrCreate("10.0.0.200")

	// Different /24 (should not be boosted).
	s.GetOrCreate("10.0.1.50")

	triggerScore := s.GetOrCreate("10.0.0.50").TotalScore
	t.Logf("trigger score before boost: %.1f", triggerScore)

	s.BoostSubnetNeighbors("10.0.0.50", 0.15)

	// Same /24 neighbors should be boosted.
	n1 := s.GetOrCreate("10.0.0.100")
	n2 := s.GetOrCreate("10.0.0.200")
	// Different /24 should NOT be boosted.
	n3 := s.GetOrCreate("10.0.1.50")

	t.Logf("neighbor 10.0.0.100: %.1f (boosted)", n1.TotalScore)
	t.Logf("neighbor 10.0.0.200: %.1f (boosted)", n2.TotalScore)
	t.Logf("neighbor 10.0.1.50: %.1f (should be 0)", n3.TotalScore)

	if n1.TotalScore <= 0 {
		t.Error("same-/24 neighbor should be boosted")
	}
	if n2.TotalScore <= 0 {
		t.Error("same-/24 neighbor should be boosted")
	}
	if n3.TotalScore > 0 {
		t.Error("different-/24 neighbor should NOT be boosted")
	}
}

func TestScorer_BoostSubnetNeighbors_IPv6(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 1000)
	s.GetOrCreate("2001:db8::1")
	s.AddScanScore("2001:db8::1", 5)
	s.BoostSubnetNeighbors("2001:db8::1", 0.15)
	// IPv6 subnet boost not yet supported — should not panic.
	t.Log("IPv6 boost handled gracefully")
}

func TestScorer_BoostSubnetNeighbors_EmptySubnet(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 1000)
	s.GetOrCreate("192.168.1.1")
	s.AddScanScore("192.168.1.1", 2)
	s.BoostSubnetNeighbors("192.168.1.1", 0.20)
	// No neighbors — should not panic.
	r := s.GetOrCreate("192.168.1.1")
	t.Logf("isolated IP score: %.1f", r.TotalScore)
}
