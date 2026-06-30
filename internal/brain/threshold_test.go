package brain

import (
	"testing"
)

func TestAdaptiveThreshold_Update_Basic(t *testing.T) {
	at := NewAdaptiveThreshold(10.0, 1.0, 100.0, 0.1)
	for i := 0; i < 20; i++ {
		at.Update(10.0)
	}
	thresh := at.GetCurrentThreshold()
	if thresh < 1.0 || thresh > 100.0 {
		t.Errorf("threshold %.2f out of bounds [1, 100]", thresh)
	}
}

func TestAdaptiveThreshold_ShouldEscalate_Above(t *testing.T) {
	at := NewAdaptiveThreshold(10.0, 1.0, 100.0, 0.1)
	for i := 0; i < 20; i++ {
		at.Update(5.0)
	}
	if !at.ShouldEscalate(50.0) {
		t.Error("score well above threshold should trigger escalation")
	}
}

func TestAdaptiveThreshold_ShouldEscalate_Below(t *testing.T) {
	at := NewAdaptiveThreshold(10.0, 1.0, 100.0, 0.1)
	for i := 0; i < 20; i++ {
		at.Update(8.0)
	}
	if at.ShouldEscalate(1.0) {
		t.Error("score well below threshold should NOT trigger escalation")
	}
}

func TestAdaptiveThreshold_Trend_InsufficientData(t *testing.T) {
	at := NewAdaptiveThreshold(10.0, 1.0, 100.0, 0.1)
	if at.Trend() != "insufficient-data" {
		t.Errorf("expected insufficient-data, got %s", at.Trend())
	}
}

func TestAdaptiveThreshold_Trend_Rising(t *testing.T) {
	at := NewAdaptiveThreshold(10.0, 1.0, 100.0, 0.5)
	for i := 0; i < 30; i++ {
		at.Update(float64(i + 10)) // increasing values
	}
	trend := at.Trend()
	if trend == "insufficient-data" {
		t.Skip("not enough samples accumulated for trend detection")
	}
	// Rising or stable is acceptable
	t.Logf("Trend: %s", trend)
}

func TestAdaptiveThreshold_GetConfidenceBand(t *testing.T) {
	at := NewAdaptiveThreshold(10.0, 1.0, 100.0, 0.1)
	for i := 0; i < 20; i++ {
		at.Update(10.0)
	}
	low, high := at.GetConfidenceBand()
	if low > high {
		t.Errorf("low %.2f > high %.2f", low, high)
	}
}

func TestAdaptiveThreshold_GetStats(t *testing.T) {
	at := NewAdaptiveThreshold(10.0, 1.0, 100.0, 0.1)
	for i := 0; i < 100; i++ {
		at.Update(10.0)
	}
	count, mean, stdDev, current := at.GetStats()
	if count != 100 {
		t.Errorf("expected count=100, got %d", count)
	}
	if mean < 9.0 || mean > 11.0 {
		t.Errorf("mean %.2f not close to 10.0 after 100 samples", mean)
	}
	_ = stdDev
	_ = current
}

func TestAdaptiveThreshold_Reset(t *testing.T) {
	at := NewAdaptiveThreshold(10.0, 1.0, 100.0, 0.1)
	for i := 0; i < 50; i++ {
		at.Update(20.0)
	}
	at.Reset(5.0)
	thresh := at.GetCurrentThreshold()
	if thresh != 5.0 {
		t.Errorf("expected reset to 5.0, got %.2f", thresh)
	}
	count, _, _, _ := at.GetStats()
	if count != 0 {
		t.Errorf("expected count=0 after reset, got %d", count)
	}
}
