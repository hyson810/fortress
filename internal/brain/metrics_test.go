package brain

import (
	"strings"
	"testing"
	"time"
)

func TestMetricsCollector_RecordDecision(t *testing.T) {
	mc := NewMetricsCollector()
	mc.RecordDecision(10 * time.Millisecond)
	mc.RecordDecision(20 * time.Millisecond)
	mc.RecordDecision(30 * time.Millisecond)

	m := mc.GetMetrics()
	if m.DecisionsTotal != 3 {
		t.Errorf("expected 3 decisions, got %d", m.DecisionsTotal)
	}
	if m.AvgDecisionLatency != 20*time.Millisecond {
		t.Errorf("expected avg=20ms, got %v", m.AvgDecisionLatency)
	}
	if m.MaxDecisionLatency != 30*time.Millisecond {
		t.Errorf("expected max=30ms, got %v", m.MaxDecisionLatency)
	}
}

func TestMetricsCollector_RecordScore(t *testing.T) {
	mc := NewMetricsCollector()
	for i := 0; i < 100; i++ {
		mc.RecordScore(float64(i))
	}
	m := mc.GetMetrics()
	if m.AvgScorePerIP < 40 || m.AvgScorePerIP > 60 {
		t.Errorf("expected avg ~50, got %.2f", m.AvgScorePerIP)
	}
}

func TestMetricsCollector_Precision(t *testing.T) {
	mc := NewMetricsCollector()
	// No events yet
	if p := mc.Precision(); p != 1.0 {
		t.Errorf("empty should be precision=1.0, got %.2f", p)
	}
	mc.RecordTruePositive()
	mc.RecordTruePositive()
	mc.RecordFalsePositive()
	if p := mc.Precision(); p != 2.0/3.0 {
		t.Errorf("expected 2/3 precision, got %.2f", p)
	}
}

func TestMetricsCollector_Counterstrikes(t *testing.T) {
	mc := NewMetricsCollector()
	mc.RecordCounterstrike()
	mc.RecordCounterstrike()
	mc.RecordCounterstrike()
	m := mc.GetMetrics()
	if m.AutoCounterstrikes != 3 {
		t.Errorf("expected 3 counterstrikes, got %d", m.AutoCounterstrikes)
	}
}

func TestMetricsCollector_StagePerf(t *testing.T) {
	mc := NewMetricsCollector()
	mc.RecordStagePerf(0, "L1-Packet", 5*time.Millisecond)
	mc.RecordStagePerf(0, "L1-Packet", 8*time.Millisecond)
	mc.RecordStagePerf(1, "L2-Flow", 3*time.Millisecond)
	mc.RecordStageError(0)

	perf := mc.GetStagePerf()
	if len(perf) == 0 {
		t.Fatal("expected stage perf data")
	}
	if perf[0].Calls != 2 {
		t.Errorf("expected 2 L1 calls, got %d", perf[0].Calls)
	}
	if perf[0].ErrorCount != 1 {
		t.Errorf("expected 1 L1 error, got %d", perf[0].ErrorCount)
	}
}

func TestMetricsCollector_AvgOneMinScore(t *testing.T) {
	mc := NewMetricsCollector()
	if mc.AvgOneMinScore() != 0 {
		t.Error("empty should be 0")
	}
	mc.RecordScore(100)
	if mc.AvgOneMinScore() == 0 {
		t.Error("should be >0 after recording")
	}
}

func TestMetricsCollector_ExportPrometheus(t *testing.T) {
	mc := NewMetricsCollector()
	mc.RecordDecision(10 * time.Millisecond)
	mc.RecordEscalation("A", "B", "10.0.0.1")
	mc.RecordTruePositive()
	mc.RecordCounterstrike()

	output := mc.ExportPrometheus()
	if !strings.Contains(output, "fortress_decisions_total") {
		t.Error("missing fortress_decisions_total metric")
	}
	if !strings.Contains(output, "fortress_uptime_seconds") {
		t.Error("missing fortress_uptime_seconds metric")
	}
	t.Logf("Prometheus output: %d lines", len(strings.Split(output, "\n")))
}

func TestMetricsCollector_PacketAndThreatRecording(t *testing.T) {
	mc := NewMetricsCollector()
	mc.RecordPackets(1000)
	mc.RecordThreats(50)
	mc.RecordPackets(2000)

	m := mc.GetMetrics()
	if m.PacketsProcessed != 3000 {
		t.Errorf("expected 3000 packets, got %d", m.PacketsProcessed)
	}
	if m.ThreatsCreated != 50 {
		t.Errorf("expected 50 threats, got %d", m.ThreatsCreated)
	}
}
