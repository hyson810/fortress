package brain

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// BrainMetrics tracks real-time performance counters for the decision engine.
type BrainMetrics struct {
	// Counters
	DecisionsTotal    uint64
	EscalationsTotal  uint64
	FalsePositives    uint64
	TruePositives     uint64
	AutoCounterstrikes uint64

	// Timing
	AvgDecisionLatency time.Duration
	MaxDecisionLatency time.Duration
	TotalDecisionTime  time.Duration
	decisionCount      uint64

	// Scoring
	AvgScorePerIP  float64
	TopAttackerIPs []string
	TopAttackerScore float64

	// Pipeline
	PacketsProcessed uint64
	ThreatsCreated   uint64
	Uptime           time.Duration

	startTime time.Time
}

// MetricsCollector gathers and exposes brain performance metrics.
type MetricsCollector struct {
	metrics     BrainMetrics
	perStagePerf [10]StagePerf

	// Sliding windows
	minuteScores []float64
	hourScores   []float64

	mu sync.Mutex
}

// StagePerf tracks per-pipeline-stage performance.
type StagePerf struct {
	Name       string
	Calls      uint64
	TotalTime  time.Duration
	MaxTime    time.Duration
	ErrorCount uint64
}

// NewMetricsCollector creates a performance metrics collector.
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: BrainMetrics{
			startTime: time.Now(),
		},
		minuteScores: make([]float64, 0, 600),
		hourScores:   make([]float64, 0, 3600),
	}
}

// RecordDecision increments the decision counter and tracks latency.
func (mc *MetricsCollector) RecordDecision(latency time.Duration) {
	atomic.AddUint64(&mc.metrics.DecisionsTotal, 1)

	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.metrics.TotalDecisionTime += latency
	mc.metrics.decisionCount++
	mc.metrics.AvgDecisionLatency = mc.metrics.TotalDecisionTime / time.Duration(mc.metrics.decisionCount)
	if latency > mc.metrics.MaxDecisionLatency {
		mc.metrics.MaxDecisionLatency = latency
	}
}

// RecordEscalation tracks response ladder escalations.
func (mc *MetricsCollector) RecordEscalation(from, to string, ip string) {
	atomic.AddUint64(&mc.metrics.EscalationsTotal, 1)
}

// RecordFalsePositive marks a false positive detection.
func (mc *MetricsCollector) RecordFalsePositive() {
	atomic.AddUint64(&mc.metrics.FalsePositives, 1)
}

// RecordTruePositive marks a confirmed true positive.
func (mc *MetricsCollector) RecordTruePositive() {
	atomic.AddUint64(&mc.metrics.TruePositives, 1)
}

// RecordCounterstrike tracks autonomous counterstrike actions.
func (mc *MetricsCollector) RecordCounterstrike() {
	atomic.AddUint64(&mc.metrics.AutoCounterstrikes, 1)
}

// RecordScore adds a score to the sliding windows.
func (mc *MetricsCollector) RecordScore(score float64) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.minuteScores = append(mc.minuteScores, score)
	if len(mc.minuteScores) > 600 {
		mc.minuteScores = mc.minuteScores[len(mc.minuteScores)-600:]
	}

	mc.hourScores = append(mc.hourScores, score)
	if len(mc.hourScores) > 3600 {
		mc.hourScores = mc.hourScores[len(mc.hourScores)-3600:]
	}

	// Update average
	var sum float64
	for _, s := range mc.hourScores {
		sum += s
	}
	mc.metrics.AvgScorePerIP = sum / float64(len(mc.hourScores))
}

// RecordPackets increments the processed packet counter.
func (mc *MetricsCollector) RecordPackets(n uint64) {
	atomic.AddUint64(&mc.metrics.PacketsProcessed, n)
}

// RecordThreats increments the threat detection counter.
func (mc *MetricsCollector) RecordThreats(n uint64) {
	atomic.AddUint64(&mc.metrics.ThreatsCreated, n)
}

// RecordStagePerf records latency for a pipeline stage.
func (mc *MetricsCollector) RecordStagePerf(stageIndex int, name string, latency time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if stageIndex >= len(mc.perStagePerf) {
		return
	}
	sp := &mc.perStagePerf[stageIndex]
	sp.Name = name
	sp.Calls++
	sp.TotalTime += latency
	if latency > sp.MaxTime {
		sp.MaxTime = latency
	}
}

// RecordStageError increments the error counter for a stage.
func (mc *MetricsCollector) RecordStageError(stageIndex int) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if stageIndex < len(mc.perStagePerf) {
		mc.perStagePerf[stageIndex].ErrorCount++
	}
}

// GetMetrics returns a snapshot of current metrics.
func (mc *MetricsCollector) GetMetrics() BrainMetrics {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	m := mc.metrics
	m.Uptime = time.Since(mc.metrics.startTime)
	return m
}

// GetStagePerf returns per-stage performance data.
func (mc *MetricsCollector) GetStagePerf() []StagePerf {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	result := make([]StagePerf, 0, len(mc.perStagePerf))
	for _, sp := range mc.perStagePerf {
		if sp.Calls > 0 {
			result = append(result, sp)
		}
	}
	return result
}

// Precision returns the current precision (TP / (TP + FP)).
func (mc *MetricsCollector) Precision() float64 {
	tp := atomic.LoadUint64(&mc.metrics.TruePositives)
	fp := atomic.LoadUint64(&mc.metrics.FalsePositives)
	if tp+fp == 0 {
		return 1.0
	}
	return float64(tp) / float64(tp+fp)
}

// AvgOneMinScore returns the average threat score over the last minute.
func (mc *MetricsCollector) AvgOneMinScore() float64 {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if len(mc.minuteScores) == 0 {
		return 0
	}
	var sum float64
	for _, s := range mc.minuteScores {
		sum += s
	}
	return sum / float64(len(mc.minuteScores))
}

// ExportPrometheus returns metrics in Prometheus text format.
func (mc *MetricsCollector) ExportPrometheus() string {
	m := mc.GetMetrics()

	return fmt.Sprintf(`# HELP fortress_decisions_total Total number of threat decisions
# TYPE fortress_decisions_total counter
fortress_decisions_total %d
# HELP fortress_escalations_total Total number of response escalations
# TYPE fortress_escalations_total counter
fortress_escalations_total %d
# HELP fortress_false_positives_total False positive detections
# TYPE fortress_false_positives_total counter
fortress_false_positives_total %d
# HELP fortress_true_positives_total Confirmed true positive detections
# TYPE fortress_true_positives_total counter
fortress_true_positives_total %d
# HELP fortress_autonomous_counterstrikes D阶 auto-counterstrikes triggered
# TYPE fortress_autonomous_counterstrikes counter
fortress_autonomous_counterstrikes %d
# HELP fortress_avg_decision_latency_seconds Average decision latency
# TYPE fortress_avg_decision_latency_seconds gauge
fortress_avg_decision_latency_seconds %.6f
# HELP fortress_avg_score_per_ip Average threat score per tracked IP
# TYPE fortress_avg_score_per_ip gauge
fortress_avg_score_per_ip %.2f
# HELP fortress_packets_processed_total Total packets through pipeline
# TYPE fortress_packets_processed_total counter
fortress_packets_processed_total %d
# HELP fortress_threats_created_total Total threat detections
# TYPE fortress_threats_created_total counter
fortress_threats_created_total %d
# HELP fortress_uptime_seconds Process uptime
# TYPE fortress_uptime_seconds gauge
fortress_uptime_seconds %.0f
`,
		m.DecisionsTotal, m.EscalationsTotal,
		m.FalsePositives, m.TruePositives,
		m.AutoCounterstrikes,
		m.AvgDecisionLatency.Seconds(),
		m.AvgScorePerIP,
		m.PacketsProcessed, m.ThreatsCreated,
		m.Uptime.Seconds(),
	)
}
