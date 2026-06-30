package brain

import (
	"math"
	"sync"
	"time"
)

// AdaptiveThreshold dynamically adjusts detection sensitivity based on
// traffic patterns, time of day, and day of week. Uses online Welford-style
// statistics for continuous baseline adaptation.
type AdaptiveThreshold struct {
	baseline    float64
	current     float64
	min         float64
	max         float64
	learningRate float64 // 0.0-1.0, higher = faster adaptation

	count       int
	mean        float64
	m2          float64 // Welford M2 for variance

	history     []thresholdSample
	maxHistory  int

	mu sync.RWMutex
}

type thresholdSample struct {
	value     float64
	timestamp time.Time
}

// NewAdaptiveThreshold creates an adaptive threshold tracker.
// initial is the starting threshold, learningRate controls adaptation speed.
func NewAdaptiveThreshold(initial, min, max, learningRate float64) *AdaptiveThreshold {
	return &AdaptiveThreshold{
		baseline:     initial,
		current:      initial,
		min:          min,
		max:          max,
		learningRate: learningRate,
		history:      make([]thresholdSample, 0, 1000),
		maxHistory:   1000,
	}
}

// Update feeds a new observed value into the adaptive threshold.
// Returns the updated threshold.
func (at *AdaptiveThreshold) Update(observed float64) float64 {
	at.mu.Lock()
	defer at.mu.Unlock()

	// Welford online mean/variance update
	at.count++
	delta := observed - at.mean
	at.mean += delta / float64(at.count)
	delta2 := observed - at.mean
	at.m2 += delta * delta2

	// Compute new threshold with time-of-day and day-of-week awareness
	now := time.Now()
	todMultiplier := timeOfDayMultiplier(now)
	dowMultiplier := dayOfWeekMultiplier(now)

	// Adjust: pull toward observed + 2σ (upper bound of normal)
	var stdDev float64
	if at.count > 1 {
		stdDev = math.Sqrt(at.m2 / float64(at.count-1))
	}
	target := at.mean + 2.0*stdDev

	// Smooth transition
	at.baseline = at.baseline + at.learningRate*(target-at.baseline)
	at.current = at.baseline * todMultiplier * dowMultiplier

	// Clamp to bounds
	if at.current < at.min {
		at.current = at.min
	}
	if at.current > at.max {
		at.current = at.max
	}

	// Store history
	at.history = append(at.history, thresholdSample{value: at.current, timestamp: now})
	if len(at.history) > at.maxHistory {
		at.history = at.history[len(at.history)-at.maxHistory:]
	}

	return at.current
}

// ShouldEscalate returns true if the given score exceeds the current threshold.
func (at *AdaptiveThreshold) ShouldEscalate(score float64) bool {
	at.mu.RLock()
	defer at.mu.RUnlock()
	return score >= at.current
}

// GetCurrentThreshold returns the active threshold value.
func (at *AdaptiveThreshold) GetCurrentThreshold() float64 {
	at.mu.RLock()
	defer at.mu.RUnlock()
	return at.current
}

// GetConfidenceBand returns the low/high range around the current threshold.
func (at *AdaptiveThreshold) GetConfidenceBand() (low, high float64) {
	at.mu.RLock()
	defer at.mu.RUnlock()
	var stdDev float64
	if at.count > 1 {
		stdDev = math.Sqrt(at.m2 / float64(at.count-1))
	}
	low = at.current - stdDev
	high = at.current + stdDev
	if low < at.min {
		low = at.min
	}
	if high > at.max {
		high = at.max
	}
	return
}

// GetStats returns summary statistics.
func (at *AdaptiveThreshold) GetStats() (count int, mean, stdDev, current float64) {
	at.mu.RLock()
	defer at.mu.RUnlock()
	if at.count > 1 {
		stdDev = math.Sqrt(at.m2 / float64(at.count-1))
	}
	return at.count, at.mean, stdDev, at.current
}

// Trend returns whether the threshold is rising, falling, or stable.
func (at *AdaptiveThreshold) Trend() string {
	at.mu.RLock()
	defer at.mu.RUnlock()
	if len(at.history) < 10 {
		return "insufficient-data"
	}
	// Compare last 10 samples average with previous 10
	half := len(at.history) / 2
	recent := at.history[half:]
	older := at.history[:half]

	var recentSum, olderSum float64
	for _, s := range recent {
		recentSum += s.value
	}
	for _, s := range older {
		olderSum += s.value
	}
	recentAvg := recentSum / float64(len(recent))
	olderAvg := olderSum / float64(len(older))

	diff := recentAvg - olderAvg
	if diff > 0.1*at.baseline {
		return "rising"
	} else if diff < -0.1*at.baseline {
		return "falling"
	}
	return "stable"
}

// Reset clears all statistics and resets to the initial threshold.
func (at *AdaptiveThreshold) Reset(initial float64) {
	at.mu.Lock()
	defer at.mu.Unlock()
	at.baseline = initial
	at.current = initial
	at.count = 0
	at.mean = 0
	at.m2 = 0
	at.history = at.history[:0]
}

// ---------------------------------------------------------------------------
// Time-awareness helpers
// ---------------------------------------------------------------------------

// timeOfDayMultiplier returns a sensitivity multiplier based on hour.
// Night hours (0-6) = higher sensitivity (attackers prefer nighttime).
func timeOfDayMultiplier(t time.Time) float64 {
	hour := t.Hour()
	switch {
	case hour >= 0 && hour < 6:
		return 0.7 // 30% more sensitive at night
	case hour >= 6 && hour < 9:
		return 0.85 // transition
	case hour >= 9 && hour < 18:
		return 1.0 // normal business hours
	case hour >= 18 && hour < 22:
		return 0.9 // evening
	default:
		return 0.7 // late night
	}
}

// dayOfWeekMultiplier returns a sensitivity multiplier based on day.
// Weekends = higher sensitivity (less normal traffic, easier to spot anomalies).
func dayOfWeekMultiplier(t time.Time) float64 {
	switch t.Weekday() {
	case time.Saturday, time.Sunday:
		return 0.75 // 25% more sensitive on weekends
	default:
		return 1.0
	}
}
