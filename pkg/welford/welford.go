package welford

import "math"

// Tracker implements Welford's online algorithm for computing
// mean and variance in a single pass.
type Tracker struct {
	count uint64
	mean  float64
	m2    float64
}

// New returns an initialized Tracker.
func New() *Tracker {
	return &Tracker{}
}

// Add incorporates a new value into the running statistics.
func (t *Tracker) Add(value float64) {
	t.count++
	delta := value - t.mean
	t.mean += delta / float64(t.count)
	delta2 := value - t.mean
	t.m2 += delta * delta2
}

// Mean returns the current arithmetic mean.
func (t *Tracker) Mean() float64 {
	return t.mean
}

// Variance returns the sample variance (n-1 denominator).
// Returns 0 when fewer than 2 values have been added.
func (t *Tracker) Variance() float64 {
	if t.count < 2 {
		return 0
	}
	return t.m2 / float64(t.count-1)
}

// Std returns the sample standard deviation.
func (t *Tracker) Std() float64 {
	return math.Sqrt(t.Variance())
}

// Count returns the number of values added.
func (t *Tracker) Count() uint64 {
	return t.count
}
