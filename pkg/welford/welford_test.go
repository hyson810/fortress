package welford

import (
	"math"
	"testing"
)

func TestEmpty(t *testing.T) {
	tr := New()
	if tr.Count() != 0 {
		t.Errorf("expected count 0")
	}
	if tr.Variance() != 0 {
		t.Errorf("expected variance 0")
	}
	if tr.Std() != 0 {
		t.Errorf("expected std 0")
	}
}

func TestSingleValue(t *testing.T) {
	tr := New()
	tr.Add(42.0)
	if tr.Mean() != 42.0 {
		t.Errorf("expected mean 42.0, got %f", tr.Mean())
	}
	if tr.Variance() != 0 {
		t.Errorf("expected variance 0 with single value")
	}
}

func TestKnownValues(t *testing.T) {
	// Values: 2, 4, 4, 4, 5, 5, 7, 9
	// Mean = 5.0, sample variance = 4.571428...
	values := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	tr := New()
	for _, v := range values {
		tr.Add(v)
	}

	expectedMean := 5.0
	if math.Abs(tr.Mean()-expectedMean) > 1e-9 {
		t.Errorf("expected mean %f, got %f", expectedMean, tr.Mean())
	}

	expectedVar := 4.571428571428571
	if math.Abs(tr.Variance()-expectedVar) > 1e-6 {
		t.Errorf("expected variance %f, got %f", expectedVar, tr.Variance())
	}

	expectedStd := math.Sqrt(expectedVar)
	if math.Abs(tr.Std()-expectedStd) > 1e-6 {
		t.Errorf("expected std %f, got %f", expectedStd, tr.Std())
	}

	if tr.Count() != 8 {
		t.Errorf("expected count 8, got %d", tr.Count())
	}
}
