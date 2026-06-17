package entropy

import (
	"math"
	"testing"
)

func TestShannonEmpty(t *testing.T) {
	e := Shannon(map[string]uint64{})
	if e != 0 {
		t.Errorf("expected 0 for empty map, got %f", e)
	}
}

func TestShannonUniform(t *testing.T) {
	// 4 equally frequent symbols → entropy = log2(4) = 2.0
	freq := map[string]uint64{
		"a": 1,
		"b": 1,
		"c": 1,
		"d": 1,
	}
	e := Shannon(freq)
	expected := 2.0
	if math.Abs(e-expected) > 1e-9 {
		t.Errorf("expected %f, got %f", expected, e)
	}
}

func TestShannonSingle(t *testing.T) {
	// One symbol → entropy = 0
	freq := map[string]uint64{"x": 100}
	e := Shannon(freq)
	if e != 0 {
		t.Errorf("expected 0 for single symbol, got %f", e)
	}
}

func TestBytes(t *testing.T) {
	// "aaaa" has zero entropy.
	e := Bytes([]byte("aaaa"))
	if e != 0 {
		t.Errorf("expected 0 for uniform bytes, got %f", e)
	}

	// "ab" has 1.0 entropy.
	e = Bytes([]byte("ab"))
	if math.Abs(e-1.0) > 1e-9 {
		t.Errorf("expected 1.0, got %f", e)
	}
}

func TestBytesEmpty(t *testing.T) {
	e := Bytes([]byte{})
	if e != 0 {
		t.Errorf("expected 0 for empty slice, got %f", e)
	}
}
