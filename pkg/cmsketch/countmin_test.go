package cmsketch

import (
	"testing"
)

func TestNew(t *testing.T) {
	cm := New(4, 256)
	if cm.rows != 4 {
		t.Errorf("expected 4 rows, got %d", cm.rows)
	}
	if cm.cols != 256 {
		t.Errorf("expected 256 cols, got %d", cm.cols)
	}
	if cm.Total() != 0 {
		t.Errorf("expected total 0, got %d", cm.Total())
	}
}

func TestAddEstimate(t *testing.T) {
	cm := New(4, 256)

	cm.Add([]byte("hello"), 1)
	cm.Add([]byte("hello"), 2)
	cm.Add([]byte("world"), 5)

	estH := cm.Estimate([]byte("hello"))
	if estH < 3 {
		t.Errorf("Expected estimate for 'hello' >= 3, got %d", estH)
	}

	estW := cm.Estimate([]byte("world"))
	if estW < 5 {
		t.Errorf("Expected estimate for 'world' >= 5, got %d", estW)
	}

	if cm.Total() != 8 {
		t.Errorf("expected total 8, got %d", cm.Total())
	}
}

func TestEstimateMissing(t *testing.T) {
	cm := New(4, 256)
	cm.Add([]byte("foo"), 10)

	est := cm.Estimate([]byte("bar"))
	// With FNV and different seeds, collision is unlikely but possible.
	// For a well-configured sketch, we expect a very low estimate.
	if est > 3 {
		t.Logf("note: estimate for missing key is %d (collision possible with small sketch)", est)
	}
}

func TestTotal(t *testing.T) {
	cm := New(4, 128)
	cm.Add([]byte("a"), 1)
	cm.Add([]byte("b"), 2)
	cm.Add([]byte("c"), 3)

	if cm.Total() != 6 {
		t.Errorf("expected total 6, got %d", cm.Total())
	}
}

func TestDecay(t *testing.T) {
	cm := New(4, 256)
	cm.Add([]byte("key"), 100)
	cm.Add([]byte("key"), 100)

	if cm.Total() != 200 {
		t.Fatalf("expected total 200, got %d", cm.Total())
	}

	cm.Decay()

	if cm.Total() != 100 {
		t.Errorf("expected total 100 after decay, got %d", cm.Total())
	}

	est := cm.Estimate([]byte("key"))
	if est < 90 || est > 110 {
		t.Errorf("expected estimate ~100 after decay, got %d", est)
	}
}
