package ringbuf

import (
	"testing"
	"time"
)

func TestPushCap(t *testing.T) {
	cap := 5
	rb := New(cap)
	base := time.Now()

	for i := 0; i < cap+3; i++ {
		rb.Push(base.Add(time.Duration(i) * time.Second))
	}

	if rb.Len() != cap {
		t.Fatalf("expected len %d, got %d", cap, rb.Len())
	}

	entries := rb.Entries()
	// The first 3 entries should have been overwritten; the buf should contain
	// indices 3..7 of the (cap+3) values we pushed.
	for i := 0; i < cap; i++ {
		expected := base.Add(time.Duration(i+3) * time.Second)
		if !entries[i].Equal(expected) {
			t.Errorf("entries[%d]: expected %v, got %v", i, expected, entries[i])
		}
	}
}

func TestPruneBefore(t *testing.T) {
	rb := New(10)
	base := time.Now()

	for i := 0; i < 8; i++ {
		rb.Push(base.Add(time.Duration(i) * time.Second))
	}

	// Prune everything before t=4s (indices 0,1,2,3 should be removed).
	cutoff := base.Add(4 * time.Second)
	rb.PruneBefore(cutoff)

	if rb.Len() != 4 {
		t.Fatalf("expected len 4 after prune, got %d", rb.Len())
	}

	entries := rb.Entries()
	for i := 0; i < 4; i++ {
		expected := base.Add(time.Duration(i+4) * time.Second)
		if !entries[i].Equal(expected) {
			t.Errorf("entries[%d]: expected %v, got %v", i, expected, entries[i])
		}
	}
}

func TestPruneBeforeAll(t *testing.T) {
	rb := New(10)
	base := time.Now()

	for i := 0; i < 5; i++ {
		rb.Push(base.Add(time.Duration(i) * time.Second))
	}

	cutoff := base.Add(10 * time.Second)
	rb.PruneBefore(cutoff)

	if rb.Len() != 0 {
		t.Fatalf("expected len 0 after prune-all, got %d", rb.Len())
	}
}

func TestDefaultCapacity(t *testing.T) {
	rb := New(0)
	if rb.Len() != 0 {
		t.Errorf("expected empty buf")
	}
	// Should be able to push defaultCapacity items without issue.
	for i := 0; i < 1000; i++ {
		rb.Push(time.Now())
	}
	if rb.Len() != 1000 {
		t.Errorf("expected 1000 entries, got %d", rb.Len())
	}
}
