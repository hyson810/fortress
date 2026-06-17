package ringbuf

import "time"

const defaultCapacity = 1000

// RingBuf is a fixed-capacity circular buffer of timestamps.
type RingBuf struct {
	buf      []time.Time
	head     int
	size     int
	capacity int
}

// New creates a RingBuf with the given capacity. A zero or negative capacity
// defaults to 1000.
func New(capacity int) *RingBuf {
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	return &RingBuf{
		buf:      make([]time.Time, capacity),
		capacity: capacity,
	}
}

// Push adds a timestamp to the buffer. If the buffer is full, the oldest
// entry is silently overwritten.
func (r *RingBuf) Push(t time.Time) {
	idx := (r.head + r.size) % r.capacity
	r.buf[idx] = t
	if r.size < r.capacity {
		r.size++
	} else {
		r.head = (r.head + 1) % r.capacity
	}
}

// PruneBefore removes all entries whose timestamp is before the given cutoff.
func (r *RingBuf) PruneBefore(cutoff time.Time) {
	// Find the first index that is >= cutoff by scanning from head.
	// This is a linear scan — fine for the expected sizes.
	dst := 0
	for i := 0; i < r.size; i++ {
		idx := (r.head + i) % r.capacity
		if !r.buf[idx].Before(cutoff) {
			// Keep this entry; compact in-place.
			destIdx := (r.head + dst) % r.capacity
			r.buf[destIdx] = r.buf[idx]
			dst++
		}
	}
	r.size = dst
}

// Len returns the number of entries currently in the buffer.
func (r *RingBuf) Len() int {
	return r.size
}

// Entries returns a copy of the timestamps in insertion order.
func (r *RingBuf) Entries() []time.Time {
	out := make([]time.Time, r.size)
	for i := 0; i < r.size; i++ {
		out[i] = r.buf[(r.head+i)%r.capacity]
	}
	return out
}
