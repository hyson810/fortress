<<<<<<< HEAD
// Package ringbuf provides a fixed-capacity sliding window of timestamps
// used by the L1 packet inspector for per-IP rate limiting.
=======
>>>>>>> 1f89c68 (feat: project scaffolding, config types, shared engine types, ringbuf, entropy, welford, cmsketch)
package ringbuf

import "time"

const defaultCapacity = 1000

<<<<<<< HEAD
// RingBuffer is a fixed-capacity sliding window of timestamps.
// It provides O(1) amortized push and O(n) pruning where n is the
// number of expired entries removed during each PruneBefore call.
type RingBuffer struct {
	buf []time.Time
	cap int
}

// New creates a ring buffer with the given maximum capacity.
// If cap is 0 or negative, defaultCapacity (1000) is used.
func New(cap int) *RingBuffer {
	if cap <= 0 {
		cap = defaultCapacity
	}
	return &RingBuffer{
		buf: make([]time.Time, 0, cap),
		cap: cap,
	}
}

// Push adds a timestamp to the buffer. If the buffer is full the oldest
// entry is dropped before appending.
func (rb *RingBuffer) Push(t time.Time) {
	if len(rb.buf) >= rb.cap {
		rb.buf = rb.buf[1:]
	}
	rb.buf = append(rb.buf, t)
}

// PruneBefore drops all entries older than the cutoff time.
func (rb *RingBuffer) PruneBefore(cutoff time.Time) {
	i := 0
	for i < len(rb.buf) && rb.buf[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		rb.buf = rb.buf[i:]
	}
}

// Len returns the number of timestamps currently in the buffer.
func (rb *RingBuffer) Len() int {
	return len(rb.buf)
}

// Entries returns a copy of all timestamps currently in the buffer.
func (rb *RingBuffer) Entries() []time.Time {
	out := make([]time.Time, len(rb.buf))
	copy(out, rb.buf)
=======
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
>>>>>>> 1f89c68 (feat: project scaffolding, config types, shared engine types, ringbuf, entropy, welford, cmsketch)
	return out
}
