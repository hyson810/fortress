// Package ringbuf provides a fixed-capacity sliding window of timestamps
// used by the L1 packet inspector for per-IP rate limiting.
package ringbuf

import "time"

const defaultCapacity = 1000

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
	return out
}
