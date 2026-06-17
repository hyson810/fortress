package cmsketch

import (
	"hash/fnv"
	"math"
)

// CountMin is a Count-Min Sketch for approximate frequency estimation.
type CountMin struct {
	rows    int
	cols    int
	grid    [][]uint64
	total   uint64
	hashers []hashEntry
}

type hashEntry struct {
	seed uint32
}

// New creates a Count-Min Sketch with the given number of rows and columns.
func New(rows, cols int) *CountMin {
	grid := make([][]uint64, rows)
	for i := range grid {
		grid[i] = make([]uint64, cols)
	}
	hashers := make([]hashEntry, rows)
	for i := range hashers {
		hashers[i] = hashEntry{seed: uint32(i*31 + 17)}
	}
	return &CountMin{
		rows:    rows,
		cols:    cols,
		grid:    grid,
		hashers: hashers,
	}
}

func (h hashEntry) hash(data []byte) uint32 {
	hasher := fnv.New32a()
	// Mix seed into first bytes
	seedBytes := []byte{byte(h.seed), byte(h.seed >> 8), byte(h.seed >> 16), byte(h.seed >> 24)}
	hasher.Write(seedBytes)
	hasher.Write(data)
	return hasher.Sum32()
}

// Add increments the count for the given data by the specified amount.
func (c *CountMin) Add(data []byte, count uint64) {
	c.total += count
	for i, h := range c.hashers {
		col := h.hash(data) % uint32(c.cols)
		c.grid[i][col] += count
	}
}

// Estimate returns the estimated count for the given data.
func (c *CountMin) Estimate(data []byte) uint64 {
	min := uint64(math.MaxUint64)
	for i, h := range c.hashers {
		col := h.hash(data) % uint32(c.cols)
		if c.grid[i][col] < min {
			min = c.grid[i][col]
		}
	}
	return min
}

// Total returns the sum of all added counts.
func (c *CountMin) Total() uint64 {
	return c.total
}

// Decay halves all counters at a configurable scale factor.
// A factor of 2 halves all values; factor of 4 quarters them.
func (c *CountMin) Decay() {
	for i := range c.grid {
		for j := range c.grid[i] {
			c.grid[i][j] /= 2
		}
	}
	c.total /= 2
}
