package entropy

import "math"

// Shannon computes the Shannon entropy of a frequency map.
// The keys are generic comparable types and values are counts.
func Shannon[T comparable](freq map[T]uint64) float64 {
	var total uint64
	for _, count := range freq {
		total += count
	}
	if total == 0 {
		return 0
	}

	totalF := float64(total)
	var entropy float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / totalF
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// Bytes computes the Shannon entropy of a byte slice directly.
func Bytes(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]uint64, 256)
	for _, b := range data {
		freq[b]++
	}
	return Shannon(freq)
}
