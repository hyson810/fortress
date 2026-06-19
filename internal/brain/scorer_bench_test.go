package brain

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// BENCHMARK: Mutex Scorer vs Shard Scorer
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func benchMutexScorer(tb testing.TB, numIPs, numWorkers int) (float64, float64) {
	weights := DefaultWeights()
	scorer := NewScorer(weights, 1*time.Hour, 0)

	start := time.Now()
	var wg sync.WaitGroup
	chunkSize := numIPs / numWorkers

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < chunkSize; i++ {
				idx := offset*chunkSize + i
				ip := fmt.Sprintf("10.%d.%d.%d", (idx>>16)&0xFF, (idx>>8)&0xFF, idx&0xFF)
				scorer.GetOrCreate(ip)
				scorer.AddScanScore(ip, idx%100)
			}
		}(w)
	}
	wg.Wait()

	elapsed := time.Since(start)
	rate := float64(numIPs) / elapsed.Seconds()
	return float64(elapsed.Nanoseconds()) / 1e6, rate
}

func benchShardScorer(tb testing.TB, numIPs, numWorkers int) (float64, float64) {
	weights := DefaultWeights()
	scorer := NewShardScorer(weights, 1*time.Hour, 0)

	start := time.Now()
	var wg sync.WaitGroup
	chunkSize := numIPs / numWorkers

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < chunkSize; i++ {
				idx := offset*chunkSize + i
				ip := fmt.Sprintf("10.%d.%d.%d", (idx>>16)&0xFF, (idx>>8)&0xFF, idx&0xFF)
				scorer.GetOrCreate(ip)
				scorer.AddScanScore(ip, idx%100)
			}
		}(w)
	}
	wg.Wait()

	elapsed := time.Since(start)
	rate := float64(numIPs) / elapsed.Seconds()
	return float64(elapsed.Nanoseconds()) / 1e6, rate
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 1-Worker Baseline (sequential, no contention)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestBench_1Worker_100K(t *testing.T) {
	mt, mr := benchMutexScorer(t, 100_000, 1)
	st, sr := benchShardScorer(t, 100_000, 1)
	t.Logf("1-Worker 100K | Mutex: %.1fms (%.0f/s) | Shard: %.1fms (%.0f/s) | diff: %+.0f%%",
		mt, mr, st, sr, (sr-mr)/mr*100)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 4-Worker (moderate contention)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestBench_4Worker_100K(t *testing.T) {
	mt, mr := benchMutexScorer(t, 100_000, 4)
	st, sr := benchShardScorer(t, 100_000, 4)
	t.Logf("4-Worker 100K | Mutex: %.1fms (%.0f/s) | Shard: %.1fms (%.0f/s) | diff: %+.0f%%",
		mt, mr, st, sr, (sr-mr)/mr*100)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 8-Worker (high contention — real-world scenario)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestBench_8Worker_100K(t *testing.T) {
	mt, mr := benchMutexScorer(t, 100_000, 8)
	st, sr := benchShardScorer(t, 100_000, 8)
	t.Logf("8-Worker 100K | Mutex: %.1fms (%.0f/s) | Shard: %.1fms (%.0f/s) | diff: %+.0f%%",
		mt, mr, st, sr, (sr-mr)/mr*100)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 16-Worker (extreme contention — full thread count)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestBench_16Worker_100K(t *testing.T) {
	mt, mr := benchMutexScorer(t, 100_000, 16)
	st, sr := benchShardScorer(t, 100_000, 16)
	t.Logf("16-Worker 100K | Mutex: %.1fms (%.0f/s) | Shard: %.1fms (%.0f/s) | diff: %+.0f%%",
		mt, mr, st, sr, (sr-mr)/mr*100)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 500K Scale Test — mutex vs shard at massive scale
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestBench_Scale_500K_12Workers(t *testing.T) {
	runtime.GC()
	mt, mr := benchMutexScorer(t, 500_000, 12)
	runtime.GC()
	st, sr := benchShardScorer(t, 500_000, 12)
	improvement := (sr - mr) / mr * 100
	t.Logf("500K/12-Worker | Mutex: %.1fms (%.0f/s) | Shard: %.1fms (%.0f/s) | ⚡SPEEDUP: %+.0f%%",
		mt, mr, st, sr, improvement)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Mixed Workload — scan + anomaly + honeypot + intel simultaneously
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestBench_MixedWorkload_50K_8Workers(t *testing.T) {
	numIPs := 50_000
	numWorkers := 8
	chunkSize := numIPs / numWorkers

	// Mutex scorer
	weights := DefaultWeights()
	mutexScorer := NewScorer(weights, 1*time.Hour, 0)
	mStart := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(off int) {
			defer wg.Done()
			for i := 0; i < chunkSize; i++ {
				idx := off*chunkSize + i
				ip := fmt.Sprintf("10.%d.%d.%d", (idx>>16)&0xFF, (idx>>8)&0xFF, idx&0xFF)
				mutexScorer.GetOrCreate(ip)
				mutexScorer.AddScanScore(ip, idx%100)
				mutexScorer.AddAnomalyScore(ip, float64(idx%7))
				if idx%500 == 0 {
					mutexScorer.AddHoneypotTrip(ip)
				}
			}
		}(w)
	}
	wg.Wait()
	mElapsed := time.Since(mStart)
	mRate := float64(numIPs) / mElapsed.Seconds()

	// Shard scorer
	shardScorer := NewShardScorer(weights, 1*time.Hour, 0)
	sStart := time.Now()
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(off int) {
			defer wg.Done()
			for i := 0; i < chunkSize; i++ {
				idx := off*chunkSize + i
				ip := fmt.Sprintf("10.%d.%d.%d", (idx>>16)&0xFF, (idx>>8)&0xFF, idx&0xFF)
				shardScorer.GetOrCreate(ip)
				shardScorer.AddScanScore(ip, idx%100)
				shardScorer.AddAnomalyScore(ip, float64(idx%7))
				if idx%500 == 0 {
					shardScorer.AddHoneypotTrip(ip)
				}
			}
		}(w)
	}
	wg.Wait()
	sElapsed := time.Since(sStart)
	sRate := float64(numIPs) / sElapsed.Seconds()

	improvement := (sRate - mRate) / mRate * 100
	t.Logf("Mixed 50K/8W | Mutex: %.1fms (%.0f/s) | Shard: %.1fms (%.0f/s) | ⚡ %+.0f%%",
		float64(mElapsed.Nanoseconds())/1e6, mRate,
		float64(sElapsed.Nanoseconds())/1e6, sRate, improvement)
}
