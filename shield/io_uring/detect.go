// Package io_uring detects abuse of the io_uring subsystem for batch syscall
// execution bypassing eBPF telemetry hooks.
//
// Attack vector: io_uring uses shared memory rings (SQ/CQ) to submit syscalls
// without triggering tracepoint/syscalls/sys_enter_* which eBPF monitors rely on.
//
// Reference: Elastic Security 2026 — "io_uring: The New Syscall Gateway for Malware"

package io_uring

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// BurstThreshold is the max io_uring_enter calls per second before alerting
	BurstThreshold = 20
	// MonitorInterval is the default sampling interval
	MonitorInterval = 5 * time.Second
	// MaxTrackedProcs is the max number of processes to track
	MaxTrackedProcs = 1024
)

// IoUringStats tracks io_uring usage for a single process.
type IoUringStats struct {
	PID         int
	Comm        string
	EnterCount  uint64
	RegCount    uint64
	LastBurstAt time.Time
	BurstCount  int
	IsAlerted   bool
}

// IoUringMonitor detects anomalous io_uring activity across processes.
type IoUringMonitor struct {
	mu       sync.RWMutex
	stats    map[int]*IoUringStats
	stopCh   chan struct{}
	running  bool
	onAlert  func(stats *IoUringStats)
}

// IoUringAlert is emitted when suspicious io_uring activity is detected.
type IoUringAlert struct {
	PID       int
	Comm      string
	Rate      float64 // calls/sec
	Threshold float64
	Detail    string
	Timestamp time.Time
}

// NewMonitor creates a new io_uring monitor.
func NewMonitor(onAlert func(stats *IoUringStats)) *IoUringMonitor {
	if onAlert == nil {
		onAlert = func(s *IoUringStats) {}
	}
	return &IoUringMonitor{
		stats:  make(map[int]*IoUringStats),
		stopCh: make(chan struct{}),
		onAlert: onAlert,
	}
}

// Start begins monitoring io_uring syscall rates.
func (m *IoUringMonitor) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	go m.monitorLoop()
	return nil
}

// Stop terminates monitoring.
func (m *IoUringMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		close(m.stopCh)
		m.running = false
	}
}

func (m *IoUringMonitor) monitorLoop() {
	ticker := time.NewTicker(MonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.sampleAndAnalyze()
		}
	}
}

func (m *IoUringMonitor) sampleAndAnalyze() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Sample io_uring stats from /proc/*/io_uring
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if !isNumericOnly(pid) {
			continue
		}

		var pidNum int
		fmt.Sscanf(pid, "%d", &pidNum)

		// Check if process uses io_uring
		ioUringPath := fmt.Sprintf("/proc/%s/io_uring", pid)
		if _, err := os.Stat(ioUringPath); os.IsNotExist(err) {
			continue
		}

		stats, exists := m.stats[pidNum]
		if !exists {
			if len(m.stats) >= MaxTrackedProcs {
				continue
			}
			comm := readProcComm(pid)
			stats = &IoUringStats{PID: pidNum, Comm: comm}
			m.stats[pidNum] = stats
		}

		// Count io_uring operations (simplified: count fd entries)
		fdCount := countDirEntries(ioUringPath)
		prevTotal := stats.EnterCount
		stats.EnterCount = uint64(fdCount)

		// Detect burst
		rate := float64(stats.EnterCount-prevTotal) / MonitorInterval.Seconds()
		if rate > BurstThreshold {
			stats.BurstCount++
			stats.LastBurstAt = time.Now()
			if !stats.IsAlerted {
				stats.IsAlerted = true
				m.onAlert(stats)
			}
		}
	}

	// Evict stale entries
	for pid, stats := range m.stats {
		if time.Since(stats.LastBurstAt) > 10*MonitorInterval {
			delete(m.stats, pid)
		}
	}
}

// GetStats returns current statistics for all tracked processes.
func (m *IoUringMonitor) GetStats() []*IoUringStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*IoUringStats, 0, len(m.stats))
	for _, s := range m.stats {
		result = append(result, s)
	}
	return result
}

// Alerts returns processes currently in alert state.
func (m *IoUringMonitor) Alerts() []*IoUringAlert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var alerts []*IoUringAlert
	for _, s := range m.stats {
		if s.IsAlerted {
			alerts = append(alerts, &IoUringAlert{
				PID: s.PID, Comm: s.Comm,
				Rate: float64(s.EnterCount) / MonitorInterval.Seconds(),
				Threshold: BurstThreshold,
				Detail: fmt.Sprintf("burst count: %d", s.BurstCount),
				Timestamp: s.LastBurstAt,
			})
		}
	}
	return alerts
}

func readProcComm(pid string) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func countDirEntries(path string) int {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0
	}
	return len(entries)
}

func isNumericOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
