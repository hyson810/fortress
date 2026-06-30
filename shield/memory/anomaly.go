// Package memory provides memory allocation anomaly detection.
//
// Detects: RWX memory regions (shellcode injection), hidden pages (pages
// present in pagemap but absent from /proc/*/maps), and anomalous memory
// allocation patterns that indicate process injection or rootkit activity.
//
// Reference: gspy (BlackArch 2026) — eBPF uprobe Go goroutine → syscall mapping

package memory

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

const (
	DefaultScanInterval     = 30 * time.Second
	RWXAlertThreshold       = 3      // alert when >3 RWX regions found
	HiddenPageAlertThreshold = 5     // alert when >5 hidden pages
	MaxScannedProcs         = 512
)

// MemoryAnomalyStats holds current anomaly detection statistics.
type MemoryAnomalyStats struct {
	mu             sync.RWMutex
	TotalRWXPages  int
	TotalHiddenPages int
	AlertedProcs   map[int]string // PID → reason
	ScanCount      uint64
	LastScanAt     time.Time
}

// StartMemoryAnomalyDetector begins periodic memory anomaly scanning.
// Uses /proc/*/maps and /proc/*/pagemap for cross-referencing.
func StartMemoryAnomalyDetector(interval time.Duration) (*MemoryAnomalyStats, func()) {
	if interval <= 0 {
		interval = DefaultScanInterval
	}
	stats := &MemoryAnomalyStats{AlertedProcs: make(map[int]string)}
	stopCh := make(chan struct{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[memory/anomaly] scan panic: %v\nstack: %s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				scanMemoryAnomalies(stats)
			}
		}
	}()

	return stats, func() { close(stopCh) }
}

func scanMemoryAnomalies(stats *MemoryAnomalyStats) {
	stats.mu.Lock()
	stats.ScanCount++
	stats.LastScanAt = time.Now()
	stats.mu.Unlock()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	totalRWX := 0
	totalHidden := 0
	scanned := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !isPID(entry.Name()) {
			continue
		}
		if scanned >= MaxScannedProcs {
			break
		}
		scanned++

		var pid int
		fmt.Sscanf(entry.Name(), "%d", &pid)

		// Check /proc/PID/maps for RWX regions
		rwxCount := countRWXRegions(entry.Name())
		if rwxCount > RWXAlertThreshold {
			stats.mu.Lock()
			stats.AlertedProcs[pid] = fmt.Sprintf("RWX regions: %d", rwxCount)
			stats.mu.Unlock()
		}
		totalRWX += rwxCount

		// Check for hidden pages (present in pagemap but not in maps)
		hiddenCount := countHiddenPages(entry.Name())
		if hiddenCount > HiddenPageAlertThreshold {
			stats.mu.Lock()
			stats.AlertedProcs[pid] = fmt.Sprintf("hidden pages: %d", hiddenCount)
			stats.mu.Unlock()
		}
		totalHidden += hiddenCount
	}

	stats.mu.Lock()
	stats.TotalRWXPages = totalRWX
	stats.TotalHiddenPages = totalHidden
	stats.mu.Unlock()
}

// countRWXRegions counts the number of RWX (read-write-execute) memory regions
// for a given process. RWX regions are a strong indicator of shellcode injection.
func countRWXRegions(pid string) int {
	mapsPath := fmt.Sprintf("/proc/%s/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0
	}

	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) < 20 {
			continue
		}
		// Format: start-end perms offset dev inode pathname
		// perms: rwxp (rwx = private, rwxs = shared)
		if strings.Contains(line, "rwxp") {
			// Check if this is an anonymous region (no file backing)
			parts := strings.Fields(line)
			if len(parts) >= 6 && parts[5] == "0" && (len(parts) < 7 || parts[6] == "") {
				count++
			}
		}
	}
	return count
}

// countHiddenPages detects pages that are present in the process's pagemap
// (physically allocated) but absent from /proc/PID/maps (hidden from userspace).
// This is the key indicator of DKOM (Direct Kernel Object Manipulation) hiding.
func countHiddenPages(pid string) int {
	// Read maps to get the set of visible virtual addresses
	mapsPath := fmt.Sprintf("/proc/%s/maps", pid)
	mapsData, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0
	}

	visiblePages := make(map[uint64]bool)
	for _, line := range strings.Split(string(mapsData), "\n") {
		if len(line) < 20 {
			continue
		}
		var start, end uint64
		if n, _ := fmt.Sscanf(line, "%x-%x", &start, &end); n == 2 {
			for addr := start; addr < end; addr += 4096 {
				visiblePages[addr] = true
			}
		}
	}

	// Read pagemap to check which pages are actually present
	pagemapPath := fmt.Sprintf("/proc/%s/pagemap", pid)
	pagemapData, err := os.ReadFile(pagemapPath)
	if err != nil {
		return 0
	}

	hiddenCount := 0
	// pagemap is 8 bytes per virtual page (4096 bytes)
	// Each entry: bits 0-54 = PFN, bit 63 = page present
	for addr := range visiblePages {
		if addr >= uint64(len(visiblePages))*4096 {
			continue
		}
		offset := (addr / 4096) * 8
		if offset+8 > uint64(len(pagemapData)) {
			continue
		}
		entry := uint64(0)
		for i := 0; i < 8; i++ {
			entry |= uint64(pagemapData[offset+uint64(i)]) << (i * 8)
		}
		// Page is present (bit 63 set) but not in maps → hidden
		if entry&(1<<63) != 0 && !visiblePages[addr] {
			hiddenCount++
		}
	}

	// Also check: are there present pages in pagemap that are NOT in maps?
	// This catches pages hidden via DKOM.
	pagemapEntryCount := len(pagemapData) / 8
	for i := 0; i < pagemapEntryCount && i < 100000; i++ {
		offset := i * 8
		entry := uint64(0)
		for j := 0; j < 8; j++ {
			entry |= uint64(pagemapData[offset+j]) << (j * 8)
		}
		if entry&(1<<63) != 0 {
			addr := uint64(i) * 4096
			if !visiblePages[addr] {
				hiddenCount++
			}
		}
	}

	return hiddenCount
}

// GetStats returns the current anomaly statistics.
func (s *MemoryAnomalyStats) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"total_rwx_pages":   s.TotalRWXPages,
		"total_hidden_pages": s.TotalHiddenPages,
		"alerted_procs":     s.AlertedProcs,
		"scan_count":        s.ScanCount,
		"last_scan":         s.LastScanAt.Format(time.RFC3339),
	}
}

// Alerts returns the current list of alerted processes.
func (s *MemoryAnomalyStats) Alerts() map[int]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[int]string, len(s.AlertedProcs))
	for k, v := range s.AlertedProcs {
		result[k] = v
	}
	return result
}

func isPID(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
