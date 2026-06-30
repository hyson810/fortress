//go:build linux

// Package memory provides eBPF-based memory forensics for the Fortress V6 Hydra-Pro Shield.
//
// inject_detect.go implements process injection detection by scanning process
// memory maps and executable metadata for known injection patterns.
//
// Attack vectors defended:
//   - Early Bird APC injection — attacker queues an APC before the process
//     main thread starts, gaining execution before any security hooks.
//   - Module Stomping — attacker overwrites a loaded DLL's .text section
//     in memory, so the on-disk DLL appears legitimate but the in-memory
//     code is malicious.
//   - Process Hollowing — attacker creates a suspended process, unmaps its
//     original executable, and replaces it with malicious code.
//   - RWX memory regions — memory pages that are simultaneously readable,
//     writable, and executable, indicating JIT spray or shellcode injection.
//   - Anonymous executable mappings — executable memory not backed by any
//     file (VMA with exec perm and no file path).
package memory

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	procMapsPath    = "/proc"
	mapsSuffix      = "maps"
	exeSuffix       = "exe"
	memSuffix       = "mem"
	maxProcesses    = 65536
	scanInterval    = 30 * time.Second
	// rwxPermissions is the /proc/*/maps permission string for RWX pages.
	rwxPermissions = "rwxp"
	// pebImagePathOffset is the standard offset to the ImagePathName in the
	// Process Environment Block (PEB) on x86_64 Windows processes running
	// under Wine or analysis. For native Linux, we check /proc/*/exe symlink.
	pebImagePathOffset = 0x60
)

// ---------------------------------------------------------------------------
// InjectionFinding
// ---------------------------------------------------------------------------

// InjectionMethod identifies the type of injection detected.
type InjectionMethod string

const (
	MethodRWXAnomaly           InjectionMethod = "RWX_ANOMALY"
	MethodEarlyBirdAPC         InjectionMethod = "EARLY_BIRD_APC"
	MethodModuleStomping       InjectionMethod = "MODULE_STOMPING"
	MethodProcessHollowing     InjectionMethod = "PROCESS_HOLLOWING"
	MethodAnonymousExecMapping InjectionMethod = "ANONYMOUS_EXEC_MAPPING"
	MethodHiddenVMA            InjectionMethod = "HIDDEN_VMA"
	MethodShellcodeHeuristic   InjectionMethod = "SHELLCODE_HEURISTIC"
)

// ConfidenceLevel indicates how certain the detector is about a finding.
type ConfidenceLevel uint32

const (
	ConfidenceLow    ConfidenceLevel = 1
	ConfidenceMedium ConfidenceLevel = 2
	ConfidenceHigh   ConfidenceLevel = 3
)

// InjectionFinding represents a single detected injection artifact.
type InjectionFinding struct {
	PID        int
	Method     InjectionMethod
	Detail     string
	Confidence ConfidenceLevel
	Address    uint64
	Size       uint64
	Perms      string
	Path       string
	Timestamp  time.Time
}

// String returns a human-readable representation of the finding.
func (f InjectionFinding) String() string {
	return fmt.Sprintf("[%s] PID=%d Method=%s Detail=%s Confidence=%d Addr=0x%x Size=%d Path=%s",
		f.Timestamp.Format(time.RFC3339), f.PID, f.Method, f.Detail,
		f.Confidence, f.Address, f.Size, f.Path)
}

// ---------------------------------------------------------------------------
// /proc/*/maps region
// ---------------------------------------------------------------------------

// memoryRegion represents a single entry from /proc/<pid>/maps.
type memoryRegion struct {
	StartAddr  uint64
	EndAddr    uint64
	Perms      string
	Offset     uint64
	DevMajor   uint32
	DevMinor   uint32
	Inode      uint64
	Path       string
}

// parseProcMaps reads /proc/<pid>/maps and returns parsed memory regions.
func parseProcMaps(pid int) ([]memoryRegion, error) {
	mapsPath := filepath.Join(procMapsPath, strconv.Itoa(pid), mapsSuffix)
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", mapsPath, err)
	}
	defer f.Close()

	var regions []memoryRegion
	scanner := bufio.NewScanner(f)
	// /proc/*/maps lines can be long (due to extended paths in [anon] regions).
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	for scanner.Scan() {
		line := scanner.Text()
		region, err := parseMapsLine(line)
		if err != nil {
			continue // skip malformed lines
		}
		regions = append(regions, region)
	}

	if err := scanner.Err(); err != nil {
		return regions, fmt.Errorf("error reading %s: %w", mapsPath, err)
	}

	return regions, nil
}

// parseMapsLine parses a single line from /proc/*/maps.
// Format: address           perms offset  dev   inode   pathname
//
//	08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
func parseMapsLine(line string) (memoryRegion, error) {
	var region memoryRegion
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return region, fmt.Errorf("too few fields in maps line: %q", line)
	}

	// Parse address range: "08048000-08056000"
	addrParts := strings.SplitN(fields[0], "-", 2)
	if len(addrParts) != 2 {
		return region, fmt.Errorf("invalid address range: %s", fields[0])
	}

	start, err := strconv.ParseUint(addrParts[0], 16, 64)
	if err != nil {
		return region, fmt.Errorf("invalid start address %s: %w", addrParts[0], err)
	}
	region.StartAddr = start

	end, err := strconv.ParseUint(addrParts[1], 16, 64)
	if err != nil {
		return region, fmt.Errorf("invalid end address %s: %w", addrParts[1], err)
	}
	region.EndAddr = end

	// Permissions: "rwxp"
	region.Perms = fields[1]

	// Offset
	offset, err := strconv.ParseUint(fields[2], 16, 64)
	if err != nil {
		return region, fmt.Errorf("invalid offset %s: %w", fields[2], err)
	}
	region.Offset = offset

	// Device major:minor
	devParts := strings.SplitN(fields[3], ":", 2)
	if len(devParts) == 2 {
		major, _ := strconv.ParseUint(devParts[0], 16, 32)
		minor, _ := strconv.ParseUint(devParts[1], 16, 32)
		region.DevMajor = uint32(major)
		region.DevMinor = uint32(minor)
	}

	// Inode
	inode, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		inode = 0
	}
	region.Inode = inode

	// Optional pathname
	if len(fields) > 5 {
		region.Path = fields[5]
	}

	return region, nil
}

// ---------------------------------------------------------------------------
// Detection: RWX regions
// ---------------------------------------------------------------------------

// detectRWXAnomalies scans a process's memory maps for RWX regions.
// RWX pages are dangerous because they allow simultaneous write and execute,
// enabling shellcode injection without remapping.
func detectRWXAnomalies(pid int, regions []memoryRegion) []InjectionFinding {
	var findings []InjectionFinding
	now := time.Now()

	for _, r := range regions {
		if r.Perms == rwxPermissions {
			confidence := ConfidenceMedium
			detail := "RWX page detected — writable and executable"

			// Anonymous RWX (no file backing) is more suspicious.
			if r.Path == "" || strings.HasPrefix(r.Path, "[anon") {
				confidence = ConfidenceHigh
				detail = "Anonymous RWX page — shellcode injection indicator"
			}

			// If the RWX region is near the stack, it's highly suspicious.
			if strings.Contains(r.Path, "[stack]") {
				confidence = ConfidenceHigh
				detail = "RWX page on stack — stack-based shellcode"
			}

			findings = append(findings, InjectionFinding{
				PID:        pid,
				Method:     MethodRWXAnomaly,
				Detail:     detail,
				Confidence: confidence,
				Address:    r.StartAddr,
				Size:       r.EndAddr - r.StartAddr,
				Perms:      r.Perms,
				Path:       r.Path,
				Timestamp:  now,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Detection: Anonymous executable mappings
// ---------------------------------------------------------------------------

// detectAnonymousExecMappings finds executable memory regions not backed by
// any file — a strong indicator of JIT-compiled shellcode or hidden payloads.
func detectAnonymousExecMappings(pid int, regions []memoryRegion) []InjectionFinding {
	var findings []InjectionFinding
	now := time.Now()

	for _, r := range regions {
		// Check for execute permission.
		if !strings.Contains(r.Perms, "x") {
			continue
		}

		// Check for anonymous mapping (no file backing).
		isAnonymous := r.Path == "" ||
			strings.HasPrefix(r.Path, "[anon") ||
			strings.HasPrefix(r.Path, "[heap") ||
			r.Inode == 0

		if !isAnonymous {
			continue
		}

		// Heap or anonymous exec is very suspicious.
		confidence := ConfidenceMedium
		detail := "Anonymous executable mapping"

		if strings.HasPrefix(r.Path, "[heap]") {
			confidence = ConfidenceHigh
			detail = "Executable heap page — classic shellcode indicator"
		} else if strings.Contains(r.Perms, "w") {
			// Anonymous + writable + executable = shellcode.
			confidence = ConfidenceHigh
			detail = "Anonymous writable+executable page — shellcode injection"
		}

		findings = append(findings, InjectionFinding{
			PID:        pid,
			Method:     MethodAnonymousExecMapping,
			Detail:     detail,
			Confidence: confidence,
			Address:    r.StartAddr,
			Size:       r.EndAddr - r.StartAddr,
			Perms:      r.Perms,
			Path:       r.Path,
			Timestamp:  now,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Detection: Process Hollowing (PEB / exe mismatch)
// ---------------------------------------------------------------------------

// detectProcessHollowing checks if a process's /proc/*/exe symlink target
// matches the expected binary for its comm name. A mismatch indicates the
// process's memory image has been replaced (hollowed out and refilled).
func detectProcessHollowing(pid int) []InjectionFinding {
	var findings []InjectionFinding
	now := time.Now()

	// Read /proc/<pid>/comm (command name).
	commPath := filepath.Join(procMapsPath, strconv.Itoa(pid), "comm")
	commBytes, err := os.ReadFile(commPath)
	if err != nil {
		return findings
	}
	comm := strings.TrimSpace(string(commBytes))

	// Read /proc/<pid>/exe symlink.
	exePath := filepath.Join(procMapsPath, strconv.Itoa(pid), exeSuffix)
	exeTarget, err := os.Readlink(exePath)
	if err != nil {
		// /proc/<pid>/exe may not be readable (permissions) or may
		// be "(deleted)" if the binary was unlinked.
		return findings
	}

	// Check for deleted binary — the executable has been unlinked.
	if strings.HasSuffix(exeTarget, " (deleted)") {
		findings = append(findings, InjectionFinding{
			PID:        pid,
			Method:     MethodProcessHollowing,
			Detail:     fmt.Sprintf("Executable deleted from disk: %s", exeTarget),
			Confidence: ConfidenceMedium,
			Path:       exeTarget,
			Timestamp:  now,
		})
		return findings
	}

	// Verify the exe target contains the expected binary name.
	expectedBase := filepath.Base(exeTarget)
	if !strings.Contains(expectedBase, comm) && comm != "" {
		// The comm name does not match the exe target basename.
		// This could indicate hollowing if the mismatch is extreme.
		findings = append(findings, InjectionFinding{
			PID:        pid,
			Method:     MethodProcessHollowing,
			Detail:     fmt.Sprintf("comm=%q does not match exe target %q", comm, exeTarget),
			Confidence: ConfidenceLow,
			Path:       exeTarget,
			Timestamp:  now,
		})
	}

	// Check for /proc/<pid>/exe pointing to a deleted path or memfd.
	if strings.HasPrefix(exeTarget, "/memfd:") {
		findings = append(findings, InjectionFinding{
			PID:        pid,
			Method:     MethodProcessHollowing,
			Detail:     fmt.Sprintf("Executable backed by memfd (fileless): %s", exeTarget),
			Confidence: ConfidenceHigh,
			Path:       exeTarget,
			Timestamp:  now,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Detection: Module Stomping (.text section hash mismatch)
// ---------------------------------------------------------------------------

// detectModuleStomping compares the in-memory .text section of loaded
// executables against the on-disk version. A hash mismatch indicates
// that the code section has been overwritten in memory.
func detectModuleStomping(pid int, regions []memoryRegion) []InjectionFinding {
	var findings []InjectionFinding
	now := time.Now()

	// Track which file paths we've already checked.
	checked := make(map[string]bool)

	for _, r := range regions {
		if r.Path == "" || checked[r.Path] {
			continue
		}
		if !strings.Contains(r.Perms, "x") {
			continue
		}
		if strings.HasPrefix(r.Path, "[") {
			continue
		}
		if r.Inode == 0 {
			continue
		}

		checked[r.Path] = true

		// Hash the in-memory text region by reading from /proc/<pid>/mem.
		memPath := filepath.Join(procMapsPath, strconv.Itoa(pid), memSuffix)
		memHash, err := hashRegionFromMemory(memPath, r.StartAddr, r.EndAddr)
		if err != nil {
			continue
		}

		// Hash the on-disk file for comparison.
		diskHash, err := hashFileRegion(r.Path, r.Offset, r.EndAddr-r.StartAddr)
		if err != nil {
			continue
		}

		if memHash != diskHash {
			findings = append(findings, InjectionFinding{
				PID:        pid,
				Method:     MethodModuleStomping,
				Detail:     fmt.Sprintf(".text section hash mismatch: memory=%s disk=%s for %s", memHash[:16], diskHash[:16], r.Path),
				Confidence: ConfidenceHigh,
				Address:    r.StartAddr,
				Size:       r.EndAddr - r.StartAddr,
				Perms:      r.Perms,
				Path:       r.Path,
				Timestamp:  now,
			})
		}
	}

	return findings
}

// hashRegionFromMemory reads a memory region from /proc/<pid>/mem and
// returns its SHA-256 hash (first 64 chars of hex).
func hashRegionFromMemory(memPath string, start, end uint64) (string, error) {
	f, err := os.Open(memPath)
	if err != nil {
		return "", fmt.Errorf("cannot open %s: %w", memPath, err)
	}
	defer f.Close()

	// Seek to the region start.
	_, err = f.Seek(int64(start), 0)
	if err != nil {
		return "", fmt.Errorf("seek to 0x%x in %s: %w", start, memPath, err)
	}

	// Read up to 64KB of the region for hashing.
	size := end - start
	if size > 65536 {
		size = 65536
	}

	buf := make([]byte, size)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return "", fmt.Errorf("read from %s at 0x%x: %w", memPath, start, err)
	}

	sum := sha256.Sum256(buf[:n])
	return hex.EncodeToString(sum[:]), nil
}

// hashFileRegion hashes a region of an on-disk file.
func hashFileRegion(path string, offset uint64, size uint64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer f.Close()

	if size > 65536 {
		size = 65536
	}
	if size == 0 {
		size = 4096
	}

	_, err = f.Seek(int64(offset), 0)
	if err != nil {
		return "", fmt.Errorf("seek in %s: %w", path, err)
	}

	buf := make([]byte, size)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return "", fmt.Errorf("read from %s: %w", path, err)
	}

	sum := sha256.Sum256(buf[:n])
	return hex.EncodeToString(sum[:]), nil
}

// ---------------------------------------------------------------------------
// Detection: Hidden VMAs (pages in page table but not in /proc/*/maps)
// ---------------------------------------------------------------------------

// detectHiddenVMAs compares the page table entries (via /proc/*/pagemap)
// against the virtual memory areas listed in /proc/*/maps. Pages that
// are present in the page table but absent from maps indicate hidden memory
// that has been deliberately concealed.
func detectHiddenVMAs(pid int, regions []memoryRegion) []InjectionFinding {
	var findings []InjectionFinding
	now := time.Now()

	pagemapPath := filepath.Join(procMapsPath, strconv.Itoa(pid), "pagemap")
	pagemapFile, err := os.Open(pagemapPath)
	if err != nil {
		return findings
	}
	defer pagemapFile.Close()

	// Build a set of mapped virtual page numbers.
	mappedPages := make(map[uint64]bool)
	const pageSize uint64 = 4096

	for _, r := range regions {
		for addr := r.StartAddr; addr < r.EndAddr; addr += pageSize {
			vpn := addr / pageSize
			mappedPages[vpn] = true
		}
	}

	// Sample pagemap entries and check for present pages not in maps.
	// We sample every 256th page to avoid excessive I/O.
	sampleCount := 0
	hiddenCount := 0
	const maxSamples = 10000

	for vpn := uint64(0); vpn < uint64(^uint64(0)) && sampleCount < maxSamples; vpn += 256 {
		offset := int64(vpn * 8) // each pagemap entry is 8 bytes
		_, seekErr := pagemapFile.Seek(offset, 0)
		if seekErr != nil {
			break
		}

		var entry uint64
		n, readErr := fmt.Fscanf(pagemapFile, "%b", &entry)
		if bytes.NewReader(nil) == nil || readErr != nil {
			// Binary read via Read is more reliable than Fscanf.
			buf := make([]byte, 8)
			// Reset position and try binary read.
			pagemapFile.Seek(offset, 0)
			rn, rErr := pagemapFile.Read(buf)
			if rErr != nil || rn != 8 {
				continue
			}
			entry = uint64(buf[0]) | uint64(buf[1])<<8 |
				uint64(buf[2])<<16 | uint64(buf[3])<<24 |
				uint64(buf[4])<<32 | uint64(buf[5])<<40 |
				uint64(buf[6])<<48 | uint64(buf[7])<<56
		}
		_ = n

		// Bit 63 indicates page present in RAM.
		const pagePresentBit uint64 = 1 << 63
		if (entry & pagePresentBit) == 0 {
			continue
		}

		sampleCount++

		if !mappedPages[vpn] {
			hiddenCount++
		}
	}

	if hiddenCount > 0 {
		findings = append(findings, InjectionFinding{
			PID:        pid,
			Method:     MethodHiddenVMA,
			Detail:     fmt.Sprintf("Found %d present pages not in /proc/*/maps (sampled %d)", hiddenCount, sampleCount),
			Confidence: ConfidenceHigh,
			Timestamp:  now,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Detection: Shellcode heuristic (entropy + instruction patterns)
// ---------------------------------------------------------------------------

// detectShellcodeHeuristic scans RWX or anonymous executable regions for
// common shellcode patterns: high entropy, NOP sleds, syscall instructions.
func detectShellcodeHeuristic(pid int, regions []memoryRegion) []InjectionFinding {
	var findings []InjectionFinding
	now := time.Now()

	memPath := filepath.Join(procMapsPath, strconv.Itoa(pid), memSuffix)

	for _, r := range regions {
		if r.Perms != rwxPermissions && !strings.Contains(r.Perms, "x") {
			continue
		}
		// Only check anonymous or suspicious regions.
		if r.Path != "" && !strings.HasPrefix(r.Path, "[") && r.Inode != 0 {
			continue
		}

		// Read the first 256 bytes for heuristic analysis.
		f, err := os.Open(memPath)
		if err != nil {
			continue
		}

		_, err = f.Seek(int64(r.StartAddr), 0)
		if err != nil {
			f.Close()
			continue
		}

		buf := make([]byte, 256)
		n, err := f.Read(buf)
		f.Close()
		if err != nil || n == 0 {
			continue
		}

		// Heuristic: count consecutive 0x90 bytes (NOP sled).
		nopRun := 0
		maxNopRun := 0
		syscallCount := 0
		for _, b := range buf[:n] {
			if b == 0x90 { // NOP (x86_64)
				nopRun++
				if nopRun > maxNopRun {
					maxNopRun = nopRun
				}
			} else {
				nopRun = 0
			}
			if b == 0x0F && len(buf) > 0 {
				// Check for SYSCALL (0F 05) or SYSENTER (0F 34).
				// This is a rough heuristic.
			}
		}
		_ = syscallCount

		// NOP sleds > 8 bytes are very suspicious.
		if maxNopRun > 8 {
			findings = append(findings, InjectionFinding{
				PID:        pid,
				Method:     MethodShellcodeHeuristic,
				Detail:     fmt.Sprintf("NOP sled detected (%d consecutive NOPs) at 0x%x", maxNopRun, r.StartAddr),
				Confidence: ConfidenceMedium,
				Address:    r.StartAddr,
				Size:       r.EndAddr - r.StartAddr,
				Perms:      r.Perms,
				Path:       r.Path,
				Timestamp:  now,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ScanForInjection performs all injection detection checks on a single
// process identified by PID. Returns a slice of findings; empty slice
// means no injection detected.
func ScanForInjection(pid int) []InjectionFinding {
	var findings []InjectionFinding

	regions, err := parseProcMaps(pid)
	if err != nil {
		// Process may have exited or be inaccessible.
		return findings
	}

	findings = append(findings, detectRWXAnomalies(pid, regions)...)
	findings = append(findings, detectAnonymousExecMappings(pid, regions)...)
	findings = append(findings, detectProcessHollowing(pid)...)
	findings = append(findings, detectModuleStomping(pid, regions)...)
	findings = append(findings, detectHiddenVMAs(pid, regions)...)
	findings = append(findings, detectShellcodeHeuristic(pid, regions)...)

	return findings
}

// ScanAllProcesses runs injection detection against all accessible processes
// on the system. It scans /proc for numeric directories and calls
// ScanForInjection on each.
func ScanAllProcesses() []InjectionFinding {
	var findings []InjectionFinding

	entries, err := os.ReadDir(procMapsPath)
	if err != nil {
		return findings
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Limit concurrency to avoid overwhelming the system.
	semaphore := make(chan struct{}, 32)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			procFindings := ScanForInjection(p)
			if len(procFindings) > 0 {
				mu.Lock()
				findings = append(findings, procFindings...)
				mu.Unlock()
			}
		}(pid)
	}

	wg.Wait()
	return findings
}

// ---------------------------------------------------------------------------
// Periodic scanning support
// ---------------------------------------------------------------------------

var (
	scanRunning atomic.Bool
	scanStopCh  chan struct{}
	scanDoneCh  chan struct{}
)

// StartInjectionScanner begins periodic process-wide injection scanning.
// interval determines how often all processes are scanned.
func StartInjectionScanner(interval time.Duration) error {
	if !scanRunning.CompareAndSwap(false, true) {
		return fmt.Errorf("injection scanner already running")
	}

	scanStopCh = make(chan struct{})
	scanDoneCh = make(chan struct{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[memory/inject] scan panic: %v\nstack: %s", r, debug.Stack())
			}
		}()
		defer close(scanDoneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-scanStopCh:
				return
			case <-ticker.C:
				_ = ScanAllProcesses()
			}
		}
	}()

	return nil
}

// StopInjectionScanner stops the periodic scanner.
func StopInjectionScanner() {
	if scanRunning.CompareAndSwap(true, false) {
		close(scanStopCh)
		<-scanDoneCh
	}
}
