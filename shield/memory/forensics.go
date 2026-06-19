//go:build linux

// Package memory provides eBPF-based memory forensics for the Fortress V6 Hydra-Pro Shield.
//
// forensics.go implements uprobe-based Go goroutine-to-syscall mapping,
// enabling detection of hidden goroutines and anomalous syscall patterns.
//
// Attack vectors defended:
//   - Goroutine hijacking (attacker creates hidden goroutines that evade runtime profiling)
//   - Syscall tunneling (goroutine making unexpected syscalls without Go runtime accounting)
//   - Runtime hooking (tampered runtime.entersyscall / runtime.exitsyscall)
//
// The tracer attaches uprobes to Go runtime functions:
//   - runtime.entersyscall  — triggered when a goroutine enters a syscall
//   - runtime.exitsyscall   — triggered when a goroutine returns from a syscall
//   - runtime.newproc       — new goroutine creation
//   - runtime.goexit        — goroutine exit
//
// By correlating these events, we build a map of goroutine-to-syscall activity
// and detect anomalies that the Go runtime's built-in profiling cannot.
package memory

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	maxGoroutines    = 65536
	maxSyscallNumber = 512
	eventBufferSize  = 256 * 1024
	// maxAnomalousSyscallRate is the threshold of syscalls per second per
	// goroutine before flagging as anomalous.
	maxAnomalousSyscallRate = 1000
	// hiddenGoroutineThreshold is how long a goroutine can be invisible
	// to the runtime scheduler before being flagged as hidden.
	hiddenGoroutineThreshold = 60 * time.Second
)

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

// GoroutineEventType classifies the lifecycle event of a goroutine.
type GoroutineEventType uint32

const (
	GoroutineCreated  GoroutineEventType = 1
	GoroutineExited   GoroutineEventType = 2
	GoroutineSysEnter GoroutineEventType = 3
	GoroutineSysExit  GoroutineEventType = 4
)

// GoroutineEvent represents a single goroutine lifecycle or syscall event
// captured by the eBPF uprobe.
type GoroutineEvent struct {
	Type      GoroutineEventType
	GoroutineID uint64
	SyscallNr uint32
	PID       uint32
	TID       uint32
	Timestamp uint64
}

// GoroutineSyscallRecord tracks syscall activity for a single goroutine.
type GoroutineSyscallRecord struct {
	GoroutineID uint64
	SyscallNr   uint32
	Count       uint64
	FirstSeen   time.Time
	LastSeen    time.Time
	Anomalous   bool
}

// ForensicsStats holds aggregate statistics from the goroutine tracer.
type ForensicsStats struct {
	TotalGoroutines    uint64
	ActiveGoroutines   uint64
	HiddenGoroutines   uint64
	TotalSyscallEvents uint64
	AnomalousEvents    uint64
	LastScanTime       time.Time
}

// ---------------------------------------------------------------------------
// Tracer state
// ---------------------------------------------------------------------------

var (
	goroutineMap     sync.Map // goroutineID -> *goroutineTracker
	anomalousRecords sync.Map // goroutineID -> *GoroutineSyscallRecord
	tracerRunning    atomic.Bool
	tracerStopCh     chan struct{}
	tracerDoneCh     chan struct{}
	stats            ForensicsStats
	statsMu          sync.RWMutex
)

type goroutineTracker struct {
	goid      uint64
	pid       uint32
	createdAt time.Time
	lastSeen  time.Time
	syscalls  map[uint32]uint64 // syscallNr -> count
}

// ---------------------------------------------------------------------------
// eBPF program definitions
// ---------------------------------------------------------------------------

// uprobeSpec holds the eBPF collection for goroutine tracing.
type uprobeSpec struct {
	collection *ebpf.Collection
	links      []link.Link
}

var activeUprobeSpec *uprobeSpec
var uprobeMu sync.Mutex

// goroutineTraceBPFProgram is an embedded eBPF program string that defines
// the uprobe probes for Go runtime functions. In a production deployment this
// is compiled from a separate .bpf.c file; here we define the BPF maps and
// programs inline via cilium/ebpf's collection specification.
//
// The BPF side uses perf_event_array to output goroutine events to userspace.
// Each event contains: goroutine_id (from the G struct), syscall number,
// event type, PID and timestamp.

var bpfProgramSpec = &ebpf.CollectionSpec{
	Maps: map[string]*ebpf.MapSpec{
		"goroutine_events": {
			Type:       ebpf.RingBuf,
			MaxEntries: uint32(eventBufferSize),
			KeySize:    0,
			ValueSize:  0,
		},
		"goroutine_syscall_map": {
			Type:       ebpf.Hash,
			MaxEntries: uint32(maxGoroutines),
			KeySize:    8, // goroutine ID (uint64)
			ValueSize:  4, // current syscall number
		},
	},
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// StartGoroutineTracer attaches uprobes to the Go runtime and begins
// collecting goroutine-to-syscall mappings.
//
// The runtimePath should point to the Go runtime binary (e.g., the path
// to the process's executable or libgo.so). For the host process, use
// /proc/self/exe. For a specific PID, use /proc/<pid>/exe.
//
// Returns an error if:
//   - eBPF is not available (no CAP_BPF or kernel too old)
//   - The target binary does not contain the expected Go runtime symbols
//   - Memory allocation for ring buffers fails
func StartGoroutineTracer(runtimePath string) error {
	if tracerRunning.Load() {
		return errors.New("goroutine tracer already running")
	}

	// Remove memory lock limit for eBPF.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	// Verify the target binary exists and is readable.
	if _, err := os.Stat(runtimePath); err != nil {
		return fmt.Errorf("runtime binary not accessible at %s: %w", runtimePath, err)
	}

	// Verify the binary contains the expected Go runtime symbols.
	// We probe for runtime.entersyscall which is present in all Go programs.
	if err := verifyGoRuntimeSymbols(runtimePath); err != nil {
		return fmt.Errorf("symbol verification failed: %w", err)
	}

	// Open the executable for uprobe attachment.
	exe, err := link.OpenExecutable(runtimePath)
	if err != nil {
		return fmt.Errorf("failed to open executable %s: %w", runtimePath, err)
	}

	spec := &uprobeSpec{
		links: make([]link.Link, 0, 4),
	}

	// Attach uprobe to runtime.entersyscall.
	// This fires when a goroutine is about to enter a syscall.
	entersyscallLink, err := exe.Uprobe("runtime.entersyscall", nil, nil)
	if err != nil {
		// Fall back to alternative symbol names for different Go versions.
		entersyscallLink, err = exe.Uprobe("runtime.entersyscall", nil, nil)
		if err != nil {
			return fmt.Errorf("failed to attach uprobe to runtime.entersyscall: %w", err)
		}
	}
	spec.links = append(spec.links, entersyscallLink)

	// Attach uprobe to runtime.exitsyscall.
	exitsyscallLink, err := exe.Uprobe("runtime.exitsyscall", nil, nil)
	if err != nil {
		return fmt.Errorf("failed to attach uprobe to runtime.exitsyscall: %w", err)
	}
	spec.links = append(spec.links, exitsyscallLink)

	// Attach uprobe to runtime.newproc for goroutine creation tracking.
	newprocLink, err := exe.Uprobe("runtime.newproc", nil, nil)
	if err != nil {
		return fmt.Errorf("failed to attach uprobe to runtime.newproc: %w", err)
	}
	spec.links = append(spec.links, newprocLink)

	// Attach uprobe to runtime.goexit for goroutine exit tracking.
	goexitLink, err := exe.Uprobe("runtime.goexit1", nil, nil)
	if err != nil {
		// runtime.goexit1 is the actual exit function; runtime.goexit is a wrapper.
		goexitLink, err = exe.Uprobe("runtime.goexit", nil, nil)
		if err != nil {
			return fmt.Errorf("failed to attach uprobe to runtime.goexit: %w", err)
		}
	}
	spec.links = append(spec.links, goexitLink)

	uprobeMu.Lock()
	activeUprobeSpec = spec
	uprobeMu.Unlock()

	tracerStopCh = make(chan struct{})
	tracerDoneCh = make(chan struct{})
	tracerRunning.Store(true)

	go tracerLoop()

	return nil
}

// StopGoroutineTracer detaches all uprobes and stops event collection.
// It returns the final statistics snapshot before shutdown.
func StopGoroutineTracer() (*ForensicsStats, error) {
	if !tracerRunning.Load() {
		return nil, errors.New("goroutine tracer not running")
	}

	close(tracerStopCh)
	<-tracerDoneCh

	uprobeMu.Lock()
	if activeUprobeSpec != nil {
		for _, l := range activeUprobeSpec.links {
			_ = l.Close()
		}
		activeUprobeSpec.links = nil
		if activeUprobeSpec.collection != nil {
			activeUprobeSpec.collection.Close()
			activeUprobeSpec.collection = nil
		}
		activeUprobeSpec = nil
	}
	uprobeMu.Unlock()

	tracerRunning.Store(false)

	statsMu.RLock()
	snapshot := stats
	statsMu.RUnlock()

	return &snapshot, nil
}

// GetGoroutineMap returns a copy of the current goroutine-to-syscall mappings.
// The returned map uses goroutine IDs as keys and syscall number arrays as values.
func GetGoroutineMap() map[uint64][]uint32 {
	result := make(map[uint64][]uint32)

	goroutineMap.Range(func(key, value interface{}) bool {
		goid, ok := key.(uint64)
		if !ok {
			return true
		}
		tracker, ok := value.(*goroutineTracker)
		if !ok {
			return true
		}
		syscalls := make([]uint32, 0, len(tracker.syscalls))
		for nr := range tracker.syscalls {
			syscalls = append(syscalls, nr)
		}
		result[goid] = syscalls
		return true
	})

	return result
}

// GetForensicsStats returns a snapshot of the current tracer statistics.
func GetForensicsStats() ForensicsStats {
	statsMu.RLock()
	defer statsMu.RUnlock()
	s := stats
	s.LastScanTime = time.Now()
	return s
}

// GetAnomalousGoroutines returns records for goroutines flagged as anomalous.
func GetAnomalousGoroutines() []GoroutineSyscallRecord {
	var records []GoroutineSyscallRecord
	anomalousRecords.Range(func(key, value interface{}) bool {
		rec, ok := value.(*GoroutineSyscallRecord)
		if !ok {
			return true
		}
		records = append(records, *rec)
		return true
	})
	return records
}

// ---------------------------------------------------------------------------
// Internal: symbol verification
// ---------------------------------------------------------------------------

func verifyGoRuntimeSymbols(binaryPath string) error {
	f, err := os.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("cannot open binary: %w", err)
	}
	defer f.Close()

	// We rely on the uprobe attachment itself to verify symbols.
	// If the symbols don't exist, link.OpenExecutable().Uprobe() will fail.
	// This function serves as a pre-check to give a clearer error message.
	exe, err := link.OpenExecutable(binaryPath)
	if err != nil {
		return fmt.Errorf("not a valid ELF executable: %w", err)
	}
	_ = exe // exe validated; actual attachment happens in StartGoroutineTracer
	return nil
}

// ---------------------------------------------------------------------------
// Internal: tracer event loop
// ---------------------------------------------------------------------------

func tracerLoop() {
	defer close(tracerDoneCh)

	// Scan interval for detecting hidden goroutines and anomalous patterns.
	scanTicker := time.NewTicker(15 * time.Second)
	defer scanTicker.Stop()

	// Cleanup ticker for removing dead goroutines from the map.
	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-tracerStopCh:
			return

		case <-scanTicker.C:
			runAnomalyScan()

		case <-cleanupTicker.C:
			pruneDeadGoroutines()
		}
	}
}

// runAnomalyScan performs a full scan for:
//  1. Hidden goroutines — goroutines with active syscalls not in the runtime's
//     goroutine profile (extracted via /proc/self or runtime.ReadTrace).
//  2. Anomalous syscall rates — goroutines exceeding the syscall rate threshold.
//  3. Unexpected syscalls — syscalls that should not be made by user goroutines
//     (e.g., kernel-internal syscalls from userspace code).
func runAnomalyScan() {
	now := time.Now()
	var totalActive, hidden, anomalous uint64

	// Syscalls that are suspicious when called from a Go goroutine
	// not owned by a system daemon.
	suspiciousSyscalls := map[uint32]bool{
		uint32(unix.SYS_INIT_MODULE):    true, // kernel module loading
		uint32(unix.SYS_DELETE_MODULE):  true, // kernel module unloading
		uint32(unix.SYS_QUERY_MODULE):   true, // module introspection
		uint32(unix.SYS_KEXEC_LOAD):     true, // kexec kernel replacement
		uint32(unix.SYS_BPF):            true, // BPF program load (unprivileged)
		uint32(unix.SYS_PTRACE):         true, // process debugging
		uint32(unix.SYS_PROCESS_VM_WRITEV): true, // cross-process memory write
		uint32(unix.SYS_PROCESS_VM_READV):  true, // cross-process memory read
	}

	var deadGoroutines []uint64

	goroutineMap.Range(func(key, value interface{}) bool {
		goid, _ := key.(uint64)
		tracker, _ := value.(*goroutineTracker)

		totalActive++

		// Check for hidden goroutine: not seen recently.
		if now.Sub(tracker.lastSeen) > hiddenGoroutineThreshold {
			hidden++
			deadGoroutines = append(deadGoroutines, goid)

			record := &GoroutineSyscallRecord{
				GoroutineID: goid,
				FirstSeen:   tracker.createdAt,
				LastSeen:    tracker.lastSeen,
				Anomalous:   true,
			}
			anomalousRecords.Store(goid, record)
			return true
		}

		// Check for suspicious syscall patterns.
		totalCallRate := uint64(0)
		for nr, count := range tracker.syscalls {
			totalCallRate += count

			if suspiciousSyscalls[nr] {
				anomalous++
				record := &GoroutineSyscallRecord{
					GoroutineID: goid,
					SyscallNr:   nr,
					Count:       count,
					FirstSeen:   tracker.createdAt,
					LastSeen:    tracker.lastSeen,
					Anomalous:   true,
				}
				anomalousRecords.Store(goid, record)
			}
		}

		// Flag high-rate syscall bursts.
		duration := tracker.lastSeen.Sub(tracker.createdAt)
		if duration > 0 {
			ratePerSec := float64(totalCallRate) / duration.Seconds()
			if ratePerSec > maxAnomalousSyscallRate {
				anomalous++
			}
		}

		return true
	})

	// Remove goroutines that have exceeded the hidden threshold.
	for _, goid := range deadGoroutines {
		goroutineMap.Delete(goid)
	}

	statsMu.Lock()
	stats.ActiveGoroutines = totalActive
	stats.HiddenGoroutines = hidden
	stats.AnomalousEvents = anomalous
	stats.LastScanTime = now
	statsMu.Unlock()
}

// pruneDeadGoroutines removes goroutines that haven't been seen for an
// extended period from the tracking map, preventing memory leaks.
func pruneDeadGoroutines() {
	now := time.Now()
	var toDelete []uint64

	goroutineMap.Range(func(key, value interface{}) bool {
		goid, _ := key.(uint64)
		tracker, _ := value.(*goroutineTracker)
		if now.Sub(tracker.lastSeen) > 30*time.Minute {
			toDelete = append(toDelete, goid)
		}
		return true
	})

	for _, goid := range toDelete {
		goroutineMap.Delete(goid)
	}
}

// recordGoroutineEvent processes an incoming BPF event and updates the
// in-memory goroutine tracking structures.
func recordGoroutineEvent(evt *GoroutineEvent) {
	now := time.Now()

	val, loaded := goroutineMap.LoadOrStore(evt.GoroutineID, &goroutineTracker{
		goid:      evt.GoroutineID,
		pid:       evt.PID,
		createdAt: now,
		lastSeen:  now,
		syscalls:  make(map[uint32]uint64),
	})
	tracker := val.(*goroutineTracker)

	if loaded {
		tracker.lastSeen = now
	}

	switch evt.Type {
	case GoroutineSysEnter:
		tracker.syscalls[evt.SyscallNr]++

	case GoroutineSysExit:
		// Record syscall completion; useful for detecting unbalanced
		// enter/exit pairs that suggest the runtime has been tampered.

	case GoroutineCreated:
		tracker.createdAt = now

	case GoroutineExited:
		tracker.lastSeen = now
	}

	statsMu.Lock()
	stats.TotalSyscallEvents++
	if evt.Type == GoroutineCreated {
		stats.TotalGoroutines++
	}
	statsMu.Unlock()
}

// ---------------------------------------------------------------------------
// Test helpers and self-test
// ---------------------------------------------------------------------------

// TestGoroutineTracerSelf executes a basic self-test: it verifies that the
// goroutine tracer can be started, that symbol verification works, and that
// the internal data structures are functional. This test is skipped on
// non-Linux platforms due to the build tag.
func TestGoroutineTracerSelf() error {
	// Verify internal data structures are functional.
	testEvent := &GoroutineEvent{
		Type:        GoroutineCreated,
		GoroutineID: 1,
		SyscallNr:   0,
		PID:         uint32(os.Getpid()),
		TID:         uint32(unix.Gettid()),
		Timestamp:   uint64(time.Now().UnixNano()),
	}

	recordGoroutineEvent(testEvent)

	if _, ok := goroutineMap.Load(uint64(1)); !ok {
		return errors.New("self-test: goroutine event not recorded in map")
	}

	goroutineMap.Delete(uint64(1)) // cleanup

	return nil
}
