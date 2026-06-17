package stealth

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Watchdog monitors a target process and respawns it if it dies.
// It also provides anti-debugging and integrity verification checks.
type Watchdog struct {
	mu            sync.Mutex
	pid           int
	restartCmd    []string
	running       bool
	stopCh        chan struct{}
	checkInterval time.Duration
}

// NewWatchdog creates a Watchdog that guards the given PID.
// If the process dies, it is restarted using restartCmd.
func NewWatchdog(pid int, restartCmd []string) *Watchdog {
	return &Watchdog{
		pid:           pid,
		restartCmd:    restartCmd,
		stopCh:        make(chan struct{}),
		checkInterval: 5 * time.Second,
	}
}

// Start begins the watchdog monitoring loop in a background goroutine.
func (w *Watchdog) Start() {
	w.running = true
	go w.loop()
	log.Printf("[watchdog] guarding PID %d with restart: %v", w.pid, w.restartCmd)
}

// loop is the main monitoring loop that periodically checks process health.
func (w *Watchdog) loop() {
	ticker := time.NewTicker(w.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			if !w.isProcessAlive(w.pid) {
				log.Printf("[watchdog] PID %d died — respawning...", w.pid)
				newPID := w.respawn()
				if newPID > 0 {
					w.mu.Lock()
					w.pid = newPID
					w.mu.Unlock()
					log.Printf("[watchdog] respawned as PID %d", newPID)
				}
			}
		}
	}
}

// isProcessAlive checks whether a process with the given PID exists
// by reading its /proc entry.
func (w *Watchdog) isProcessAlive(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d/stat", pid))
	return err == nil
}

// respawn starts a new process using the configured restart command.
// Returns the new PID, or 0 on failure.
func (w *Watchdog) respawn() int {
	if len(w.restartCmd) == 0 {
		return 0
	}
	cmd := exec.Command(w.restartCmd[0], w.restartCmd[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Printf("[watchdog] respawn failed: %v", err)
		return 0
	}
	return cmd.Process.Pid
}

// Stop signals the watchdog to stop monitoring.
func (w *Watchdog) Stop() {
	close(w.stopCh)
	w.running = false
}

// IsDebugged checks /proc/self/status for a non-zero TracerPid,
// indicating the process is being traced by a debugger.
func (w *Watchdog) IsDebugged() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return true
			}
			return false
		}
	}
	return false
}

// HasSuspiciousEnv scans environment variables for debugging or
// injection indicators (LD_PRELOAD, gdb, frida, etc.).
func (w *Watchdog) HasSuspiciousEnv() bool {
	for _, env := range os.Environ() {
		for _, keyword := range []string{
			"LD_PRELOAD", "LD_LIBRARY_PATH",
			"frida", "gdb", "lldb", "strace", "ltrace",
		} {
			if strings.Contains(env, keyword) {
				return true
			}
		}
	}
	return false
}

// VerifyIntegrity checks that the given files match their expected
// SHA-256 hashes. Returns false if any file is missing or mismatched.
func (w *Watchdog) VerifyIntegrity(files []string, expectedHashes map[string]string) bool {
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Printf("[watchdog] integrity check failed for %s: %v", f, err)
			return false
		}
		hash := fmt.Sprintf("%x", sha256.Sum256(data))
		if expected, ok := expectedHashes[f]; ok && hash != expected {
			log.Printf("[watchdog] INTEGRITY VIOLATION: %s hash mismatch", f)
			return false
		}
	}
	return true
}

// SetCheckInterval overrides the default 5-second health-check interval.
func (w *Watchdog) SetCheckInterval(d time.Duration) {
	w.checkInterval = d
}

// PID returns the currently guarded PID.
func (w *Watchdog) PID() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pid
}

// IsRunning reports whether the watchdog loop is active.
func (w *Watchdog) IsRunning() bool {
	return w.running
}
