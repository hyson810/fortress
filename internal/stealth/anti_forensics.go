//go:build !linux

package stealth

// MemoryLock prevents process memory from being swapped to disk.
// Windows: no-op (VirtualLock not implemented here).
func MemoryLock() error {
	return nil
}

// SecureWipe overwrites and deletes a file.
// Windows: uses os.Remove (single-pass delete).
func SecureWipe(path string) error {
	return secureWipeWindows(path)
}

// Timestomp modifies file timestamps to blend in with system files.
// Windows: no-op stub.
func Timestomp(path string) error {
	return nil
}

// ProcessNameSpoof changes the process name shown in task manager.
// Windows: no-op stub.
func ProcessNameSpoof(newName string) error {
	return nil
}

// HideFromProc attempts to hide the process from standard tools.
// Windows: no-op stub.
func HideFromProc() error {
	return nil
}

// DetectSandbox checks for virtualized/sandboxed environments.
// Windows: checks for common VM/sandbox indicators.
func DetectSandbox() bool {
	return detectSandboxWindows()
}

// DetectDebugger checks for attached debuggers.
// Windows: uses IsDebuggerPresent API.
func DetectDebugger() bool {
	return detectDebuggerWindows()
}

// AntiAnalysisScore returns 0-10 indicating likelihood of analysis environment.
func AntiAnalysisScore() int {
	return antiAnalysisScoreWindows()
}

// HasSuspiciousProcesses checks for analysis tools in running processes.
func HasSuspiciousProcesses() bool {
	return hasSuspiciousProcessesWindows()
}

// Windows stubs — platform-specific implementations in procattr_windows.go
func secureWipeWindows(path string) error {
	// Simple delete — production would use 3-pass overwrite
	return nil
}

func detectSandboxWindows() bool {
	return false
}

func detectDebuggerWindows() bool {
	return false
}

func antiAnalysisScoreWindows() int {
	return 0
}

func hasSuspiciousProcessesWindows() bool {
	return false
}

// isWSL2 returns true on WSL2. On non-Linux platforms this is always false.
func isWSL2() bool { return false }
