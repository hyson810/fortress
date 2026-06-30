package bpf_lsm

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

const (
	DefaultBPFFSPath    = "/sys/fs/bpf"
	DefaultAuditInterval = 30 * time.Second
)

// BPFAuditFinding represents a suspicious or unknown BPF program discovery.
type BPFAuditFinding struct {
	Path        string
	ProgramType string
	Hash        [32]byte
	Issue       string
	Severity    string
	Detail      string
	DetectedAt  time.Time
}

// BPFAuditor continuously audits the BPF filesystem and running programs.
type BPFAuditor struct {
	mu        sync.RWMutex
	whitelist *BPFWhitelist
	findings  []*BPFAuditFinding
	bpfFSPath string
	stopCh    chan struct{}
	running   bool
}

// NewBPFAuditor creates a new auditor bound to a whitelist.
func NewBPFAuditor(whitelist *BPFWhitelist) *BPFAuditor {
	return &BPFAuditor{
		whitelist: whitelist,
		bpfFSPath: DefaultBPFFSPath,
		stopCh:    make(chan struct{}),
	}
}

// AuditBPFPrograms performs a complete scan of pinned and unpinned BPF programs.
func (a *BPFAuditor) AuditBPFPrograms() []*BPFAuditFinding {
	var findings []*BPFAuditFinding
	findings = append(findings, a.auditPinnedPrograms()...)
	findings = append(findings, a.auditUnpinnedPrograms()...)
	a.mu.Lock()
	a.findings = findings
	a.mu.Unlock()
	return findings
}

func (a *BPFAuditor) auditPinnedPrograms() []*BPFAuditFinding {
	var findings []*BPFAuditFinding

	_ = filepath.Walk(a.bpfFSPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			findings = append(findings, &BPFAuditFinding{
				Path: path, Issue: "inaccessible", Severity: "medium",
				Detail: fmt.Sprintf("cannot access: %v", err), DetectedAt: time.Now(),
			})
			return nil
		}
		if info.IsDir() {
			return nil
		}

		if strings.Contains(path, "/tmp/") || strings.Contains(path, ".tmp") {
			findings = append(findings, &BPFAuditFinding{
				Path: path, Issue: "suspicious_path", Severity: "high",
				Detail: "BPF program pinned to non-standard location", DetectedAt: time.Now(),
			})
		}

		if data, err := os.ReadFile(path); err == nil {
			hash := sha256.Sum256(data)
			if !a.whitelist.IsWhitelisted(hash) {
				findings = append(findings, &BPFAuditFinding{
					Path: path, Hash: hash, Issue: "unknown", Severity: "high",
					Detail: "pinned BPF program not in whitelist", DetectedAt: time.Now(),
				})
			}
		}
		return nil
	})

	return findings
}

func (a *BPFAuditor) auditUnpinnedPrograms() []*BPFAuditFinding {
	var findings []*BPFAuditFinding

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return findings
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if !isDigitOnly(pid) {
			continue
		}

		fdDir := filepath.Join("/proc", pid, "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fdEntry := range fdEntries {
			link, err := os.Readlink(filepath.Join(fdDir, fdEntry.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "anon_inode:bpf") {
				findings = append(findings, &BPFAuditFinding{
					Path:     fmt.Sprintf("/proc/%s/fd/%s", pid, fdEntry.Name()),
					Issue:    "unpinned",
					Severity: "medium",
					Detail:   fmt.Sprintf("running BPF program without pin in PID %s", pid),
					DetectedAt: time.Now(),
				})
			}
		}
	}
	return findings
}

// StartContinuousAudit starts periodic auditing.
func (a *BPFAuditor) StartContinuousAudit(interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultAuditInterval
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("auditor already running")
	}
	a.running = true
	a.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[bpf_lsm] audit loop panic: %v\nstack: %s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-a.stopCh:
				return
			case <-ticker.C:
				a.AuditBPFPrograms()
			}
		}
	}()
	return nil
}

// Stop terminates continuous auditing.
func (a *BPFAuditor) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		close(a.stopCh)
		a.running = false
	}
}

// LatestFindings returns the most recent audit results.
func (a *BPFAuditor) LatestFindings() []*BPFAuditFinding {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]*BPFAuditFinding{}, a.findings...)
}

func isDigitOnly(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
