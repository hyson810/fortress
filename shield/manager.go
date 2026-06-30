// Package shield provides the Hydra-Pro Shield integration manager.
//
// The ShieldManager initializes and coordinates all shield sub-modules
// (memory forensics, injection detection, ftrace integrity, io_uring
// monitoring, BPF LSM audit) based on the ShieldConfig.
//
// All shield modules are OPT-IN (default off) for zero-overhead baseline.
// This package is the single entry point for shield functionality — it
// replaces the previous approach of standalone go.mod modules.
package shield

import (
	"time"

	"github.com/fortress/v6/internal/config"
)

// Manager coordinates all shield sub-modules based on ShieldConfig.
type Manager struct {
	cfg      config.ShieldConfig
	stopCh   chan struct{}
	interval time.Duration
}

// NewManager creates a shield manager with the given config.
// Returns nil if no shield modules are enabled (zero-overhead).
func NewManager(cfg config.ShieldConfig) *Manager {
	if !cfg.InjectDetect && !cfg.MemoryAnomaly &&
		!cfg.FtraceInteg && !cfg.IOUringDetect && !cfg.BPFAudit {
		return nil // no shield modules enabled — zero overhead
	}

	interval := time.Duration(cfg.ScanInterval)
	if interval <= 0 {
		interval = 30
	}
	intervalSec := interval * time.Second

	return &Manager{
		cfg:      cfg,
		stopCh:   make(chan struct{}),
		interval: intervalSec,
	}
}

// Start launches all enabled shield modules as background goroutines.
// Linux implementation in manager_linux.go; stub in manager_stub.go for non-Linux.
// Stop signals all shield modules to shut down gracefully.
func (m *Manager) Stop() {
	if m == nil {
		return
	}
	close(m.stopCh)
}

// Enabled returns the number of enabled shield modules.
func (m *Manager) Enabled() int {
	n := 0
	if m.cfg.InjectDetect {
		n++
	}
	if m.cfg.MemoryAnomaly {
		n++
	}
	if m.cfg.FtraceInteg {
		n++
	}
	if m.cfg.IOUringDetect {
		n++
	}
	if m.cfg.BPFAudit {
		n++
	}
	return n
}
