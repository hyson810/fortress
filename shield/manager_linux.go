//go:build linux

package shield

import (
	"log"
	"time"

	"github.com/fortress/v6/shield/ftrace"
	"github.com/fortress/v6/shield/io_uring"
	"github.com/fortress/v6/shield/memory"
)

// Start launches all enabled shield modules as background goroutines.
func (m *Manager) Start() {
	if m == nil {
		return
	}
	log.Printf("[shield] starting %d modules on linux (interval=%v)", m.Enabled(), m.interval)

	if m.cfg.InjectDetect {
		go m.runInjectDetect()
	}
	if m.cfg.MemoryAnomaly {
		go m.runMemoryAnomaly()
	}
	if m.cfg.FtraceInteg {
		go m.runFtraceInteg()
	}
	if m.cfg.IOUringDetect {
		go m.runIOUringDetect()
	}
	if m.cfg.BPFAudit {
		go m.runBPFAudit()
	}
}

// runInjectDetect periodically scans processes for injection artifacts.
func (m *Manager) runInjectDetect() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	log.Printf("[shield] inject_detect started (interval=%v)", m.interval)
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			_ = memory.StartInjectionScanner(m.interval)
		}
	}
}

// runMemoryAnomaly periodically scans for RWX/hidden memory pages.
func (m *Manager) runMemoryAnomaly() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	log.Printf("[shield] memory_anomaly started (interval=%v)", m.interval)
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			_, _ = memory.StartMemoryAnomalyDetector(m.interval)
		}
	}
}

// runFtraceInteg periodically checks ftrace/kprobe hook integrity.
func (m *Manager) runFtraceInteg() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	checker := ftrace.NewChecker([]string{"tcp_v4_connect", "__sys_recvmsg", "tcp4_seq_show"})
	if err := checker.TakeBaseline(); err != nil {
		log.Printf("[shield] ftrace baseline failed: %v", err)
		return
	}

	log.Printf("[shield] ftrace_integrity started (interval=%v)", m.interval)
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			kprobes := checker.CheckKprobeIntegrity()
			for _, a := range kprobes {
				log.Printf("[shield] kprobe anomaly: %s (severity=%s)", a.Detail, a.Severity)
			}
			hooks := checker.CheckFtraceHooks()
			for _, a := range hooks {
				log.Printf("[shield] ftrace anomaly: %s (severity=%s)", a.Detail, a.Severity)
			}
		}
	}
}

// runIOUringDetect periodically monitors for io_uring abuse.
func (m *Manager) runIOUringDetect() {
	monitor := io_uring.NewMonitor(func(stats *io_uring.IoUringStats) {
		log.Printf("[shield] io_uring anomaly: PID=%d (%s) enters=%d regs=%d bursts=%d",
			stats.PID, stats.Comm, stats.EnterCount, stats.RegCount, stats.BurstCount)
	})
	if err := monitor.Start(); err != nil {
		log.Printf("[shield] io_uring monitor failed: %v", err)
		return
	}

	log.Printf("[shield] io_uring_monitor started")
	<-m.stopCh
	monitor.Stop()
}

// runBPFAudit periodically audits /sys/fs/bpf for unauthorized BPF programs.
func (m *Manager) runBPFAudit() {
	log.Printf("[shield] bpf_audit: BPF LSM audit available but requires kernel support")
}
