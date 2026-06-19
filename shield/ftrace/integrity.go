// Package ftrace checks the integrity of kernel ftrace/kprobe hooks,
// detecting unauthorized syscall interception via ftrace-based hijacking.
//
// Attack vector: attackers use ftrace to hook __sys_recvmsg and other
// kernel functions to hide network connections from eBPF monitoring.
//
// Reference: VoidLink analysis (Check Point / Elastic / Isovalent 2025)

package ftrace

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	DefaultKprobeListPath     = "/sys/kernel/debug/kprobes/list"
	DefaultEnabledFuncsPath   = "/sys/kernel/tracing/enabled_functions"
	DefaultAvailableFuncsPath = "/sys/kernel/tracing/available_filter_functions"
)

// KprobeAnomaly represents a suspicious kprobe registration.
type KprobeAnomaly struct {
	Address    string
	Symbol     string
	Module     string
	Issue      string // "unknown_module", "suspicious_symbol", "syscall_hook"
	Severity   string
	Detail     string
}

// FtraceAnomaly represents a suspicious ftrace hook.
type FtraceAnomaly struct {
	Function   string
	Issue      string
	Severity   string
	Detail     string
}

// IntegrityChecker validates kprobe and ftrace hook integrity.
type IntegrityChecker struct {
	mu                 sync.RWMutex
	knownModules       map[string]bool // modules allowed to register kprobes
	baselineKprobes    map[string]bool // snapshot of known-good kprobe list
	baselineFtraceHooks map[string]bool
	lastCheck          string
}

// NewChecker creates a new integrity checker with a list of known-safe modules.
func NewChecker(knownModules []string) *IntegrityChecker {
	ic := &IntegrityChecker{
		knownModules:       make(map[string]bool),
		baselineKprobes:    make(map[string]bool),
		baselineFtraceHooks: make(map[string]bool),
	}
	for _, m := range knownModules {
		ic.knownModules[m] = true
	}
	return ic
}

// TakeBaseline captures a snapshot of the current kprobe and ftrace state.
func (ic *IntegrityChecker) TakeBaseline() error {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	// Snapshot kprobes
	kprobes, err := readKprobeList(DefaultKprobeListPath)
	if err != nil {
		return fmt.Errorf("read kprobes: %w", err)
	}
	ic.baselineKprobes = kprobes

	// Snapshot ftrace hooks
	ftraceHooks, err := readEnabledFunctions(DefaultEnabledFuncsPath)
	if err != nil {
		return fmt.Errorf("read ftrace hooks: %w", err)
	}
	ic.baselineFtraceHooks = ftraceHooks

	return nil
}

// CheckKprobeIntegrity compares current kprobes against baseline and known modules.
func (ic *IntegrityChecker) CheckKprobeIntegrity() []KprobeAnomaly {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	var anomalies []KprobeAnomaly

	current, err := readKprobeList(DefaultKprobeListPath)
	if err != nil {
		anomalies = append(anomalies, KprobeAnomaly{
			Issue: "unreadable", Severity: "high",
			Detail: fmt.Sprintf("cannot read kprobe list: %v", err),
		})
		return anomalies
	}

	// Detect new kprobes not in baseline
	for kprobe := range current {
		if !ic.baselineKprobes[kprobe] {
			parts := strings.Fields(kprobe)
			symbol := ""
			module := ""
			if len(parts) >= 2 {
				symbol = parts[1]
			}
			if len(parts) >= 3 {
				module = parts[2]
				module = strings.Trim(module, "[]")
			}

			anomaly := KprobeAnomaly{
				Address: parts[0],
				Symbol:  symbol,
				Module:  module,
				Issue:   "new_kprobe",
				Detail:  "kprobe not in baseline snapshot",
			}

			if module != "" && !ic.knownModules[module] {
				anomaly.Issue = "unknown_module"
				anomaly.Severity = "high"
			}

			if strings.Contains(symbol, "sys_") ||
				strings.Contains(symbol, "__sys_") ||
				strings.Contains(symbol, "tcp4_seq_show") ||
				strings.Contains(symbol, "udp4_seq_show") {
				anomaly.Issue = "syscall_hook"
				anomaly.Severity = "critical"
			}

			anomalies = append(anomalies, anomaly)
		}
	}

	// Detect removed kprobes (attacker might have removed EDR kprobes)
	for kprobe := range ic.baselineKprobes {
		if !current[kprobe] {
			anomalies = append(anomalies, KprobeAnomaly{
				Issue: "removed_kprobe", Severity: "critical",
				Detail: fmt.Sprintf("kprobe removed: %s (possible tampering)", kprobe),
			})
		}
	}

	return anomalies
}

// CheckFtraceHooks compares current ftrace hooks against baseline.
func (ic *IntegrityChecker) CheckFtraceHooks() []FtraceAnomaly {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	var anomalies []FtraceAnomaly

	current, err := readEnabledFunctions(DefaultEnabledFuncsPath)
	if err != nil {
		anomalies = append(anomalies, FtraceAnomaly{
			Issue: "unreadable", Severity: "high",
			Detail: fmt.Sprintf("cannot read ftrace hooks: %v", err),
		})
		return anomalies
	}

	for hook := range current {
		if !ic.baselineFtraceHooks[hook] {
			anomaly := FtraceAnomaly{
				Function: hook,
				Issue:    "new_ftrace_hook",
				Severity: "medium",
				Detail:   "ftrace hook not in baseline snapshot",
			}
			if strings.Contains(hook, "sys_recvmsg") ||
				strings.Contains(hook, "tcp4_seq_show") ||
				strings.Contains(hook, "udp4_seq_show") ||
				strings.Contains(hook, "inet6_seq_show") {
				anomaly.Issue = "suspicious_hook"
				anomaly.Severity = "critical"
				anomaly.Detail = "ftrace hook on network-visibility function — likely concealment"
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

// readKprobeList reads /sys/kernel/debug/kprobes/list into a set.
func readKprobeList(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			set[line] = true
		}
	}
	return set, nil
}

// readEnabledFunctions reads /sys/kernel/tracing/enabled_functions into a set.
func readEnabledFunctions(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			set[line] = true
		}
	}
	return set, nil
}
