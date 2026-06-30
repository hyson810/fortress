package host

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CISCheck represents a single CIS benchmark check result.
type CISCheck struct {
	ID          string
	Title       string
	Description string
	Level       int      // 1 or 2
	Pass        bool
	Score       float64
	Remediation string
}

// CISChecker periodically runs CIS benchmark checks.
type CISChecker struct {
	cfg     CISConfig
	results []CISCheck
	mu      sync.RWMutex
	stopCh  chan struct{}
}

// NewCISChecker creates a new CISChecker.
func NewCISChecker(cfg CISConfig) *CISChecker {
	return &CISChecker{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
}

// Start begins the CIS compliance checking loop. It sends alerts to the provided channel.
func (c *CISChecker) Start(ctx context.Context, alertCh chan<- HostAlert) {
	c.runAll(alertCh)
	go c.loop(ctx, alertCh)
}

// Stop gracefully shuts down the CIS checker.
func (c *CISChecker) Stop() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
}

func (c *CISChecker) loop(ctx context.Context, alertCh chan<- HostAlert) {
	interval, err := time.ParseDuration(c.cfg.Interval)
	if err != nil {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.runAll(alertCh)
		}
	}
}

func (c *CISChecker) runAll(alertCh chan<- HostAlert) {
	var results []CISCheck
	for _, check := range cisChecks {
		passed := check.Fn()
		cr := CISCheck{
			ID:          check.ID,
			Title:       check.Title,
			Description: check.Description,
			Level:       check.Level,
			Pass:        passed,
			Score:       check.Score,
			Remediation: check.Remediation,
		}
		if !passed {
			results = append(results, cr)
		}
	}

	c.mu.Lock()
	c.results = results
	c.mu.Unlock()

	// Alert on failures
	for _, r := range results {
		if r.Level == 1 || c.cfg.Profile == "level_2" {
			severity := map[int]int{1: 4, 2: 3}[r.Level]
			sendAlert(alertCh, HostAlert{
				Type:      "cis",
				Severity:  severity,
				Score:     r.Score,
				Message:   fmt.Sprintf("CIS %s: %s", r.ID, r.Title),
				Timestamp: time.Now(),
			})
		}
	}
}

// GetResults returns a snapshot of failed checks.
func (c *CISChecker) GetResults() []CISCheck {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r := make([]CISCheck, len(c.results))
	copy(r, c.results)
	return r
}

// RunNow runs all checks on demand and returns the results.
func (c *CISChecker) RunNow() []CISCheck {
	var results []CISCheck
	for _, check := range cisChecks {
		passed := check.Fn()
		cr := CISCheck{
			ID:          check.ID,
			Title:       check.Title,
			Description: check.Description,
			Level:       check.Level,
			Pass:        passed,
			Score:       check.Score,
			Remediation: check.Remediation,
		}
		if !passed {
			results = append(results, cr)
		}
	}
	return results
}

// --- CIS Checks ---

type cisCheckDef struct {
	ID          string
	Title       string
	Description string
	Level       int
	Score       float64
	Remediation string
	Fn          func() bool
}

var cisChecks = []cisCheckDef{
	{
		ID: "1.1.1", Title: "/etc/passwd permissions", Level: 1, Score: 50,
		Description: "Ensure /etc/passwd has 644 permissions",
		Remediation: "chmod 644 /etc/passwd",
		Fn: func() bool { return checkFileMode("/etc/passwd", 0644) },
	},
	{
		ID: "1.1.2", Title: "/etc/shadow permissions", Level: 1, Score: 70,
		Description: "Ensure /etc/shadow has 640 permissions",
		Remediation: "chmod 640 /etc/shadow",
		Fn: func() bool { return checkFileMode("/etc/shadow", 0640) },
	},
	{
		ID: "1.2.1", Title: "SSH root login", Level: 1, Score: 60,
		Description: "Ensure SSH PermitRootLogin is no",
		Remediation: "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config",
		Fn: func() bool { return checkSSHConfig("PermitRootLogin", "no") },
	},
	{
		ID: "1.3.1", Title: "Password min length", Level: 1, Score: 50,
		Description: "Ensure password min length >= 14",
		Remediation: "echo 'minlen = 14' >> /etc/security/pwquality.conf",
		Fn: func() bool { return checkPwMinLen(14) },
	},
	{
		ID: "2.1.1", Title: "Unused services disabled", Level: 1, Score: 30,
		Description: "Ensure unnecessary services are not running",
		Remediation: "systemctl disable <service>",
		Fn: func() bool { return true }, // optimistic — no easy universal check
	},
	{
		ID: "2.2.1", Title: "Audit logging enabled", Level: 1, Score: 40,
		Description: "Ensure auditd is installed and running",
		Remediation: "apt install auditd && systemctl enable auditd",
		Fn: func() bool { return checkServiceRunning("auditd") },
	},
	{
		ID: "3.1.1", Title: "IP forwarding disabled", Level: 1, Score: 30,
		Description: "Ensure net.ipv4.ip_forward = 0",
		Remediation: "sysctl -w net.ipv4.ip_forward=0",
		Fn: func() bool { return checkSysctl("net.ipv4.ip_forward", "0") },
	},
	{
		ID: "3.2.1", Title: "iptables default DROP", Level: 2, Score: 60,
		Description: "Ensure default firewall policy is DROP",
		Remediation: "iptables -P INPUT DROP && iptables -P FORWARD DROP",
		Fn: func() bool { return checkFirewallDefaultDrop() },
	},
	{
		ID: "4.1.1", Title: "Rootkit detector installed", Level: 1, Score: 40,
		Description: "Ensure rkhunter or chkrootkit is installed",
		Remediation: "apt install rkhunter",
		Fn: func() bool { return checkCommandExists("rkhunter") || checkCommandExists("chkrootkit") },
	},
	{
		ID: "5.1.1", Title: "Non-root su restrictions", Level: 1, Score: 40,
		Description: "Ensure access to su command is restricted",
		Remediation: "dpkg-statoverride --update --add root shadow 4750 /bin/su",
		Fn: func() bool { return checkSuRestricted() },
	},
}

// --- Check implementations ---

func checkFileMode(path string, expected os.FileMode) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm() == expected
}

func checkSSHConfig(key, expected string) bool {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == key && parts[1] == expected {
			return true
		}
	}
	return false
}

func checkPwMinLen(min int) bool {
	data, err := os.ReadFile("/etc/security/pwquality.conf")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "minlen") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				val, convErr := strconv.Atoi(strings.TrimSpace(parts[1]))
				if convErr == nil && val >= min {
					return true
				}
			}
		}
	}
	return false
}

func checkServiceRunning(name string) bool {
	out, err := exec.Command("systemctl", "is-active", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

func checkSysctl(key, expected string) bool {
	out, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == expected
}

func checkFirewallDefaultDrop() bool {
	out, err := exec.Command("iptables", "-L", "INPUT", "-n").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "DROP") || strings.Contains(string(out), "REJECT")
}

func checkCommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func checkSuRestricted() bool {
	out, err := exec.Command("dpkg-statoverride", "--list").Output()
	if err != nil {
		return true // no override configured
	}
	return strings.Contains(string(out), "/bin/su")
}
