package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type RootkitScanner struct {
	cfg    RootkitConfig
	stopCh chan struct{}
}

func NewRootkitScanner(cfg RootkitConfig) *RootkitScanner {
	return &RootkitScanner{cfg: cfg, stopCh: make(chan struct{})}
}

func (r *RootkitScanner) Start(ctx context.Context, alertCh chan<- AuditAlert) {
	r.scanOnce(alertCh)
	go r.loop(ctx, alertCh)
}

func (r *RootkitScanner) loop(ctx context.Context, alertCh chan<- AuditAlert) {
	interval, err := time.ParseDuration(r.cfg.ScanInterval)
	if err != nil {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.scanOnce(alertCh)
		}
	}
}

func (r *RootkitScanner) Stop() { close(r.stopCh) }

func (r *RootkitScanner) scanOnce(alertCh chan<- AuditAlert) {
	r.checkRootkitFiles(alertCh)
	r.checkCrontab(alertCh)
	r.checkSSHKeys(alertCh)
}

var knownRootkitPaths = []struct {
	path        string
	description string
	score       float64
}{
	{"/dev/.kits", "Known rootkit directory", 90},
	{"/dev/.md", "Rootkit metadata", 90},
	{"/.snake", ".snake rootkit", 90},
	{"/usr/bin/.login", "Login backdoor", 80},
	{"/tmp/.backdoor", "Backdoor file", 80},
	{"/tmp/.bsd", "Rootkit shadow", 80},
	{"/etc/.system", "Rootkit config", 70},
	{"/var/tmp/.cache", "Rootkit cache", 60},
	{"/var/spool/.lock", "Rootkit lock", 60},
}

func (r *RootkitScanner) checkRootkitFiles(alertCh chan<- AuditAlert) {
	for _, entry := range knownRootkitPaths {
		if _, err := os.Stat(entry.path); err == nil {
			sendAuditAlert(alertCh, AuditAlert{
				Type:      "rootkit",
				Severity:  5,
				Score:     entry.score,
				Message:   "Rootkit: " + entry.description + " at " + entry.path,
				Timestamp: time.Now(),
			})
		}
	}
}

func (r *RootkitScanner) checkCrontab(alertCh chan<- AuditAlert) {
	data, err := os.ReadFile("/etc/crontab")
	if err != nil {
		return
	}
	suspicious := []string{"curl", "wget", "nc ", "netcat", "bash -c", "python -c", "chmod 777", "/dev/tcp/"}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, ind := range suspicious {
			if strings.Contains(line, ind) {
				sendAuditAlert(alertCh, AuditAlert{
					Type:      "rootkit",
					Severity:  4,
					Score:     70,
					Message:   "Suspicious crontab: " + truncateStr(line, 80),
					Timestamp: time.Now(),
				})
				break
			}
		}
	}
}

func (r *RootkitScanner) checkSSHKeys(alertCh chan<- AuditAlert) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "command=") &&
			(strings.Contains(line, "curl") || strings.Contains(line, "bash") ||
				strings.Contains(line, "/dev/tcp")) {
			sendAuditAlert(alertCh, AuditAlert{
				Type:      "rootkit",
				Severity:  4,
				Score:     70,
				Message:   "Suspicious SSH key command restriction",
				Timestamp: time.Now(),
			})
		}
	}
}
