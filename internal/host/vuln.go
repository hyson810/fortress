package host

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// VulnResult represents a single vulnerability finding.
type VulnResult struct {
	Package     string
	Version     string
	CVE         string
	Severity    string // CRITICAL / HIGH / MEDIUM / LOW
	Score       float64
	Description string
	FixedIn     string // fixed version, if known
}

// VulnScanner scans installed packages against known vulnerabilities.
type VulnScanner struct {
	cfg     VulnConfig
	results []VulnResult
	mu      sync.RWMutex
	stopCh  chan struct{}
}

func NewVulnScanner(cfg VulnConfig) *VulnScanner {
	return &VulnScanner{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
}

func (v *VulnScanner) Start(ctx context.Context, alertCh chan<- HostAlert) {
	// Initial scan
	v.scanAndReport(alertCh)
	go v.loop(ctx, alertCh)
}

func (v *VulnScanner) loop(ctx context.Context, alertCh chan<- HostAlert) {
	interval, err := time.ParseDuration(v.cfg.ScanInterval)
	if err != nil {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-v.stopCh:
			return
		case <-ticker.C:
			v.scanAndReport(alertCh)
		}
	}
}

func (v *VulnScanner) Stop() { close(v.stopCh) }

func (v *VulnScanner) scanAndReport(alertCh chan<- HostAlert) {
	results := v.scan()

	v.mu.Lock()
	v.results = results
	v.mu.Unlock()

	// Only alert on new findings at or above configured severity
	minLevel := severityWeight(v.cfg.Severity)

	for _, r := range results {
		if severityWeight(r.Severity) >= minLevel {
			sendAlertNonBlocking(alertCh, HostAlert{
				Type:      "vuln",
				Severity:  severityToLevel(r.Severity),
				Score:     r.Score,
				Message:   fmt.Sprintf("Vulnerability: %s %s (%s) — %s", r.Package, r.Version, r.CVE, r.Severity),
				Timestamp: time.Now(),
			})
		}
	}
}

func (v *VulnScanner) scan() []VulnResult {
	packages := getInstalledPackages()
	var results []VulnResult
	for _, pkg := range packages {
		if matches := matchCVE(pkg.Name, pkg.Version); len(matches) > 0 {
			results = append(results, matches...)
		}
	}
	return results
}

// GetResults returns a snapshot of scan results.
func (v *VulnScanner) GetResults() []VulnResult {
	v.mu.RLock()
	defer v.mu.RUnlock()
	r := make([]VulnResult, len(v.results))
	copy(r, v.results)
	return r
}

// --- Package info ---

type packageInfo struct {
	Name    string
	Version string
}

func getInstalledPackages() []packageInfo {
	out, err := exec.Command("dpkg-query", "-W", "-f", "${Package} ${Version}\n").Output()
	if err != nil {
		log.Printf("vuln: dpkg-query failed: %v", err)
		return nil
	}
	var pkgs []packageInfo
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			pkgs = append(pkgs, packageInfo{Name: parts[0], Version: parts[1]})
		}
	}
	return pkgs
}

// --- Simplified CVE matching ---
// This is a simplified embedded database for the most common critical vulnerabilities.
// In production, replace with a full CVE feed sync.

type cveEntry struct {
	Package     string
	VersionMin  string // inclusive
	VersionMax  string // inclusive, "" = any
	CVE         string
	Severity    string
	Description string
	FixedIn     string
}

var embeddedCVE = []cveEntry{
	// These are examples — real CVEs change frequently
	{Package: "openssl", VersionMax: "1.1.1", CVE: "CVE-2024-XXXX", Severity: "HIGH", Description: "Buffer overflow in TLS handshake", FixedIn: "1.1.1u"},
	{Package: "libssl3", VersionMax: "3.0.8", CVE: "CVE-2024-YYYY", Severity: "CRITICAL", Description: "Remote code execution in TLS", FixedIn: "3.0.9"},
	{Package: "bash", VersionMax: "5.0", CVE: "CVE-2024-SHOCK", Severity: "HIGH", Description: "Shell injection via environment", FixedIn: "5.1"},
	{Package: "sudo", VersionMax: "1.9.12", CVE: "CVE-2024-BARON", Severity: "HIGH", Description: "Privilege escalation via sudoedit", FixedIn: "1.9.13"},
	{Package: "systemd", VersionMax: "248", CVE: "CVE-2024-LOG", Severity: "MEDIUM", Description: "Log injection via service name", FixedIn: "249"},
}

func matchCVE(name, version string) []VulnResult {
	var results []VulnResult
	for _, entry := range embeddedCVE {
		if entry.Package != name {
			continue
		}
		if entry.VersionMax != "" && compareVersions(version, entry.VersionMax) > 0 {
			continue
		}
		results = append(results, VulnResult{
			Package: name, Version: version,
			CVE: entry.CVE, Severity: entry.Severity,
			Score:       severityScore(entry.Severity),
			Description: entry.Description,
			FixedIn:     entry.FixedIn,
		})
	}
	return results
}

// compareVersions is a simplified version comparison.
// Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
// Only handles basic semver-like version strings.
func compareVersions(v1, v2 string) int {
	// Simplified — in production use a real version comparison library
	v1 = strings.Split(v1, "-")[0] // strip debian revision
	v2 = strings.Split(v2, "-")[0]
	if v1 == v2 {
		return 0
	}
	return strings.Compare(v1, v2) // lexicographic approximation
}

func severityScore(s string) float64 {
	switch s {
	case "CRITICAL":
		return 90
	case "HIGH":
		return 70
	case "MEDIUM":
		return 40
	case "LOW":
		return 10
	default:
		return 0
	}
}

func severityWeight(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	default:
		return 1
	}
}

func severityToLevel(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	default:
		return 1
	}
}

func sendAlertNonBlocking(alertCh chan<- HostAlert, a HostAlert) {
	select {
	case alertCh <- a:
	default:
	}
}
