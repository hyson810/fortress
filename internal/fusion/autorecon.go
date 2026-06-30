package fusion

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fortress/v6/internal/config"
)

// PhaseResult captures the outcome of a single reconnaissance phase.
type PhaseResult struct {
	PhaseNum    int                      `json:"phase_num"`
	ToolResults map[string]interface{}   `json:"tool_results"`
	Duration    time.Duration            `json:"duration"`
	Findings    int                      `json:"findings"`
}

// ReconReport is the top-level report produced by AutoRecon after
// executing all configured phases against a target.
type ReconReport struct {
	Target        string        `json:"target"`
	Phases        []PhaseResult `json:"phases"`
	TotalFindings int           `json:"total_findings"`
	RiskScore     float64       `json:"risk_score"`
}

// AutoRecon orchestrates multi-phase automated reconnaissance against a
// single target. It composes all available fusion tool wrappers and
// executes them in sequence: passive, active, deep, then exploit phases.
//
// D阶 weapons (destructive/exploitation) are gated behind the ExploitOK
// flag and are disabled by default.
type AutoRecon struct {
	cfg      *config.WeaponsConfig
	amass    *AmassScanner
	nmap     *NmapScanner
	nuclei   *NucleiScanner
	hydra    *HydraBruteForcer
	sqlmap   *SqlmapScanner
	msf      *MsfConsole
	gobuster *GoBuster

	ExploitOK bool // enables Phase 4 (destructive actions)
}

// NewAutoRecon creates an AutoRecon orchestrator from a WeaponsConfig.
// All tool wrappers are initialized eagerly so that configuration errors
// surface early.
func NewAutoRecon(cfg *config.WeaponsConfig) *AutoRecon {
	wordlists := cfg.Wordlists
	if wordlists == "" {
		wordlists = "/usr/share/wordlists"
	}

	return &AutoRecon{
		cfg:      cfg,
		amass:    NewAmass(cfg.NmapBin), // Amass bin may be installed separately.
		nmap:     NewNmapScanner(cfg),
		nuclei:   NewNucleiScanner(cfg),
		hydra:    NewHydraBruteForcer(cfg),
		sqlmap:   NewSqlmapScanner(cfg),
		msf:      NewMsfConsole(cfg),
		gobuster: NewGoBuster(cfg.NmapBin, wordlists+"/directory-list-2.3-medium.txt"),
	}
}

// Phase1Passive performs passive reconnaissance against target using
// OSINT techniques only — no packets are sent directly to the target.
func (ar *AutoRecon) Phase1Passive(target string) (*PhaseResult, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("autorecon: %w", err)
	}

	start := time.Now()
	pr := &PhaseResult{
		PhaseNum:    1,
		ToolResults: make(map[string]interface{}),
	}

	log.Printf("[autorecon] Phase 1 (passive) starting for %s", target)

	// Amass passive enumeration.
	if amassResult, err := ar.amass.PassiveEnum(target); err != nil {
		log.Printf("[autorecon] amass passive: %v", err)
		pr.ToolResults["amass_passive"] = err.Error()
	} else {
		pr.ToolResults["amass_passive"] = amassResult
		pr.Findings += amassResult.TotalDiscovered
	}

	// Nmap quick scan (mostly passive with -Pn).
	if scanResult, err := ar.nmap.QuickScan(target); err != nil {
		log.Printf("[autorecon] nmap quick: %v", err)
		pr.ToolResults["nmap_quick"] = err.Error()
	} else {
		pr.ToolResults["nmap_quick"] = scanResult
		pr.Findings += len(scanResult.Ports)
	}

	pr.Duration = time.Since(start)
	log.Printf("[autorecon] Phase 1 complete: %d findings in %s", pr.Findings, pr.Duration)
	return pr, nil
}

// Phase2Active performs active reconnaissance against target, including
// service scanning and initial vulnerability checks.
func (ar *AutoRecon) Phase2Active(target string) (*PhaseResult, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("autorecon: %w", err)
	}

	start := time.Now()
	pr := &PhaseResult{
		PhaseNum:    2,
		ToolResults: make(map[string]interface{}),
	}

	log.Printf("[autorecon] Phase 2 (active) starting for %s", target)

	// Nmap deep scan with service detection.
	if scanResult, err := ar.nmap.DeepScan(target); err != nil {
		log.Printf("[autorecon] nmap deep: %v", err)
		pr.ToolResults["nmap_deep"] = err.Error()
	} else {
		pr.ToolResults["nmap_deep"] = scanResult
		pr.Findings += len(scanResult.Ports)
	}

	// DNS subdomain enumeration via gobuster.
	if dnsResult, err := ar.gobuster.DnsScan(target); err != nil {
		log.Printf("[autorecon] gobuster dns: %v", err)
		pr.ToolResults["gobuster_dns"] = err.Error()
	} else {
		pr.ToolResults["gobuster_dns"] = dnsResult
		pr.Findings += len(dnsResult.FoundPaths)
	}

	pr.Duration = time.Since(start)
	log.Printf("[autorecon] Phase 2 complete: %d findings in %s", pr.Findings, pr.Duration)
	return pr, nil
}

// Phase3Deep performs deep reconnaissance including full vulnerability
// scanning and directory brute forcing.
func (ar *AutoRecon) Phase3Deep(target string) (*PhaseResult, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("autorecon: %w", err)
	}

	start := time.Now()
	pr := &PhaseResult{
		PhaseNum:    3,
		ToolResults: make(map[string]interface{}),
	}

	log.Printf("[autorecon] Phase 3 (deep) starting for %s", target)

	// Full nmap vulnerability scan.
	if scanResult, err := ar.nmap.VulnScan(target); err != nil {
		log.Printf("[autorecon] nmap vuln: %v", err)
		pr.ToolResults["nmap_vuln"] = err.Error()
	} else {
		pr.ToolResults["nmap_vuln"] = scanResult
		pr.Findings += len(scanResult.Ports)
	}

	// Nuclei vulnerability scan.
	if findings, err := ar.nuclei.Scan(target); err != nil {
		log.Printf("[autorecon] nuclei: %v", err)
		pr.ToolResults["nuclei"] = err.Error()
	} else {
		pr.ToolResults["nuclei"] = findings
		pr.Findings += len(findings)
	}

	// GoBuster directory scan (only if target is an HTTP URL).
	if isHTTP(target) {
		httpURL := target
		if !hasScheme(httpURL) {
			httpURL = "http://" + httpURL
		}
		if dirResult, err := ar.gobuster.DirScan(httpURL); err != nil {
			log.Printf("[autorecon] gobuster dir: %v", err)
			pr.ToolResults["gobuster_dir"] = err.Error()
		} else {
			pr.ToolResults["gobuster_dir"] = dirResult
			pr.Findings += len(dirResult.FoundPaths)
		}
	}

	// Amass active enumeration (only for domain-like targets).
	if isDomainish(target) {
		if amassResult, err := ar.amass.ActiveEnum(target); err != nil {
			log.Printf("[autorecon] amass active: %v", err)
			pr.ToolResults["amass_active"] = err.Error()
		} else {
			pr.ToolResults["amass_active"] = amassResult
			pr.Findings += amassResult.TotalDiscovered
		}
	}

	pr.Duration = time.Since(start)
	log.Printf("[autorecon] Phase 3 complete: %d findings in %s", pr.Findings, pr.Duration)
	return pr, nil
}

// Phase4Exploit performs exploitation actions against target. This phase
// is gated behind the ExploitOK flag — if disabled, the phase returns an
// error. Only D阶 (destructive/exploitation) tools are run here.
func (ar *AutoRecon) Phase4Exploit(target string) (*PhaseResult, error) {
	if !ar.ExploitOK {
		return nil, fmt.Errorf("autorecon: Phase 4 (exploit) is disabled — set ExploitOK=true to enable")
	}

	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("autorecon: %w", err)
	}

	start := time.Now()
	pr := &PhaseResult{
		PhaseNum:    4,
		ToolResults: make(map[string]interface{}),
	}

	log.Printf("[autorecon] Phase 4 (exploit) starting for %s", target)

	// SQLMap scan.
	if sqlmapResult, err := ar.sqlmap.Scan(target); err != nil {
		log.Printf("[autorecon] sqlmap: %v", err)
		pr.ToolResults["sqlmap"] = err.Error()
	} else {
		pr.ToolResults["sqlmap"] = sqlmapResult
		pr.Findings += len(sqlmapResult)
	}

	// Hydra brute force on SSH (port 22).
	if hydraResult, err := ar.hydra.BruteSSH(target); err != nil {
		log.Printf("[autorecon] hydra: %v", err)
		pr.ToolResults["hydra"] = err.Error()
	} else {
		pr.ToolResults["hydra"] = hydraResult
		pr.Findings += len(hydraResult)
	}

	pr.Duration = time.Since(start)
	log.Printf("[autorecon] Phase 4 complete: %d findings in %s", pr.Findings, pr.Duration)
	return pr, nil
}

// RunAll executes all four reconnaissance phases against target and
// returns a consolidated ReconReport. Phases that fail are recorded
// with their error but do not abort the remaining phases.
func (ar *AutoRecon) RunAll(target string) (*ReconReport, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("autorecon: %w", err)
	}

	report := &ReconReport{Target: target}

	// Phase 1: Passive.
	if pr, err := ar.Phase1Passive(target); err != nil {
		log.Printf("[autorecon] phase 1 error: %v", err)
	} else {
		report.Phases = append(report.Phases, *pr)
		report.TotalFindings += pr.Findings
	}

	// Phase 2: Active.
	if pr, err := ar.Phase2Active(target); err != nil {
		log.Printf("[autorecon] phase 2 error: %v", err)
	} else {
		report.Phases = append(report.Phases, *pr)
		report.TotalFindings += pr.Findings
	}

	// Phase 3: Deep.
	if pr, err := ar.Phase3Deep(target); err != nil {
		log.Printf("[autorecon] phase 3 error: %v", err)
	} else {
		report.Phases = append(report.Phases, *pr)
		report.TotalFindings += pr.Findings
	}

	// Phase 4: Exploit (best-effort if enabled).
	if ar.ExploitOK {
		if pr, err := ar.Phase4Exploit(target); err != nil {
			log.Printf("[autorecon] phase 4 error: %v", err)
		} else {
			report.Phases = append(report.Phases, *pr)
			report.TotalFindings += pr.Findings
		}
	}

	report.RiskScore = computeRiskScore(report)
	log.Printf("[autorecon] full recon complete for %s: %d findings, risk %.1f",
		target, report.TotalFindings, report.RiskScore)

	return report, nil
}

// computeRiskScore derives a 0-100 risk score from the total findings
// count and composition of the report.
func computeRiskScore(report *ReconReport) float64 {
	if report.TotalFindings == 0 {
		return 0
	}

	// Simple heuristic: each finding contributes up to 10 points,
	// capped at 100, scaled by phase depth.
	var score float64
	for _, phase := range report.Phases {
		weight := float64(phase.PhaseNum) * 0.25 // phases 1-4 weighted 0.25-1.0
		score += float64(phase.Findings) * weight * 10
	}

	if score > 100 {
		score = 100
	}
	if score < 1 && report.TotalFindings > 0 {
		score = 1
	}

	return score
}

// isHTTP returns true if target appears to be an HTTP-based target
// (has port 80/443 or starts with http scheme).
func isHTTP(target string) bool {
	return hasScheme(target) ||
		hasPortSuffix(target, "80") ||
		hasPortSuffix(target, "443")
}

// hasScheme returns true if target starts with http:// or https://.
func hasScheme(target string) bool {
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}

// hasPortSuffix returns true if target ends with ":port".
func hasPortSuffix(target, port string) bool {
	suffix := ":" + port
	return len(target) > len(suffix) && target[len(target)-len(suffix):] == suffix
}

// isDomainish returns true if target looks like a domain name rather
// than a bare IP address.
func isDomainish(target string) bool {
	// Strip scheme if present.
	t := target
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	// Strip port suffix if present.
	for i := len(t) - 1; i >= 0; i-- {
		if t[i] == ':' {
			t = t[:i]
			break
		}
	}
	// If it contains a letter, it's a domain (IPs are all digits and dots).
	for _, c := range t {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}
