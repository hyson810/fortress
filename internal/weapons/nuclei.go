package weapons

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/fortress/v6/internal/config"
)

// NucleiFinding represents a single vulnerability finding
type NucleiFinding struct {
	Template  string `json:"template-id"`
	Name      string `json:"name"`
	Severity  string `json:"severity"`
	MatchedAt string `json:"matched-at,omitempty"`
	Host      string `json:"host,omitempty"`
}

// NucleiResult wraps nuclei scan output
type NucleiResult struct {
	Target   string           `json:"target"`
	Findings []NucleiFinding  `json:"findings"`
	Critical int              `json:"critical"`
	High     int              `json:"high"`
	Medium   int              `json:"medium"`
	Total    int              `json:"total"`
}

// Nuclei wraps the nuclei binary
type Nuclei struct {
	BinPath string
}

// NewNuclei creates a nuclei weapon
func NewNuclei(binPath string) *Nuclei {
	return &Nuclei{BinPath: binPath}
}

// Scan runs nuclei against a target URL
func (n *Nuclei) Scan(target string) (*NucleiResult, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}

	// If target is IP, try both http and https
	urls := []string{target}
	if !strings.HasPrefix(target, "http") {
		urls = []string{
			"http://" + target,
			"https://" + target,
		}
	}

	result := &NucleiResult{Target: target}
	seen := make(map[string]bool)

	for _, url := range urls {
		cmd := exec.Command(n.BinPath,
			"-u", url,
			"-severity", "critical,high,medium",
			"-silent",
			"-json",
			"-timeout", "10",
		)
		output, err := cmd.CombinedOutput()
		if err != nil && len(output) == 0 {
			continue
		}

		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			var finding NucleiFinding
			if err := json.Unmarshal([]byte(line), &finding); err != nil {
				continue
			}

			// Dedup
			if seen[finding.Template] {
				continue
			}
			seen[finding.Template] = true

			result.Findings = append(result.Findings, finding)
			switch finding.Severity {
			case "critical": result.Critical++
			case "high":     result.High++
			case "medium":   result.Medium++
			}
		}
	}

	result.Total = len(result.Findings)
	return result, nil
}

// Summary returns a one-line summary
func (r *NucleiResult) Summary() string {
	if r.Total == 0 {
		return fmt.Sprintf("nuclei: 0 findings on %s", r.Target)
	}
	return fmt.Sprintf("nuclei: %d vulns (%dC/%dH/%dM) on %s",
		r.Total, r.Critical, r.High, r.Medium, r.Target)
}
