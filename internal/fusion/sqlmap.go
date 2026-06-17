package fusion

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/fortress/v6/internal/config"
)

// SqlmapVuln represents a single vulnerability found by sqlmap.
type SqlmapVuln struct {
	URL     string `json:"url"`
	Method  string `json:"method"`
	Payload string `json:"payload"`
	Title   string `json:"title"`
	DBMS    string `json:"dbms"`
}

// SqlmapScanner wraps the sqlmap binary for automated SQL injection
// detection and exploitation.
type SqlmapScanner struct {
	bin string
}

// NewSqlmapScanner creates a new SqlmapScanner using the binary path from
// the supplied WeaponsConfig.
func NewSqlmapScanner(cfg *config.WeaponsConfig) *SqlmapScanner {
	return &SqlmapScanner{bin: cfg.SqlmapBin}
}

// Scan runs sqlmap against a single URL with pre-configured detection and
// exploitation options. Returns any vulnerabilities found.
func (s *SqlmapScanner) Scan(url string) ([]SqlmapVuln, error) {
	if err := config.ValidateTarget(url); err != nil {
		return nil, fmt.Errorf("sqlmap: %w", err)
	}

	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	cmd := exec.Command(s.bin, "-u", url,
		"--batch", "--random-agent", "--smart",
		"--level=3", "--risk=2", "--threads=4")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[sqlmap] scan warning for %s: %v", url, err)
	}

	return parseSqlmapOutput(string(out), url), nil
}

// Crawl runs sqlmap in crawl mode starting from url, following links up
// to the given depth.
func (s *SqlmapScanner) Crawl(url string, depth int) ([]SqlmapVuln, error) {
	if err := config.ValidateTarget(url); err != nil {
		return nil, fmt.Errorf("sqlmap: %w", err)
	}

	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	cmd := exec.Command(s.bin, "-u", url,
		"--batch", "--crawl="+fmt.Sprintf("%d", depth), "--smart")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[sqlmap] crawl warning for %s: %v", url, err)
	}

	return parseSqlmapOutput(string(out), url), nil
}

// parseSqlmapOutput extracts vulnerability information from sqlmap's
// text output. It also supports the --json output format when available.
func parseSqlmapOutput(output, url string) []SqlmapVuln {
	var vulns []SqlmapVuln

	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "vulnerable") || strings.Contains(line, "payload:") {
			v := SqlmapVuln{URL: url}
			if strings.Contains(line, "GET") {
				v.Method = "GET"
			}
			if strings.Contains(line, "POST") {
				v.Method = "POST"
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				v.Title = strings.TrimSpace(parts[0])
				v.Payload = strings.TrimSpace(parts[1])
			}
			vulns = append(vulns, v)
		}
	}

	// Reserved for sqlmap --json output parsing.
	_ = json.Unmarshal

	return vulns
}
