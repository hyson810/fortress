// Package brain implements the Fortress AI engine: threat scoring, pattern
// recognition, and predictive defense.
//
// predict.go provides predictive vulnerability analysis ("杀器5 预知防御")
// that scans source code for known-dangerous CWE patterns and maps service
// banners to likely CVE classes — enabling proactive defense before a CVE
// is even published.
package brain

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// CWEPattern — maps a CWE ID to compiled detection patterns and CVSS score
// ---------------------------------------------------------------------------

// CWEPattern maps a CWE ID to compiled detection patterns and CVSS score.
type CWEPattern struct {
	CWE         string
	Title       string
	CVSS        float64
	Patterns    []*regexp.Regexp
	Languages   []string
	Description string
}

// ---------------------------------------------------------------------------
// Prediction — a concrete finding
// ---------------------------------------------------------------------------

// Prediction represents a predicted vulnerability.
type Prediction struct {
	CWE        string  `json:"cwe"`
	Title      string  `json:"title"`
	RiskScore  float64 `json:"risk_score"`
	File       string  `json:"file,omitempty"`
	Service    string  `json:"service,omitempty"`
	Line       int     `json:"line,omitempty"`
	Confidence float64 `json:"confidence"`
	EBPFRule   string  `json:"ebpf_rule,omitempty"`
}

// ---------------------------------------------------------------------------
// BannerRule — maps service banners to known CWE classes
// ---------------------------------------------------------------------------

// BannerRule maps a service banner to known CWE classes.
type BannerRule struct {
	Pattern    string
	CWEs       []string
	Confidence float64
}

// ---------------------------------------------------------------------------
// PredictiveEngine — the core predictor
// ---------------------------------------------------------------------------

// PredictiveEngine analyzes source code and service banners to predict
// likely vulnerabilities before they are exploited.
//
// All exported methods are safe for concurrent use.
type PredictiveEngine struct {
	mu          sync.RWMutex
	patterns    []CWEPattern
	bannerRules []BannerRule
	predictions map[string][]Prediction
}

// NewPredictiveEngine creates a PredictiveEngine pre-loaded with 12 CWE
// patterns and banner-matching rules.
func NewPredictiveEngine() *PredictiveEngine {
	pe := &PredictiveEngine{
		predictions: make(map[string][]Prediction),
	}
	pe.loadPatterns()
	pe.loadBannerRules()
	return pe
}

// ---------------------------------------------------------------------------
// loadPatterns — 12 CWE patterns covering the most exploited classes
// ---------------------------------------------------------------------------

// loadPatterns loads 12 CWE patterns covering the most exploited vulnerability classes.
func (pe *PredictiveEngine) loadPatterns() {
	pe.patterns = []CWEPattern{
		{
			CWE:       "CWE-89",
			Title:     "SQL Injection",
			CVSS:      9.8,
			Languages: []string{"php", "java", "python", "go", "js", "ruby", "csharp"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(execute\s*\(\s*["\x60].*\$|query\s*\(\s*["\x60].*\$|\.execute\(.*\+|db\.Query\(.*\+|mysql_query\()|rawQuery\(|createQuery\(`),
				regexp.MustCompile(`(?i)(SELECT\s+.*FROM\s+.*WHERE\s+.*\+|INSERT\s+INTO\s+.*\+|UPDATE\s+.*SET\s+.*\+)`),
				regexp.MustCompile(`(?i)(fmt\.Sprintf\s*\(\s*["\x60].*SELECT|fmt\.Sprintf\s*\(\s*["\x60].*INSERT)`),
			},
			Description: "SQL injection via unsanitized user input in database queries",
		},
		{
			CWE:       "CWE-79",
			Title:     "Cross-Site Scripting (XSS)",
			CVSS:      6.1,
			Languages: []string{"js", "ts", "php", "python", "ruby", "go", "java"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(innerHTML\s*=|document\.write\(|\.html\(.*\$|dangerouslySetInnerHTML)`),
				regexp.MustCompile(`(?i)(res\.send\(.*\+|response\.write\(.*\+|echo\s+.*\$)`),
			},
			Description: "XSS via unsanitized user input rendered in HTML",
		},
		{
			CWE:       "CWE-22",
			Title:     "Path Traversal",
			CVSS:      7.5,
			Languages: []string{"python", "php", "ruby", "go", "java", "js"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(os\.Open\(.*\+|open\(.*\+|file_get_contents\(.*\+|readFile\(.*\+|fs\.readFileSync\(.*\+)`),
				regexp.MustCompile(`(?i)(\.\./|\.\.\\)`),
			},
			Description: "Path traversal via unsanitized file path from user input",
		},
		{
			CWE:       "CWE-78",
			Title:     "Command Injection",
			CVSS:      9.8,
			Languages: []string{"python", "ruby", "php", "go", "js", "java"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(os\.system\(|subprocess\.|exec\(|child_process\.exec\(|Runtime\.exec\(|popen\(|shell_exec\(|passthru\()`),
				regexp.MustCompile(`(?i)(os\.exec\.Command\(.*\+|exec\.Command\(.*,)`),
			},
			Description: "Command injection via unsanitized user input in system calls",
		},
		{
			CWE:       "CWE-918",
			Title:     "Server-Side Request Forgery (SSRF)",
			CVSS:      7.5,
			Languages: []string{"python", "js", "go", "java", "php", "ruby"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(requests\.get\(.*\$|http\.Get\(.*\+|fetch\(.*\+|axios\.|\.get\(.*\+|curl_exec\(.*\+)`),
			},
			Description: "SSRF via user-controlled URL in HTTP requests",
		},
		{
			CWE:       "CWE-287",
			Title:     "Authentication Bypass",
			CVSS:      9.8,
			Languages: []string{"go", "js", "python", "java"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(if\s+err\s*!=\s*nil\s*{\s*return\s*nil)|if err != nil { return nil }`),
				regexp.MustCompile(`(?i)(auth\s*==\s*true|isAdmin\s*=\s*true|admin\s*=\s*true)`),
			},
			Description: "Authentication bypass via hardcoded credentials or weak checks",
		},
		{
			CWE:       "CWE-200",
			Title:     "Information Exposure",
			CVSS:      5.3,
			Languages: []string{"go", "js", "python", "java"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(fmt\.Printf\(.*err|console\.log\(.*err|print\(.*traceback|\.stack)`),
			},
			Description: "Sensitive information leaked via error messages or debug output",
		},
		{
			CWE:       "CWE-502",
			Title:     "Deserialization of Untrusted Data",
			CVSS:      8.1,
			Languages: []string{"python", "java", "php", "js", "ruby"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(pickle\.loads\(|yaml\.load\(|ObjectInputStream|unserialize\(|JSON\.parse\(.*req)`),
			},
			Description: "Insecure deserialization of user-controlled data",
		},
		{
			CWE:       "CWE-611",
			Title:     "XML External Entity (XXE)",
			CVSS:      7.5,
			Languages: []string{"java", "python", "php", "csharp"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(xml\.Unmarshal|DocumentBuilder|SimpleXMLElement|xml\.etree)`),
			},
			Description: "XXE via unsafe XML parser configuration",
		},
		{
			CWE:       "CWE-434",
			Title:     "Unrestricted File Upload",
			CVSS:      8.1,
			Languages: []string{"php", "python", "js", "go", "java"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(move_uploaded_file|\.save\(|fs\.writeFile\(|io\.Copy\(.*req\.Body)`),
			},
			Description: "Unrestricted file upload without type/extension validation",
		},
		{
			CWE:       "CWE-798",
			Title:     "Hardcoded Credentials",
			CVSS:      9.8,
			Languages: []string{"all"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(password\s*=\s*["\x60][^"\x60]{3,}["\x60]|secret\s*=\s*["\x60][^"\x60]{8,}["\x60]|api_key\s*=\s*["\x60][^"\x60]{8,}["\x60])`),
			},
			Description: "Hardcoded credentials or secrets in source code",
		},
		{
			CWE:       "CWE-416",
			Title:     "Use After Free",
			CVSS:      8.8,
			Languages: []string{"c", "cpp", "rust-unsafe"},
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(unsafe\s*\{.*free|free\(.*->|delete\s+\w+;\s*\w+\s*->)`),
			},
			Description: "Use-after-free in memory-unsafe code",
		},
	}
}

// ---------------------------------------------------------------------------
// loadBannerRules — service banner → CWE mapping heuristics
// ---------------------------------------------------------------------------

func (pe *PredictiveEngine) loadBannerRules() {
	pe.bannerRules = []BannerRule{
		{Pattern: "Apache/2.4", CWEs: []string{"CWE-22", "CWE-918", "CWE-200"}, Confidence: 0.3},
		{Pattern: "Apache/2.2", CWEs: []string{"CWE-22", "CWE-918", "CWE-200", "CWE-287"}, Confidence: 0.6},
		{Pattern: "OpenSSH", CWEs: []string{"CWE-287", "CWE-798"}, Confidence: 0.2},
		{Pattern: "nginx", CWEs: []string{"CWE-22", "CWE-200"}, Confidence: 0.2},
		{Pattern: "PHP/5", CWEs: []string{"CWE-89", "CWE-79", "CWE-22", "CWE-78", "CWE-502"}, Confidence: 0.8},
		{Pattern: "PHP/7", CWEs: []string{"CWE-89", "CWE-79", "CWE-78", "CWE-502"}, Confidence: 0.5},
		{Pattern: "MySQL", CWEs: []string{"CWE-89"}, Confidence: 0.4},
		{Pattern: "WordPress", CWEs: []string{"CWE-89", "CWE-79", "CWE-22", "CWE-287", "CWE-502"}, Confidence: 0.6},
		{Pattern: "Tomcat", CWEs: []string{"CWE-22", "CWE-200", "CWE-502"}, Confidence: 0.4},
		{Pattern: "Drupal", CWEs: []string{"CWE-89", "CWE-79", "CWE-22", "CWE-287", "CWE-502"}, Confidence: 0.5},
		{Pattern: "Postfix", CWEs: []string{"CWE-78", "CWE-200"}, Confidence: 0.3},
		{Pattern: "Exim", CWEs: []string{"CWE-78", "CWE-287"}, Confidence: 0.5},
	}
}

// ---------------------------------------------------------------------------
// AnalyzeFile — source code analysis
// ---------------------------------------------------------------------------

// AnalyzeFile scans source code for CWE patterns and returns risk predictions.
func (pe *PredictiveEngine) AnalyzeFile(path string, content []byte, language string) []Prediction {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	var predictions []Prediction
	lines := strings.Split(string(content), "\n")

	for _, cwe := range pe.patterns {
		langMatch := false
		for _, l := range cwe.Languages {
			if l == "all" || l == language {
				langMatch = true
				break
			}
		}
		if !langMatch {
			continue
		}

		for lineNum, line := range lines {
			for _, pat := range cwe.Patterns {
				if loc := pat.FindStringIndex(line); loc != nil {
					risk := (cwe.CVSS / 10.0) * 100
					predictions = append(predictions, Prediction{
						CWE: cwe.CWE, Title: cwe.Title, RiskScore: risk,
						File: path, Line: lineNum + 1, Confidence: 0.7,
						EBPFRule: pe.generateEBPFRule(cwe.CWE),
					})
					break // one match per line per CWE is enough
				}
			}
		}
	}

	// Store
	pe.predictions[path] = predictions
	return predictions
}

// ---------------------------------------------------------------------------
// AnalyzeService — banner-based analysis
// ---------------------------------------------------------------------------

// AnalyzeService checks a service banner against known vulnerable versions.
func (pe *PredictiveEngine) AnalyzeService(ip string, banner string, service string) []Prediction {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	var predictions []Prediction
	for _, rule := range pe.bannerRules {
		if strings.Contains(strings.ToLower(banner), strings.ToLower(rule.Pattern)) {
			for _, cweID := range rule.CWEs {
				for _, cwe := range pe.patterns {
					if cwe.CWE == cweID {
						risk := (cwe.CVSS / 10.0) * 100 * rule.Confidence * 2
						predictions = append(predictions, Prediction{
							CWE: cwe.CWE, Title: cwe.Title,
							RiskScore: risk, Service: service,
							Confidence: rule.Confidence,
							EBPFRule:  pe.generateEBPFRule(cwe.CWE),
						})
					}
				}
			}
		}
	}
	pe.predictions[ip] = predictions
	return predictions
}

// ---------------------------------------------------------------------------
// generateEBPFRule — kernel-level defense rules
// ---------------------------------------------------------------------------

func (pe *PredictiveEngine) generateEBPFRule(cwe string) string {
	rules := map[string]string{
		"CWE-89":  "xdp: drop tcp dport 3306,5432 payload match 'union.*select'",
		"CWE-79":  "tc: alert tcp dport 80,443 payload len > 256 && match '<script'",
		"CWE-22":  "tc: alert tcp payload match '../' || '..\\\\'",
		"CWE-78":  "xdp: alert tcp dport 22 payload match ';' || '|' || '`'",
		"CWE-918": "xdp: alert tcp dport 80,443 src not in whitelist dst in private_ranges",
		"CWE-287": "xdp: drop tcp dport 22,3389 burst > 10/min",
		"CWE-200": "tc: alert tcp payload match 'stack trace' || 'debug' || 'traceback'",
		"CWE-502": "tc: alert tcp dport 8080,8000 payload match 'pickle' || 'unserialize'",
		"CWE-611": "tc: alert tcp payload match '<!DOCTYPE' && match 'SYSTEM'",
		"CWE-434": "xdp: alert tcp dport 80,443 payload size > 1048576",
		"CWE-798": "xdp: alert tcp dport 22,3306 payload match 'password='",
		"CWE-416": "xdp: drop tcp all if cgroup not in whitelist",
	}
	if rule, ok := rules[cwe]; ok {
		return rule
	}
	return fmt.Sprintf("xdp: monitor tcp all // predicted CWE %s", cwe)
}

// ---------------------------------------------------------------------------
// Query methods
// ---------------------------------------------------------------------------

// GetHighRiskPredictions returns predictions with risk score above threshold.
func (pe *PredictiveEngine) GetHighRiskPredictions(threshold float64) []Prediction {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	var result []Prediction
	for _, preds := range pe.predictions {
		for _, p := range preds {
			if p.RiskScore >= threshold {
				result = append(result, p)
			}
		}
	}
	return result
}

// GetPredictionCount returns total stored predictions.
func (pe *PredictiveEngine) GetPredictionCount() int {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	count := 0
	for _, preds := range pe.predictions {
		count += len(preds)
	}
	return count
}

// ---------------------------------------------------------------------------
// Convenience entry points
// ---------------------------------------------------------------------------

// PredictFromCode performs a full predictive analysis on source code.
func (pe *PredictiveEngine) PredictFromCode(path, language string, content []byte) []Prediction {
	sum := sha256.Sum256(content)
	hash := fmt.Sprintf("%x", sum[:])
	_ = hash // for dedup in future
	return pe.AnalyzeFile(path, content, language)
}

// PredictFromBanner performs service-level prediction from a grabbed banner.
func (pe *PredictiveEngine) PredictFromBanner(ip, banner, service string) []Prediction {
	return pe.AnalyzeService(ip, banner, service)
}
