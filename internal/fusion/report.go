package fusion

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity levels for findings.
const (
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
	SeverityInfo     = "Info"
)

// severityOrder maps severity strings to numeric ordering (lower is
// more severe).
var severityOrder = map[string]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

// Finding represents a single security finding across any tool.
type Finding struct {
	ID           string `json:"id"`
	Tool         string `json:"tool"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Evidence     string `json:"evidence,omitempty"`
	Remediation  string `json:"remediation,omitempty"`
}

// FusionReport is the unified scan report format that aggregates
// results from all fusion tools.
type FusionReport struct {
	Target    string                 `json:"target"`
	Timestamp time.Time              `json:"timestamp"`
	Scanners  map[string]interface{} `json:"scanners"`
	Findings  []Finding              `json:"findings"`
}

// MergeFindings merges multiple Finding slices, deduplicating entries
// that share the same or similar title. The first occurrence of each
// title is kept; subsequent duplicates are dropped.
func MergeFindings(findings ...[]Finding) []Finding {
	merged := make([]Finding, 0, len(findings)*2)
	seen := make(map[string]bool)

	for _, batch := range findings {
		for _, f := range batch {
			key := dedupKey(f.Title)
			if seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, f)
		}
	}

	// Sort by severity (critical first), then by title.
	sort.Slice(merged, func(i, j int) bool {
		si, iok := severityOrder[merged[i].Severity]
		sj, jok := severityOrder[merged[j].Severity]
		if !iok {
			si = 99
		}
		if !jok {
			sj = 99
		}
		if si != sj {
			return si < sj
		}
		return merged[i].Title < merged[j].Title
	})

	return merged
}

// dedupKey normalizes a finding title for deduplication by lowercasing
// and stripping whitespace.
func dedupKey(title string) string {
	return strings.ToLower(strings.TrimSpace(title))
}

// FormatMarkdown renders a FusionReport as a human-readable Markdown
// document suitable for pasting into tickets or sharing with stakeholders.
func FormatMarkdown(report FusionReport) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Fusion Scan Report\n\n")
	fmt.Fprintf(&b, "**Target:** %s\n", report.Target)
	fmt.Fprintf(&b, "**Timestamp:** %s\n", report.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "**Total Findings:** %d\n\n", len(report.Findings))

	// Severity summary.
	counts := SeverityCounts(report.Findings)
	fmt.Fprintf(&b, "## Severity Summary\n\n")
	fmt.Fprintf(&b, "| Severity | Count |\n")
	fmt.Fprintf(&b, "|----------|-------|\n")
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		if count, ok := counts[sev]; ok {
			fmt.Fprintf(&b, "| %s | %d |\n", sev, count)
		}
	}
	fmt.Fprintf(&b, "\n")

	// Findings by severity.
	fmt.Fprintf(&b, "## Findings\n\n")
	currentSev := ""
	for _, f := range report.Findings {
		if f.Severity != currentSev {
			currentSev = f.Severity
			fmt.Fprintf(&b, "### %s\n\n", currentSev)
		}
		fmt.Fprintf(&b, "#### %s\n", f.Title)
		fmt.Fprintf(&b, "- **Tool:** %s\n", f.Tool)
		fmt.Fprintf(&b, "- **ID:** %s\n", f.ID)
		if f.Description != "" {
			fmt.Fprintf(&b, "- **Description:** %s\n", f.Description)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "- **Evidence:** `%s`\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "- **Remediation:** %s\n", f.Remediation)
		}
		fmt.Fprintf(&b, "\n")
	}

	// Scanner summary.
	if len(report.Scanners) > 0 {
		fmt.Fprintf(&b, "## Scanner Details\n\n")
		for name := range report.Scanners {
			fmt.Fprintf(&b, "- %s\n", name)
		}
		fmt.Fprintf(&b, "\n")
	}

	return b.String()
}

// FormatJSON serializes a FusionReport as pretty-printed JSON.
func FormatJSON(report FusionReport) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: marshal JSON: %w", err)
	}
	return data, nil
}

// FormatSARIF renders a FusionReport as a SARIF v2.1.0 document suitable
// for ingestion by CI/CD systems, GitHub code scanning, and other SARIF-
// compatible tools.
func FormatSARIF(report FusionReport) ([]byte, error) {
	type sarifResult struct {
		RuleID    string `json:"ruleId"`
		Level     string `json:"level"`
		Message   struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}

	type sarifRun struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}

	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	// Map fortress severity to SARIF level.
	sevToLevel := map[string]string{
		SeverityCritical: "error",
		SeverityHigh:     "error",
		SeverityMedium:   "warning",
		SeverityLow:      "warning",
		SeverityInfo:     "note",
	}

	var results []sarifResult
	for _, f := range report.Findings {
		level, ok := sevToLevel[f.Severity]
		if !ok {
			level = "warning"
		}

		r := sarifResult{
			RuleID: fmt.Sprintf("%s/%s", f.Tool, f.ID),
			Level:  level,
		}
		r.Message.Text = f.Title
		if f.Description != "" {
			r.Message.Text += ": " + f.Description
		}

		r.Locations = []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		}{
			{
				PhysicalLocation: struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				}{
					ArtifactLocation: struct {
						URI string `json:"uri"`
					}{
						URI: report.Target,
					},
				},
			},
		}

		results = append(results, r)
	}

	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Results: results,
			},
		},
	}
	doc.Runs[0].Tool.Driver.Name = "Fortress Fusion"
	doc.Runs[0].Tool.Driver.Version = "6.0"

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: marshal SARIF JSON: %w", err)
	}
	return data, nil
}

// SeverityCounts returns a map of severity level to count for a slice
// of findings.
func SeverityCounts(findings []Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// NewFusionReport creates a FusionReport initialized with the current
// timestamp and empty scanners/findings maps.
func NewFusionReport(target string) *FusionReport {
	return &FusionReport{
		Target:    target,
		Timestamp: time.Now().UTC(),
		Scanners:  make(map[string]interface{}),
		Findings:  make([]Finding, 0),
	}
}

// AddFindings appends findings to the report and deduplicates.
func (r *FusionReport) AddFindings(findings ...Finding) {
	r.Findings = MergeFindings(r.Findings, findings)
}

// AddScannerResult records a scanner's output in the report for inclusion
// in the scanner details section.
func (r *FusionReport) AddScannerResult(name string, result interface{}) {
	r.Scanners[name] = result
}

// MapSeverity normalizes tool-specific severity strings to the standard
// Fusion severity scale.
func MapSeverity(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(normalized, "critical"):
		return SeverityCritical
	case strings.Contains(normalized, "high"):
		return SeverityHigh
	case strings.Contains(normalized, "medium") || strings.Contains(normalized, "moderate"):
		return SeverityMedium
	case strings.Contains(normalized, "low"):
		return SeverityLow
	case strings.Contains(normalized, "info") || strings.Contains(normalized, "none"):
		return SeverityInfo
	default:
		return SeverityInfo
	}
}
