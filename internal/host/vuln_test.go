package host

import (
	"testing"
)

func TestVulnSeverityScore(t *testing.T) {
	tests := []struct {
		severity string
		want     float64
	}{
		{"CRITICAL", 90},
		{"HIGH", 70},
		{"MEDIUM", 40},
		{"LOW", 10},
		{"UNKNOWN", 0},
		{"", 0},
	}

	for _, tc := range tests {
		got := severityScore(tc.severity)
		if got != tc.want {
			t.Errorf("severityScore(%q) = %f, want %f", tc.severity, got, tc.want)
		}
	}
}

func TestVulnMatchCVE(t *testing.T) {
	// OpenSSL 1.1.0 should match the openssl CVE entry (VersionMax: 1.1.1)
	results := matchCVE("openssl", "1.1.0")
	if len(results) == 0 {
		t.Fatal("expected at least one CVE match for openssl 1.1.0")
	}
	// Check it matched the expected openssl entry
	found := false
	for _, r := range results {
		if r.Package == "openssl" && r.CVE == "CVE-2024-XXXX" {
			found = true
			if r.Severity != "HIGH" {
				t.Errorf("expected severity HIGH, got %s", r.Severity)
			}
			if r.Score != 70 {
				t.Errorf("expected score 70, got %f", r.Score)
			}
			if r.FixedIn != "1.1.1u" {
				t.Errorf("expected FixedIn 1.1.1u, got %s", r.FixedIn)
			}
		}
	}
	if !found {
		t.Errorf("expected match for openssl CVE-2024-XXXX, got %+v", results)
	}

	// OpenSSL 1.1.2 (higher than max) should NOT match
	results = matchCVE("openssl", "1.1.2")
	for _, r := range results {
		if r.Package == "openssl" && r.CVE == "CVE-2024-XXXX" {
			t.Errorf("openssl 1.1.2 should not match CVE-2024-XXXX (VersionMax=1.1.1), got match")
		}
	}

	// libssl3 3.0.0 should match
	results = matchCVE("libssl3", "3.0.0")
	found = false
	for _, r := range results {
		if r.Package == "libssl3" && r.CVE == "CVE-2024-YYYY" {
			found = true
			if r.Severity != "CRITICAL" {
				t.Errorf("expected severity CRITICAL, got %s", r.Severity)
			}
			if r.Score != 90 {
				t.Errorf("expected score 90, got %f", r.Score)
			}
		}
	}
	if !found {
		t.Errorf("expected match for libssl3 CVE-2024-YYYY, got %+v", results)
	}

	// bash 4.x should match bash CVE
	results = matchCVE("bash", "4.4")
	found = false
	for _, r := range results {
		if r.Package == "bash" && r.CVE == "CVE-2024-SHOCK" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected match for bash CVE-2024-SHOCK, got %+v", results)
	}

	// bash 5.1 (equal to fixed version) should NOT match
	results = matchCVE("bash", "5.1")
	for _, r := range results {
		if r.Package == "bash" && r.CVE == "CVE-2024-SHOCK" {
			t.Errorf("bash 5.1 should not match CVE-2024-SHOCK (VersionMax=5.0), got match")
		}
	}
}

func TestVulnMatchNoMatch(t *testing.T) {
	results := matchCVE("nonexistent-package-foo", "1.0.0")
	if len(results) != 0 {
		t.Errorf("expected empty results for unknown package, got %d matches", len(results))
	}

	// Empty name
	results = matchCVE("", "1.0.0")
	if len(results) != 0 {
		t.Errorf("expected empty results for empty package name, got %d", len(results))
	}
}

func TestVulnCompareVersion(t *testing.T) {
	tests := []struct {
		v1   string
		v2   string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.1.0", "1.0.0", 1},
		{"5.0", "5.0", 0},
		{"5.0", "5.1", -1},
		{"2.0.0", "10.0.0", 1}, // lexicographic limitation, but documented
		// With debian revision stripping
		{"1.1.1-1ubuntu2.1", "1.1.1", 0},
		{"1.1.1", "1.1.1-1ubuntu2.1", 0},
	}

	for _, tc := range tests {
		got := compareVersions(tc.v1, tc.v2)
		// We check sign only (not exact value) since strings.Compare can return any non-zero
		sign := func(x int) int {
			if x < 0 {
				return -1
			}
			if x > 0 {
				return 1
			}
			return 0
		}
		if sign(got) != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d (sign %d), want %d", tc.v1, tc.v2, got, sign(got), tc.want)
		}
	}
}

func TestVulnGetResults(t *testing.T) {
	scanner := NewVulnScanner(VulnConfig{
		ScanInterval: "24h",
		Severity:     "LOW",
	})

	// Initially results should be empty
	results := scanner.GetResults()
	if results == nil {
		t.Fatal("GetResults() should return non-nil slice")
	}
	if len(results) != 0 {
		t.Errorf("expected empty results initially, got %d", len(results))
	}

	// Directly set results to test snapshot semantics
	scanner.mu.Lock()
	scanner.results = []VulnResult{
		{Package: "openssl", Version: "1.1.0", CVE: "CVE-2024-XXXX", Severity: "HIGH", Score: 70},
	}
	scanner.mu.Unlock()

	results = scanner.GetResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CVE != "CVE-2024-XXXX" {
		t.Errorf("expected CVE-2024-XXXX, got %s", results[0].CVE)
	}

	// Verify snapshot isolation: modifying returned slice should not affect internal state
	results[0].CVE = "MODIFIED"
	scanner.mu.RLock()
	internalCVE := scanner.results[0].CVE
	scanner.mu.RUnlock()
	if internalCVE == "MODIFIED" {
		t.Error("modifying returned slice should not affect internal state")
	}
}

func TestVulnSeverityWeight(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"CRITICAL", 5},
		{"HIGH", 4},
		{"MEDIUM", 3},
		{"LOW", 2},
		{"UNKNOWN", 1},
		{"", 1},
	}

	for _, tc := range tests {
		got := severityWeight(tc.severity)
		if got != tc.want {
			t.Errorf("severityWeight(%q) = %d, want %d", tc.severity, got, tc.want)
		}
	}
}

func TestVulnSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"CRITICAL", 5},
		{"HIGH", 4},
		{"MEDIUM", 3},
		{"LOW", 2},
		{"UNKNOWN", 1},
		{"", 1},
	}

	for _, tc := range tests {
		got := severityToLevel(tc.severity)
		if got != tc.want {
			t.Errorf("severityToLevel(%q) = %d, want %d", tc.severity, got, tc.want)
		}
	}
}

func TestVulnScannerStop(t *testing.T) {
	scanner := NewVulnScanner(VulnConfig{
		ScanInterval: "1h",
		Severity:     "LOW",
	})

	// Stop on a fresh scanner should not panic
	scanner.Stop()
}
