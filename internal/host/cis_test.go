package host

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCISCheckFileMode(t *testing.T) {
	dir := t.TempDir()

	file := filepath.Join(dir, "testfile")
	if err := os.WriteFile(file, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	if !checkFileMode(file, 0644) {
		t.Error("expected checkFileMode to return true for 0644 file with 0644 expected")
	}

	if checkFileMode(file, 0600) {
		t.Error("expected checkFileMode to return false for 0644 file with 0600 expected")
	}

	if checkFileMode(filepath.Join(dir, "nonexistent"), 0644) {
		t.Error("expected checkFileMode to return false for non-existent file")
	}
}

func TestCISCheckCommandExists(t *testing.T) {
	if !checkCommandExists("ls") {
		t.Error("expected checkCommandExists('ls') to return true")
	}
}

func TestCISCheckCommandNotExists(t *testing.T) {
	if checkCommandExists("nonexistent_cmd_xyzzy_abc123") {
		t.Error("expected checkCommandExists to return false for bogus command")
	}
}

func TestCISDefaultChecks(t *testing.T) {
	if len(cisChecks) != 10 {
		t.Fatalf("expected exactly 10 CIS checks, got %d", len(cisChecks))
	}

	for _, check := range cisChecks {
		if check.ID == "" {
			t.Error("check has empty ID")
		}
		if check.Title == "" {
			t.Errorf("check %s has empty Title", check.ID)
		}
		if check.Description == "" {
			t.Errorf("check %s has empty Description", check.ID)
		}
		if check.Remediation == "" {
			t.Errorf("check %s has empty Remediation", check.ID)
		}
		if check.Level != 1 && check.Level != 2 {
			t.Errorf("check %s has invalid Level: %d", check.ID, check.Level)
		}
		if check.Fn == nil {
			t.Errorf("check %s has nil Fn", check.ID)
		}
	}
}

func TestCISGetResults(t *testing.T) {
	cfg := CISConfig{Interval: "1h", Profile: "level_1"}
	checker := NewCISChecker(cfg)

	results := checker.GetResults()
	if len(results) != 0 {
		t.Errorf("expected empty results before running, got %d", len(results))
	}
}
