package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFIMComputeHash(t *testing.T) {
	// Create temp file with known content
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := "hello world"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	// SHA256
	hash, err := computeHash(path, "sha256")
	if err != nil {
		t.Fatalf("computeHash failed: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("expected sha256 hash length 64, got %d", len(hash))
	}

	// SHA1
	hash, err = computeHash(path, "sha1")
	if err != nil {
		t.Fatalf("computeHash(sha1) failed: %v", err)
	}
	if len(hash) != 40 {
		t.Errorf("expected sha1 hash length 40, got %d", len(hash))
	}

	// MD5
	hash, err = computeHash(path, "md5")
	if err != nil {
		t.Fatalf("computeHash(md5) failed: %v", err)
	}
	if len(hash) != 32 {
		t.Errorf("expected md5 hash length 32, got %d", len(hash))
	}

	// Default (sha256)
	hash, err = computeHash(path, "")
	if err != nil {
		t.Fatalf("computeHash(default) failed: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("expected default hash length 64, got %d", len(hash))
	}
}

func TestFIMComputeScore(t *testing.T) {
	tests := []struct {
		path     string
		expected float64
	}{
		{"/etc/passwd", 80},
		{"/etc/shadow", 80},
		{"/etc/ssh/sshd_config", 80},
		{"/bin/bash", 90},
		{"/usr/bin/python3", 90},
		{"/bin/ls", 90},
		{"/var/log/syslog", 20},
		{"/var/log/auth.log", 20},
		{"/tmp/random.txt", 40},
		{"/home/user/file.txt", 40},
		{"/opt/app/config.yaml", 40},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			score := computeScore(tt.path)
			if score != tt.expected {
				t.Errorf("computeScore(%q) = %f, want %f", tt.path, score, tt.expected)
			}
		})
	}
}

func TestFIMNewFileDetected(t *testing.T) {
	dir := t.TempDir()

	// Create an initial file so baseline is not empty
	initialFile := filepath.Join(dir, "initial.txt")
	if err := os.WriteFile(initialFile, []byte("initial"), 0644); err != nil {
		t.Fatalf("failed to create initial file: %v", err)
	}

	cfg := FIMConfig{
		WatchPaths:   []string{dir},
		ExcludePaths: []string{},
		HashAlgo:     "sha256",
		ScanInterval: "1h",
	}
	fim := NewFIMMonitor(cfg)

	// Build baseline
	fim.scan()

	// Create a new file after baseline
	newFile := filepath.Join(dir, "new.txt")
	if err := os.WriteFile(newFile, []byte("new content"), 0644); err != nil {
		t.Fatalf("failed to create new file: %v", err)
	}

	// Scan for changes
	alertCh := make(chan HostAlert, 10)
	fim.scanAndDiff(alertCh)
	close(alertCh)

	found := false
	for alert := range alertCh {
		if alert.Type == "fim" && strings.Contains(alert.Message, "File created") && strings.Contains(alert.Message, "new.txt") {
			found = true
			if alert.Severity != 3 {
				t.Errorf("expected severity 3 for new file, got %d", alert.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected 'File created' alert for new.txt, but none found")
	}
}

func TestFIMFileModified(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "monitored.txt")

	// Create file and build baseline
	if err := os.WriteFile(filePath, []byte("original content"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := FIMConfig{
		WatchPaths:   []string{dir},
		ExcludePaths: []string{},
		HashAlgo:     "sha256",
		ScanInterval: "1h",
	}
	fim := NewFIMMonitor(cfg)
	fim.scan()

	// Modify the file
	time.Sleep(time.Millisecond) // ensure different modtime
	if err := os.WriteFile(filePath, []byte("modified content"), 0644); err != nil {
		t.Fatalf("failed to modify file: %v", err)
	}

	// Scan for changes
	alertCh := make(chan HostAlert, 10)
	fim.scanAndDiff(alertCh)
	close(alertCh)

	found := false
	for alert := range alertCh {
		if alert.Type == "fim" && strings.Contains(alert.Message, "File modified") && strings.Contains(alert.Message, "monitored.txt") {
			found = true
			if alert.Severity != 4 {
				t.Errorf("expected severity 4 for modified file, got %d", alert.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected 'File modified' alert for monitored.txt, but none found")
	}
}

func TestFIMFileDeleted(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "todelete.txt")

	// Create file and build baseline
	if err := os.WriteFile(filePath, []byte("delete me"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := FIMConfig{
		WatchPaths:   []string{dir},
		ExcludePaths: []string{},
		HashAlgo:     "sha256",
		ScanInterval: "1h",
	}
	fim := NewFIMMonitor(cfg)
	fim.scan()

	// Delete the file
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("failed to delete file: %v", err)
	}

	// Scan for changes
	alertCh := make(chan HostAlert, 10)
	fim.scanAndDiff(alertCh)
	close(alertCh)

	found := false
	for alert := range alertCh {
		if alert.Type == "fim" && strings.Contains(alert.Message, "File deleted") && strings.Contains(alert.Message, "todelete.txt") {
			found = true
			if alert.Severity != 5 {
				t.Errorf("expected severity 5 for deleted file, got %d", alert.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected 'File deleted' alert for todelete.txt, but none found")
	}
}

func TestFIMExcludePaths(t *testing.T) {
	dir := t.TempDir()
	watchDir := filepath.Join(dir, "watch")
	excludeDir := filepath.Join(dir, "exclude")

	if err := os.MkdirAll(watchDir, 0755); err != nil {
		t.Fatalf("failed to create watch dir: %v", err)
	}
	if err := os.MkdirAll(excludeDir, 0755); err != nil {
		t.Fatalf("failed to create exclude dir: %v", err)
	}

	// Create a file in the watch dir
	watchFile := filepath.Join(watchDir, "watch.txt")
	if err := os.WriteFile(watchFile, []byte("watch me"), 0644); err != nil {
		t.Fatalf("failed to create watch file: %v", err)
	}

	// Create a file in the excluded dir
	excludeFile := filepath.Join(excludeDir, "excluded.txt")
	if err := os.WriteFile(excludeFile, []byte("exclude me"), 0644); err != nil {
		t.Fatalf("failed to create excluded file: %v", err)
	}

	cfg := FIMConfig{
		WatchPaths:   []string{dir},
		ExcludePaths: []string{excludeDir},
		HashAlgo:     "sha256",
		ScanInterval: "1h",
	}
	fim := NewFIMMonitor(cfg)

	// Build baseline (should skip excluded)
	fim.scan()

	// Check baseline has watch file but not excluded file
	fim.mu.RLock()
	if _, ok := fim.baseline[watchFile]; !ok {
		t.Error("expected watch file in baseline, but not found")
	}
	if _, ok := fim.baseline[excludeFile]; ok {
		t.Error("expected excluded file NOT in baseline, but it was found")
	}
	fim.mu.RUnlock()

	// Now modify the excluded file and scan for changes - should not generate alerts
	if err := os.WriteFile(excludeFile, []byte("changed content"), 0644); err != nil {
		t.Fatalf("failed to modify excluded file: %v", err)
	}

	alertCh := make(chan HostAlert, 10)
	fim.scanAndDiff(alertCh)
	close(alertCh)

	for alert := range alertCh {
		if strings.Contains(alert.Message, "excluded.txt") {
			t.Errorf("unexpected alert for excluded file: %s", alert.Message)
		}
	}
}

func TestFIMTruncate(t *testing.T) {
	tests := []struct {
		input    string
		n        int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello", 3, "hel"},
		{"", 5, ""},
		{"abc", 0, ""},
		{"short", 5, "short"},
	}
	for _, tt := range tests {
		result := truncate(tt.input, tt.n)
		if result != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.n, result, tt.expected)
		}
	}
}

func TestFIMSendAlertNonBlocking(t *testing.T) {
	// Channel with small buffer should not block
	ch := make(chan HostAlert, 2)

	sendAlert(ch, HostAlert{Type: "fim", Severity: 3, Message: "alert 1"})
	sendAlert(ch, HostAlert{Type: "fim", Severity: 4, Message: "alert 2"})
	// Third send should not block even though buffer is full
	sendAlert(ch, HostAlert{Type: "fim", Severity: 5, Message: "alert 3 (dropped)"})

	close(ch)
	count := 0
	for range ch {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 alerts (buffer size), got %d", count)
	}
}

func TestFIMHashConsistency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")

	// Write binary data
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Compute hash twice - must be identical
	h1, err := computeHash(path, "sha256")
	if err != nil {
		t.Fatalf("first computeHash failed: %v", err)
	}
	h2, err := computeHash(path, "sha256")
	if err != nil {
		t.Fatalf("second computeHash failed: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash not deterministic: %s != %s", h1, h2)
	}
}
