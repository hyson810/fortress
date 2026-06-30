package host

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileEntry stores file metadata for integrity tracking.
type FileEntry struct {
	Path    string
	Hash    string
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
}

// FIMMonitor periodically scans files and reports changes.
type FIMMonitor struct {
	cfg      FIMConfig
	baseline map[string]FileEntry // path -> entry
	mu       sync.RWMutex
	stopCh   chan struct{}
}

// NewFIMMonitor creates a new FIMMonitor.
func NewFIMMonitor(cfg FIMConfig) *FIMMonitor {
	return &FIMMonitor{
		cfg:      cfg,
		baseline: make(map[string]FileEntry),
		stopCh:   make(chan struct{}),
	}
}

// Start begins the FIM monitoring loop. It sends alerts to the provided channel.
func (f *FIMMonitor) Start(ctx context.Context, alertCh chan<- HostAlert) {
	// Initial scan to build baseline
	f.scan()
	go f.loop(ctx, alertCh)
}

// Stop gracefully shuts down the FIM monitor.
func (f *FIMMonitor) Stop() {
	select {
	case <-f.stopCh:
		// already closed
	default:
		close(f.stopCh)
	}
}

func (f *FIMMonitor) loop(ctx context.Context, alertCh chan<- HostAlert) {
	interval, err := time.ParseDuration(f.cfg.ScanInterval)
	if err != nil {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.stopCh:
			return
		case <-ticker.C:
			f.scanAndDiff(alertCh)
		}
	}
}

// scan builds the initial baseline without sending alerts.
func (f *FIMMonitor) scan() {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, watchPath := range f.cfg.WatchPaths {
		filepath.Walk(watchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // skip inaccessible
			}
			if info.IsDir() {
				return nil
			}
			// Check exclude
			for _, excl := range f.cfg.ExcludePaths {
				if strings.HasPrefix(path, excl) {
					return nil
				}
			}
			entry := FileEntry{
				Path:    path,
				Size:    info.Size(),
				Mode:    info.Mode(),
				ModTime: info.ModTime(),
			}
			if hash, err := computeHash(path, f.cfg.HashAlgo); err == nil {
				entry.Hash = hash
			}
			f.baseline[path] = entry
			return nil
		})
	}
}

// scanAndDiff scans watch paths and sends alerts for changes.
func (f *FIMMonitor) scanAndDiff(alertCh chan<- HostAlert) {
	f.mu.Lock()
	defer f.mu.Unlock()

	current := make(map[string]bool)

	for _, watchPath := range f.cfg.WatchPaths {
		filepath.Walk(watchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			for _, excl := range f.cfg.ExcludePaths {
				if strings.HasPrefix(path, excl) {
					return nil
				}
			}
			current[path] = true

			prev, existed := f.baseline[path]
			newEntry := FileEntry{
				Path:    path,
				Size:    info.Size(),
				Mode:    info.Mode(),
				ModTime: info.ModTime(),
			}
			newHash, err := computeHash(path, f.cfg.HashAlgo)
			if err == nil {
				newEntry.Hash = newHash
			}
			f.baseline[path] = newEntry

			if !existed {
				// New file
				sendAlert(alertCh, HostAlert{
					Type:      "fim",
					Severity:  3,
					Score:     computeScore(path),
					Message:   fmt.Sprintf("File created: %s (hash=%s)", path, truncate(newHash, 16)),
					Timestamp: time.Now(),
				})
			} else if newHash != prev.Hash {
				// Modified
				sendAlert(alertCh, HostAlert{
					Type:      "fim",
					Severity:  4,
					Score:     computeScore(path),
					Message:   fmt.Sprintf("File modified: %s (old=%s new=%s)", path, truncate(prev.Hash, 16), truncate(newHash, 16)),
					Timestamp: time.Now(),
				})
			}
			return nil
		})
	}

	// Detect deletions
	for path := range f.baseline {
		if !current[path] {
			sendAlert(alertCh, HostAlert{
				Type:      "fim",
				Severity:  5,
				Score:     computeScore(path),
				Message:   fmt.Sprintf("File deleted: %s", path),
				Timestamp: time.Now(),
			})
			delete(f.baseline, path)
		}
	}
}

// computeHash returns the hex-encoded hash of the file at path using the given algorithm.
func computeHash(path, algo string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var h hash.Hash
	switch algo {
	case "sha1":
		h = sha1.New()
	case "md5":
		h = md5.New()
	default:
		h = sha256.New()
	}
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// computeScore returns a severity score based on the file path.
func computeScore(path string) float64 {
	if strings.HasPrefix(path, "/etc/") {
		return 80
	}
	if strings.HasPrefix(path, "/bin/") || strings.HasPrefix(path, "/usr/bin/") {
		return 90
	}
	if strings.HasPrefix(path, "/var/log/") {
		return 20
	}
	return 40
}

// truncate shortens a string to n characters.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// sendAlert sends an alert to the channel or drops it if the channel is full.
func sendAlert(alertCh chan<- HostAlert, a HostAlert) {
	select {
	case alertCh <- a:
	default:
	}
}
