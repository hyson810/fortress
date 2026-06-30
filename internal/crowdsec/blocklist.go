package crowdsec

import (
	"bufio"
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Default community blocklist URL.
const defaultBlocklistURL = "https://www.crowdsec.net/blocklists/community/"

// BlocklistEntry stores a single IP from the blocklist.
type BlocklistEntry struct {
	IP        string
	Labels    []string
	Source    string
	Score     float64
	UpdatedAt time.Time
}

// BlocklistConsumer periodically fetches and caches the CrowdSec community blocklist.
type BlocklistConsumer struct {
	cfg     BlocklistConfig
	entries map[string]BlocklistEntry
	mu      sync.RWMutex
	client  *http.Client
	stopCh  chan struct{}
}

// NewBlocklistConsumer creates a new BlocklistConsumer.
func NewBlocklistConsumer(cfg BlocklistConfig) *BlocklistConsumer {
	return &BlocklistConsumer{
		cfg:     cfg,
		entries: make(map[string]BlocklistEntry),
		client:  &http.Client{},
		stopCh:  make(chan struct{}),
	}
}

// Start begins polling the blocklist on a background goroutine.
// It triggers an immediate fetch, then every cfg.Interval thereafter.
func (bc *BlocklistConsumer) Start(ctx context.Context) {
	go func() {
		bc.fetchOnce()

		ticker := time.NewTicker(bc.cfg.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				bc.fetchOnce()
			case <-ctx.Done():
				return
			case <-bc.stopCh:
				return
			}
		}
	}()
}

// Stop signals the blocklist consumer to shut down.
func (bc *BlocklistConsumer) Stop() {
	select {
	case <-bc.stopCh:
		// already closed
	default:
		close(bc.stopCh)
	}
}

// fetchOnce fetches the default blocklist and logs any error.
func (bc *BlocklistConsumer) fetchOnce() {
	if err := bc.fetchFromURL(defaultBlocklistURL); err != nil {
		log.Printf("[crowdsec] blocklist fetch error: %v", err)
	}
}

// fetchFromURL fetches and parses a blocklist from the given URL.
// This is exported for testing with httptest servers.
func (bc *BlocklistConsumer) fetchFromURL(url string) error {
	resp, err := bc.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	entries, err := parseBlocklistResponse(resp.Body, time.Now(), bc.cfg)
	if err != nil {
		return err
	}

	bc.mu.Lock()
	bc.entries = entries
	bc.mu.Unlock()

	return nil
}

// parseBlocklistResponse parses a blocklist response body into a map of
// IP address to BlocklistEntry. Lines may optionally have space-separated
// labels after the IP.
func parseBlocklistResponse(r io.Reader, now time.Time, cfg BlocklistConfig) (map[string]BlocklistEntry, error) {
	entries := make(map[string]BlocklistEntry)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		ip := parts[0]
		var labels []string
		if len(parts) > 1 {
			labels = parts[1:]
		}

		score := computeLabelScore(labels, cfg)

		entries[ip] = BlocklistEntry{
			IP:        ip,
			Labels:    labels,
			Source:    "crowdsec",
			Score:     score,
			UpdatedAt: now,
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// computeLabelScore returns the highest score for the given labels based on
// the configured score thresholds.
func computeLabelScore(labels []string, cfg BlocklistConfig) float64 {
	if len(labels) == 0 {
		return cfg.ScoreOnScan
	}

	var maxScore float64
	for _, label := range labels {
		var s float64
		switch strings.ToLower(label) {
		case "malware", "bot":
			s = cfg.ScoreOnMalicious
		case "bruteforce", "password":
			s = cfg.ScoreOnBrute
		case "scan", "recon":
			s = cfg.ScoreOnScan
		default:
			s = cfg.ScoreOnScan
		}
		if s > maxScore {
			maxScore = s
		}
	}
	return maxScore
}

// BlockedIPs returns a snapshot of all blocklist entries.
func (bc *BlocklistConsumer) BlockedIPs() []BlocklistEntry {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	snapshot := make([]BlocklistEntry, 0, len(bc.entries))
	for _, entry := range bc.entries {
		snapshot = append(snapshot, entry)
	}
	return snapshot
}

// Score returns the blocklist score for the given IP, or 0 if not found.
func (bc *BlocklistConsumer) Score(ip string) float64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	entry, ok := bc.entries[ip]
	if !ok {
		return 0
	}
	return entry.Score
}
