package crowdsec

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testBlocklistConfig() BlocklistConfig {
	return BlocklistConfig{
		Interval:         time.Hour,
		ScoreOnScan:      30,
		ScoreOnBrute:     50,
		ScoreOnMalicious: 70,
	}
}

func blocklistServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body)
	}))
}

// TestBlocklistParse validates parsing of various line formats.
func TestBlocklistParse(t *testing.T) {
	body := `1.2.3.4 scan
5.6.7.8 bruteforce
9.10.11.12 scan bruteforce
192.168.1.1 malware
10.0.0.1 bot
172.16.0.1 recon
10.0.0.2 password
203.0.113.1 unknownlabel
10.0.0.3
# comment line
  10.0.0.4 scan

`
	entries, err := parseBlocklistResponse(
		strings.NewReader(body),
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		testBlocklistConfig(),
	)
	if err != nil {
		t.Fatalf("parseBlocklistResponse returned error: %v", err)
	}

	tests := []struct {
		ip       string
		want     float64
		wantLen  int
	}{
		{"1.2.3.4", 30, 1},
		{"5.6.7.8", 50, 1},
		{"9.10.11.12", 50, 2},  // highest: bruteforce (50) over scan (30)
		{"192.168.1.1", 70, 1},
		{"10.0.0.1", 70, 1},
		{"172.16.0.1", 30, 1},
		{"10.0.0.2", 50, 1},
		{"203.0.113.1", 30, 1}, // unknown label defaults to ScoreOnScan
		{"10.0.0.3", 30, 0},    // no labels defaults to ScoreOnScan
		{"10.0.0.4", 30, 1},    // leading whitespace trimmed
	}

	for _, tt := range tests {
		entry, ok := entries[tt.ip]
		if !ok {
			t.Errorf("IP %q not found in parsed entries", tt.ip)
			continue
		}
		if entry.Score != tt.want {
			t.Errorf("IP %q Score = %.0f, want %.0f", tt.ip, entry.Score, tt.want)
		}
		if len(entry.Labels) != tt.wantLen {
			t.Errorf("IP %q len(Labels) = %d, want %d", tt.ip, len(entry.Labels), tt.wantLen)
		}
		if entry.Source != "crowdsec" {
			t.Errorf("IP %q Source = %q, want \"crowdsec\"", tt.ip, entry.Source)
		}
	}

	// Comment and empty lines should not produce entries.
	for _, bad := range []string{"#", ""} {
		if _, ok := entries[bad]; ok {
			t.Errorf("bad key %q produced an entry", bad)
		}
	}
}

// TestBlocklistScore checks that Score() returns the correct value for known IPs.
func TestBlocklistScore(t *testing.T) {
	server := blocklistServer("1.2.3.4 scan\n5.6.7.8 bruteforce\n9.10.11.12 malware\n")
	defer server.Close()

	bc := NewBlocklistConsumer(testBlocklistConfig())
	if err := bc.fetchFromURL(server.URL); err != nil {
		t.Fatalf("fetchFromURL: %v", err)
	}

	if s := bc.Score("1.2.3.4"); s != 30 {
		t.Errorf("Score(1.2.3.4) = %.0f, want 30", s)
	}
	if s := bc.Score("5.6.7.8"); s != 50 {
		t.Errorf("Score(5.6.7.8) = %.0f, want 50", s)
	}
	if s := bc.Score("9.10.11.12"); s != 70 {
		t.Errorf("Score(9.10.11.12) = %.0f, want 70", s)
	}
}

// TestBlocklistScoreUnknown verifies that Score() returns 0 for unknown IPs.
func TestBlocklistScoreUnknown(t *testing.T) {
	bc := NewBlocklistConsumer(testBlocklistConfig())
	if s := bc.Score("1.2.3.4"); s != 0 {
		t.Errorf("Score() for unknown IP = %.0f, want 0", s)
	}
}

// TestBlocklistConcurrentRead exercises concurrent reads during an async update.
func TestBlocklistConcurrentRead(t *testing.T) {
	server1 := blocklistServer("1.2.3.4 scan\n5.6.7.8 bruteforce\n")
	defer server1.Close()
	server2 := blocklistServer("9.10.11.12 malware\n10.0.0.1 recon\n")
	defer server2.Close()

	bc := NewBlocklistConsumer(testBlocklistConfig())

	// Initial fetch.
	if err := bc.fetchFromURL(server1.URL); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}

	var wg sync.WaitGroup

	// Readers: call Score and BlockedIPs concurrently.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				bc.Score("1.2.3.4")
				bc.Score("9.9.9.9")
				_ = bc.BlockedIPs()
			}
		}()
	}

	// Writer: update entries while readers are active.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 20; j++ {
			_ = bc.fetchFromURL(server2.URL)
		}
	}()

	wg.Wait()

	// Final state should be from server2 (last write wins).
	if s := bc.Score("9.10.11.12"); s != 70 {
		t.Errorf("final Score(9.10.11.12) = %.0f, want 70", s)
	}
	// server1 IPs may or may not be present (racy by design).
}

// TestBlocklistFetchFromURL uses an httptest server to verify entries are populated.
func TestBlocklistFetchFromURL(t *testing.T) {
	server := blocklistServer("1.2.3.4 scan\n5.6.7.8 bruteforce\n")
	defer server.Close()

	bc := NewBlocklistConsumer(testBlocklistConfig())
	if err := bc.fetchFromURL(server.URL); err != nil {
		t.Fatalf("fetchFromURL: %v", err)
	}

	entries := bc.BlockedIPs()
	if len(entries) != 2 {
		t.Fatalf("BlockedIPs() returned %d entries, want 2", len(entries))
	}

	entryMap := make(map[string]BlocklistEntry)
	for _, e := range entries {
		entryMap[e.IP] = e
	}

	if e, ok := entryMap["1.2.3.4"]; !ok {
		t.Error("1.2.3.4 not found")
	} else if e.Score != 30 {
		t.Errorf("1.2.3.4 Score = %.0f, want 30", e.Score)
	}

	if e, ok := entryMap["5.6.7.8"]; !ok {
		t.Error("5.6.7.8 not found")
	} else if e.Score != 50 {
		t.Errorf("5.6.7.8 Score = %.0f, want 50", e.Score)
	}
}

// TestBlocklistEmptyResponse verifies that an empty body doesn't cause an error.
func TestBlocklistEmptyResponse(t *testing.T) {
	server := blocklistServer("")
	defer server.Close()

	bc := NewBlocklistConsumer(testBlocklistConfig())
	if err := bc.fetchFromURL(server.URL); err != nil {
		t.Fatalf("fetchFromURL with empty body returned error: %v", err)
	}

	entries := bc.BlockedIPs()
	if len(entries) != 0 {
		t.Errorf("BlockedIPs() = %d entries, want 0 for empty response", len(entries))
	}
}

// TestBlocklistBadURL verifies that an unreachable URL returns an error.
func TestBlocklistBadURL(t *testing.T) {
	bc := NewBlocklistConsumer(testBlocklistConfig())
	if err := bc.fetchFromURL("http://127.0.0.1:1/nonexistent"); err == nil {
		t.Error("fetchFromURL with bad URL should return error, got nil")
	}
}

// TestBlocklistStartStop verifies Start/Stop lifecycle.
func TestBlocklistStartStop(t *testing.T) {
	server := blocklistServer("1.2.3.4 scan\n")
	defer server.Close()

	// Create a config with a very short interval for quick test.
	cfg := testBlocklistConfig()
	cfg.Interval = 10 * time.Millisecond

	bc := NewBlocklistConsumer(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	bc.Start(ctx)

	// Let it run a couple of cycles.
	time.Sleep(50 * time.Millisecond)

	// Should not panic.
	bc.Stop()
	cancel()
}
