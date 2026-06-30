package crowdsec

import (
	"context"
	"testing"
	"time"

	"github.com/fortress/v6/internal/brain"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("DefaultConfig().Enabled should be false")
	}
	if cfg.Blocklist.Interval != 2*time.Hour {
		t.Errorf("DefaultConfig().Blocklist.Interval = %v, want 2h", cfg.Blocklist.Interval)
	}
	if cfg.Blocklist.ScoreOnScan != 30 {
		t.Errorf("DefaultConfig().Blocklist.ScoreOnScan = %v, want 30", cfg.Blocklist.ScoreOnScan)
	}
	if cfg.Blocklist.ScoreOnBrute != 50 {
		t.Errorf("DefaultConfig().Blocklist.ScoreOnBrute = %v, want 50", cfg.Blocklist.ScoreOnBrute)
	}
	if cfg.Blocklist.ScoreOnMalicious != 70 {
		t.Errorf("DefaultConfig().Blocklist.ScoreOnMalicious = %v, want 70", cfg.Blocklist.ScoreOnMalicious)
	}
	if cfg.Reputation.CacheSize != 1024 {
		t.Errorf("DefaultConfig().Reputation.CacheSize = %v, want 1024", cfg.Reputation.CacheSize)
	}
	if cfg.Reputation.CacheTTL != 10*time.Minute {
		t.Errorf("DefaultConfig().Reputation.CacheTTL = %v, want 10m", cfg.Reputation.CacheTTL)
	}
	if cfg.Reputation.Timeout != 3*time.Second {
		t.Errorf("DefaultConfig().Reputation.Timeout = %v, want 3s", cfg.Reputation.Timeout)
	}
	if cfg.Reporter.BatchSize != 10 {
		t.Errorf("DefaultConfig().Reporter.BatchSize = %v, want 10", cfg.Reporter.BatchSize)
	}
	if cfg.Reporter.FlushInterval != 5*time.Second {
		t.Errorf("DefaultConfig().Reporter.FlushInterval = %v, want 5s", cfg.Reporter.FlushInterval)
	}
	if cfg.Reporter.LAPIURL != "http://127.0.0.1:8080" {
		t.Errorf("DefaultConfig().Reporter.LAPIURL = %q, want http://127.0.0.1:8080", cfg.Reporter.LAPIURL)
	}
}

func TestCrowdSecNew(t *testing.T) {
	cfg := DefaultConfig() // disabled
	scorer := brain.NewShardScorer(brain.DefaultWeights(), time.Hour, 1000)
	cs := New(cfg, scorer)

	if cs == nil {
		t.Fatal("New() returned nil")
	}
	if cs.blocklist != nil {
		t.Error("blocklist should be nil when disabled")
	}
	if cs.reputation != nil {
		t.Error("reputation should be nil when disabled")
	}
	if cs.reporter != nil {
		t.Error("reporter should be nil when disabled")
	}
}

func TestCrowdSecStartStop(t *testing.T) {
	cfg := DefaultConfig() // disabled — safe for lifecycle test
	scorer := brain.NewShardScorer(brain.DefaultWeights(), time.Hour, 1000)
	cs := New(cfg, scorer)

	// Should not panic
	cs.Start(context.Background())
	cs.Stop()
}

func TestCrowdSecReportAlert(t *testing.T) {
	cfg := DefaultConfig() // disabled
	scorer := brain.NewShardScorer(brain.DefaultWeights(), time.Hour, 1000)
	cs := New(cfg, scorer)

	alert := AlertItem{
		IP:        "192.0.2.1",
		Scenario:  "crowdsec/ssh-bf",
		Message:   "SSH bruteforce detected",
		Timestamp: time.Now(),
		Source:    "test",
	}

	// Report alert — should queue, not panic
	cs.ReportAlert(alert)
	cs.ReportAlert(alert)

	// Verify queued by checking channel length
	if len(cs.alertCh) != 2 {
		t.Errorf("alertCh length = %d, want 2", len(cs.alertCh))
	}
}

func TestCrowdSecQueryReputationDisabled(t *testing.T) {
	cfg := DefaultConfig() // disabled
	scorer := brain.NewShardScorer(brain.DefaultWeights(), time.Hour, 1000)
	cs := New(cfg, scorer)

	result, ok := cs.QueryReputation("192.0.2.1")
	if ok {
		t.Error("QueryReputation should return false when disabled")
	}
	if result != nil {
		t.Error("QueryReputation should return nil when disabled")
	}
}

func TestCrowdSecEnabledNew(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	scorer := brain.NewShardScorer(brain.DefaultWeights(), time.Hour, 1000)
	cs := New(cfg, scorer)

	if cs == nil {
		t.Fatal("New() returned nil")
	}
	if cs.blocklist == nil {
		t.Error("blocklist should not be nil when enabled")
	}
	if cs.reputation == nil {
		t.Error("reputation should not be nil when enabled")
	}
	if cs.reporter == nil {
		t.Error("reporter should not be nil when enabled")
	}
}

func TestCrowdSecAlertChannelOverflow(t *testing.T) {
	cfg := DefaultConfig()
	scorer := brain.NewShardScorer(brain.DefaultWeights(), time.Hour, 1000)
	cs := New(cfg, scorer)

	// Fill the channel beyond capacity (1000)
	for i := 0; i < 1100; i++ {
		cs.ReportAlert(AlertItem{
			IP:        "10.0.0.1",
			Scenario:  "test/overflow",
			Message:   "overflow test",
			Timestamp: time.Now(),
			Source:    "test",
		})
	}

	// Channel should have at most 1000 items (buffer size)
	if len(cs.alertCh) > 1000 {
		t.Errorf("alertCh length = %d, want at most 1000 (buffer size)", len(cs.alertCh))
	}
}

func TestCrowdSecEndToEnd(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Blocklist.Interval = time.Hour // won't trigger in test

	var scorer brain.ShardScorer
	cs := New(cfg, &scorer)

	ctx, cancel := context.WithCancel(context.Background())
	cs.Start(ctx)
	defer cs.Stop()
	defer cancel()

	// Test reputation query (no network = empty result)
	result, ok := cs.QueryReputation("1.2.3.4")
	if ok {
		t.Log("Reputation found:", result.Labels)
	} else {
		t.Log("No reputation (expected in test env)")
	}

	// Test alert reporting (no LAPI = dropped gracefully)
	cs.ReportAlert(AlertItem{
		IP:        "1.2.3.4",
		Scenario:  "fortress/test",
		Message:   "test alert",
		Timestamp: time.Now(),
	})
}
