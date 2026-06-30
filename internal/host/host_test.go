package host

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("DefaultConfig().Enabled should be false")
	}

	// FIM defaults
	if len(cfg.FIM.WatchPaths) != 3 {
		t.Errorf("expected 3 watch paths, got %d", len(cfg.FIM.WatchPaths))
	}
	if cfg.FIM.HashAlgo != "sha256" {
		t.Errorf("expected sha256 hash algo, got %s", cfg.FIM.HashAlgo)
	}
	if cfg.FIM.ScanInterval != "24h" {
		t.Errorf("expected 24h scan interval, got %s", cfg.FIM.ScanInterval)
	}
	if len(cfg.FIM.ExcludePaths) != 0 {
		t.Errorf("expected empty exclude paths, got %v", cfg.FIM.ExcludePaths)
	}

	// Vuln defaults
	if cfg.Vuln.ScanInterval != "24h" {
		t.Errorf("expected 24h vuln scan interval, got %s", cfg.Vuln.ScanInterval)
	}
	if cfg.Vuln.Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM severity, got %s", cfg.Vuln.Severity)
	}

	// CIS defaults
	if cfg.CIS.Interval != "24h" {
		t.Errorf("expected 24h cis interval, got %s", cfg.CIS.Interval)
	}
	if cfg.CIS.Profile != "level_1" {
		t.Errorf("expected level_1 profile, got %s", cfg.CIS.Profile)
	}
	if cfg.CIS.Benchmark != "ubuntu_22" {
		t.Errorf("expected ubuntu_22 benchmark, got %s", cfg.CIS.Benchmark)
	}

	// Inventory defaults
	if cfg.Inventory.Interval != "1h" {
		t.Errorf("expected 1h inventory interval, got %s", cfg.Inventory.Interval)
	}
}

func TestHostMonitorNew(t *testing.T) {
	cfg := DefaultConfig()
	hm := New(cfg)

	if hm == nil {
		t.Fatal("New() returned nil")
	}

	// Alert channel should be non-nil and have buffer 1000
	if hm.Alerts() == nil {
		t.Error("Alerts() channel should not be nil")
	}
}

func TestHostMonitorStartStop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FIM.Enabled = true
	cfg.Vuln.Enabled = true
	cfg.CIS.Enabled = true
	cfg.Inventory.Enabled = true

	hm := New(cfg)
	if hm == nil {
		t.Fatal("New() returned nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hm.Start(ctx)

	// Let components spin up briefly
	time.Sleep(10 * time.Millisecond)

	// Should not panic or block
	hm.Stop()
}

func TestHostMonitorDisabledStartStop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false

	hm := New(cfg)
	if hm == nil {
		t.Fatal("New() returned nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Should be safe to call Start/Stop on disabled monitor
	hm.Start(ctx)
	hm.Stop()
}

func TestAlertChannel(t *testing.T) {
	cfg := DefaultConfig()
	hm := New(cfg)

	ch := hm.Alerts()
	if cap(ch) != 1000 {
		t.Errorf("expected alert channel capacity 1000, got %d", cap(ch))
	}
}
