package audit

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

    // LogWatcher defaults
    if len(cfg.LogWatcher.LogPaths) != 3 {
        t.Errorf("expected 3 log paths, got %d", len(cfg.LogWatcher.LogPaths))
    }
    if cfg.LogWatcher.LogPaths[0] != "/var/log/auth.log" {
        t.Errorf("expected /var/log/auth.log, got %s", cfg.LogWatcher.LogPaths[0])
    }
    if cfg.LogWatcher.LogPaths[1] != "/var/log/syslog" {
        t.Errorf("expected /var/log/syslog, got %s", cfg.LogWatcher.LogPaths[1])
    }
    if cfg.LogWatcher.LogPaths[2] != "/var/log/kern.log" {
        t.Errorf("expected /var/log/kern.log, got %s", cfg.LogWatcher.LogPaths[2])
    }

    // Rootkit defaults
    if cfg.Rootkit.ScanInterval != "24h" {
        t.Errorf("expected 24h scan interval, got %s", cfg.Rootkit.ScanInterval)
    }
}

func TestAuditMonitorNew(t *testing.T) {
    cfg := DefaultConfig()
    am := New(cfg)

    if am == nil {
        t.Fatal("New() returned nil")
    }

    // Alert channel should be non-nil
    if am.Alerts() == nil {
        t.Error("Alerts() channel should not be nil")
    }
}

func TestAuditMonitorDisabledStartStop(t *testing.T) {
    cfg := DefaultConfig()
    cfg.Enabled = false

    am := New(cfg)
    if am == nil {
        t.Fatal("New() returned nil")
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Should be safe to call Start/Stop on disabled monitor
    am.Start(ctx)
    am.Stop()
}

func TestAuditMonitorStartStop(t *testing.T) {
    cfg := DefaultConfig()
    cfg.Enabled = true

    am := New(cfg)
    if am == nil {
        t.Fatal("New() returned nil")
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    am.Start(ctx)

    // Let components spin up briefly
    time.Sleep(10 * time.Millisecond)

    // Should not panic or block
    am.Stop()
}

func TestAlertChannel(t *testing.T) {
    cfg := DefaultConfig()
    am := New(cfg)

    ch := am.Alerts()
    if cap(ch) != 1000 {
        t.Errorf("expected alert channel capacity 1000, got %d", cap(ch))
    }
}
