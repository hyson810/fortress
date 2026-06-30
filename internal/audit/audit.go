package audit

import (
    "context"
    "sync"
    "time"
)

type Config struct {
    Enabled    bool              `yaml:"enabled"`
    LogWatcher LogWatcherConfig  `yaml:"logwatcher"`
    Rootkit    RootkitConfig     `yaml:"rootkit"`
}

func DefaultConfig() Config {
    return Config{
        Enabled: false,
        LogWatcher: LogWatcherConfig{
            LogPaths: []string{"/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"},
        },
        Rootkit: RootkitConfig{
            ScanInterval: "24h",
        },
    }
}

type LogWatcherConfig struct {
    LogPaths  []string `yaml:"log_paths"`
    RulesPath string   `yaml:"rules_path"`
}

type RootkitConfig struct {
    ScanInterval string `yaml:"scan_interval"`
}

type AuditAlert struct {
    Type      string    // "log" / "rootkit"
    Severity  int       // 1-5
    Score     float64
    Message   string
    Timestamp time.Time
}

type AuditMonitor struct {
    cfg        Config
    logWatcher *LogWatcher
    rootkit    *RootkitScanner
    alertCh    chan AuditAlert
    ctx        context.Context
    cancel     context.CancelFunc
    wg         sync.WaitGroup
}

func New(cfg Config) *AuditMonitor {
    ctx, cancel := context.WithCancel(context.Background())
    am := &AuditMonitor{
        cfg:     cfg,
        alertCh: make(chan AuditAlert, 1000),
        ctx:     ctx,
        cancel:  cancel,
    }
    if cfg.Enabled {
        am.logWatcher = NewLogWatcher(cfg.LogWatcher)
        am.rootkit = NewRootkitScanner(cfg.Rootkit)
    }
    return am
}

func (a *AuditMonitor) Start(ctx context.Context) {
    if !a.cfg.Enabled { return }
    if a.logWatcher != nil { a.logWatcher.Start(ctx, a.alertCh) }
    if a.rootkit != nil { a.rootkit.Start(ctx, a.alertCh) }
}

func (a *AuditMonitor) Stop() {
    a.cancel()
    a.wg.Wait()
    if a.logWatcher != nil { a.logWatcher.Stop() }
    if a.rootkit != nil { a.rootkit.Stop() }
}

func (a *AuditMonitor) Alerts() <-chan AuditAlert { return a.alertCh }
