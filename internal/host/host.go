package host

import (
	"context"
	"sync"
	"time"
)

// --- Config ---

type Config struct {
	Enabled   bool            `yaml:"enabled"`
	FIM       FIMConfig       `yaml:"fim"`
	Vuln      VulnConfig      `yaml:"vuln"`
	CIS       CISConfig       `yaml:"cis"`
	Inventory InventoryConfig `yaml:"inventory"`
}

func DefaultConfig() Config {
	return Config{
		Enabled: false,
		FIM: FIMConfig{
			WatchPaths:   []string{"/etc/", "/bin/", "/usr/bin/"},
			ExcludePaths: []string{},
			HashAlgo:     "sha256",
			ScanInterval: "24h",
		},
		Vuln: VulnConfig{
			ScanInterval: "24h",
			Severity:     "MEDIUM",
		},
		CIS: CISConfig{
			Interval:  "24h",
			Profile:   "level_1",
			Benchmark: "ubuntu_22",
		},
		Inventory: InventoryConfig{
			Interval: "1h",
		},
	}
}

type FIMConfig struct {
	Enabled      bool     `yaml:"enabled"`
	WatchPaths   []string `yaml:"watch_paths"`
	ExcludePaths []string `yaml:"exclude_paths"`
	HashAlgo     string   `yaml:"hash_algo"`
	ScanInterval string   `yaml:"scan_interval"`
}

type VulnConfig struct {
	Enabled      bool   `yaml:"enabled"`
	ScanInterval string `yaml:"scan_interval"`
	CVEAPIURL    string `yaml:"cve_api_url"`
	Severity     string `yaml:"severity"`
}

type CISConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Interval  string `yaml:"interval"`
	Profile   string `yaml:"profile"`
	Benchmark string `yaml:"benchmark"`
}

type InventoryConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
}

// --- HostAlert ---

type HostAlert struct {
	Type      string    // "fim" / "vuln" / "cis"
	Severity  int       // 1-5
	Score     float64
	Message   string
	Timestamp time.Time
}

// --- HostMonitor ---

type HostMonitor struct {
	cfg       Config
	fim       *FIMMonitor
	vuln      *VulnScanner
	cis       *CISChecker
	inventory *InventoryCollector
	alertCh   chan HostAlert
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func New(cfg Config) *HostMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	hm := &HostMonitor{
		cfg:     cfg,
		alertCh: make(chan HostAlert, 1000),
		ctx:     ctx,
		cancel:  cancel,
	}
	if cfg.Enabled {
		hm.inventory = NewInventoryCollector(cfg.Inventory)
		hm.fim = NewFIMMonitor(cfg.FIM)
		hm.vuln = NewVulnScanner(cfg.Vuln)
		hm.cis = NewCISChecker(cfg.CIS)
	}
	return hm
}

func (h *HostMonitor) Start(ctx context.Context) {
	if !h.cfg.Enabled {
		return
	}
	if h.inventory != nil {
		h.inventory.Start(ctx)
	}
	if h.fim != nil {
		h.fim.Start(ctx, h.alertCh)
	}
	if h.vuln != nil {
		h.vuln.Start(ctx, h.alertCh)
	}
	if h.cis != nil {
		h.cis.Start(ctx, h.alertCh)
	}
}

func (h *HostMonitor) Stop() {
	h.cancel()
	h.wg.Wait()
	if h.inventory != nil {
		h.inventory.Stop()
	}
	if h.fim != nil {
		h.fim.Stop()
	}
	if h.vuln != nil {
		h.vuln.Stop()
	}
	if h.cis != nil {
		h.cis.Stop()
	}
}

// Alerts returns the alert channel for pipeline integration.
func (h *HostMonitor) Alerts() <-chan HostAlert { return h.alertCh }
