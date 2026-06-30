// Package crowdsec provides CrowdSec threat intelligence integration.
//
// It combines blocklist consumption, IP reputation queries, and alert
// reporting to enrich the fortress scoring engine with external threat data.
package crowdsec

import (
	"context"
	"sync"
	"time"

	"github.com/fortress/v6/internal/brain"
)

// --- Config types ---

// Config is the top-level configuration for the CrowdSec module.
type Config struct {
	Enabled    bool             `yaml:"enabled"`
	Blocklist  BlocklistConfig  `yaml:"blocklist"`
	Reputation ReputationConfig `yaml:"reputation"`
	Reporter   ReporterConfig   `yaml:"reporter"`
}

// DefaultConfig returns a Config with sensible defaults (module disabled).
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		Blocklist: BlocklistConfig{
			Interval:         2 * time.Hour,
			ScoreOnScan:      30,
			ScoreOnBrute:     50,
			ScoreOnMalicious: 70,
		},
		Reputation: ReputationConfig{
			CacheSize: 1024,
			CacheTTL:  10 * time.Minute,
			Timeout:   3 * time.Second,
		},
		Reporter: ReporterConfig{
			BatchSize:      10,
			FlushInterval:  5 * time.Second,
			LAPIURL:        "http://127.0.0.1:8080",
		},
	}
}

// BlocklistConfig controls the blocklist polling behaviour.
type BlocklistConfig struct {
	Interval        time.Duration `yaml:"interval"`
	CachePath       string        `yaml:"cache_path"`
	APIKey          string        `yaml:"api_key"`
	ScoreOnScan     float64       `yaml:"score_scan"`
	ScoreOnBrute    float64       `yaml:"score_bruteforce"`
	ScoreOnMalicious float64      `yaml:"score_malicious"`
}

// ReputationConfig controls the IP reputation client.
type ReputationConfig struct {
	CacheSize int           `yaml:"cache_size"`
	CacheTTL  time.Duration `yaml:"cache_ttl"`
	Timeout   time.Duration `yaml:"timeout"`
}

// ReporterConfig controls the alert reporter (LAPI push).
type ReporterConfig struct {
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	LAPIURL       string        `yaml:"lapi_url"`
}

// --- Domain types ---

// AlertItem represents a threat alert to be forwarded to CrowdSec.
type AlertItem struct {
	IP        string
	Scenario  string
	Message   string
	Timestamp time.Time
	Source    string
}

// ReputationResult holds the result of an IP reputation query.
type ReputationResult struct {
	IP            string
	Reputation    int
	Confidence    float64
	LastSeen      time.Time
	Scope         string
	Simulated     bool
}

// --- Stub sub-component types ---
// These will be replaced with full implementations in later tasks.

// BlocklistConsumer polls CrowdSec blocklists and feeds scores into the scorer.
type BlocklistConsumer struct {
	cfg    BlocklistConfig
	cancel context.CancelFunc
}

// NewBlocklistConsumer creates a new BlocklistConsumer.
func NewBlocklistConsumer(cfg BlocklistConfig) *BlocklistConsumer {
	return &BlocklistConsumer{cfg: cfg}
}

// Start begins polling the blocklist on a background goroutine.
func (bc *BlocklistConsumer) Start(ctx context.Context) {
	ctx, bc.cancel = context.WithCancel(ctx)
	// TODO: implement blocklist polling (V2 feature)
	<-ctx.Done()
}

// Stop signals the blocklist consumer to shut down.
func (bc *BlocklistConsumer) Stop() {
	if bc.cancel != nil {
		bc.cancel()
	}
}

// ReputationClient queries the CrowdSec LAPI for IP reputation.
type ReputationClient struct {
	cfg    ReputationConfig
	cancel context.CancelFunc
}

// NewReputationClient creates a new ReputationClient.
func NewReputationClient(cfg ReputationConfig) *ReputationClient {
	return &ReputationClient{cfg: cfg}
}

// Query performs a reputation lookup for the given IP.
func (rc *ReputationClient) Query(ctx context.Context, ip string) (*ReputationResult, bool) {
	// TODO: implement LAPI query (V2 feature)
	return nil, false
}

// AlertReporter batches alerts and forwards them to the CrowdSec LAPI.
type AlertReporter struct {
	cfg      ReporterConfig
	alerts   chan AlertItem
	cancel   context.CancelFunc
	started  bool
	mu       sync.Mutex
}

// NewAlertReporter creates a new AlertReporter with the given config.
func NewAlertReporter(cfg ReporterConfig) *AlertReporter {
	return &AlertReporter{
		cfg:    cfg,
		alerts: make(chan AlertItem, cfg.BatchSize*2),
	}
}

// Start begins the alert flush loop.
func (ar *AlertReporter) Start(ctx context.Context) {
	ar.mu.Lock()
	ar.started = true
	ar.mu.Unlock()
	// TODO: implement alert batching and LAPI push (V2 feature)
	<-ctx.Done()
}

// Stop signals the reporter to shut down.
func (ar *AlertReporter) Stop() {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	if ar.cancel != nil {
		ar.cancel()
	}
	ar.started = false
}

// Report enqueues an alert for batching.
func (ar *AlertReporter) Report(alert AlertItem) {
	select {
	case ar.alerts <- alert:
	default:
		// channel full, drop alert
	}
}

// CrowdSec is the main module that integrates CrowdSec threat intelligence.
type CrowdSec struct {
	cfg        Config
	scorer     *brain.ShardScorer
	blocklist  *BlocklistConsumer
	reputation *ReputationClient
	reporter   *AlertReporter
	alertCh    chan AlertItem
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// New creates a new CrowdSec module. Pass cfg.Enabled = true to activate it.
func New(cfg Config, scorer *brain.ShardScorer) *CrowdSec {
	ctx, cancel := context.WithCancel(context.Background())
	cs := &CrowdSec{
		cfg:     cfg,
		scorer:  scorer,
		alertCh: make(chan AlertItem, 1000),
		ctx:     ctx,
		cancel:  cancel,
	}
	if cfg.Enabled {
		cs.blocklist = NewBlocklistConsumer(cfg.Blocklist)
		cs.reputation = NewReputationClient(cfg.Reputation)
		cs.reporter = NewAlertReporter(cfg.Reporter)
	}
	return cs
}

// Start launches the CrowdSec background workers.
func (c *CrowdSec) Start(ctx context.Context) {
	if !c.cfg.Enabled {
		return
	}
	if c.blocklist != nil {
		c.blocklist.Start(ctx)
	}
	if c.reporter != nil {
		c.reporter.Start(ctx)
	}
	c.wg.Add(1)
	go c.loop()
}

func (c *CrowdSec) loop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case alert := <-c.alertCh:
			if c.reporter != nil {
				c.reporter.Report(alert)
			}
		}
	}
}

// Stop gracefully shuts down the CrowdSec module.
func (c *CrowdSec) Stop() {
	c.cancel()
	c.wg.Wait()
	if c.blocklist != nil {
		c.blocklist.Stop()
	}
	if c.reporter != nil {
		c.reporter.Stop()
	}
}

// QueryReputation performs an IP reputation lookup through the reputation client.
func (c *CrowdSec) QueryReputation(ip string) (*ReputationResult, bool) {
	if c.reputation == nil {
		return nil, false
	}
	return c.reputation.Query(c.ctx, ip)
}

// ReportAlert enqueues an alert for batching and forwarding to CrowdSec.
func (c *CrowdSec) ReportAlert(alert AlertItem) {
	select {
	case c.alertCh <- alert:
	default:
		// channel full, drop alert
	}
}
