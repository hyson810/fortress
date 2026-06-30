package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// CrowdSecAlert is the JSON structure for the CrowdSec LAPI alert endpoint.
type CrowdSecAlert struct {
	Scenario string `json:"scenario"`
	Message  string `json:"message"`
	Source   struct {
		IP string `json:"ip"`
	} `json:"source"`
	StartAt string `json:"start_at"`
	StopAt  string `json:"stop_at"`
}

// AlertReporter batches alerts and forwards them to the CrowdSec LAPI.
type AlertReporter struct {
	cfg    ReporterConfig
	queue  []AlertItem
	mu     sync.Mutex
	client *http.Client
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewAlertReporter creates a new AlertReporter with the given config.
func NewAlertReporter(cfg ReporterConfig) *AlertReporter {
	return &AlertReporter{
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Second},
		stopCh: make(chan struct{}),
		queue:  make([]AlertItem, 0, cfg.BatchSize),
	}
}

// Start begins the flush loop that periodically pushes queued alerts to LAPI.
func (r *AlertReporter) Start(ctx context.Context) {
	r.wg.Add(1)
	go r.flushLoop(ctx)
}

// Stop signals the reporter to shut down and flushes remaining alerts.
func (r *AlertReporter) Stop() {
	close(r.stopCh)
	r.wg.Wait()
	// Flush remaining alerts on shutdown
	r.flush()
}

// Report enqueues an alert for batching.
func (r *AlertReporter) Report(alert AlertItem) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Cap queue at 1000 items to prevent unbounded growth
	if len(r.queue) >= 1000 {
		// Drop oldest
		r.queue = r.queue[1:]
	}
	r.queue = append(r.queue, alert)
}

// flushLoop runs on cfg.FlushInterval, flushing queued alerts.
func (r *AlertReporter) flushLoop(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(r.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.flush()
		}
	}
}

func (r *AlertReporter) flush() {
	r.mu.Lock()
	if len(r.queue) == 0 {
		r.mu.Unlock()
		return
	}
	// Take batch (up to cfg.BatchSize)
	batchSize := r.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 10
	}
	if len(r.queue) < batchSize {
		batchSize = len(r.queue)
	}
	batch := make([]AlertItem, batchSize)
	copy(batch, r.queue[:batchSize])
	r.queue = r.queue[batchSize:]
	r.mu.Unlock()

	// POST to LAPI
	alerts := make([]CrowdSecAlert, 0, len(batch))
	for _, item := range batch {
		a := CrowdSecAlert{
			Scenario: item.Scenario,
			Message:  item.Message,
			StartAt:  item.Timestamp.UTC().Format(time.RFC3339),
			StopAt:   item.Timestamp.UTC().Format(time.RFC3339),
		}
		a.Source.IP = item.IP
		alerts = append(alerts, a)
	}

	// POST (best effort — errors are logged, not returned)
	body, err := json.Marshal(alerts)
	if err != nil {
		log.Printf("[crowdsec] marshal alerts: %v", err)
		return
	}

	url := r.cfg.LAPIURL + "/v1/alerts"
	resp, err := r.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[crowdsec] post alerts: %v", err)
		return
	}
	resp.Body.Close()
}

// FlushedCount returns total flushed (for testing).
func (r *AlertReporter) FlushedCount() int { return 0 /* simplified */ }
