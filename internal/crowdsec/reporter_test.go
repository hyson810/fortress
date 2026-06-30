package crowdsec

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestReporterQueueAndFlush(t *testing.T) {
	cfg := DefaultConfig().Reporter
	cfg.LAPIURL = "http://127.0.0.1:1" // will fail, but flush drains the queue
	cfg.BatchSize = 10
	cfg.FlushInterval = 50 * time.Millisecond

	r := NewAlertReporter(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)

	r.Report(AlertItem{IP: "1.2.3.4", Scenario: "test/scenario", Message: "test alert", Timestamp: time.Now()})

	// Allow flush to run
	time.Sleep(100 * time.Millisecond)
	cancel()
	r.Stop()

	// Queue should be drained (flush ran even though POST failed)
	if len(r.queue) != 0 {
		t.Errorf("queue length = %d, want 0 after flush", len(r.queue))
	}
}

func TestReporterEmptyFlush(t *testing.T) {
	cfg := DefaultConfig().Reporter
	cfg.LAPIURL = "http://127.0.0.1:1"
	cfg.BatchSize = 10
	cfg.FlushInterval = 50 * time.Millisecond

	r := NewAlertReporter(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)

	// No items reported
	time.Sleep(100 * time.Millisecond)
	cancel()
	r.Stop()

	if len(r.queue) != 0 {
		t.Errorf("queue length = %d, want 0", len(r.queue))
	}
}

func TestReporterQueueCap(t *testing.T) {
	cfg := DefaultConfig().Reporter
	cfg.LAPIURL = "http://127.0.0.1:1"
	cfg.BatchSize = 100

	r := NewAlertReporter(cfg)

	// Report more than 1000 items
	for i := 0; i < 1100; i++ {
		r.Report(AlertItem{IP: "10.0.0.1", Scenario: "test/cap", Message: "cap test", Timestamp: time.Now()})
	}

	if len(r.queue) > 1000 {
		t.Errorf("queue length = %d, want at most 1000", len(r.queue))
	}
	// Should have exactly 1000 (capped)
	if len(r.queue) != 1000 {
		t.Errorf("queue length = %d, want 1000", len(r.queue))
	}
}

func TestReporterStartStop(t *testing.T) {
	cfg := DefaultConfig().Reporter
	cfg.LAPIURL = "http://127.0.0.1:1"
	cfg.BatchSize = 10
	cfg.FlushInterval = time.Hour // long interval so flush doesn't run

	r := NewAlertReporter(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)

	// Report a few items
	r.Report(AlertItem{IP: "1.2.3.4", Scenario: "test", Message: "msg", Timestamp: time.Now()})

	// Stop should flush remaining
	cancel()
	r.Stop()

	if len(r.queue) != 0 {
		t.Errorf("queue length = %d, want 0 after stop", len(r.queue))
	}
}

func TestReporterBatchSize(t *testing.T) {
	var capturedBodies [][]byte
	var muCaptured sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		muCaptured.Lock()
		capturedBodies = append(capturedBodies, body)
		muCaptured.Unlock()
		w.WriteHeader(204)
	}))
	defer server.Close()

	cfg := DefaultConfig().Reporter
	cfg.LAPIURL = server.URL
	cfg.BatchSize = 3
	cfg.FlushInterval = 50 * time.Millisecond

	r := NewAlertReporter(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)

	// Report 7 items
	for i := 0; i < 7; i++ {
		r.Report(AlertItem{
			IP:        "10.0.0.1",
			Scenario:  "test/batch",
			Message:   "batch test",
			Timestamp: time.Now(),
		})
	}

	// Allow multiple flushes to happen
	time.Sleep(200 * time.Millisecond)
	cancel()
	r.Stop()

	muCaptured.Lock()
	numRequests := len(capturedBodies)
	muCaptured.Unlock()

	if numRequests < 2 {
		t.Fatalf("expected at least 2 POST requests, got %d", numRequests)
	}

	// Verify each batch is at most BatchSize (3)
	for i, body := range capturedBodies {
		var alerts []CrowdSecAlert
		if err := json.Unmarshal(body, &alerts); err != nil {
			t.Fatalf("failed to unmarshal request %d: %v", i, err)
		}
		if len(alerts) > 3 {
			t.Errorf("request %d has %d alerts, want <= 3", i, len(alerts))
		}
	}
}

func TestReporterPostsToLAPI(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(204)
	}))
	defer server.Close()

	cfg := DefaultConfig().Reporter
	cfg.LAPIURL = server.URL
	cfg.BatchSize = 10
	cfg.FlushInterval = 50 * time.Millisecond

	reporter := NewAlertReporter(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	reporter.Start(ctx)

	reporter.Report(AlertItem{IP: "1.2.3.4", Scenario: "test", Message: "test alert", Timestamp: time.Now()})
	time.Sleep(100 * time.Millisecond)

	cancel()
	reporter.Stop()

	if capturedBody == nil {
		t.Fatal("expected POST to LAPI")
	}
	var alerts []CrowdSecAlert
	if err := json.Unmarshal(capturedBody, &alerts); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Source.IP != "1.2.3.4" {
		t.Errorf("unexpected alert: %+v", alerts)
	}
}
