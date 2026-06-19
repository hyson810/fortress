package io_uring

import (
	"sync"
	"testing"
	"time"
)

func TestNewMonitor(t *testing.T) {
	m := NewMonitor(nil)
	if m == nil {
		t.Fatal("NewMonitor returned nil")
	}
	if m.onAlert == nil {
		t.Fatal("onAlert callback is nil (should default to no-op)")
	}
	if m.stopCh == nil {
		t.Fatal("stopCh should not be nil")
	}
}

func TestNewMonitorWithAlert(t *testing.T) {
	var alertCalled bool
	var alertPID int
	onAlert := func(s *IoUringStats) {
		alertCalled = true
		alertPID = s.PID
	}
	m := NewMonitor(onAlert)

	// Simulate an alert
	m.onAlert(&IoUringStats{PID: 9999, Comm: "test-process"})

	if !alertCalled {
		t.Error("alert callback should have been called")
	}
	if alertPID != 9999 {
		t.Errorf("expected PID 9999, got %d", alertPID)
	}
}

func TestStartStop(t *testing.T) {
	m := NewMonitor(nil)
	err := m.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Double start should fail
	err2 := m.Start()
	if err2 == nil {
		t.Error("expected error on double start")
	}

	// Stop should succeed
	m.Stop()

	// Restart after stop
	m2 := NewMonitor(nil)
	err3 := m2.Start()
	if err3 != nil {
		t.Fatalf("restart: %v", err3)
	}
	m2.Stop()
}

func TestGetStatsEmpty(t *testing.T) {
	m := NewMonitor(nil)
	stats := m.GetStats()
	if stats == nil {
		t.Fatal("GetStats returned nil")
	}
	if len(stats) > 0 {
		t.Logf("stats not empty (may have real io_uring users): %d entries", len(stats))
	}
}

func TestAlertsEmpty(t *testing.T) {
	m := NewMonitor(nil)
	alerts := m.Alerts()
	if alerts == nil {
		// nil is valid in Go — just means empty
		t.Log("Alerts returned nil (valid empty)")
		return
	}
	if len(alerts) > 0 {
		t.Logf("alerts not empty: %d active", len(alerts))
	}
}

func TestStatsTracking(t *testing.T) {
	m := NewMonitor(nil)
	m.mu.Lock()
	m.stats[1234] = &IoUringStats{
		PID:         1234,
		Comm:        "test-process",
		EnterCount:  50,
		BurstCount:  5,
		IsAlerted:   true,
		LastBurstAt: time.Now(),
	}
	m.mu.Unlock()

	stats := m.GetStats()
	if len(stats) != 1 {
		t.Fatalf("expected 1 stat entry, got %d", len(stats))
	}
	if stats[0].PID != 1234 {
		t.Errorf("expected PID 1234, got %d", stats[0].PID)
	}
	if stats[0].Comm != "test-process" {
		t.Errorf("expected comm 'test-process', got %q", stats[0].Comm)
	}

	alerts := m.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].PID != 1234 {
		t.Errorf("alert PID mismatch: %d", alerts[0].PID)
	}
}

func TestConcurrentAccess(t *testing.T) {
	m := NewMonitor(nil)
	m.Start()
	defer m.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			m.GetStats()
			m.Alerts()
		}(i)
	}
	wg.Wait()
}

func TestBurstThreshold(t *testing.T) {
	if BurstThreshold <= 0 {
		t.Error("BurstThreshold should be positive")
	}
	if BurstThreshold > 1000 {
		t.Error("BurstThreshold seems too high")
	}
}

func TestMonitorInterval(t *testing.T) {
	if MonitorInterval <= 0 {
		t.Error("MonitorInterval should be positive")
	}
	if MonitorInterval > 60*time.Second {
		t.Error("MonitorInterval seems too long")
	}
}

func TestMaxTrackedProcs(t *testing.T) {
	if MaxTrackedProcs < 100 {
		t.Error("MaxTrackedProcs should be at least 100")
	}
}

func TestIsNumericOnly(t *testing.T) {
	tests := []struct {
		input string
		exp   bool
	}{
		{"1234", true},
		{"0", true},
		{"", false},
		{"12a34", false},
		{"1.5", false},
		{"-1", false},
	}
	for _, tt := range tests {
		got := isNumericOnly(tt.input)
		if got != tt.exp {
			t.Errorf("isNumericOnly(%q) = %v, want %v", tt.input, got, tt.exp)
		}
	}
}
