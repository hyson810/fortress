package dashboard

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

type mockBrain struct{}

func (m *mockBrain) Top(n int) []interface{}              { return nil }
func (m *mockBrain) GetScore(ip string) (float64, string) { return 0, "none" }
func (m *mockBrain) Count() int                           { return 0 }
func (m *mockBrain) GetMetrics() map[string]interface{}   { return nil }

func TestDashboardStartStop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Port = 9191

	d := New(cfg, &mockBrain{})
	if d.Started() {
		t.Error("should not be started yet")
	}

	if err := d.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if !d.Started() {
		t.Error("should be started now")
	}

	// Repeated start should be safe
	if err := d.Start(); err != nil {
		t.Fatalf("second start should no-op: %v", err)
	}

	if err := d.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	if d.Started() {
		t.Error("should not be started after stop")
	}

	// Repeated stop should be safe
	if err := d.Stop(); err != nil {
		t.Fatalf("second stop should no-op: %v", err)
	}
}

func TestDashboardStartDisabled(t *testing.T) {
	// Even with disabled config, Start() doesn't fail -- just no-op server
	cfg := DefaultConfig() // Enabled: false
	d := New(cfg, &mockBrain{})
	if err := d.Start(); err != nil {
		t.Fatalf("start disabled dashboard failed: %v", err)
	}
	// Started() should return true after Start() call
	if !d.Started() {
		t.Error("dashboard should be started after Start() call")
	}
	d.Stop()
}

func TestAPIEndpoints(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Port = 9193
	d := New(cfg, &mockBrain{})
	if err := d.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer d.Stop()
	time.Sleep(50 * time.Millisecond)

	tests := []struct {
		path string
		code int
	}{
		{"/api/stats", 200},
		{"/api/threats", 200},
		{"/api/threats/192.168.1.1", 200},
		{"/api/timeline", 200},
		{"/api/correlations", 200},
		{"/api/evidence/10.0.0.1", 200},
		{"/api/config", 200},
	}

	for _, tt := range tests {
		resp, err := http.Get("http://127.0.0.1:9193" + tt.path)
		if err != nil {
			t.Errorf("GET %s: %v", tt.path, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != tt.code {
			t.Errorf("GET %s: got status %d, want %d", tt.path, resp.StatusCode, tt.code)
		}
	}
}

func TestAPIStatsJSON(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Port = 9194
	d := New(cfg, &mockBrain{})
	if err := d.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer d.Stop()
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:9194/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	defer resp.Body.Close()

	var stats StatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if stats.ActiveThreats != 0 {
		t.Errorf("expected 0 threats, got %d", stats.ActiveThreats)
	}
}
