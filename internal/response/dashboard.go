package response

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// ThreatProvider supplies threat data for dashboard display.
type ThreatProvider interface {
	GetThreats() []map[string]interface{}
	GetThreat(ip string) (map[string]interface{}, bool)
}

// StatusResponse provides a snapshot of system state for the /status endpoint.
type StatusResponse struct {
	Threats        int      `json:"threats"`
	DefensesActive []string `json:"defenses_active"`
	Uptime         string   `json:"uptime"`
	Mode           string   `json:"mode"`
	AlertsLast24h  int      `json:"alerts_last_24h"`
}

// Dashboard serves an HTTP status dashboard with API endpoints.
type Dashboard struct {
	mu       sync.Mutex
	server   *http.Server
	alerter  *Alerter
	threats  ThreatProvider
	startAt  time.Time
	mode     string
	metrics  map[string]int64
}

// NewDashboard creates a Dashboard backed by the given alerter and threat provider.
func NewDashboard(alerter *Alerter, threats ThreatProvider) *Dashboard {
	return &Dashboard{
		alerter: alerter,
		threats: threats,
		startAt: time.Now(),
		mode:    "defend",
		metrics: map[string]int64{
			"fortress_alerts_total":     0,
			"fortress_threats_active":   0,
			"fortress_uptime_seconds":   0,
		},
	}
}

// SetMode updates the operational mode reported in status responses.
func (d *Dashboard) SetMode(mode string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mode = mode
}

// IncrementMetric adds delta to a named Prometheus counter metric.
func (d *Dashboard) IncrementMetric(name string, delta int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.metrics[name] += delta
}

// Start begins serving the dashboard on localhost:9090.
func (d *Dashboard) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleIndex)
	mux.HandleFunc("/status", d.handleStatus)
	mux.HandleFunc("/health", d.handleHealth)
	mux.HandleFunc("/metrics", d.handleMetrics)
	mux.HandleFunc("/api/threats", d.handleThreats)
	mux.HandleFunc("/api/threats/", d.handleThreatDetail)

	handler := corsMiddleware(mux)

	d.server = &http.Server{
		Addr:         "localhost:9090",
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("[dashboard] starting on http://localhost:9090")
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[dashboard] panic: %v\nstack: %s", r, debug.Stack())
			}
		}()
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[dashboard] server error: %v", err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the dashboard server.
func (d *Dashboard) Stop() error {
	if d.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	log.Println("[dashboard] shutting down...")
	return d.server.Shutdown(ctx)
}

// handleIndex renders the HTML dashboard page.
func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	status := d.buildStatus()
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, status); err != nil {
		log.Printf("[dashboard] template error: %v", err)
	}
}

// handleStatus returns JSON system status.
func (d *Dashboard) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := d.buildStatus()
	writeJSON(w, http.StatusOK, status)
}

// handleHealth returns a liveness probe response.
func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"status": "ok",
		"uptime": time.Since(d.startAt).String(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleMetrics returns Prometheus text format metrics.
func (d *Dashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	uptime := int64(time.Since(d.startAt).Seconds())
	d.metrics["fortress_uptime_seconds"] = uptime
	if d.threats != nil {
		d.metrics["fortress_threats_active"] = int64(len(d.threats.GetThreats()))
	}
	if d.alerter != nil {
		d.metrics["fortress_alerts_total"] = int64(d.alerter.Count())
	}
	metrics := make(map[string]int64)
	for k, v := range d.metrics {
		metrics[k] = v
	}
	d.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP fortress_alerts_total Total alerts processed\n")
	fmt.Fprintf(w, "# TYPE fortress_alerts_total counter\n")
	fmt.Fprintf(w, "fortress_alerts_total %d\n", metrics["fortress_alerts_total"])
	fmt.Fprintf(w, "# HELP fortress_threats_active Currently tracked threats\n")
	fmt.Fprintf(w, "# TYPE fortress_threats_active gauge\n")
	fmt.Fprintf(w, "fortress_threats_active %d\n", metrics["fortress_threats_active"])
	fmt.Fprintf(w, "# HELP fortress_uptime_seconds System uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE fortress_uptime_seconds gauge\n")
	fmt.Fprintf(w, "fortress_uptime_seconds %d\n", metrics["fortress_uptime_seconds"])
}

// handleThreats returns JSON list of current threats.
func (d *Dashboard) handleThreats(w http.ResponseWriter, r *http.Request) {
	if d.threats == nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}
	threats := d.threats.GetThreats()
	if threats == nil {
		threats = []map[string]interface{}{}
	}
	writeJSON(w, http.StatusOK, threats)
}

// handleThreatDetail returns JSON details for a threat by IP.
func (d *Dashboard) handleThreatDetail(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/threats/")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}
	if d.threats == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no threat provider"})
		return
	}
	threat, ok := d.threats.GetThreat(ip)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, threat)
}

// buildStatus constructs the current StatusResponse snapshot.
func (d *Dashboard) buildStatus() StatusResponse {
	d.mu.Lock()
	mode := d.mode
	d.mu.Unlock()

	threatCount := 0
	if d.threats != nil {
		threatCount = len(d.threats.GetThreats())
	}

	alertCount := 0
	if d.alerter != nil {
		alertCount = d.alerter.Count()
	}

	return StatusResponse{
		Threats: threatCount,
		DefensesActive: []string{
			"packet_inspector",
			"flow_analyzer",
			"dns_tunnel_detector",
			"http_inspector",
			"brute_force_detector",
			"hybrid_anomaly_detector",
			"behavior_analyzer",
			"correlation_engine",
			"fingerprint_engine",
			"honeypot_manager",
			"tarpit",
		},
		Uptime:        time.Since(d.startAt).Truncate(time.Second).String(),
		Mode:          mode,
		AlertsLast24h: alertCount,
	}
}

// corsMiddleware adds CORS headers to HTTP responses and handles OPTIONS preflight.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeJSON serializes data and writes it as a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[dashboard] json encode error: %v", err)
	}
}

// dashboardHTML is the dark-themed dashboard template with auto-refresh.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="5">
<title>FORTRESS V6 — Defense Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background: #0a0a0a; color: #00ff00;
  font-family: 'Courier New', monospace;
  padding: 20px;
}
h1 { color: #00cc00; border-bottom: 2px solid #00cc00; padding-bottom: 10px; margin-bottom: 20px; }
h2 { color: #009900; margin: 20px 0 10px 0; }
.section {
  border: 1px solid #1a3a1a;
  border-radius: 4px;
  padding: 15px;
  margin-bottom: 20px;
  background: #0d0d0d;
}
.row { display: flex; gap: 20px; flex-wrap: wrap; }
.card {
  border: 1px solid #1a3a1a;
  border-radius: 4px;
  padding: 15px;
  flex: 1;
  min-width: 200px;
  background: #111;
}
.label { color: #008800; font-size: 0.85em; }
.value { color: #00ff00; font-size: 1.4em; font-weight: bold; }
.warn { color: #ffaa00; }
.crit { color: #ff4444; }
.defense-tag {
  display: inline-block;
  background: #0a2a0a;
  color: #00aa00;
  padding: 4px 10px;
  margin: 3px;
  border-radius: 3px;
  font-size: 0.85em;
}
</style>
</head>
<body>
<h1>FORTRESS V6 — Defense Dashboard</h1>

<div class="section">
  <h2>System Status</h2>
  <div class="row">
    <div class="card">
      <div class="label">Uptime</div>
      <div class="value">{{.Uptime}}</div>
    </div>
    <div class="card">
      <div class="label">Mode</div>
      <div class="value">{{.Mode}}</div>
    </div>
    <div class="card">
      <div class="label">Active Threats</div>
      <div class="value{{if gt .Threats 0}} crit{{end}}">{{.Threats}}</div>
    </div>
    <div class="card">
      <div class="label">Alerts (24h)</div>
      <div class="value">{{.AlertsLast24h}}</div>
    </div>
  </div>
</div>

<div class="section">
  <h2>Active Defenses</h2>
  <div>
    {{range .DefensesActive}}
    <span class="defense-tag">{{.}}</span>
    {{end}}
  </div>
</div>

<div class="section">
  <h2>API Endpoints</h2>
  <div style="color:#008800;font-size:0.85em;">
    <div>GET /status — System status JSON</div>
    <div>GET /health — Liveness probe</div>
    <div>GET /metrics — Prometheus metrics</div>
    <div>GET /api/threats — Threat list</div>
    <div>GET /api/threats/{ip} — Threat detail</div>
  </div>
</div>

<p style="color:#004400;text-align:center;margin-top:20px;font-size:0.8em;">
  Auto-refresh: 5s | Fortress V6
</p>
</body>
</html>`
