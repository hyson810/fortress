// Package response provides REST API, alerting, and health monitoring
// for the Fortress V6 ecosystem.
package response

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/engine"
	"github.com/fortress/v6/internal/logger"
)

// ───────────────────────────────────────────────────────────────────────────
// API Server — lightweight HTTP API for health, metrics, and threats
// ───────────────────────────────────────────────────────────────────────────

// APIServer serves the Fortress HTTP API with three endpoints:
//   GET /health   — service health + uptime
//   GET /metrics  — pipeline stats + active threats
//   GET /threats  — top N threats with scores
type APIServer struct {
	server       *http.Server
	started      time.Time
	scorer       *brain.ShardScorer
	pipeline     *engine.DetectionPipeline
	mu           sync.RWMutex
	allowedIPs   []string
	strikeEnabled bool
}

// NewAPIServer creates an API server. Pass nil for optional components.
// By default only localhost (127.0.0.1, ::1) is allowed and /strike is disabled.
func NewAPIServer(addr string, scorer *brain.ShardScorer, pipeline *engine.DetectionPipeline) *APIServer {
	s := &APIServer{
		started:       time.Now(),
		scorer:        scorer,
		pipeline:      pipeline,
		allowedIPs:    []string{"127.0.0.1", "::1"},
		strikeEnabled: false,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/threats", s.handleThreats)
	mux.HandleFunc("/inject", s.handleInject)
	mux.HandleFunc("/strike", s.handleStrike)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// SetAllowedIPs replaces the default IP whitelist with the given list.
func (s *APIServer) SetAllowedIPs(ips []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowedIPs = ips
}

// EnableStrike enables the /strike debug endpoint (disabled by default).
func (s *APIServer) EnableStrike() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.strikeEnabled = true
}

// isAllowed checks whether the given remote address is in the IP whitelist.
// It strips the port portion before comparing.
func (s *APIServer) isAllowed(addr string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Extract IP from "IP:port"
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		// If there's no port, use the address directly
		ip = addr
	}
	for _, allowed := range s.allowedIPs {
		if ip == allowed {
			return true
		}
	}
	return false
}

// Start begins listening in a background goroutine.
func (s *APIServer) Start() {
	go func() {
		logger.Info("API server listening", "addr", s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("API server error", "err", err)
		}
	}()
}

// Stop gracefully shuts down the HTTP server.
func (s *APIServer) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.server.Shutdown(ctx)
	logger.Info("API server stopped")
}

// ───────────────────────────────────────────────────────────────────────────
// Handlers
// ───────────────────────────────────────────────────────────────────────────

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"status":   "ok",
		"uptime":   time.Since(s.started).Round(time.Second).String(),
		"version":  "v6.0.0",
		"entries":  0,
		"threats":  0,
	}

	if s.scorer != nil {
		resp["entries"] = s.scorer.Count()
	}
	if s.pipeline != nil {
		stats := s.pipeline.Stats()
		resp["processed"] = stats.PacketsProcessed
		resp["dropped"] = stats.PacketsDropped
		resp["threats"] = stats.ThreatsDetected
	}

	apiWriteJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"uptime": time.Since(s.started).Round(time.Second).String(),
	}

	if s.pipeline != nil {
		stats := s.pipeline.Stats()
		resp["packets_processed"] = stats.PacketsProcessed
		resp["packets_dropped"] = stats.PacketsDropped
		resp["threats_detected"] = stats.ThreatsDetected
	}

	if s.scorer != nil {
		resp["active_entries"] = s.scorer.Count()
		top := s.scorer.Top(10)
		var threats []map[string]interface{}
		for _, rec := range top {
			if rec == nil {
				continue
			}
			threats = append(threats, map[string]interface{}{
				"ip":         rec.IP,
				"score":      rec.TotalScore,
				"level":      rec.Level.String(),
				"scan_score": rec.ScanScore,
				"flood_score": rec.FloodScore,
			})
		}
		if len(threats) > 0 {
			resp["top_threats"] = threats
		}
	}

	apiWriteJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleThreats(w http.ResponseWriter, r *http.Request) {
	if s.scorer == nil {
		apiWriteJSON(w, http.StatusOK, map[string]string{"error": "scorer not available"})
		return
	}

	top := s.scorer.Top(10)
	var threats []map[string]interface{}
	for _, rec := range top {
		if rec == nil {
			continue
		}
		threats = append(threats, map[string]interface{}{
			"ip":         rec.IP,
			"score":      rec.TotalScore,
			"level":      rec.Level.String(),
			"scan_score": rec.ScanScore,
			"flood_score": rec.FloodScore,
		})
	}

	apiWriteJSON(w, http.StatusOK, map[string]interface{}{
		"count":   len(threats),
		"threats": threats,
	})
}

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

func apiWriteJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// handleInject accepts synthetic packets for pipeline testing (cockfight mode).
// POST /inject with JSON body: {"src_ip":"1.2.3.4","dst_port":80,"proto":"TCP","flags":"S","size":64}
func (s *APIServer) handleInject(w http.ResponseWriter, r *http.Request) {
	if !s.isAllowed(r.RemoteAddr) {
		apiWriteJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
		return
	}
	if r.Method != http.MethodPost {
		apiWriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		SrcIP   string `json:"src_ip"`
		DstIP   string `json:"dst_ip"`
		DstPort int    `json:"dst_port"`
		Proto   string `json:"proto"`
		Flags   string `json:"flags"`
		Size    int    `json:"size"`
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiWriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if req.SrcIP == "" {
		req.SrcIP = "0.0.0.0"
	}
	if req.DstIP == "" {
		req.DstIP = "10.0.0.1"
	}
	if req.DstPort == 0 {
		req.DstPort = 80
	}
	if req.Proto == "" {
		req.Proto = "TCP"
	}
	var pktPayload []byte
	if req.Payload != "" {
		pktPayload = []byte(req.Payload)
	} else {
		pktPayload = []byte("GET / HTTP/1.0")
	}
	if s.pipeline == nil {
		apiWriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "pipeline not available"})
		return
	}
	if req.Size <= 0 || req.Size > 65535 {
		req.Size = 64
	}
	s.pipeline.Inject(engine.PipelinePacket{
		Timestamp:   time.Now(),
		SrcIP:       req.SrcIP,
		DstIP:       req.DstIP,
		SrcPort:     40000,
		DstPort:     uint16(req.DstPort),
		Protocol:    req.Proto,
		TCPFlags:    req.Flags,
		PayloadSize: req.Size,
		Payload:     pktPayload,
		Direction:   "ingress",
	})
	logger.Info("injected packet", "src", req.SrcIP, "dst_port", req.DstPort)
	apiWriteJSON(w, http.StatusOK, map[string]string{"status": "injected"})
}

// handleStrike directly scores an IP high — simulates confirmed multi-vector attack.
// POST /strike {"ip":"5.5.5.5","reason":"flood+scan+exploit"}
func (s *APIServer) handleStrike(w http.ResponseWriter, r *http.Request) {
	if !s.isAllowed(r.RemoteAddr) {
		apiWriteJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
		return
	}
	s.mu.RLock()
	enabled := s.strikeEnabled
	s.mu.RUnlock()
	if !enabled {
		apiWriteJSON(w, http.StatusForbidden, map[string]string{"error": "strike endpoint disabled"})
		return
	}
	if r.Method != http.MethodPost {
		apiWriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error":"POST required"})
		return
	}
	var req struct {
		IP     string  `json:"ip"`
		Power  float64 `json:"power"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		apiWriteJSON(w, http.StatusBadRequest, map[string]string{"error":"ip required"})
		return
	}
	if s.scorer == nil {
		apiWriteJSON(w, http.StatusOK, map[string]string{"error":"no scorer"})
		return
	}
	// Multi-vector strike: hits ALL score types at once
	s.scorer.GetOrCreate(req.IP)
	s.scorer.AddScanScore(req.IP, int(1000.0 * req.Power))     // heavy scan
	s.scorer.AddFloodScore(req.IP, 500.0 * req.Power)      // heavy flood
	s.scorer.AddAnomalyScore(req.IP, 15.0 * req.Power)   // extreme anomaly
	s.scorer.AddHoneypotTrip(req.IP)          // honeypot interaction
	s.scorer.AddIntelMatch(req.IP, "deathmatch")
	rec := s.scorer.GetOrCreate(req.IP)
	logger.Warn("deathstrike", "ip", req.IP, "score", rec.TotalScore, "reason", req.Reason, "power", req.Power)
	apiWriteJSON(w, http.StatusOK, map[string]interface{}{
		"status": "struck",
		"ip": req.IP,
		"score": rec.TotalScore,
		"level": rec.Level.String(),
	})
}
