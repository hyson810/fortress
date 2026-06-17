package dashboard

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	count := d.brain.Count()
	metrics := d.brain.GetMetrics()

	resp := StatsResponse{
		ActiveThreats:    count,
		PipelineStatus:   []PipelineStatus{},
	}

	if metrics != nil {
		if v, ok := metrics["packets_processed"].(uint64); ok {
			resp.PacketsProcessed = v
		}
		if v, ok := metrics["threats_detected"].(uint64); ok {
			resp.ThreatsDetected = v
		}
	}

	jsonResponse(w, resp)
}

func (d *Dashboard) handleThreats(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	records := d.brain.Top(limit)
	threats := make([]ThreatSummary, 0, len(records))
	for _, rec := range records {
		if m, ok := rec.(map[string]interface{}); ok {
			ts := ThreatSummary{}
			if ip, ok := m["ip"].(string); ok {
				ts.IP = ip
			}
			if s, ok := m["score"].(float64); ok {
				ts.TotalScore = s
			}
			if s, ok := m["scan_score"].(float64); ok {
				ts.ScanScore = s
			}
			if s, ok := m["flood_score"].(float64); ok {
				ts.FloodScore = s
			}
			if s, ok := m["anomaly_score"].(float64); ok {
				ts.AnomalyScore = s
			}
			if s, ok := m["honeypot_score"].(float64); ok {
				ts.HoneypotScore = s
			}
			if s, ok := m["intel_score"].(float64); ok {
				ts.IntelScore = s
			}
			if l, ok := m["level"].(string); ok {
				ts.Level = l
			}
			threats = append(threats, ts)
		}
	}

	jsonResponse(w, threats)
}

func (d *Dashboard) handleThreatByIP(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/threats/")
	if ip == "" {
		http.Error(w, "missing IP", http.StatusBadRequest)
		return
	}

	score, level := d.brain.GetScore(ip)
	jsonResponse(w, map[string]interface{}{
		"ip":    ip,
		"score": score,
		"level": level,
	})
}

func (d *Dashboard) handleTimeline(w http.ResponseWriter, r *http.Request) {
	// Return empty timeline for now; will be connected to alerter in Task 9
	jsonResponse(w, make([]AlertEvent, 0))
}

func (d *Dashboard) handleCorrelations(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, make([]CrossLayerResult, 0))
}

func (d *Dashboard) handleEvidence(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/evidence/")
	if ip == "" {
		http.Error(w, "missing IP", http.StatusBadRequest)
		return
	}

	jsonResponse(w, EvidenceChain{
		IP:         ip,
		Items:      []EvidenceItem{},
		ChainValid: true,
	})
}

func (d *Dashboard) handleConfig(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, d.config)
}
