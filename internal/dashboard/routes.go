package dashboard

func (d *Dashboard) registerRoutes() {
	d.mux.HandleFunc("/api/stats", d.handleStats)
	d.mux.HandleFunc("/api/threats", d.handleThreats)
	d.mux.HandleFunc("/api/threats/", d.handleThreatByIP)
	d.mux.HandleFunc("/api/timeline", d.handleTimeline)
	d.mux.HandleFunc("/api/correlations", d.handleCorrelations)
	d.mux.HandleFunc("/api/evidence/", d.handleEvidence)
	d.mux.HandleFunc("/api/config", d.handleConfig)
	d.mux.HandleFunc("/ws", d.handleWebSocket)
}
