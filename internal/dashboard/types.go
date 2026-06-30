package dashboard

// ThreatSummary is a summary of a single threat IP with its detection scores and status.
type ThreatSummary struct {
	IP            string  `json:"ip"`
	TotalScore    float64 `json:"total_score"`
	ScanScore     float64 `json:"scan_score"`
	FloodScore    float64 `json:"flood_score"`
	AnomalyScore  float64 `json:"anomaly_score"`
	HoneypotScore float64 `json:"honeypot_score"`
	IntelScore    float64 `json:"intel_score"`
	Level         string  `json:"level"`    // "critical","high","medium","low","none"
	Response      string  `json:"response"` // "A","B","C","D"
	Banned        bool    `json:"banned"`
	BanExpires    int64   `json:"ban_expires"` // unix timestamp
	FirstSeen     int64   `json:"first_seen"`
	LastSeen      int64   `json:"last_seen"`
}

// PipelineStatus reports the current load and throughput of a single pipeline stage.
type PipelineStatus struct {
	Stage   string  `json:"stage"`
	LoadPct float64 `json:"load_pct"` // 0-100
	PPS     float64 `json:"pps"`      // packets per second
	Status  string  `json:"status"`   // "ok","warning","critical"
}

// AlertEvent represents a single security event in the alert timeline.
type AlertEvent struct {
	ID        string  `json:"id"`
	Timestamp int64   `json:"ts"`
	Severity  int     `json:"severity"` // 1-5
	Source    string  `json:"source"`   // "L1","L2",...,"suricata","crowdsec","host","audit"
	Message   string  `json:"message"`
	IP        string  `json:"ip,omitempty"`
	Score     float64 `json:"score,omitempty"`
}

// StatsResponse is the top-level response for the /api/stats endpoint.
type StatsResponse struct {
	PacketsProcessed uint64           `json:"packets_processed"`
	ThreatsDetected  uint64           `json:"threats_detected"`
	ActiveThreats    int              `json:"active_threats"`
	PacketsDropped   uint64           `json:"packets_dropped"`
	PipelineStatus   []PipelineStatus `json:"pipeline_status"`
	UptimeSeconds    int64            `json:"uptime_seconds"`
	AlertsToday      int              `json:"alerts_today"`
}

// WSMessage is a WebSocket/SSE message with a type tag and arbitrary payload.
type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// CrossLayerResult describes a multi-layer attack chain detected by the correlation engine.
type CrossLayerResult struct {
	IP         string   `json:"ip"`
	Layers     []string `json:"layers"` // ["L1","L3","L5","L7"]
	Boost      float64  `json:"boost"`  // score boost multiplier
	TotalScore float64  `json:"total_score"`
	Tactics    []string `json:"tactics"` // MITRE ATT&CK
}

// EvidenceItem is a single forensic record in the evidence chain.
type EvidenceItem struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"ts"`
	Type      string `json:"type"`
	Summary   string `json:"summary"`
	Hash      string `json:"hash"`
}

// EvidenceChain contains all forensic records for an IP and their hash-chain integrity status.
type EvidenceChain struct {
	IP         string         `json:"ip"`
	Items      []EvidenceItem `json:"items"`
	ChainValid bool           `json:"chain_valid"`
}
