package dashboard

type ThreatSummary struct {
	IP           string  `json:"ip"`
	TotalScore   float64 `json:"total_score"`
	ScanScore    float64 `json:"scan_score"`
	FloodScore   float64 `json:"flood_score"`
	AnomalyScore float64 `json:"anomaly_score"`
	HoneypotScore float64 `json:"honeypot_score"`
	IntelScore   float64 `json:"intel_score"`
	Level        string  `json:"level"`    // "critical","high","medium","low","none"
	Response     string  `json:"response"` // "A","B","C","D"
	Banned       bool    `json:"banned"`
	BanExpires   int64   `json:"ban_expires"` // unix timestamp
	FirstSeen    int64   `json:"first_seen"`
	LastSeen     int64   `json:"last_seen"`
}

type PipelineStatus struct {
	Stage   string  `json:"stage"`
	LoadPct float64 `json:"load_pct"` // 0-100
	PPS     float64 `json:"pps"`      // 每秒处理数
	Status  string  `json:"status"`   // "ok","warning","critical"
}

type AlertEvent struct {
	ID        string  `json:"id"`
	Timestamp int64   `json:"ts"`
	Severity  int     `json:"severity"` // 1-5
	Source    string  `json:"source"`   // "L1","L2",...,"suricata","crowdsec","host","audit"
	Message   string  `json:"message"`
	IP        string  `json:"ip,omitempty"`
	Score     float64 `json:"score,omitempty"`
}

type StatsResponse struct {
	PacketsProcessed uint64           `json:"packets_processed"`
	ThreatsDetected  uint64           `json:"threats_detected"`
	ActiveThreats    int              `json:"active_threats"`
	PacketsDropped   uint64           `json:"packets_dropped"`
	PipelineStatus   []PipelineStatus `json:"pipeline_status"`
	UptimeSeconds    int64            `json:"uptime_seconds"`
	AlertsToday      int              `json:"alerts_today"`
}

type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type CrossLayerResult struct {
	IP         string   `json:"ip"`
	Layers     []string `json:"layers"`      // ["L1","L3","L5","L7"]
	Boost      float64  `json:"boost"`       // 分数提升倍数
	TotalScore float64  `json:"total_score"`
	Tactics    []string `json:"tactics"`     // MITRE ATT&CK
}

type EvidenceItem struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"ts"`
	Type      string `json:"type"`
	Summary   string `json:"summary"`
	Hash      string `json:"hash"`
}

type EvidenceChain struct {
	IP         string         `json:"ip"`
	Items      []EvidenceItem `json:"items"`
	ChainValid bool           `json:"chain_valid"`
}
