package brain

import (
	"sync"
	"time"
)

// alertEntry records a single alert for correlation analysis.
type alertEntry struct {
	Time time.Time
	IP   string
	Type string
}

// CorrelationEngine tracks recent alerts and detects coordinated
// activity across multiple IPs within a short time window.
type CorrelationEngine struct {
	mu     sync.Mutex
	alerts []alertEntry
}

const maxCorrelationAlerts = 100
const correlationWindow = 60 * time.Second
const minCorrelatedIPs = 3

// NewCorrelationEngine creates a new CorrelationEngine.
func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{alerts: make([]alertEntry, 0, maxCorrelationAlerts)}
}

// Feed records a new alert for correlation analysis.
func (ce *CorrelationEngine) Feed(ip, alertType string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.alerts = append(ce.alerts, alertEntry{time.Now(), ip, alertType})
	if len(ce.alerts) > maxCorrelationAlerts {
		ce.alerts = ce.alerts[len(ce.alerts)-maxCorrelationAlerts:]
	}
}

// Check examines recent alerts for correlation.
//
// It returns the set of IPs involved and a score multiplier (>0) when
// multiple distinct IPs emit similar alert types within the correlation
// window.  Returns (nil, 0) when no correlation is detected.
func (ce *CorrelationEngine) Check() ([]string, float64) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-correlationWindow)
	ipSet := make(map[string]struct{})
	typeSet := make(map[string]struct{})
	for i := len(ce.alerts) - 1; i >= 0; i-- {
		a := ce.alerts[i]
		if a.Time.Before(cutoff) {
			break
		}
		ipSet[a.IP] = struct{}{}
		typeSet[a.Type] = struct{}{}
	}
	if len(ipSet) >= minCorrelatedIPs && len(typeSet) <= 3 {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		multiplier := 1.0 + 0.1*float64(len(ipSet))
		if multiplier > 1.5 {
			multiplier = 1.5
		}
		return ips, multiplier
	}
	return nil, 0
}
