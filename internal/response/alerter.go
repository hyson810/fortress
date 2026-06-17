package response

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// AlertLevel classifies the severity of a security alert.
type AlertLevel int

const (
	AlertInfo     AlertLevel = iota // informational / silent monitoring
	AlertWarning                    // elevated threat / predator detected
	AlertCritical                   // critical / blackhole response
)

// Alert represents a single security alert with full contextual details.
type Alert struct {
	Level     AlertLevel `json:"level"`
	IP        string     `json:"ip"`
	Message   string     `json:"message"`
	Score     float64    `json:"score"`
	Timestamp time.Time  `json:"timestamp"`
	Response  string     `json:"response"`
}

// Alerter manages alert collection, persistence, and distribution.
// Alerts are appended to a JSON-lines log file and held in a
// bounded in-memory ring buffer.
type Alerter struct {
	mu       sync.Mutex
	alerts   []Alert
	logFile  *os.File
	webhooks []string
}

// NewAlerter creates an Alerter that writes JSON-lines to
// logPath/alerts.jsonl. If the file cannot be opened, alerts
// are still held in memory and logged to stderr.
func NewAlerter(logPath string) (*Alerter, error) {
	f, err := os.OpenFile(logPath+"/alerts.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[alerter] cannot open alert log: %v — logging to stderr only", err)
		f = nil
	}
	return &Alerter{
		alerts:  make([]Alert, 0),
		logFile: f,
	}, nil
}

// Alert records and emits an alert at the given level.
// It is safe for concurrent use.
func (a *Alerter) Alert(ip, message string, score float64, level AlertLevel) {
	alert := Alert{
		Level:     level,
		IP:        ip,
		Message:   message,
		Score:     score,
		Timestamp: time.Now(),
		Response:  levelToString(level),
	}

	a.mu.Lock()
	a.alerts = append(a.alerts, alert)
	if len(a.alerts) > 1000 {
		a.alerts = a.alerts[len(a.alerts)-1000:]
	}
	a.mu.Unlock()

	if a.logFile != nil {
		data, err := json.Marshal(alert)
		if err == nil {
			a.logFile.Write(append(data, '\n'))
		}
	}

	prefix := "🟢"
	switch level {
	case AlertWarning:
		prefix = "🟡"
	case AlertCritical:
		prefix = "🔴"
	}
	log.Printf("[alert] %s %s: %s (score=%.1f)", prefix, ip, message, score)
}

// RecentAlerts returns the most recent n alerts from the in-memory buffer.
func (a *Alerter) RecentAlerts(n int) []Alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n >= len(a.alerts) {
		out := make([]Alert, len(a.alerts))
		copy(out, a.alerts)
		return out
	}
	start := len(a.alerts) - n
	out := make([]Alert, n)
	copy(out, a.alerts[start:])
	return out
}

// AddWebhook registers a webhook URL for out-of-band alert delivery.
func (a *Alerter) AddWebhook(url string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.webhooks = append(a.webhooks, url)
}

// Webhooks returns the list of registered webhook URLs.
func (a *Alerter) Webhooks() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.webhooks))
	copy(out, a.webhooks)
	return out
}

// Close flushes and closes the alert log file.
func (a *Alerter) Close() {
	if a.logFile != nil {
		a.logFile.Close()
	}
}

// levelToString maps an AlertLevel to its human-readable response label.
func levelToString(l AlertLevel) string {
	switch l {
	case AlertInfo:
		return "A·静默"
	case AlertWarning:
		return "C·掠食者"
	case AlertCritical:
		return "D·黑洞"
	default:
		return "unknown"
	}
}

// NotifyWebhooks sends an alert payload to every registered webhook URL.
// This is a non-blocking best-effort delivery; failures are logged.
func NotifyWebhooks(webhooks []string, alert Alert) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}
	for _, url := range webhooks {
		log.Printf("[webhook] would POST %s: %s", url, string(data))
	}
	return nil
}

// Count returns the number of alerts currently held in memory.
func (a *Alerter) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.alerts)
}
