// Package response — Webhook Alert Dispatcher
//
// Sends alerts (from alerter.go) to configured Slack/Discord/custom webhooks.
// Integrates with the pipeline threat callback and counterstrike engine.
package response

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/fortress/v6/internal/logger"
)

// ───────────────────────────────────────────────────────────────────────────
// WebhookDispatcher sends alerts to external webhook URLs
// ───────────────────────────────────────────────────────────────────────────

// WebhookDispatcher sends alerts to configured webhook URLs with
// cooldown tracking to prevent flooding.
type WebhookDispatcher struct {
	mu       sync.Mutex
	webhooks []string
	cooldown map[string]time.Time
	interval time.Duration
	client   *http.Client
}

// NewWebhookDispatcher creates a webhook dispatcher.
// webhooks: Slack/Discord incoming webhook URLs.
// interval: minimum time between alerts for the same source IP.
func NewWebhookDispatcher(interval time.Duration, webhooks ...string) *WebhookDispatcher {
	return &WebhookDispatcher{
		webhooks: webhooks,
		cooldown: make(map[string]time.Time),
		interval: interval,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Send dispatches an alert to all configured webhooks with cooldown.
func (wd *WebhookDispatcher) Send(a Alert) {
	wd.mu.Lock()
	if a.IP != "" {
		if last, ok := wd.cooldown[a.IP]; ok {
			if time.Since(last) < wd.interval {
				wd.mu.Unlock()
				return
			}
		}
		wd.cooldown[a.IP] = time.Now()
	}
	hooks := make([]string, len(wd.webhooks))
	copy(hooks, wd.webhooks)
	wd.mu.Unlock()

	// Always log structured alert
	logger.Warn("alert_dispatch",
		"level", levelToString(a.Level),
		"ip", a.IP,
		"msg", a.Message,
		"score", a.Score,
		"response", a.Response,
	)

	for _, url := range hooks {
		go wd.post(url, a)
	}
}

// post sends a single alert to one webhook URL.
func (wd *WebhookDispatcher) post(url string, a Alert) {
	payload := map[string]interface{}{
		"text": fmt.Sprintf("[%s] %s — %s (score=%.1f, src=%s)",
			levelToString(a.Level), a.Message, a.Response, a.Score, a.IP),
		"attachments": []map[string]interface{}{
			{
				"color": wd.color(a.Level),
				"fields": []map[string]interface{}{
					{"title": "Level", "value": levelToString(a.Level), "short": true},
					{"title": "Source", "value": a.IP, "short": true},
					{"title": "Score", "value": fmt.Sprintf("%.1f", a.Score), "short": true},
					{"title": "Action", "value": a.Response, "short": true},
				},
				"ts": a.Timestamp.Unix(),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		logger.Error("webhook marshal", "err", err)
		return
	}

	resp, err := wd.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		logger.Warn("webhook post failed", "url", url, "err", err)
		return
	}
	resp.Body.Close()
}

func (wd *WebhookDispatcher) color(lvl AlertLevel) string {
	switch lvl {
	case AlertCritical:
		return "danger"
	case AlertWarning:
		return "warning"
	default:
		return "good"
	}
}

// levelToString converts an AlertLevel to its human-readable name.
