package response

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// Channel represents an alert delivery channel type.
type Channel int

const (
	ChannelJSONL     Channel = iota // local JSON-lines file
	ChannelWebhook                  // generic HTTP webhook
	ChannelSlack                    // Slack incoming webhook
	ChannelTeams                    // Microsoft Teams connector
	ChannelDiscord                  // Discord webhook
	ChannelEmail                    // SMTP email
	ChannelSyslog                   // syslog forwarding
	ChannelPagerDuty                // PagerDuty incident
)

// String returns a human-readable channel name.
func (c Channel) String() string {
	switch c {
	case ChannelJSONL:
		return "jsonl"
	case ChannelWebhook:
		return "webhook"
	case ChannelSlack:
		return "slack"
	case ChannelTeams:
		return "teams"
	case ChannelDiscord:
		return "discord"
	case ChannelEmail:
		return "email"
	case ChannelSyslog:
		return "syslog"
	case ChannelPagerDuty:
		return "pagerduty"
	default:
		return "unknown"
	}
}

// EscalationPolicy defines how alerts of a given severity should be escalated.
type EscalationPolicy struct {
	Name           string        `json:"name"`
	Channels       []Channel     `json:"channels"`
	Cooldown       time.Duration `json:"cooldown"`
	MaxEscalations int           `json:"max_escalations"`
}

// EscalationState tracks the delivery status of a single escalation.
type EscalationState struct {
	AlertID     string    `json:"alert_id"`
	Alert       Alert     `json:"alert"`
	Policy      string    `json:"policy"`
	Channel     Channel   `json:"channel"`
	Delivered   bool      `json:"delivered"`
	DeliveredAt time.Time `json:"delivered_at,omitempty"`
	Attempts    int       `json:"attempts"`
	LastError   string    `json:"last_error,omitempty"`
}

// CooldownManager tracks per-entity cooldown windows to suppress duplicates.
type CooldownManager struct {
	mu        sync.Mutex
	cooldowns map[string]time.Time
}

// NewCooldownManager creates a CooldownManager with no active cooldowns.
func NewCooldownManager() *CooldownManager {
	return &CooldownManager{cooldowns: make(map[string]time.Time)}
}

// IsOnCooldown checks if the given key is within its cooldown window.
func (cm *CooldownManager) IsOnCooldown(key string, window time.Duration) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	expiry, exists := cm.cooldowns[key]
	if !exists {
		return false
	}
	return time.Now().Before(expiry)
}

// SetCooldown starts a cooldown window for the given key.
func (cm *CooldownManager) SetCooldown(key string, window time.Duration) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.cooldowns[key] = time.Now().Add(window)
}

// Cleanup removes cooldown entries older than the specified duration.
func (cm *CooldownManager) Cleanup(olderThan time.Duration) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	for key, expiry := range cm.cooldowns {
		if expiry.Before(cutoff) {
			delete(cm.cooldowns, key)
		}
	}
}

// SuppressDuplicates returns true if a similar alert has been seen recently.
// Uses the IP + first 50 characters of the message as the dedup key.
func SuppressDuplicates(cm *CooldownManager, alert Alert, window time.Duration) bool {
	prefix := alert.Message
	if len(prefix) > 50 {
		prefix = prefix[:50]
	}
	key := fmt.Sprintf("%s:%s", alert.IP, prefix)
	return cm.IsOnCooldown(key, window)
}

// ---------------------------------------------------------------------------
// Escalation Engine
// ---------------------------------------------------------------------------

// EscalationEngine manages multi-channel alert escalation with policies.
type EscalationEngine struct {
	mu        sync.Mutex
	policies  map[string]EscalationPolicy
	cooldowns *CooldownManager
	states    []EscalationState
	history   []EscalationState
	maxStates int
}

// NewEscalationEngine creates an EscalationEngine with default policies.
func NewEscalationEngine() *EscalationEngine {
	ee := &EscalationEngine{
		policies:  make(map[string]EscalationPolicy),
		cooldowns: NewCooldownManager(),
		states:    make([]EscalationState, 0),
		history:   make([]EscalationState, 0),
		maxStates: 500,
	}
	for _, p := range defaultPolicies() {
		ee.RegisterPolicy(p)
	}
	log.Println("[escalation] engine initialized with default policies")
	return ee
}

// RegisterPolicy adds or overwrites an escalation policy.
func (ee *EscalationEngine) RegisterPolicy(policy EscalationPolicy) {
	ee.mu.Lock()
	defer ee.mu.Unlock()
	ee.policies[policy.Name] = policy
}

// Trigger evaluates the alert against registered policies and delivers via
// configured channels. Returns the escalation states for each channel attempted.
func (ee *EscalationEngine) Trigger(alert Alert) []EscalationState {
	policy := ee.findPolicy(alert.Level)
	if policy.Name == "" {
		log.Printf("[escalation] no policy for alert level %d", alert.Level)
		return nil
	}

	// Deduplicate within cooldown window
	if SuppressDuplicates(ee.cooldowns, alert, policy.Cooldown) {
		log.Printf("[escalation] suppressed duplicate alert for %s", alert.IP)
		return nil
	}

	// Check escalation count
	if ee.countForPolicy(policy.Name) >= policy.MaxEscalations {
		log.Printf("[escalation] max escalations reached for policy %s", policy.Name)
		return nil
	}

	ee.cooldowns.SetCooldown(fmt.Sprintf("%s:%s", alert.IP,
		alert.Message[:min(50, len(alert.Message))]), policy.Cooldown)

	states := deliverAlert(policy, alert)
	ee.recordStates(states)
	return states
}

// findPolicy returns the escalation policy matching the alert level.
func (ee *EscalationEngine) findPolicy(level AlertLevel) EscalationPolicy {
	ee.mu.Lock()
	defer ee.mu.Unlock()

	switch level {
	case AlertInfo:
		if p, ok := ee.policies["info"]; ok {
			return p
		}
	case AlertWarning:
		if p, ok := ee.policies["warning"]; ok {
			return p
		}
	case AlertCritical:
		if p, ok := ee.policies["critical"]; ok {
			return p
		}
	}
	return EscalationPolicy{}
}

// countForPolicy counts recent escalation states for a policy.
func (ee *EscalationEngine) countForPolicy(name string) int {
	ee.mu.Lock()
	defer ee.mu.Unlock()

	count := 0
	cutoff := time.Now().Add(-1 * time.Hour)
	for _, s := range ee.history {
		if s.Policy == name && s.DeliveredAt.After(cutoff) {
			count++
		}
	}
	return count
}

// recordStates appends escalation states to the ring buffer.
func (ee *EscalationEngine) recordStates(states []EscalationState) {
	ee.mu.Lock()
	defer ee.mu.Unlock()

	for _, s := range states {
		ee.states = append(ee.states, s)
		if len(ee.states) > ee.maxStates {
			ee.states = ee.states[len(ee.states)-ee.maxStates:]
		}
		ee.history = append(ee.history, s)
	}
}

// GetStates returns a copy of recent escalation states.
func (ee *EscalationEngine) GetStates() []EscalationState {
	ee.mu.Lock()
	defer ee.mu.Unlock()

	out := make([]EscalationState, len(ee.states))
	copy(out, ee.states)
	return out
}

// GetHistory returns a copy of all escalation history.
func (ee *EscalationEngine) GetHistory() []EscalationState {
	ee.mu.Lock()
	defer ee.mu.Unlock()

	out := make([]EscalationState, len(ee.history))
	copy(out, ee.history)
	return out
}

// defaultPolicies returns the built-in escalation policies.
func defaultPolicies() []EscalationPolicy {
	return []EscalationPolicy{
		{
			Name:           "info",
			Channels:       []Channel{ChannelJSONL},
			Cooldown:       30 * time.Second,
			MaxEscalations: 100,
		},
		{
			Name:           "warning",
			Channels:       []Channel{ChannelJSONL, ChannelWebhook, ChannelDiscord},
			Cooldown:       5 * time.Minute,
			MaxEscalations: 20,
		},
		{
			Name:           "critical",
			Channels:       []Channel{ChannelJSONL, ChannelWebhook, ChannelDiscord, ChannelEmail, ChannelPagerDuty},
			Cooldown:       1 * time.Minute,
			MaxEscalations: 50,
		},
	}
}

// ---------------------------------------------------------------------------
// Channel Implementations
// ---------------------------------------------------------------------------

// WebhookChannel delivers alerts via generic HTTP POST webhook.
type WebhookChannel struct {
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	RetryCount int               `json:"retry_count"`
	Backoff    time.Duration     `json:"backoff"`
}

// NewWebhookChannel creates a webhook channel with sensible defaults.
func NewWebhookChannel(url string) *WebhookChannel {
	return &WebhookChannel{
		URL: url,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		RetryCount: 3,
		Backoff:    2 * time.Second,
	}
}

// Send marshals the alert as JSON and logs the webhook delivery.
func (w *WebhookChannel) Send(alert Alert) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}
	log.Printf("[escalation] webhook POST %s: %s", w.URL, string(data))
	return nil
}

// DiscordChannel delivers alerts as Discord embeds via webhook.
type DiscordChannel struct {
	WebhookURL string `json:"webhook_url"`
}

// NewDiscordChannel creates a Discord channel with the given webhook URL.
func NewDiscordChannel(webhookURL string) *DiscordChannel {
	return &DiscordChannel{WebhookURL: webhookURL}
}

// Send formats the alert as a Discord embed and logs the delivery.
func (d *DiscordChannel) Send(alert Alert) error {
	color := getDiscordColor(alert.Level)
	embed := map[string]interface{}{
		"title":       fmt.Sprintf("Fortress Alert: %s", alert.IP),
		"description": alert.Message,
		"color":       color,
		"timestamp":   alert.Timestamp.Format(time.RFC3339),
		"fields": []map[string]interface{}{
			{"name": "Score", "value": fmt.Sprintf("%.1f", alert.Score), "inline": true},
			{"name": "Level", "value": alert.Response, "inline": true},
			{"name": "IP", "value": alert.IP, "inline": true},
		},
	}
	data, err := json.Marshal(map[string]interface{}{"embeds": []interface{}{embed}})
	if err != nil {
		return fmt.Errorf("discord marshal: %w", err)
	}
	log.Printf("[escalation] discord POST %s: %s", d.WebhookURL, string(data))
	return nil
}

// getDiscordColor maps alert level to Discord embed color.
func getDiscordColor(level AlertLevel) int {
	switch level {
	case AlertInfo:
		return 0x00FF00 // green
	case AlertWarning:
		return 0xFFA500 // orange
	case AlertCritical:
		return 0xFF0000 // red
	default:
		return 0x808080 // gray
	}
}

// deliverAlert sends an alert through each channel in the escalation policy.
func deliverAlert(policy EscalationPolicy, alert Alert) []EscalationState {
	alertID := generateAlertID()
	states := make([]EscalationState, 0, len(policy.Channels))

	for _, ch := range policy.Channels {
		state := EscalationState{
			AlertID: alertID,
			Alert:   alert,
			Policy:  policy.Name,
			Channel: ch,
		}

		state.Attempts = 1
		if err := deliverToChannel(ch, alert); err != nil {
			state.LastError = err.Error()
			log.Printf("[escalation] delivery failed: %s -> %s: %v", policy.Name, ch, err)
		} else {
			state.Delivered = true
			state.DeliveredAt = time.Now()
		}
		states = append(states, state)
	}
	return states
}

// deliverToChannel routes the alert to the appropriate channel implementation.
func deliverToChannel(ch Channel, alert Alert) error {
	switch ch {
	case ChannelJSONL:
		// JSONL delivery handled by the Alerter log file — pass through
		log.Printf("[escalation] JSONL: %s score=%.1f", alert.IP, alert.Score)
		return nil
	case ChannelWebhook:
		// Placeholder — actual webhook URL would be configured
		log.Printf("[escalation] webhook would POST alert for %s", alert.IP)
		return nil
	case ChannelDiscord:
		log.Printf("[escalation] discord would POST embed for %s", alert.IP)
		return nil
	case ChannelSlack:
		log.Printf("[escalation] slack would POST message for %s", alert.IP)
		return nil
	case ChannelTeams:
		log.Printf("[escalation] teams would POST connector for %s", alert.IP)
		return nil
	case ChannelEmail:
		log.Printf("[escalation] email would send for %s", alert.IP)
		return nil
	case ChannelSyslog:
		log.Printf("[escalation] syslog would forward for %s", alert.IP)
		return nil
	case ChannelPagerDuty:
		log.Printf("[escalation] pagerduty would trigger incident for %s", alert.IP)
		return nil
	default:
		return fmt.Errorf("escalation: unsupported channel: %d", ch)
	}
}

// generateAlertID creates a unique alert identifier.
func generateAlertID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("alert-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
