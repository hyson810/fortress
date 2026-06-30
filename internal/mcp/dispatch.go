package mcp

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"
)

// AuthLevel represents the authorization level required for tool access.
type AuthLevel int

const (
	AuthReadOnly      AuthLevel = iota // basic read-only access
	AuthOperator                       // can run defensive operations
	AuthAdministrator                  // full system control
)

// String returns a human-readable representation of the auth level.
func (a AuthLevel) String() string {
	switch a {
	case AuthReadOnly:
		return "readonly"
	case AuthOperator:
		return "operator"
	case AuthAdministrator:
		return "administrator"
	default:
		return "unknown"
	}
}

// ToolPermission maps a tool name to its minimum required authorization level.
type ToolPermission struct {
	ToolName string    `json:"tool_name"`
	MinAuth  AuthLevel `json:"min_auth"`
}

// defaultPermissions defines the authorization requirements for all Fortress tools.
var defaultPermissions = map[string]AuthLevel{
	"fortress_status":                AuthReadOnly,
	"fortress_list_threats":          AuthReadOnly,
	"fortress_intel_lookup":          AuthReadOnly,
	"fortress_swarm_status":          AuthReadOnly,
	"fortress_block_ip":              AuthOperator,
	"fortress_unblock_ip":            AuthOperator,
	"fortress_scan_target":           AuthOperator,
	"fortress_launch_counterstrike":  AuthAdministrator,
	"fortress_toggle_mode":           AuthAdministrator,
}

// AuthCheck verifies that the given auth level is sufficient to invoke the named tool.
// Returns an error if the tool is unknown or the caller lacks permission.
func AuthCheck(tool string, level AuthLevel) error {
	required, ok := defaultPermissions[tool]
	if !ok {
		return fmt.Errorf("dispatch: unknown tool: %s", tool)
	}
	if level < required {
		return fmt.Errorf("dispatch: insufficient auth for %s: have %s, need %s",
			tool, level, required)
	}
	return nil
}

// tokenBucket implements a simple token bucket rate limiter.
type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

// RateLimiter provides per-tool rate limiting using token buckets.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // tokens per second
	burst   int     // max tokens
}

// NewRateLimiter creates a RateLimiter with the given rate (req/min) and burst size.
func NewRateLimiter(ratePerMin, burst int) *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    float64(ratePerMin) / 60.0,
		burst:   burst,
	}
}

// Allow checks whether a request for the given tool is within rate limits.
// Returns true if the request is permitted.
func (rl *RateLimiter) Allow(tool string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, ok := rl.buckets[tool]
	if !ok {
		bucket = &tokenBucket{
			tokens:   float64(rl.burst),
			lastTime: time.Now(),
		}
		rl.buckets[tool] = bucket
	}

	now := time.Now()
	elapsed := now.Sub(bucket.lastTime).Seconds()
	bucket.tokens += elapsed * rl.rate
	if bucket.tokens > float64(rl.burst) {
		bucket.tokens = float64(rl.burst)
	}
	bucket.lastTime = now

	if bucket.tokens < 1.0 {
		return false
	}
	bucket.tokens--
	return true
}

// Reset clears all token buckets, effectively resetting rate limits.
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.buckets = make(map[string]*tokenBucket)
}

// Dispatcher handles tool dispatch with auth checking and rate limiting.
type Dispatcher struct {
	mu       sync.Mutex
	handlers *HandlerRegistry
	limiter  *RateLimiter
	auditor  *AuditLogger
}

// NewDispatcher creates a Dispatcher backed by the given HandlerRegistry.
func NewDispatcher(hr *HandlerRegistry) *Dispatcher {
	return &Dispatcher{
		handlers: hr,
		limiter:  NewRateLimiter(60, 10),
	}
}

// SetRateLimiter configures the rate limiter used by the dispatcher.
func (d *Dispatcher) SetRateLimiter(rl *RateLimiter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.limiter = rl
}

// SetAuditLogger attaches an audit logger for recording dispatch events.
func (d *Dispatcher) SetAuditLogger(al *AuditLogger) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.auditor = al
}

// Dispatch validates auth, checks rate limits, and invokes the tool handler.
// It returns the JSON-encoded result or an error.
func (d *Dispatcher) Dispatch(tool string, params json.RawMessage, auth AuthLevel) (json.RawMessage, error) {
	if err := AuthCheck(tool, auth); err != nil {
		d.audit(tool, string(params), "", "denied: "+err.Error())
		return nil, err
	}

	d.mu.Lock()
	limiter := d.limiter
	d.mu.Unlock()

	if !limiter.Allow(tool) {
		err := fmt.Errorf("dispatch: rate limit exceeded for %s", tool)
		d.audit(tool, string(params), "", "denied: "+err.Error())
		return nil, err
	}

	var args map[string]interface{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			d.audit(tool, string(params), "", "parse error: "+err.Error())
			return nil, fmt.Errorf("dispatch: parse params: %w", err)
		}
	}

	result, err := d.handlers.Call(tool, args)
	if err != nil {
		d.audit(tool, string(params), "", "error: "+err.Error())
		return nil, err
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		d.audit(tool, string(params), "", "marshal error: "+err.Error())
		return nil, fmt.Errorf("dispatch: marshal result: %w", err)
	}

	d.audit(tool, string(params), string(resultJSON), "success")
	return resultJSON, nil
}

// audit records a dispatch event if an audit logger is configured.
func (d *Dispatcher) audit(tool, params, result, status string) {
	d.mu.Lock()
	auditor := d.auditor
	d.mu.Unlock()

	if auditor == nil {
		return
	}
	entry := AuditLog{
		Timestamp: time.Now(),
		Tool:      tool,
		Params:    params,
		Result:    result,
		Status:    status,
	}
	if err := auditor.Log(entry); err != nil {
		log.Printf("[dispatch] audit log error: %v", err)
	}
}

// AuditLog represents a single tool dispatch event for audit trail purposes.
type AuditLog struct {
	Timestamp time.Time `json:"timestamp"`
	Tool      string    `json:"tool"`
	Params    string    `json:"params"`
	Result    string    `json:"result"`
	Status    string    `json:"status"`
	SessionID string    `json:"session_id,omitempty"`
}

// AuditLogger writes audit log entries as JSON-lines to a file.
type AuditLogger struct {
	mu     sync.Mutex
	writer *os.File
}

// NewAuditLogger opens the specified path for appending JSON-lines audit records.
func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("dispatch: open audit log: %w", err)
	}
	log.Printf("[dispatch] audit logger writing to %s", path)
	return &AuditLogger{writer: f}, nil
}

// Log writes an audit log entry as a JSON line to the audit file.
func (al *AuditLogger) Log(entry AuditLog) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("dispatch: marshal audit entry: %w", err)
	}
	if _, err := al.writer.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("dispatch: write audit entry: %w", err)
	}
	return nil
}

// Close flushes and closes the audit log file.
func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.writer != nil {
		return al.writer.Close()
	}
	return nil
}

// randomID generates a short random identifier using crypto/rand.
func randomID() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			// fallback — should never happen
			b[i] = charset[i%len(charset)]
			continue
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}
