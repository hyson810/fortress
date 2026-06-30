package defense

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TokenType categorizes a honeytoken by the type of credential it emulates.
type TokenType string

const (
	TokenAWSCredentials    TokenType = "aws_credentials"
	TokenDBConnection      TokenType = "db_connection"
	TokenAPIKey            TokenType = "api_key"
	TokenSSHKey            TokenType = "ssh_key"
	TokenGeneric           TokenType = "generic"
	TokenWebBug            TokenType = "web_bug"
)

// Honeytoken represents a single deceptive credential file or token.
type Honeytoken struct {
	ID        string    `json:"id"`
	FilePath  string    `json:"file_path"`
	TokenType TokenType `json:"token_type"`
	Content   string    `json:"-"` // never serialized to logs
	Hash      string    `json:"hash"`
	Deployed  time.Time `json:"deployed"`
	Active    bool      `json:"active"`
}

// CanaryFile represents a monitored file whose integrity is periodically
// verified.
type CanaryFile struct {
	ID          string    `json:"id"`
	FilePath    string    `json:"file_path"`
	ContentHash string    `json:"content_hash"`
	Size        int64     `json:"size"`
	LastChecked time.Time `json:"last_checked"`
	Active      bool      `json:"active"`
}

// TrapAlert describes a triggered honeytoken or canary event.
type TrapAlert struct {
	TokenID   string    `json:"token_id"`
	TokenType TokenType `json:"token_type"`
	FilePath  string    `json:"file_path"`
	Timestamp time.Time `json:"timestamp"`
	AccessIP  string    `json:"access_ip,omitempty"`
	Action    string    `json:"action"` // "accessed", "modified", "deleted"
	Detail    string    `json:"detail,omitempty"`
}

// AccessCallback is invoked when a honeytoken is triggered.
type AccessCallback func(TrapAlert)

// TrapManager deploys and monitors honeytokens and canary files for
// intrusion detection.
type TrapManager struct {
	mu         sync.Mutex
	tokens     map[string]*Honeytoken
	canaries   map[string]*CanaryFile
	alerts     []TrapAlert
	maxAlerts  int
	onAlert    AccessCallback
}

// NewTrapManager creates a new TrapManager.
func NewTrapManager() *TrapManager {
	return &TrapManager{
		tokens:    make(map[string]*Honeytoken),
		canaries:  make(map[string]*CanaryFile),
		alerts:    make([]TrapAlert, 0, 256),
		maxAlerts: 10000,
	}
}

// OnAlert registers a callback that fires when a trap is triggered.
func (tm *TrapManager) OnAlert(cb AccessCallback) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.onAlert = cb
}

// DeployHoneytoken writes a honeytoken file to the given path and registers it.
func (tm *TrapManager) DeployHoneytoken(path string, tokenType TokenType, content string) (*Honeytoken, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tokenID := generateTokenID(tokenType)

	// Write file to disk.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("traps: deploy %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return nil, fmt.Errorf("traps: deploy %s: %w", path, err)
	}

	hash := sha256.Sum256([]byte(content))
	token := &Honeytoken{
		ID:        tokenID,
		FilePath:  path,
		TokenType: tokenType,
		Content:   content,
		Hash:      hex.EncodeToString(hash[:]),
		Deployed:  time.Now(),
		Active:    true,
	}
	tm.tokens[tokenID] = token

	log.Printf("[traps] honeytoken %s deployed at %s", tokenID, path)
	return token, nil
}

// DeployCanary registers an existing file as a canary for integrity monitoring.
func (tm *TrapManager) DeployCanary(path string) (*CanaryFile, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("traps: canary stat %s: %w", path, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("traps: canary read %s: %w", path, err)
	}

	hash := sha256.Sum256(data)
	canary := &CanaryFile{
		ID:          fmt.Sprintf("canary-%x", rand.Uint64()),
		FilePath:    path,
		ContentHash: hex.EncodeToString(hash[:]),
		Size:        info.Size(),
		LastChecked: time.Now(),
		Active:      true,
	}
	tm.canaries[canary.ID] = canary

	log.Printf("[traps] canary %s deployed at %s", canary.ID, path)
	return canary, nil
}

// CheckCanaries verifies the integrity of all active canary files. Returns a
// list of alerts for any canary that has been modified or deleted.
func (tm *TrapManager) CheckCanaries() []TrapAlert {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	var alerts []TrapAlert
	now := time.Now()

	for _, c := range tm.canaries {
		if !c.Active {
			continue
		}

		c.LastChecked = now

		info, err := os.Stat(c.FilePath)
		if os.IsNotExist(err) {
			alert := TrapAlert{
				TokenID: c.ID, TokenType: TokenGeneric,
				FilePath: c.FilePath, Timestamp: now,
				Action: "deleted",
				Detail: "canary file has been deleted",
			}
			alerts = append(alerts, alert)
			tm.recordAlertLocked(alert)
			log.Printf("[traps] ALERT: canary %s deleted", c.FilePath)
			continue
		}
		if err != nil {
			log.Printf("[traps] canary stat %s: %v", c.FilePath, err)
			continue
		}

		if info.Size() != c.Size {
			alert := TrapAlert{
				TokenID: c.ID, TokenType: TokenGeneric,
				FilePath: c.FilePath, Timestamp: now,
				Action: "modified",
				Detail: fmt.Sprintf("size changed from %d to %d", c.Size, info.Size()),
			}
			alerts = append(alerts, alert)
			tm.recordAlertLocked(alert)
			log.Printf("[traps] ALERT: canary %s size changed", c.FilePath)
			continue
		}

		data, err := os.ReadFile(c.FilePath)
		if err != nil {
			log.Printf("[traps] canary read %s: %v", c.FilePath, err)
			continue
		}

		newHash := hex.EncodeToString(sha256.New().Sum(data))
		if newHash != c.ContentHash {
			alert := TrapAlert{
				TokenID: c.ID, TokenType: TokenGeneric,
				FilePath: c.FilePath, Timestamp: now,
				Action: "modified",
				Detail: "content hash mismatch",
			}
			alerts = append(alerts, alert)
			tm.recordAlertLocked(alert)
			log.Printf("[traps] ALERT: canary %s content modified", c.FilePath)
		}
	}

	return alerts
}

// CheckHoneytoken verifies whether a specific honeytoken file has been
// accessed or modified on disk.
func (tm *TrapManager) CheckHoneytoken(tokenID string) ([]TrapAlert, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	token, ok := tm.tokens[tokenID]
	if !ok {
		return nil, fmt.Errorf("traps: token %s not found", tokenID)
	}

	var alerts []TrapAlert
	info, err := os.Stat(token.FilePath)
	if os.IsNotExist(err) {
		alert := TrapAlert{
			TokenID: tokenID, TokenType: token.TokenType,
			FilePath: token.FilePath, Timestamp: time.Now(),
			Action: "deleted",
		}
		alerts = append(alerts, alert)
		tm.recordAlertLocked(alert)
		token.Active = false
	} else if err == nil {
		// Check if modified.
		if info.ModTime().After(token.Deployed) {
			data, _ := os.ReadFile(token.FilePath)
			h := sha256.Sum256(data)
			newHash := hex.EncodeToString(h[:])
			if newHash != token.Hash {
				alert := TrapAlert{
					TokenID: tokenID, TokenType: token.TokenType,
					FilePath: token.FilePath, Timestamp: time.Now(),
					Action: "modified",
				}
				alerts = append(alerts, alert)
				tm.recordAlertLocked(alert)
			}
		}
	}

	return alerts, nil
}

// FakeAWSCredentials returns a deceptively-formatted AWS credentials file
// content suitable for use as a honeytoken.
func FakeAWSCredentials() string {
	accessKey := fmt.Sprintf("AKIA%04X%04X%04X%04X",
		rand.Intn(0xFFFF), rand.Intn(0xFFFF),
		rand.Intn(0xFFFF), rand.Intn(0xFFFF))
	secretKey := fmt.Sprintf("%040x%040x", rand.Uint64(), rand.Uint64())
	return fmt.Sprintf(`[default]
aws_access_key_id = %s
aws_secret_access_key = %s
region = us-east-1
output = json

# This file was auto-generated by the Fortress honeytoken system.
# Unauthorized use of these credentials is being monitored.
`, accessKey, secretKey[:40])
}

// FakeDatabaseConnectionString returns a deceptively-formatted database
// connection string suitable for use as a honeytoken.
func FakeDatabaseConnectionString() string {
	dbName := []string{"prod", "analytics", "users", "billing", "inventory"}[rand.Intn(5)]
	host := fmt.Sprintf("db-%04x.internal", rand.Intn(0xFFFF))
	user := []string{"admin", "readonly", "repl", "api", "devops"}[rand.Intn(5)]
	pass := fmt.Sprintf("P%02xssword!", rand.Intn(0xFF))
	return fmt.Sprintf(
		"postgresql://%s:%s@%s:5432/%s?sslmode=require",
		user, pass, host, dbName,
	)
}

// FakeAPIKey returns a deceptively-formatted API key string.
func FakeAPIKey() string {
	prefixes := []string{"sk-", "pk_", "ft-", "api-"}
	prefix := prefixes[rand.Intn(len(prefixes))]
	return prefix + fmt.Sprintf("%032x", rand.Uint64())+fmt.Sprintf("%016x", rand.Uint64())
}

// WebBug generates a 1x1 tracking pixel HTML snippet with a unique ID
// for tracking when an email or page is viewed.
func WebBug() string {
	id := fmt.Sprintf("wb-%08x-%04x", rand.Uint64(), rand.Intn(0xFFFF))
	return fmt.Sprintf(
		`<img src="https://track.fortress.local/pixel?id=%s" `+
			`width="1" height="1" alt="" style="display:none" />`, id,
	)
}

// RecentAlerts returns a snapshot of all recorded trap alerts.
func (tm *TrapManager) RecentAlerts() []TrapAlert {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	out := make([]TrapAlert, len(tm.alerts))
	copy(out, tm.alerts)
	return out
}

// AlertCount returns the total number of alerts recorded.
func (tm *TrapManager) AlertCount() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return len(tm.alerts)
}

// ClearAlerts removes all recorded alerts.
func (tm *TrapManager) ClearAlerts() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.alerts = tm.alerts[:0]
}

// ListTokens returns all registered honeytokens.
func (tm *TrapManager) ListTokens() []Honeytoken {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	out := make([]Honeytoken, 0, len(tm.tokens))
	for _, t := range tm.tokens {
		out = append(out, *t)
	}
	return out
}

// ListCanaries returns all registered canary files.
func (tm *TrapManager) ListCanaries() []CanaryFile {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	out := make([]CanaryFile, 0, len(tm.canaries))
	for _, c := range tm.canaries {
		out = append(out, *c)
	}
	return out
}

// RemoveToken deactivates and removes a honeytoken by ID.
func (tm *TrapManager) RemoveToken(tokenID string) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	token, ok := tm.tokens[tokenID]
	if !ok {
		return false
	}

	token.Active = false
	os.Remove(token.FilePath) // best-effort cleanup
	delete(tm.tokens, tokenID)
	log.Printf("[traps] honeytoken %s removed", tokenID)
	return true
}

// RemoveCanary deactivates and removes a canary by ID.
func (tm *TrapManager) RemoveCanary(canaryID string) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	_, ok := tm.canaries[canaryID]
	if !ok {
		return false
	}

	delete(tm.canaries, canaryID)
	log.Printf("[traps] canary %s removed", canaryID)
	return true
}

// recordAlertLocked adds an alert to the in-memory log and fires the
// callback if registered. Must be called with mu held.
func (tm *TrapManager) recordAlertLocked(alert TrapAlert) {
	tm.alerts = append(tm.alerts, alert)
	if len(tm.alerts) > tm.maxAlerts {
		tm.alerts = tm.alerts[len(tm.alerts)-tm.maxAlerts:]
	}

	if tm.onAlert != nil {
		go tm.onAlert(alert)
	}
}

// generateTokenID produces a unique identifier for a honeytoken.
func generateTokenID(tokenType TokenType) string {
	return fmt.Sprintf("%s-%08x", tokenType, rand.Uint64())
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
