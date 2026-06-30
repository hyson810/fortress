package deception

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"strings"
	"sync"
	"text/template"
	"time"
)

// DeceptionTemplate defines a pre-built template for generating fake content.
type DeceptionTemplate struct {
	Name      string   `json:"name"`
	Category  string   `json:"category"`
	Content   string   `json:"content"`
	Variables []string `json:"variables"`
	rendered  *template.Template
}

// LLMEngine generates convincing fake content for deception operations.
type LLMEngine struct {
	mu        sync.Mutex
	enabled   bool
	templates map[string]*DeceptionTemplate
	rng       *mrand.Rand
}

// NewLLMEngine creates an LLMEngine with built-in deception templates.
func NewLLMEngine() *LLMEngine {
	e := &LLMEngine{
		enabled:   true,
		templates: make(map[string]*DeceptionTemplate),
		rng:       mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}
	for _, tmpl := range builtinTemplates() {
		parsed, err := template.New(tmpl.Name).Parse(tmpl.Content)
		if err != nil {
			log.Printf("[llm_engine] template parse error (%s): %v", tmpl.Name, err)
			continue
		}
		tmpl.rendered = parsed
		e.templates[tmpl.Name] = tmpl
	}
	log.Printf("[llm_engine] initialized with %d templates", len(e.templates))
	return e
}

// Enable activates the LLM engine.
func (e *LLMEngine) Enable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = true
	log.Println("[llm_engine] enabled")
}

// Disable deactivates the LLM engine.
func (e *LLMEngine) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = false
}

// GenerateFakeConfig produces convincing fake configuration content
// resembling database configs, .env files, and credential stores.
func (e *LLMEngine) GenerateFakeConfig() string {
	vars := map[string]string{
		"DBUser":        randomChoice(e.rng, []string{"admin", "postgres", "app_user", "root", "sa"}),
		"DBPassword":    randomString(16),
		"DBHost":        fakeHostname(e.rng),
		"DBName":        randomChoice(e.rng, []string{"production", "analytics", "users_db", "billing", "core"}),
		"JWTSecret":     randomString(32),
		"APIKey":        fakeAPIKey(e.rng),
		"AWSKey":        fakeAWSKey(e.rng),
		"EncryptionKey": randomString(32),
	}
	return e.renderOrFallback("db_config", vars, varenvFallback(vars))
}

// GenerateFakeSourceCode produces fake source code with deliberate-looking vulnerabilities.
func (e *LLMEngine) GenerateFakeSourceCode() string {
	vars := map[string]string{
		"AppName":      randomChoice(e.rng, []string{"user-service", "payment-api", "auth-svc", "admin-panel"}),
		"Framework":    randomChoice(e.rng, []string{"express", "flask", "spring-boot", "laravel", "django"}),
		"DBPassword":   randomString(12),
		"APIKey":       fakeAPIKey(e.rng),
		"AdminPassword": randomString(8),
	}
	return e.renderOrFallback("source_code", vars, fakeSourceCodeFallback(vars))
}

// GenerateFakeEmail produces a fake email thread tailored to the given lure.
func (e *LLMEngine) GenerateFakeEmail(lure string) string {
	vars := map[string]string{
		"Lure":         lure,
		"SenderName":   randomChoice(e.rng, []string{"David Chen", "Sarah Mitchell", "James Liu", "Priya Patel", "Marcus Wong"}),
		"SenderTitle":  randomChoice(e.rng, []string{"CTO", "VP of Engineering", "DevOps Lead", "Security Architect", "Head of Infrastructure"}),
		"Password":     randomString(12),
		"InternalHost": fakeHostname(e.rng),
		"APIKey":       fakeAPIKey(e.rng),
		"Timestamp":    fakeTimestamp(e.rng),
	}
	return e.renderOrFallback("email", vars, fakeEmailFallback(vars))
}

// GenerateBreadcrumb produces a personalized honey trail based on attacker profile.
func (e *LLMEngine) GenerateBreadcrumb(attackerProfile string) string {
	profile := strings.ToLower(attackerProfile)
	breadcrumbType := "standard"

	switch {
	case strings.Contains(profile, "apt") || strings.Contains(profile, "advanced"):
		breadcrumbType = "sophisticated"
	case strings.Contains(profile, "script") || strings.Contains(profile, "novice"):
		breadcrumbType = "simple"
	}

	vars := map[string]string{
		"Type":       breadcrumbType,
		"Hostname":   fakeHostname(e.rng),
		"APIKey":     fakeAPIKey(e.rng),
		"Password":   randomString(14),
		"Timestamp":  fakeTimestamp(e.rng),
	}

	parts := []string{
		fmt.Sprintf(`{"type": "breadcrumb", "level": "%s"}`, breadcrumbType),
	}

	switch breadcrumbType {
	case "sophisticated":
		parts = append(parts,
			fmt.Sprintf(`{"file": "internal_docs/network_topology.pdf", "host": "%s"}`, vars["Hostname"]),
			fmt.Sprintf(`{"file": ".ssh/id_rsa_backup", "note": "emergency access key for %s"}`, vars["Hostname"]),
			fmt.Sprintf(`{"url": "https://%s/admin/debug?token=%s"}`, vars["Hostname"], vars["APIKey"][:16]),
		)
	case "simple":
		parts = append(parts,
			fmt.Sprintf(`{"url": "https://%s/admin", "note": "admin:admin"}`, vars["Hostname"]),
			fmt.Sprintf(`{"file": ".env.backup", "content": "DB_PASSWORD=%s"}`, vars["Password"]),
		)
	default:
		parts = append(parts,
			fmt.Sprintf(`{"file": "config/database.yml", "host": "%s"}`, vars["Hostname"]),
			fmt.Sprintf(`{"credential": "%s:%s"}`, randomChoice(e.rng, []string{"admin", "deploy", "backup"}), vars["Password"]),
		)
	}

	return "[" + strings.Join(parts, ",\n ") + "]"
}

// PlausibilityScore evaluates how convincing generated content is on a 0-1 scale.
func (e *LLMEngine) PlausibilityScore(content string) float64 {
	if content == "" {
		return 0
	}
	score := 0.5 // neutral baseline

	// Positive indicators
	if strings.Contains(content, "Docker") || strings.Contains(content, "Kubernetes") {
		score += 0.05
	}
	if strings.Contains(content, "AWS") || strings.Contains(content, "GCP") || strings.Contains(content, "Azure") {
		score += 0.05
	}
	if strings.Contains(content, "postgresql://") || strings.Contains(content, "mysql://") {
		score += 0.05
	}
	if strings.Contains(content, ".internal") || strings.Contains(content, ".local") {
		score += 0.05
	}
	if strings.Contains(content, "TODO") || strings.Contains(content, "FIXME") {
		score += 0.03
	}
	if strings.Contains(content, "sk-") || strings.Contains(content, "AKIA") {
		score += 0.04
	}
	if strings.Contains(content, "api_key") || strings.Contains(content, "secret") {
		score += 0.04
	}

	// Negative indicators
	exclamationCount := strings.Count(content, "!")
	if exclamationCount > 3 {
		score -= 0.05 * float64(exclamationCount-3)
	}
	if strings.Contains(content, "password123") || strings.Contains(content, "admin/admin") {
		score -= 0.1
	}
	if strings.Contains(content, "PLACEHOLDER") || strings.Contains(content, "TODO_REPLACE") {
		score -= 0.05
	}
	if strings.Contains(content, "asdf") || strings.Contains(content, "qwerty") {
		score -= 0.08
	}
	if strings.Count(content, "test") > 5 {
		score -= 0.05
	}

	if score < 0 {
		score = 0
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// renderOrFallback executes a named template with vars, falling back if not found.
func (e *LLMEngine) renderOrFallback(name string, vars map[string]string, fallback string) string {
	e.mu.Lock()
	tmpl, ok := e.templates[name]
	e.mu.Unlock()

	if ok && tmpl.rendered != nil {
		var buf bytes.Buffer
		if err := tmpl.rendered.Execute(&buf, vars); err == nil {
			return buf.String()
		}
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Template helpers
// ---------------------------------------------------------------------------

// builtinTemplates returns the pre-built deception templates.
func builtinTemplates() []*DeceptionTemplate {
	return []*DeceptionTemplate{
		{
			Name:     "db_config",
			Category: "config",
			Content: `# Database Configuration
# Generated: {{.Timestamp}}
# WARNING: Production credentials — do not commit

development:
  adapter: postgresql
  host: {{.Hostname}}
  port: 5432
  database: {{.DBName}}_dev
  username: {{.DBUser}}
  password: dev_password

production:
  adapter: postgresql
  host: {{.Hostname}}
  port: 5432
  database: {{.DBName}}
  username: {{.DBUser}}
  password: {{.DBPassword}}
  pool: 25
  ssl: true

redis:
  url: redis://:{{.RedisPassword}}@{{.Hostname}}:6379/0`,
			Variables: []string{"DBUser", "DBPassword", "DBName", "Hostname", "RedisPassword", "Timestamp"},
		},
		{
			Name:     "env_file",
			Category: "config",
			Content: `# Environment Configuration
DATABASE_URL=postgresql://{{.DBUser}}:{{.DBPassword}}@{{.Hostname}}:5432/{{.DBName}}
REDIS_URL=redis://{{.Hostname}}:6379/0
JWT_SECRET={{.JWTSecret}}
API_KEY={{.APIKey}}
AWS_ACCESS_KEY_ID={{.AWSKey}}
AWS_SECRET_ACCESS_KEY={{.AWSSecret}}
ENCRYPTION_KEY={{.EncryptionKey}}
ADMIN_EMAIL={{.AdminEmail}}
SENTRY_DSN=https://{{.SentryKey}}@sentry.internal/{{.SentryProject}}`,
			Variables: []string{"DBUser", "DBPassword", "Hostname", "DBName", "JWTSecret", "APIKey", "AWSKey", "AWSSecret", "EncryptionKey", "AdminEmail", "SentryKey", "SentryProject"},
		},
		{
			Name:     "aws_credentials",
			Category: "config",
			Content: `[default]
aws_access_key_id = {{.AWSKey}}
aws_secret_access_key = {{.AWSSecret}}
region = us-east-1

[production]
aws_access_key_id = {{.AWSProdKey}}
aws_secret_access_key = {{.AWSProdSecret}}
region = us-east-1
role_arn = arn:aws:iam::{{.AccountID}}:role/{{.RoleName}}`,
			Variables: []string{"AWSKey", "AWSSecret", "AWSProdKey", "AWSProdSecret", "AccountID", "RoleName"},
		},
		{
			Name:     "source_code",
			Category: "code",
			Content: `// {{.AppName}} — {{.Framework}} application
// TODO: Refactor auth — temporary workaround, fix before launch
// FIXME: Remove hardcoded credentials after CI migration

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
)

const (
	dbUser     = "{{.DBUser}}"
	dbPassword = "{{.DBPassword}}"
	apiKey     = "{{.APIKey}}"
	adminPass  = "{{.AdminPassword}}"
)

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	// Bypass auth for internal IPs — won't affect production, right?
	if r.RemoteAddr == "10.0.0.0/8" {
		userID = "admin"
	}

	query := "SELECT * FROM users WHERE id = '" + userID + "'"
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Internal error", 500)
		return
	}
	defer rows.Close()

	// Parse and return user...
}

func adminReset(w http.ResponseWriter, r *http.Request) {
	// Emergency admin reset — will be deleted after deploy
	if r.URL.Query().Get("token") == adminPass {
		fmt.Fprintf(w, "Admin access granted")
	}
}`,
			Variables: []string{"AppName", "Framework", "DBUser", "DBPassword", "APIKey", "AdminPassword"},
		},
		{
			Name:     "email",
			Category: "communication",
			Content: `From: {{.SenderName}} <{{.SenderName | email}}@{{.CompanyDomain}}>
To: dev-team@{{.CompanyDomain}}
Subject: Re: Emergency credentials for {{.Lure}} deployment
Date: {{.Timestamp}}

Team,

Here are the credentials for the {{.Lure}} deployment. Please handle with care — these are production keys.

SSH: deploy@{{.InternalHost}}
Key: /home/deploy/.ssh/id_rsa_backup (password: {{.Password}})

API access: https://{{.InternalHost}}/api
Key: {{.APIKey}}
Env: production

Do NOT share these outside the team. The vault migration is scheduled for next sprint.

Regards,
{{.SenderName}}
{{.SenderTitle}}`,
			Variables: []string{"SenderName", "SenderTitle", "CompanyDomain", "Lure", "InternalHost", "Password", "APIKey", "Timestamp"},
		},
		{
			Name:     "ssh_key",
			Category: "config",
			Content: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA{{.KeyBody}}
-----END OPENSSH PRIVATE KEY-----
# Backup key for {{.Hostname}} — created {{.Timestamp}}
# Passphrase: {{.Passphrase}}`,
			Variables: []string{"KeyBody", "Hostname", "Timestamp", "Passphrase"},
		},
	}
}

// ---------------------------------------------------------------------------
// Fallback content generators
// ---------------------------------------------------------------------------

func varenvFallback(vars map[string]string) string {
	return fmt.Sprintf(`DATABASE_URL=postgresql://%s:%s@%s:5432/%s
JWT_SECRET=%s
API_KEY=%s
AWS_ACCESS_KEY_ID=%s
ENCRYPTION_KEY=%s
`, vars["DBUser"], vars["DBPassword"], vars["DBHost"], vars["DBName"],
		vars["JWTSecret"], vars["APIKey"], vars["AWSKey"], vars["EncryptionKey"])
}

func fakeSourceCodeFallback(vars map[string]string) string {
	return fmt.Sprintf(`// %s — Internal API
// FIXME: Remove hardcoded credentials

const dbPassword = "%s"
const apiKey = "%s"
const adminPass = "%s"

func getUser(id string) (*User, error) {
    query := "SELECT * FROM users WHERE id = '" + id + "'"
    return db.QueryRow(query)
}`, vars["AppName"], vars["DBPassword"], vars["APIKey"], vars["AdminPassword"])
}

func fakeEmailFallback(vars map[string]string) string {
	return fmt.Sprintf(`From: %s <devops@company.internal>
Subject: Emergency credentials for %s
Date: %s

Here are the access credentials:
SSH: deploy@%s (password: %s)
API: %s

-- %s, %s`,
		vars["SenderName"], vars["Lure"], vars["Timestamp"],
		vars["InternalHost"], vars["Password"],
		vars["APIKey"],
		vars["SenderName"], vars["SenderTitle"])
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

func randomString(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = charset[i%len(charset)]
			continue
		}
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}

func randomChoice(rng *mrand.Rand, options []string) string {
	if len(options) == 0 {
		return ""
	}
	return options[rng.Intn(len(options))]
}

func fakeHostname(rng *mrand.Rand) string {
	prefixes := []string{"db-prod", "api-internal", "k8s-worker", "bastion", "monitoring", "ci-runner", "vault", "registry"}
	domains := []string{"internal", "local", "prod.private", "staging.internal", "dc1.cluster"}
	return fmt.Sprintf("%s-%02d.%s",
		randomChoice(rng, prefixes),
		rng.Intn(99)+1,
		randomChoice(rng, domains))
}

func fakeTimestamp(rng *mrand.Rand) string {
	daysBack := time.Duration(rng.Intn(30) + 1)
	return time.Now().Add(-daysBack * 24 * time.Hour).Format("Mon, 02 Jan 2006 15:04:05 -0700")
}

func fakeAPIKey(rng *mrand.Rand) string {
	prefixes := []string{"sk-", "github_pat_", "ghp_", "pk."}
	return randomChoice(rng, prefixes) + randomString(24)
}

func fakeAWSKey(rng *mrand.Rand) string {
	return "AKIA" + strings.ToUpper(randomString(12))
}
