package deception

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// AttackerProfile records observed behavior and characteristics of an attacker.
type AttackerProfile struct {
	IP          string    `json:"ip"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Tools       []string  `json:"tools"`
	SkillLevel  string    `json:"skill_level"`
	Persistence bool      `json:"persistence"`
	Objectives  []string  `json:"objectives"`
	PortsScanned []int   `json:"ports_scanned"`
	RequestRate float64   `json:"request_rate"`
	UserAgents  []string  `json:"user_agents"`
	Techniques  []string  `json:"techniques"`
}

// BehavioralFingerprint captures temporal and tool-use patterns.
type BehavioralFingerprint struct {
	TypingSpeed        float64       `json:"typing_speed_ms"`
	ToolOrder          []string      `json:"tool_order"`
	ActiveHours        []int         `json:"active_hours"`
	TimePattern        string        `json:"time_pattern"`
	AvgSessionDuration time.Duration `json:"avg_session_duration"`
}

// AttackerEvent represents a single observed attacker action.
type AttackerEvent struct {
	IP        string    `json:"ip"`
	Tool      string    `json:"tool"`
	Port      int       `json:"port"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
	Technique string    `json:"technique"`
}

// Deception represents a deployed deception asset targeting an attacker.
type Deception struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	TargetIP   string    `json:"target_ip"`
	Content    string    `json:"content"`
	DeployedAt time.Time `json:"deployed_at"`
	Activated  bool      `json:"activated"`
}

// AttributionClues represents planted breadcrumbs pointing to a false attacker.
type AttributionClues struct {
	PlantedAt time.Time `json:"planted_at"`
	TargetIP  string    `json:"target_ip"`
	ClueType  string    `json:"clue_type"`
	Content   string    `json:"content"`
	PointsTo  string    `json:"points_to"`
}

// CounterIntelEngine tracks attacker behavior and deploys counter-intelligence.
type CounterIntelEngine struct {
	mu           sync.Mutex
	profiles     map[string]*AttackerProfile
	fingerprints map[string]*BehavioralFingerprint
	deceptions   map[string][]string // IP -> deployed deception IDs
}

// NewCounterIntelEngine creates a new CounterIntelEngine.
func NewCounterIntelEngine() *CounterIntelEngine {
	return &CounterIntelEngine{
		profiles:     make(map[string]*AttackerProfile),
		fingerprints: make(map[string]*BehavioralFingerprint),
		deceptions:   make(map[string][]string),
	}
}

// TrackAttackerBehavior updates the attacker profile with a new event.
func (ce *CounterIntelEngine) TrackAttackerBehavior(ip string, event AttackerEvent) AttackerProfile {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	profile, exists := ce.profiles[ip]
	if !exists {
		profile = &AttackerProfile{
			IP:        ip,
			FirstSeen: event.Timestamp,
		}
		ce.profiles[ip] = profile
		ce.fingerprints[ip] = &BehavioralFingerprint{}
	}

	profile.LastSeen = event.Timestamp

	if event.Tool != "" {
		profile.Tools = appendUnique(profile.Tools, event.Tool)
	}
	if event.Port > 0 {
		profile.PortsScanned = appendUniqueInt(profile.PortsScanned, event.Port)
	}
	if event.UserAgent != "" {
		profile.UserAgents = appendUnique(profile.UserAgents, event.UserAgent)
	}
	if event.Technique != "" {
		profile.Techniques = appendUnique(profile.Techniques, event.Technique)
	}

	// Update fingerprint
	fp := ce.fingerprints[ip]
	fp.ToolOrder = appendUnique(fp.ToolOrder, event.Tool)
	hour := event.Timestamp.Hour()
	fp.ActiveHours = appendUniqueInt(fp.ActiveHours, hour)

	// Compute request rate based on observation window
	duration := profile.LastSeen.Sub(profile.FirstSeen)
	if duration.Seconds() > 0 {
		totalEvents := float64(len(profile.Tools) + len(profile.PortsScanned))
		profile.RequestRate = totalEvents / duration.Seconds()
	}

	// Re-assess skill and objectives
	profile.SkillLevel = classifySkillLevel(profile)
	profile.Persistence = len(fp.ActiveHours) > 6
	profile.Objectives = inferObjectives(profile)

	// Update fingerprint patterns
	fp.TimePattern = classifyTimePattern(fp.ActiveHours)
	if len(profile.Tools) > 1 {
		fp.AvgSessionDuration = duration / time.Duration(len(profile.Tools))
	}

	// Return a copy
	copied := *profile
	copied.Tools = copyStringSlice(profile.Tools)
	copied.PortsScanned = copyIntSlice(profile.PortsScanned)
	copied.UserAgents = copyStringSlice(profile.UserAgents)
	copied.Techniques = copyStringSlice(profile.Techniques)
	copied.Objectives = copyStringSlice(profile.Objectives)
	return copied
}

// ClassifyAttacker determines the attacker's skill level and potential APT affiliation.
func (ce *CounterIntelEngine) ClassifyAttacker(ip string) (skillLevel string, nationState bool, aptGroup string) {
	ce.mu.Lock()
	profile, exists := ce.profiles[ip]
	ce.mu.Unlock()

	if !exists {
		return "unknown", false, ""
	}

	skillLevel = profile.SkillLevel
	nationState = assessNationState(profile)
	aptGroup = guessAPTGroup(profile)
	return
}

// DeployTargetedDeception generates deceptions tailored to the attacker's profile.
func (ce *CounterIntelEngine) DeployTargetedDeception(profile AttackerProfile) []Deception {
	deceptions := make([]Deception, 0)

	switch profile.SkillLevel {
	case "novice":
		// Obvious traps — fake admin panels, "accidental" credential leaks
		deceptions = append(deceptions, Deception{
			ID:         generateDeceptionID(),
			Type:       "fake_admin_panel",
			TargetIP:   profile.IP,
			Content:    "login.html with admin:admin credentials exposed in source",
			DeployedAt: time.Now(),
		}, Deception{
			ID:         generateDeceptionID(),
			Type:       "env_leak",
			TargetIP:   profile.IP,
			Content:    ".env file with fake AWS credentials accessible at /.env",
			DeployedAt: time.Now(),
		})

	case "intermediate":
		// Moderate traps — fake internal docs, backup SSH keys
		deceptions = append(deceptions, Deception{
			ID:         generateDeceptionID(),
			Type:       "backup_ssh_key",
			TargetIP:   profile.IP,
			Content:    "id_rsa_backup with plausible passphrase hint",
			DeployedAt: time.Now(),
		}, Deception{
			ID:         generateDeceptionID(),
			Type:       "internal_wiki",
			TargetIP:   profile.IP,
			Content:    "Rendered internal wiki page with fake network diagrams",
			DeployedAt: time.Now(),
		})

	case "advanced", "expert":
		// Sophisticated traps — fake internal docs, counterfeit diagrams, APT-style breadcrumbs
		deceptions = append(deceptions, Deception{
			ID:         generateDeceptionID(),
			Type:       "network_diagram",
			TargetIP:   profile.IP,
			Content:    "Counterfeit network topology with honeypot subnets marked as 'sensitive'",
			DeployedAt: time.Now(),
		}, Deception{
			ID:         generateDeceptionID(),
			Type:       "classified_doc",
			TargetIP:   profile.IP,
			Content:    "Fake 'internal use only' document with misleading attribution metadata",
			DeployedAt: time.Now(),
		}, Deception{
			ID:         generateDeceptionID(),
			Type:       "breadcrumb_chain",
			TargetIP:   profile.IP,
			Content:    "Multi-hop breadcrumb trail leading to a honeypot subnet",
			DeployedAt: time.Now(),
		})
	}

	ce.mu.Lock()
	for _, d := range deceptions {
		ce.deceptions[profile.IP] = append(ce.deceptions[profile.IP], d.ID)
	}
	ce.mu.Unlock()

	log.Printf("[counter_intel] deployed %d targeted deceptions for %s (skill=%s)",
		len(deceptions), profile.IP, profile.SkillLevel)
	return deceptions
}

// FeedFalseIntel generates fake intelligence to feed into the attacker's recon.
func (ce *CounterIntelEngine) FeedFalseIntel(ip string) []Deception {
	ce.mu.Lock()
	profile := ce.profiles[ip]
	ce.mu.Unlock()

	if profile == nil {
		return nil
	}

	fakeData := []Deception{
		{
			ID:         generateDeceptionID(),
			Type:       "competitor_ip",
			TargetIP:   ip,
			Content:    fmt.Sprintf("Fake competitor IPs: 198.51.100.%d, 203.0.113.%d", ipsum()%255, ipsum()%255),
			DeployedAt: time.Now(),
		},
		{
			ID:         generateDeceptionID(),
			Type:       "fake_account",
			TargetIP:   ip,
			Content:    fmt.Sprintf("Internal user 'svc-backup' with 'elevated' access, password: %s", randomStringHex(12)),
			DeployedAt: time.Now(),
		},
		{
			ID:         generateDeceptionID(),
			Type:       "backup_ssh",
			TargetIP:   ip,
			Content:    fmt.Sprintf("SSH key for 'emergency' access to %s", fakeHostnameDet()),
			DeployedAt: time.Now(),
		},
	}

	ce.mu.Lock()
	for _, d := range fakeData {
		ce.deceptions[ip] = append(ce.deceptions[ip], d.ID)
	}
	ce.mu.Unlock()

	log.Printf("[counter_intel] deployed false intel for %s (%d items)", ip, len(fakeData))
	return fakeData
}

// PlantAttributionClues leaves breadcrumbs that point to a false target entity.
func (ce *CounterIntelEngine) PlantAttributionClues(ip string, falseTarget string) []AttributionClues {
	clues := []AttributionClues{
		{
			PlantedAt: time.Now(),
			TargetIP:  ip,
			ClueType:  "fake_timestamps",
			Content:   fmt.Sprintf("Log entries predating current incident, attributed to %s", falseTarget),
			PointsTo:  falseTarget,
		},
		{
			PlantedAt: time.Now(),
			TargetIP:  ip,
			ClueType:  "tool_signature",
			Content:   fmt.Sprintf("HTTP User-Agent and TLS fingerprint matching known %s infrastructure", falseTarget),
			PointsTo:  falseTarget,
		},
		{
			PlantedAt: time.Now(),
			TargetIP:  ip,
			ClueType:  "language_artifact",
			Content:   fmt.Sprintf("Code comments and variable names suggesting %s origin", falseTarget),
			PointsTo:  falseTarget,
		},
	}

	log.Printf("[counter_intel] planted %d attribution clues pointing to %s for attacker %s",
		len(clues), falseTarget, ip)
	return clues
}

// GetProfile returns a copy of the attacker profile for the given IP.
func (ce *CounterIntelEngine) GetProfile(ip string) (AttackerProfile, bool) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	profile, exists := ce.profiles[ip]
	if !exists {
		return AttackerProfile{}, false
	}

	copied := *profile
	copied.Tools = copyStringSlice(profile.Tools)
	copied.PortsScanned = copyIntSlice(profile.PortsScanned)
	copied.UserAgents = copyStringSlice(profile.UserAgents)
	copied.Techniques = copyStringSlice(profile.Techniques)
	copied.Objectives = copyStringSlice(profile.Objectives)
	return copied, true
}

// GetAllProfiles returns copies of all tracked attacker profiles.
func (ce *CounterIntelEngine) GetAllProfiles() []AttackerProfile {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	result := make([]AttackerProfile, 0, len(ce.profiles))
	for _, p := range ce.profiles {
		copied := *p
		copied.Tools = copyStringSlice(p.Tools)
		copied.PortsScanned = copyIntSlice(p.PortsScanned)
		copied.UserAgents = copyStringSlice(p.UserAgents)
		copied.Techniques = copyStringSlice(p.Techniques)
		copied.Objectives = copyStringSlice(p.Objectives)
		result = append(result, copied)
	}
	return result
}

// GetDeceptions returns deception IDs deployed against the given IP.
func (ce *CounterIntelEngine) GetDeceptions(ip string) []string {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ids, ok := ce.deceptions[ip]
	if !ok {
		return nil
	}
	out := make([]string, len(ids))
	copy(out, ids)
	return out
}

// ---------------------------------------------------------------------------
// Internal classification helpers
// ---------------------------------------------------------------------------

func classifySkillLevel(profile *AttackerProfile) string {
	toolCount := len(profile.Tools)
	portCount := len(profile.PortsScanned)
	techniqueCount := len(profile.Techniques)

	switch {
	case techniqueCount >= 6 && hasAdvancedTechniques(profile.Techniques):
		return "expert"
	case techniqueCount >= 4 && toolCount >= 6:
		return "advanced"
	case toolCount >= 3 && portCount >= 10:
		return "intermediate"
	default:
		return "novice"
	}
}

func hasAdvancedTechniques(techniques []string) bool {
	advanced := map[string]bool{
		"T1036": true, "T1573": true, "T1071": true,
		"T1574": true, "T1055": true, "T1027": true,
	}
	for _, t := range techniques {
		if advanced[t] {
			return true
		}
	}
	return false
}

func assessNationState(profile *AttackerProfile) bool {
	if profile.SkillLevel != "advanced" && profile.SkillLevel != "expert" {
		return false
	}
	if profile.Persistence && len(profile.Techniques) >= 5 {
		return true
	}
	// Long dwell time and living-off-the-land techniques suggest nation-state
	if time.Since(profile.FirstSeen) > 24*time.Hour && hasAdvancedTechniques(profile.Techniques) {
		return true
	}
	return false
}

func guessAPTGroup(profile *AttackerProfile) string {
	techniques := strings.Join(profile.Techniques, " ")
	tools := strings.Join(profile.Tools, " ")

	switch {
	case strings.Contains(tools, "mimikatz") || strings.Contains(techniques, "T1003"):
		return "APT29-like"
	case strings.Contains(tools, "cobalt") && strings.Contains(techniques, "T1573"):
		return "APT41-like"
	case strings.Contains(tools, "nmap") && strings.Contains(techniques, "T1046") && len(profile.PortsScanned) > 100:
		return "Lazarus-like"
	case strings.Contains(tools, "metasploit") || strings.Contains(techniques, "T1210"):
		return "APT28-like"
	default:
		return "unknown"
	}
}

func inferObjectives(profile *AttackerProfile) []string {
	objectives := make([]string, 0)

	// Port-based inference
	scannedPorts := make(map[int]bool)
	for _, p := range profile.PortsScanned {
		scannedPorts[p] = true
	}

	if scannedPorts[22] {
		objectives = append(objectives, "lateral_movement")
	}
	if scannedPorts[3306] || scannedPorts[5432] || scannedPorts[1433] {
		objectives = append(objectives, "data_exfiltration")
	}
	if scannedPorts[80] || scannedPorts[443] || scannedPorts[8080] {
		objectives = append(objectives, "web_exploitation")
	}
	if scannedPorts[3389] || scannedPorts[5900] {
		objectives = append(objectives, "remote_access")
	}
	if len(profile.Tools) > 5 && profile.Persistence {
		objectives = append(objectives, "persistent_access")
	}
	if len(profile.PortsScanned) > 50 {
		objectives = append(objectives, "network_reconnaissance")
	}

	if len(objectives) == 0 {
		objectives = append(objectives, "reconnaissance")
	}
	return deduplicateStrings(objectives)
}

func classifyTimePattern(activeHours []int) string {
	if len(activeHours) == 0 {
		return "unknown"
	}

	// Check if hours cluster around business hours (UTC 8-18)
	businessHours := 0
	for _, h := range activeHours {
		if h >= 8 && h <= 18 {
			businessHours++
		}
	}

	if len(activeHours) > 12 {
		return "automated"
	}
	if float64(businessHours)/float64(len(activeHours)) > 0.7 {
		return "office_hours"
	}
	return "sporadic"
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func generateDeceptionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("deception-%d", time.Now().UnixNano())
	}
	return "decp-" + hex.EncodeToString(b)
}

func randomStringHex(n int) string {
	b := make([]byte, n/2+1)
	if _, err := rand.Read(b); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(b)[:n]
}

func ipsum() int {
	b := make([]byte, 8)
	rand.Read(b)
	sum := 0
	for _, v := range b {
		sum += int(v)
	}
	return sum
}

func fakeHostnameDet() string {
	prefixes := []string{"bastion", "db-prod", "admin", "monitoring", "vault"}
	var b [4]byte
	rand.Read(b[:])
	return fmt.Sprintf("%s-%02x.internal", prefixes[b[0]%uint8(len(prefixes))], b[1])
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func appendUniqueInt(slice []int, item int) []int {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func copyStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

func copyIntSlice(s []int) []int {
	if s == nil {
		return nil
	}
	out := make([]int, len(s))
	copy(out, s)
	return out
}

func deduplicateStrings(s []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(s))
	for _, item := range s {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
