// Package counterstrike implements threat intelligence operations.
//
// ThreatIntel provides:
//   - WHOIS lookups via system whois CLI with cached results
//   - Known-bad IP database with JSON persistence
//   - ASN-based risk scoring (18 high-risk ASNs for bulletproof hosting)
//   - Abuse report email generation
package counterstrike

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
)

// ---------------------------------------------------------------------------
// WhoisResult
// ---------------------------------------------------------------------------

// WhoisResult holds the parsed WHOIS data for a given IP address.
type WhoisResult struct {
	ASN        string
	Country    string
	Org        string
	AbuseEmail string
	QueriedAt  time.Time
}

// ---------------------------------------------------------------------------
// ThreatIntel
// ---------------------------------------------------------------------------

// ThreatIntel performs WHOIS lookups, tracks known-bad IPs, and scores
// IPs based on ASN risk. Results are cached for a configurable TTL.
type ThreatIntel struct {
	cache        map[string]*WhoisResult
	cacheTTL     time.Duration
	knownBad     map[string]string // IP -> reason
	knownBadFile string
	highRiskASNs map[string]int // ASN -> risk score (1-10)
	mu           sync.RWMutex
}

// highRiskASNDefaults maps 18 ASNs known for bulletproof hosting,
// spam-friendly policies, and cybercrime tolerance. Scores 1-10.
var highRiskASNDefaults = map[string]int{
	"AS16276":  9,  // OVH SAS — frequently abused for hosting malware
	"AS36352":  8,  // ColoCrossing — budget hosting, spam tolerant
	"AS202425": 7,  // IP Volume / Scalaxy — bulletproof hosting
	"AS53667":  10, // FranTech Solutions / BuyVM — bulletproof reputation
	"AS40676":  8,  // Psychz Networks — DDoS-friendly
	"AS20473":  9,  // The Constant Company / Vultr — abuse complaints ignored
	"AS14061":  8,  // DigitalOcean — commodity cloud, heavily abused
	"AS24940":  7,  // Hetzner Online — hosting spam/scanning
	"AS16265":  6,  // LeaseWeb — historically tolerant of abuse
	"AS7979":   5,  // Servers.com — hosting suspicious traffic
	"AS29802":  8,  // HIVELOCITY — bulletproof hosting
	"AS32780":  7,  // Hosting Services Inc — spam-friendly
	"AS46562":  6,  // Total Server Solutions — frequent abuse
	"AS46844":  7,  // Sharktech — DDoS protection for bad actors
	"AS54290":  6,  // Hostwinds — commodity hosting
	"AS55286":  8,  // B2 Net Solutions — bulk IP leasing
	"AS132839": 9,  // POWER LINE DATACENTER — bulletproof Chinese hosting
	"AS133752": 8,  // LeaseWeb Asia Pacific — spam/scanning
}

// defaultCacheTTL is the default cache duration for WHOIS results.
const defaultCacheTTL = 24 * time.Hour

// NewThreatIntel creates a ThreatIntel instance with the given known-bad
// JSON file path for persistence. The known-bad file is loaded on init.
func NewThreatIntel(knownBadFile string) *ThreatIntel {
	ti := &ThreatIntel{
		cache:        make(map[string]*WhoisResult),
		cacheTTL:     defaultCacheTTL,
		knownBad:     make(map[string]string),
		knownBadFile: knownBadFile,
		highRiskASNs: highRiskASNDefaults,
	}
	ti.loadKnownBad()
	return ti
}

// ---------------------------------------------------------------------------
// WHOIS Lookup
// ---------------------------------------------------------------------------

// Lookup performs a WHOIS query for the given IP address. Results are
// cached and served from cache when within the TTL. Uses the system
// whois CLI as the lookup backend.
func (ti *ThreatIntel) Lookup(ip string) *WhoisResult {
	ti.mu.RLock()
	if cached, ok := ti.cache[ip]; ok {
		if time.Since(cached.QueriedAt) < ti.cacheTTL {
			ti.mu.RUnlock()
			return cached
		}
	}
	ti.mu.RUnlock()

	result := ti.queryWhois(ip)

	ti.mu.Lock()
	ti.cache[ip] = result
	ti.mu.Unlock()

	return result
}

// queryWhois runs the system whois command and parses the output.
func (ti *ThreatIntel) queryWhois(ip string) *WhoisResult {
	result := &WhoisResult{QueriedAt: time.Now()}

	if err := config.ValidateTarget(ip); err != nil {
		log.Printf("[intel] invalid target %q: %v", ip, err)
		return result
	}

	cmd := exec.Command("whois", ip)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("[intel] whois query failed for %s: %v", ip, err)
		return result
	}

	text := string(out)

	// Parse relevant fields from whois text output.
	// WHOIS formats vary by registry; we match common patterns.
	result.ASN = extractWhoisField(text, whoisASNPatterns)
	result.Country = extractWhoisField(text, whoisCountryPatterns)
	result.Org = extractWhoisField(text, whoisOrgPatterns)
	result.AbuseEmail = extractWhoisField(text, whoisAbusePatterns)

	if result.ASN == "" {
		result.ASN = "Unknown"
	}
	if result.Country == "" {
		result.Country = "Unknown"
	}
	if result.Org == "" {
		result.Org = "Unknown"
	}

	return result
}

// whoisASNPatterns matches ASN information in WHOIS output.
var whoisASNPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^Origin(?:AS)?:\s*(AS\d+)`),
	regexp.MustCompile(`(?i)^origin:\s*(AS\d+)`),
	regexp.MustCompile(`(?i)OriginAS:\s*(AS\d+)`),
	regexp.MustCompile(`(?i)aut-num:\s*(AS\d+)`),
}

// whoisCountryPatterns matches country code fields.
var whoisCountryPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^[Cc]ountry:\s*(\S+)`),
	regexp.MustCompile(`(?i)^Country:\s*(\S+)`),
	regexp.MustCompile(`(?i)^country:\s*(\S+)`),
}

// whoisOrgPatterns matches organization/owner fields.
var whoisOrgPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^[Oo]rg[Nn]ame:\s*(.+)`),
	regexp.MustCompile(`(?i)^[Oo]rgani[sz]ation:\s*(.+)`),
	regexp.MustCompile(`(?i)^[Oo]wner:\s*(.+)`),
	regexp.MustCompile(`(?i)^descr:\s*(.+)`),
}

// whoisAbusePatterns matches abuse contact email fields.
var whoisAbusePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^[Aa]buse[Cc]ontact[Aa]?[Ee]?mail:\s*(\S+@\S+)`),
	regexp.MustCompile(`(?i)^[Aa]buse-mailbox:\s*(\S+@\S+)`),
	regexp.MustCompile(`(?i)^[Aa]buse.*[Ee]mail:\s*(\S+@\S+)`),
	regexp.MustCompile(`(?i)^OrgAbuseEmail:\s*(\S+@\S+)`),
}

// extractWhoisField tries each regex in order against the text and returns
// the first capture group of the first match.
func extractWhoisField(text string, patterns []*regexp.Regexp) string {
	for _, pat := range patterns {
		matches := pat.FindStringSubmatch(text)
		if len(matches) >= 2 {
			return strings.TrimSpace(matches[1])
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Known-bad IP database
// ---------------------------------------------------------------------------

// IsKnownBad reports whether an IP is in the known-bad database.
func (ti *ThreatIntel) IsKnownBad(ip string) bool {
	ti.mu.RLock()
	defer ti.mu.RUnlock()
	_, ok := ti.knownBad[ip]
	return ok
}

// AddKnownBad adds an IP to the known-bad database with a reason and
// persists the database to disk.
func (ti *ThreatIntel) AddKnownBad(ip, reason string) {
	ti.mu.Lock()
	ti.knownBad[ip] = reason
	data := copyMap(ti.knownBad)
	ti.mu.Unlock()

	ti.saveKnownBad(data)
}

// copyMap creates a shallow copy of a string map.
func copyMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// loadKnownBad loads the known-bad database from the JSON file.
func (ti *ThreatIntel) loadKnownBad() {
	if ti.knownBadFile == "" {
		return
	}
	data, err := os.ReadFile(ti.knownBadFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[intel] failed to read known-bad file: %v", err)
		}
		return
	}

	var loaded map[string]string
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[intel] failed to parse known-bad file: %v", err)
		return
	}

	ti.mu.Lock()
	ti.knownBad = loaded
	ti.mu.Unlock()
	log.Printf("[intel] loaded %d known-bad IPs from %s", len(loaded), ti.knownBadFile)
}

// saveKnownBad persists the known-bad database to a JSON file.
func (ti *ThreatIntel) saveKnownBad(data map[string]string) {
	if ti.knownBadFile == "" {
		return
	}

	// Ensure the directory exists.
	if dir := filepathDir(ti.knownBadFile); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("[intel] failed to create directory for known-bad file: %v", err)
			return
		}
	}

	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("[intel] failed to marshal known-bad data: %v", err)
		return
	}

	if err := os.WriteFile(ti.knownBadFile, encoded, 0644); err != nil {
		log.Printf("[intel] failed to write known-bad file: %v", err)
		return
	}
}

// filepathDir returns the directory portion of a path without importing path/filepath.
func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// ASN Risk Scoring
// ---------------------------------------------------------------------------

// GetASNRiskScore returns a risk score (0-10) for the given ASN.
// Higher scores indicate more dangerous hosting providers.
// Returns 0 if the ASN is not in the high-risk list.
func (ti *ThreatIntel) GetASNRiskScore(asn string) int {
	ti.mu.RLock()
	defer ti.mu.RUnlock()

	if score, ok := ti.highRiskASNs[asn]; ok {
		return score
	}
	return 0
}

// ---------------------------------------------------------------------------
// Abuse Report Generation
// ---------------------------------------------------------------------------

// GenerateAbuseReport formats an abuse report email body for a given
// attacking IP. Includes attack type, details, and a timestamp.
func (ti *ThreatIntel) GenerateAbuseReport(ip, attackType, detail string) string {
	info := ti.Lookup(ip)

	var sb strings.Builder
	sb.WriteString("Subject: [ABUSE REPORT] Malicious Activity from ")
	sb.WriteString(ip)
	sb.WriteString("\r\n\r\n")

	sb.WriteString("To Whom It May Concern,\r\n\r\n")

	sb.WriteString("This is an automated abuse report regarding malicious network activity\r\n")
	sb.WriteString("originating from the following IP address:\r\n\r\n")

	sb.WriteString("  IP Address:      ")
	sb.WriteString(ip)
	sb.WriteString("\r\n")
	sb.WriteString("  Attack Type:     ")
	sb.WriteString(attackType)
	sb.WriteString("\r\n")
	sb.WriteString("  Details:         ")
	sb.WriteString(detail)
	sb.WriteString("\r\n")
	sb.WriteString("  Detected At:     ")
	sb.WriteString(time.Now().UTC().Format(time.RFC3339))
	sb.WriteString("\r\n\r\n")

	sb.WriteString("WHOIS Information:\r\n")
	sb.WriteString("  ASN:             ")
	sb.WriteString(info.ASN)
	sb.WriteString("\r\n")
	sb.WriteString("  Organization:    ")
	sb.WriteString(info.Org)
	sb.WriteString("\r\n")
	sb.WriteString("  Country:         ")
	sb.WriteString(info.Country)
	sb.WriteString("\r\n")

	if info.AbuseEmail != "" {
		sb.WriteString("  Abuse Contact:   ")
		sb.WriteString(info.AbuseEmail)
		sb.WriteString("\r\n")
	}

	if riskScore := ti.GetASNRiskScore(info.ASN); riskScore > 0 {
		sb.WriteString("\r\n")
		sb.WriteString("NOTE: This ASN has a risk score of ")
		sb.WriteString(formatIntScore(riskScore))
		sb.WriteString("/10 based on historical abuse data.\r\n")
	}

	sb.WriteString("\r\n")
	sb.WriteString("Please investigate and take appropriate action. The following evidence\r\n")
	sb.WriteString("is available upon request:\r\n\r\n")
	sb.WriteString("  - Packet captures (PCAP)\r\n")
	sb.WriteString("  - Connection logs with timestamps\r\n")
	sb.WriteString("  - Flow data statistics\r\n\r\n")
	sb.WriteString("This report was generated automatically by Fortress v4.\r\n")
	sb.WriteString("Confidentiality Notice: This communication may contain sensitive information.\r\n")

	return sb.String()
}

// formatIntScore formats an integer score as a string without importing fmt.
func formatIntScore(n int) string {
	return formatInt(n)
}

// ---------------------------------------------------------------------------
// Cache Eviction
// ---------------------------------------------------------------------------

// Evict removes cached WHOIS entries older than the given Unix timestamp
// (deadline in seconds). Returns the number of evicted entries.
func (ti *ThreatIntel) Evict(deadline float64) int {
	ti.mu.Lock()
	defer ti.mu.Unlock()

	cutoff := time.Unix(int64(deadline), 0)
	removed := 0

	for ip, result := range ti.cache {
		if result.QueriedAt.Before(cutoff) {
			delete(ti.cache, ip)
			removed++
		}
	}

	return removed
}
