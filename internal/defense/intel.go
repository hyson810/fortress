package defense

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
)

// IntelResult holds the result of a WHOIS lookup for a single IP address.
type IntelResult struct {
	IP         string    `json:"ip"`
	ASN        string    `json:"asn"`
	Country    string    `json:"country"`
	Org        string    `json:"org"`
	AbuseEmail string    `json:"abuse_email"`
	QueriedAt  time.Time `json:"queried_at"`
}

// ThreatIntel caches WHOIS results and generates abuse reports.
type ThreatIntel struct {
	mu     sync.Mutex
	cache  map[string]*IntelResult
	maxAge time.Duration
}

// NewThreatIntel creates a new ThreatIntel instance.
func NewThreatIntel() *ThreatIntel {
	return &ThreatIntel{
		cache:  make(map[string]*IntelResult),
		maxAge: 24 * time.Hour,
	}
}

// Lookup returns the intel result for the given IP, querying WHOIS
// if the cached entry is older than the maximum age.
func (ti *ThreatIntel) Lookup(ip string) *IntelResult {
	ti.mu.Lock()
	defer ti.mu.Unlock()

	if r, ok := ti.cache[ip]; ok && time.Since(r.QueriedAt) < ti.maxAge {
		return r
	}

	result := ti.queryWhois(ip)
	ti.cache[ip] = result
	return result
}

// queryWhois executes the system whois command and parses the output.
func (ti *ThreatIntel) queryWhois(ip string) *IntelResult {
	result := &IntelResult{IP: ip, QueriedAt: time.Now()}

	if err := config.ValidateTarget(ip); err != nil {
		log.Printf("[intel] invalid IP: %s", ip)
		return result
	}

	cmd := exec.Command("whois", ip)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("[intel] whois failed for %s: %v", ip, err)
		return result
	}

	text := string(out)

	reASN := regexp.MustCompile(`(?i)origin[:\s]+AS(\d+)`)
	if m := reASN.FindStringSubmatch(text); len(m) > 1 {
		result.ASN = "AS" + m[1]
	}

	reCountry := regexp.MustCompile(`(?i)country[:\s]+([A-Z]{2})`)
	if m := reCountry.FindStringSubmatch(text); len(m) > 1 {
		result.Country = m[1]
	}

	reOrg := regexp.MustCompile(`(?i)(org-?name|organisation)[:\s]+(.+)`)
	if m := reOrg.FindStringSubmatch(text); len(m) > 2 {
		result.Org = strings.TrimSpace(m[2])
	}

	reAbuse := regexp.MustCompile(`(?i)abuse.*?[:\s]+(\S+@\S+)`)
	if m := reAbuse.FindStringSubmatch(text); len(m) > 1 {
		result.AbuseEmail = m[1]
	}

	return result
}

// GenerateAbuseReport creates a formatted abuse report email for the given IP.
func (ti *ThreatIntel) GenerateAbuseReport(ip string, threats []string) string {
	intel := ti.Lookup(ip)
	return fmt.Sprintf(
		"To: %s\nSubject: [ABUSE] Malicious activity from %s (AS%s)\n\n"+
			"The IP %s (%s, %s) has been observed conducting the following malicious activities:\n\n%s\n\n"+
			"Please investigate and take appropriate action.\n",
		intel.AbuseEmail, ip, intel.ASN,
		ip, intel.Org, intel.Country,
		"- "+strings.Join(threats, "\n- ")+"\n",
	)
}
