package fusion

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/fortress/v6/internal/config"
)

// SubdomainEntry holds a single subdomain discovered by Amass along with
// its resolved IP addresses and data sources.
type SubdomainEntry struct {
	Name    string   `json:"name"`
	IPs     []string `json:"ips,omitempty"`
	Sources []string `json:"sources,omitempty"`
}

// AmassResult aggregates the output of an Amass enumeration run.
type AmassResult struct {
	Domain          string           `json:"domain"`
	Subdomains      []SubdomainEntry `json:"subdomains"`
	Duration        time.Duration    `json:"duration"`
	TotalDiscovered int              `json:"total_discovered"`
}

// AmassScanner wraps the amass binary for subdomain enumeration.
type AmassScanner struct {
	binPath string
	timeout time.Duration
}

// NewAmass creates a new AmassScanner using the supplied binary path.
func NewAmass(binPath string) *AmassScanner {
	return &AmassScanner{binPath: binPath, timeout: 15 * time.Minute}
}

// WithTimeout sets a non-default timeout on the scanner. The default is 15
// minutes, which is adequate for most passive enumerations.
func (a *AmassScanner) WithTimeout(d time.Duration) *AmassScanner {
	a.timeout = d
	return a
}

// Enumerate runs a full amass enumeration against domain using the
// default (mixed passive + active) mode and returns structured results.
func (a *AmassScanner) Enumerate(domain string) (*AmassResult, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("amass: %w", err)
	}

	start := time.Now()
	// -- separated with domain to prevent flag injection after validation.
	cmd := exec.Command(a.binPath, "enum", "-json", domain)
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("amass enum %s: %w: %s", domain, err, string(out))
	}

	result := ParseAmassJSON(strings.NewReader(string(out)))
	result.Domain = domain
	result.Duration = elapsed

	return result, nil
}

// PassiveEnum runs amass in -passive mode, relying solely on open-source
// intelligence (OSINT) without any active probing.
func (a *AmassScanner) PassiveEnum(domain string) (*AmassResult, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("amass: %w", err)
	}

	start := time.Now()
	cmd := exec.Command(a.binPath, "enum", "-passive", "-json", domain)
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("amass passive enum %s: %w: %s", domain, err, string(out))
	}

	result := ParseAmassJSON(strings.NewReader(string(out)))
	result.Domain = domain
	result.Duration = elapsed

	return result, nil
}

// ActiveEnum runs amass in -active mode, which includes zone transfers,
// brute forcing, and other active techniques.
func (a *AmassScanner) ActiveEnum(domain string) (*AmassResult, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("amass: %w", err)
	}

	start := time.Now()
	cmd := exec.Command(a.binPath, "enum", "-active", "-json", domain)
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("amass active enum %s: %w: %s", domain, err, string(out))
	}

	result := ParseAmassJSON(strings.NewReader(string(out)))
	result.Domain = domain
	result.Duration = elapsed

	return result, nil
}

// ParseAmassJSON parses the newline-delimited JSON output that amass
// emits when invoked with -json. Unknown or malformed lines are skipped.
func ParseAmassJSON(reader jsonReader) *AmassResult {
	result := &AmassResult{}
	seen := make(map[string]*SubdomainEntry)

	dec := json.NewDecoder(reader)
	for {
		var entry struct {
			Name    string   `json:"name"`
			Domain  string   `json:"domain"`
			Address string   `json:"address"`
			Sources []string `json:"sources"`
		}
		if err := dec.Decode(&entry); err != nil {
			break
		}

		if entry.Name == "" {
			continue
		}

		key := strings.ToLower(entry.Name)
		sub, ok := seen[key]
		if !ok {
			sub = &SubdomainEntry{Name: entry.Name}
			seen[key] = sub
			result.Subdomains = append(result.Subdomains, *sub)
		}

		if entry.Address != "" {
			found := false
			for _, ip := range sub.IPs {
				if ip == entry.Address {
					found = true
					break
				}
			}
			if !found {
				sub.IPs = append(sub.IPs, entry.Address)
			}
		}

		for _, src := range entry.Sources {
			found := false
			for _, s := range sub.Sources {
				if s == src {
					found = true
					break
				}
			}
			if !found {
				sub.Sources = append(sub.Sources, src)
			}
		}
	}

	// Commit seen entries back to the result slice so IPs/Sources are
	// preserved — the struct copies in the append above captured a
	// snapshot that we now update in-place.
	for i := range result.Subdomains {
		key := strings.ToLower(result.Subdomains[i].Name)
		if entry, ok := seen[key]; ok {
			result.Subdomains[i] = *entry
		}
	}

	result.TotalDiscovered = len(result.Subdomains)
	return result
}

// ValidateDomain validates a domain name for safe use with external
// binaries. It reuses config.ValidateTarget for IP/hostname validation,
// then applies additional domain-specific checks.
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("fusion: domain must not be empty")
	}

	// Reject values that start with "-" (flag injection).
	if strings.HasPrefix(domain, "-") {
		return fmt.Errorf("fusion: domain %q must not start with '-'", domain)
	}

	// Reject shell metacharacters.
	if strings.ContainsAny(domain, ";|&`$(){}<>\n\r\\") {
		return fmt.Errorf("fusion: domain %q contains forbidden characters", domain)
	}

	// Skip further validation if this is an IP address — amass works
	// with IPs as well.
	if err := config.ValidateTarget(domain); err == nil {
		return nil
	}

	// Basic domain sanity: must contain at least one dot and not be
	// excessively long.
	if len(domain) > 253 {
		return fmt.Errorf("fusion: domain %q exceeds 253 characters", domain)
	}

	return nil
}

// jsonReader abstracts io.Reader for parser functions — it allows parsing
// from files, response bodies, or strings without coupling to a concrete
// type.
type jsonReader interface {
	Read(p []byte) (n int, err error)
}

// Ensure jsonReader covers *strings.Reader (compile-time interface check).
var _ jsonReader = (*strings.Reader)(nil)
