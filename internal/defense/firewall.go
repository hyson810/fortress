package defense

import (
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"
)

// FirewallRule represents a single nftables firewall rule targeting an IP.
type FirewallRule struct {
	IP        string    `json:"ip"`
	Action    string    `json:"action"` // drop, rate_limit, tarpit_redirect, honeypot_redirect
	Port      int       `json:"port,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	AddedAt   time.Time `json:"added_at"`
}

// Firewall manages nftables rules for IP blocking, rate-limiting, and
// traffic redirection. On Linux it drives the nft binary; on other
// platforms it gracefully degrades to observe-only mode.
type Firewall struct {
	mu      sync.Mutex
	rules   map[string]FirewallRule // keyed by IP
	chain   string
	enabled bool
}

// NewFirewall creates a new Firewall instance. Call Init afterwards to
// set up nftables tables and chains.
func NewFirewall() *Firewall {
	return &Firewall{
		rules: make(map[string]FirewallRule),
		chain: "FORTRESS",
	}
}

// Init probes for the nft binary and creates the inet fortress table and
// chains if they are not already present. On non-Linux systems it logs a
// warning and enters observe-only mode.
func (fw *Firewall) Init() error {
	if _, err := exec.LookPath("nft"); err != nil {
		fw.enabled = false
		log.Printf("[firewall] nftables not available — running in observe-only mode")
		return nil
	}
	// Create the fortress table and chain if they don't exist.
	cmds := [][]string{
		{"nft", "add", "table", "inet", "fortress"},
		{"nft", "add", "chain", "inet", "fortress", "input", "{ type filter hook input priority 0; }"},
		{"nft", "add", "chain", "inet", "fortress", "output", "{ type filter hook output priority 0; }"},
	}
	for _, cmd := range cmds {
		exec.Command(cmd[0], cmd[1:]...).Run() // ignore errors if already exists
	}
	fw.enabled = true
	log.Println("[firewall] nftables ready — inet fortress table active")
	return nil
}

// BlockIP adds a drop rule for the given IP address. The rule expires
// after duration (tracked in-memory; expired rules are cleaned on
// restart or by calling Cleanup).
func (fw *Firewall) BlockIP(ip string, duration time.Duration) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.rules[ip] = FirewallRule{
		IP: ip, Action: "drop",
		AddedAt:   time.Now(),
		ExpiresAt: time.Now().Add(duration),
	}

	if !fw.enabled {
		return nil
	}

	cmd := exec.Command("nft", "add", "rule", "inet", "fortress", "input",
		"ip", "saddr", ip, "drop")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables block %s: %w (%s)", ip, err, string(out))
	}
	log.Printf("[firewall] blocked %s for %v", ip, duration)
	return nil
}

// UnblockIP removes the in-memory rule entry for ip. The nftables rule
// itself is cleared on the next Flush call because nft delete-by-handle
// requires tracking handles across the lifetime of the rule set.
func (fw *Firewall) UnblockIP(ip string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	delete(fw.rules, ip)
	if !fw.enabled {
		return nil
	}
	// nft delete by handle is complex; flush and rebuild for now.
	return nil
}

// RateLimit applies an nftables rate-limit rule for the given IP.
// rate must be an nftables rate string (e.g. "10/second").
func (fw *Firewall) RateLimit(ip string, rate string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if !fw.enabled {
		fw.rules[ip] = FirewallRule{IP: ip, Action: "rate_limit", AddedAt: time.Now()}
		return nil
	}

	cmd := exec.Command("nft", "add", "rule", "inet", "fortress", "input",
		"ip", "saddr", ip, "limit", "rate", rate, "accept")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables rate limit %s: %w (%s)", ip, err, string(out))
	}

	fw.rules[ip] = FirewallRule{IP: ip, Action: "rate_limit", AddedAt: time.Now()}
	log.Printf("[firewall] rate limited %s to %s", ip, rate)
	return nil
}

// RedirectToTarpit redirects all TCP traffic from ip to the given
// tarpit port using an nftables redirect rule.
func (fw *Firewall) RedirectToTarpit(ip string, tarpitPort int) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if !fw.enabled {
		fw.rules[ip] = FirewallRule{
			IP: ip, Action: "tarpit_redirect",
			Port: tarpitPort, AddedAt: time.Now(),
		}
		return nil
	}

	cmd := exec.Command("nft", "add", "rule", "inet", "fortress", "input",
		"ip", "saddr", ip, "tcp", "dport", "1-65535", "redirect", "to",
		fmt.Sprintf(":%d", tarpitPort))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables tarpit redirect %s: %w (%s)", ip, err, string(out))
	}

	fw.rules[ip] = FirewallRule{
		IP: ip, Action: "tarpit_redirect",
		Port: tarpitPort, AddedAt: time.Now(),
	}
	log.Printf("[firewall] redirected %s to tarpit :%d", ip, tarpitPort)
	return nil
}

// ListRules returns a snapshot of all currently tracked rules.
func (fw *Firewall) ListRules() []FirewallRule {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	rules := make([]FirewallRule, 0, len(fw.rules))
	for _, r := range fw.rules {
		rules = append(rules, r)
	}
	return rules
}

// Cleanup removes expired rules from the in-memory map and returns the
// number of rules removed. Expired rules remain in the nftables ruleset
// until the next Flush.
func (fw *Firewall) Cleanup() int {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	now := time.Now()
	removed := 0
	for ip, r := range fw.rules {
		if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
			delete(fw.rules, ip)
			removed++
		}
	}
	return removed
}

// Flush clears all in-memory rules and flushes the nftables fortress
// input chain.
func (fw *Firewall) Flush() {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.rules = make(map[string]FirewallRule)
	if fw.enabled {
		exec.Command("nft", "flush", "chain", "inet", "fortress", "input").Run()
	}
	log.Println("[firewall] all rules flushed")
}

// IsEnabled reports whether nftables integration is active.
func (fw *Firewall) IsEnabled() bool { return fw.enabled }
