package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// SwarmConfig holds the SWIM gossip layer parameters.
type SwarmConfig struct {
	Name      string   `yaml:"name"`
	Bind      string   `yaml:"bind"`
	Peers     []string `yaml:"peers"`
	GossipKey string   `yaml:"gossip_key"`
}

// Config is the top-level Fortress configuration.
type Config struct {
	Engine     EngineConfig  `yaml:"engine"`
	Brain      BrainConfig   `yaml:"brain"`
	Weapons    WeaponsConfig `yaml:"weapons"`
	Swarm      SwarmConfig   `yaml:"swarm"`
	Whitelist  []string      `yaml:"whitelist"`
	LogDir     string        `yaml:"log_dir"`
	mu         sync.RWMutex
	path       string
	parsedCIDRs []net.IPNet // pre-parsed CIDR whitelist entries
}

// EngineConfig holds L1 packet engine thresholds.
type EngineConfig struct {
	SynFloodPPS  int `yaml:"syn_flood_pps"`
	UdpFloodPPS  int `yaml:"udp_flood_pps"`
	IcmpFloodPPS int `yaml:"icmp_flood_pps"`
	MaxPPS       int `yaml:"max_pps"`
}

// BrainConfig holds the scoring and response configuration.
type BrainConfig struct {
	AggressiveMode bool `yaml:"aggressive_mode"`
	BanDuration    int  `yaml:"ban_duration"` // seconds
}

// WeaponsConfig holds external tool paths and wordlist locations
// for Kali Fusion weapon orchestration.
type WeaponsConfig struct {
	NmapBin       string `yaml:"nmap_bin"`
	NucleiBin     string `yaml:"nuclei_bin"`
	HydraBin      string `yaml:"hydra_bin"`
	SqlmapBin     string `yaml:"sqlmap_bin"`
	MsfBin        string `yaml:"msf_bin"`
	Wordlists     string `yaml:"wordlists"`
	MaxConcurrent int    `yaml:"max_concurrent"`
}

// Default returns a working default configuration.
func Default() *Config {
	defaultWhitelist := []string{"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	return &Config{
		Engine: EngineConfig{
			SynFloodPPS:  80,
			UdpFloodPPS:  200,
			IcmpFloodPPS: 50,
			MaxPPS:       1000000,
		},
		Brain: BrainConfig{
			AggressiveMode: false,
			BanDuration:    1800,
		},
		Swarm: SwarmConfig{
			Name:      "hive-01",
			Bind:      "0.0.0.0:9700",
			Peers:     []string{},
			GossipKey: "",
		},
		Weapons: WeaponsConfig{
			NmapBin:       "/usr/bin/nmap",
			NucleiBin:     "/usr/local/bin/nuclei",
			HydraBin:      "/usr/bin/hydra",
			SqlmapBin:     "/usr/bin/sqlmap",
			MsfBin:        "/usr/bin/msfconsole",
			Wordlists:     "/usr/share/wordlists",
			MaxConcurrent: 50,
		},
		Whitelist:   defaultWhitelist,
		LogDir:      "logs",
		parsedCIDRs: parseCIDRList(defaultWhitelist),
	}
}

// parseCIDRList parses a list of strings into net.IPNet entries for those
// that contain a "/" (CIDR notation). Entries without "/" are skipped —
// they are matched as exact strings by IsWhitelisted.
func parseCIDRList(entries []string) []net.IPNet {
	var cidrs []net.IPNet
	for _, entry := range entries {
		if !strings.Contains(entry, "/") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		cidrs = append(cidrs, *ipNet)
	}
	return cidrs
}

// Load reads config from YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Re-parse CIDRs in case the YAML overrode the whitelist.
	cfg.parsedCIDRs = parseCIDRList(cfg.Whitelist)
	cfg.path = path

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks the configuration for validity and returns all errors
// accumulated into a single error.
func (c *Config) Validate() error {
	var errs []string

	if c.Engine.SynFloodPPS <= 0 || c.Engine.SynFloodPPS >= 1000000 {
		errs = append(errs, fmt.Sprintf("engine.syn_flood_pps must be > 0 and < 1000000, got %d", c.Engine.SynFloodPPS))
	}
	if c.Engine.UdpFloodPPS <= 0 || c.Engine.UdpFloodPPS >= 1000000 {
		errs = append(errs, fmt.Sprintf("engine.udp_flood_pps must be > 0 and < 1000000, got %d", c.Engine.UdpFloodPPS))
	}
	if c.Engine.IcmpFloodPPS <= 0 || c.Engine.IcmpFloodPPS >= 1000000 {
		errs = append(errs, fmt.Sprintf("engine.icmp_flood_pps must be > 0 and < 1000000, got %d", c.Engine.IcmpFloodPPS))
	}
	if c.Engine.MaxPPS <= 0 {
		errs = append(errs, fmt.Sprintf("engine.max_pps must be > 0, got %d", c.Engine.MaxPPS))
	}

	if len(errs) > 0 {
		return fmt.Errorf("config: %w", fmt.Errorf("%s", strings.Join(errs, "; ")))
	}
	return nil
}

// IsWhitelisted checks if an IP is in the whitelist. Supports both exact
// string matches and CIDR subnet matching (via pre-parsed parsedCIDRs).
func (c *Config) IsWhitelisted(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Exact string match.
	for _, w := range c.Whitelist {
		if w == ip {
			return true
		}
	}

	// CIDR subnet match.
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range c.parsedCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}

	return false
}

// ValidateTarget performs basic validation of a scan target.
// Accepts IP addresses, hostnames, and URLs.
func ValidateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target must not be empty")
	}
	// Reject flag-like inputs (command injection via tool flags)
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("target must not start with flag prefix")
	}
	// Try parsing as IP
	if net.ParseIP(target) != nil {
		return nil
	}
	// Basic sanity: reject obviously dangerous strings
	if strings.ContainsAny(target, ";&|`$(){}[]<>") {
		return fmt.Errorf("target contains invalid characters")
	}
	return nil
}
