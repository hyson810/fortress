package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level Fortress configuration.
type Config struct {
	Engine    EngineConfig  `yaml:"engine"`
	Brain     BrainConfig   `yaml:"brain"`
	Swarm     SwarmConfig   `yaml:"swarm"`
	Weapons   WeaponsConfig `yaml:"weapons"`
	Whitelist []string      `yaml:"whitelist"`
	LogDir    string        `yaml:"log_dir"`
	DataDir   string        `yaml:"data_dir"`

	mu          sync.RWMutex
	parsedCIDRs []net.IPNet
	path        string
	lastMod     time.Time
	watchers    []func(*Config)
}

// EngineConfig holds XDP packet-engine settings.
type EngineConfig struct {
	XDPMode      string `yaml:"xdp_mode"`
	MaxPPS       int    `yaml:"max_pps"`
	SynFloodPPS  int    `yaml:"syn_flood_pps"`
	UDPFloodPPS  int    `yaml:"udp_flood_pps"`
	ICMPFloodPPS int    `yaml:"icmp_flood_pps"`
	RunUID       int    `yaml:"run_uid"`
	RunGID       int    `yaml:"run_gid"`
}

// BrainConfig holds the decision-engine settings.
type BrainConfig struct {
	RulesDir               string `yaml:"rules_dir"`
	AutoCounterstrike      bool   `yaml:"auto_counterstrike"`
	CounterstrikeThreshold int    `yaml:"counterstrike_threshold"`
	BanDuration            int    `yaml:"ban_duration"`
	AggressiveMode         bool   `yaml:"aggressive_mode"`
}

// SwarmConfig holds cluster/swarm settings.
type SwarmConfig struct {
	Name      string   `yaml:"name"`
	Bind      string   `yaml:"bind"`
	Peers     []string `yaml:"peers"`
	GossipKey string   `yaml:"gossip_key"`
}

// WeaponsConfig holds offensive toolkit binary paths.
type WeaponsConfig struct {
	NmapBin       string `yaml:"nmap_bin"`
	NucleiBin     string `yaml:"nuclei_bin"`
	HydraBin      string `yaml:"hydra_bin"`
	SqlmapBin     string `yaml:"sqlmap_bin"`
	MsfBin        string `yaml:"msf_bin"`
	Wordlists     string `yaml:"wordlists"`
	MaxConcurrent int    `yaml:"max_concurrent"`
}

// Default returns a Config populated with sensible defaults.
func Default() Config {
	return Config{
		Engine: EngineConfig{
			XDPMode:      "generic",
			MaxPPS:       1000000,
			SynFloodPPS:  80,
			UDPFloodPPS:  200,
			ICMPFloodPPS: 50,
			RunUID:       65534,
			RunGID:       65534,
		},
		Brain: BrainConfig{
			RulesDir:              "/etc/fortress/rules.d",
			AutoCounterstrike:     false,
			CounterstrikeThreshold: 75,
			BanDuration:           1800,
			AggressiveMode:        false,
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
		Whitelist: []string{
			"127.0.0.1",
			"::1",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
		LogDir:  "/var/log/fortress",
		DataDir: "/var/lib/fortress",
	}
}

// Load reads a YAML config file, falling back to Default() if the file does
// not exist. It unmarshals, validates, parses CIDRs, and applies env-var
// overrides before returning the ready-to-use Config.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("config read: %w", err)
		}
		// File not found — use defaults but still validate and parse.
	} else {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("config parse: %w", err)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	cfg.parseCIDRs()
	cfg.applyEnvOverrides()

	cfg.path = path
	if fi, fiErr := os.Stat(path); fiErr == nil {
		cfg.lastMod = fi.ModTime()
	}

	return &cfg, nil
}

// Validate checks configuration values and returns all violations as a single
// formatted error.
func (c *Config) Validate() error {
	var errs []string

	add := func(format string, args ...interface{}) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	if c.Engine.SynFloodPPS < 1 || c.Engine.SynFloodPPS > 1000000 {
		add("engine.syn_flood_pps must be 1..1000000, got %d", c.Engine.SynFloodPPS)
	}
	if c.Engine.UDPFloodPPS < 1 || c.Engine.UDPFloodPPS > 1000000 {
		add("engine.udp_flood_pps must be 1..1000000, got %d", c.Engine.UDPFloodPPS)
	}
	if c.Engine.ICMPFloodPPS < 1 || c.Engine.ICMPFloodPPS > 1000000 {
		add("engine.icmp_flood_pps must be 1..1000000, got %d", c.Engine.ICMPFloodPPS)
	}
	if c.Engine.MaxPPS <= 0 {
		add("engine.max_pps must be > 0, got %d", c.Engine.MaxPPS)
	}
	if c.Brain.CounterstrikeThreshold < 0 || c.Brain.CounterstrikeThreshold > 100 {
		add("brain.counterstrike_threshold must be 0..100, got %d", c.Brain.CounterstrikeThreshold)
	}
	if c.Brain.BanDuration < 0 {
		add("brain.ban_duration must be >= 0, got %d", c.Brain.BanDuration)
	}

	if _, _, err := net.SplitHostPort(c.Swarm.Bind); err != nil {
		add("swarm.bind %q is not a valid host:port: %v", c.Swarm.Bind, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// IsWhitelisted returns true if ip matches the whitelist — exact string match
// first (handles raw CIDR strings), then net.ParseIP + CIDR containment.
// The call is safe for concurrent use.
func (c *Config) IsWhitelisted(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, entry := range c.Whitelist {
		if entry == ip {
			return true
		}
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	for i := range c.parsedCIDRs {
		if c.parsedCIDRs[i].Contains(parsed) {
			return true
		}
	}
	return false
}

// SetWhitelist replaces the whitelist and re-parses CIDR entries. Safe for
// concurrent use.
func (c *Config) SetWhitelist(entries []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Whitelist = append([]string{}, entries...)
	c.parseCIDRsLocked()
}

// ValidateTarget rejects targets that are empty, start with "-", contain shell
// metacharacters, or are not valid IPs / hostnames.
func ValidateTarget(target string) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("target must not be empty")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("target must not start with '-'")
	}

	// Shell metacharacters — reject anything that could be used for command injection.
	shellChars := ";|&`$(){}<>\n\r"
	if strings.ContainsAny(target, shellChars) {
		return fmt.Errorf("target contains shell metacharacters")
	}

	// Valid IP or hostname.
	if ip := net.ParseIP(target); ip != nil {
		return nil
	}

	// Basic hostname validation.
	if len(target) > 253 {
		return fmt.Errorf("hostname too long (max 253 chars)")
	}
	for i := 0; i < len(target); i++ {
		c := target[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			continue
		}
		return fmt.Errorf("target %q is not a valid IP or hostname", target)
	}

	// Hostname labels must not be empty, must not start/end with hyphen.
	labels := strings.Split(target, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("hostname %q has an empty label", target)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("hostname label %q must not start or end with '-'", label)
		}
		if len(label) > 63 {
			return fmt.Errorf("hostname label %q too long (max 63 chars)", label)
		}
	}

	return nil
}

// OnChange registers fn to be called whenever the config is reloaded via
// Watch. Callbacks are invoked with the write lock held, so they may read
// safely.
func (c *Config) OnChange(fn func(*Config)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.watchers = append(c.watchers, fn)
}

// Watch polls the config file every interval. When the modification time
// changes it reloads the file, copies fields individually (no mutex copy),
// and fires registered watchers.
func (c *Config) Watch(interval time.Duration) {
	if c.path == "" {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		fi, err := os.Stat(c.path)
		if err != nil {
			continue
		}
		if !fi.ModTime().After(c.lastMod) {
			continue
		}

		reloaded, err := Load(c.path)
		if err != nil {
			continue
		}

		// Copy fields individually to avoid copying the mutex.
		c.mu.Lock()
		c.Engine = reloaded.Engine
		c.Brain = reloaded.Brain
		c.Swarm = reloaded.Swarm
		c.Weapons = reloaded.Weapons
		c.Whitelist = reloaded.Whitelist
		c.LogDir = reloaded.LogDir
		c.DataDir = reloaded.DataDir
		c.parsedCIDRs = reloaded.parsedCIDRs
		c.lastMod = fi.ModTime()

		watchers := make([]func(*Config), len(c.watchers))
		copy(watchers, c.watchers)
		c.mu.Unlock()

		for _, fn := range watchers {
			fn(c)
		}
	}
}

// parseCIDRs scans whitelist entries for strings containing "/" and parses
// them into c.parsedCIDRs. Caller must hold c.mu.Lock.
func (c *Config) parseCIDRs() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.parseCIDRsLocked()
}

func (c *Config) parseCIDRsLocked() {
	c.parsedCIDRs = nil
	for _, entry := range c.Whitelist {
		if !strings.Contains(entry, "/") {
			continue
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		c.parsedCIDRs = append(c.parsedCIDRs, *cidr)
	}
}

// applyEnvOverrides reads FORTRESS_SWARM_NAME and FORTRESS_GOSSIP_KEY env
// vars and overrides the corresponding config fields when set.
func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("FORTRESS_SWARM_NAME"); v != "" {
		c.Swarm.Name = v
	}
	if v := os.Getenv("FORTRESS_GOSSIP_KEY"); v != "" {
		c.Swarm.GossipKey = v
	}
}
