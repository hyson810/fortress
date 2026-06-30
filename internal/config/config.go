package config

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level Fortress configuration
type Config struct {
	Swarm      SwarmConfig      `yaml:"swarm"`
	Engine     EngineConfig     `yaml:"engine"`
	Brain      BrainConfig      `yaml:"brain"`
	Weapons    WeaponsConfig    `yaml:"weapons"`
	Shield     ShieldConfig     `yaml:"shield"`
	Whitelist  []string         `yaml:"whitelist"`
	LogLevel   string           `yaml:"log_level"`
	LogDir     string           `yaml:"log_dir"`
	mu         sync.RWMutex
	path       string
	lastMod    time.Time
	watchers   []func(*Config)
	parsedCIDRs []net.IPNet    // pre-parsed CIDR whitelist entries
}

// ShieldConfig controls which Hydra-Pro shield modules are active.
// All shield modules are OFF by default for zero-overhead baseline.
// Enable only what you need for your threat model.
type ShieldConfig struct {
	InjectDetect  bool `yaml:"inject_detect"`   // Process injection detection (scans /proc)
	MemoryAnomaly bool `yaml:"memory_anomaly"`  // Memory anomaly detection (RWX/hidden pages)
	FtraceInteg   bool `yaml:"ftrace_integrity"` // Ftrace/kprobe hook integrity checking
	IOUringDetect bool `yaml:"io_uring_detect"`  // io_uring anomaly detection
	BPFAudit      bool `yaml:"bpf_audit"`        // BPF LSM whitelist + continuous audit
	ScanInterval  int  `yaml:"scan_interval"`    // Seconds between shield scans (default 30)
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

type SwarmConfig struct {
	Name      string   `yaml:"name"`
	Bind      string   `yaml:"bind"`
	Peers     []string `yaml:"peers"`
	GossipKey string   `yaml:"gossip_key"`
}

type EngineConfig struct {
	XDPMode      string `yaml:"xdp_mode"`
	AFXDQueue    int    `yaml:"af_xdp_queue"`
	MaxPPS       int    `yaml:"max_pps"`
	CPUPin       []int  `yaml:"cpu_pin"`
	SynFloodPPS  int    `yaml:"syn_flood_pps"`
	UdpFloodPPS  int    `yaml:"udp_flood_pps"`
	IcmpFloodPPS int    `yaml:"icmp_flood_pps"`
	RunUID       int    `yaml:"run_uid"` // UID to drop privileges to (default 65534 = nobody)
	RunGID       int    `yaml:"run_gid"` // GID to drop privileges to (default 65534 = nogroup)
		APIPort      int    `yaml:"api_port"`
		HPSSHPort    int    `yaml:"hp_ssh_port"`
		HPHTTPPort   int    `yaml:"hp_http_port"`
		HPMySQLPort  int    `yaml:"hp_mysql_port"`
}

type BrainConfig struct {
	RulesDir                string  `yaml:"rules_dir"`
	MLModel                 string  `yaml:"ml_model"`
	AutoCounterstrike       bool    `yaml:"auto_counterstrike"`
	AggressiveMode          bool    `yaml:"aggressive_mode"`
	CounterstrikeThreshold  float64 `yaml:"counterstrike_threshold"`
	BanDuration             int     `yaml:"ban_duration"`
}

type WeaponsConfig struct {
	NmapBin       string `yaml:"nmap_bin"`
	NucleiBin     string `yaml:"nuclei_bin"`
	HydraBin      string `yaml:"hydra_bin"`
	SqlmapBin     string `yaml:"sqlmap_bin"`
	MsfBin        string `yaml:"msf_bin"`
	Wordlists     string `yaml:"wordlists"`
	MaxConcurrent int    `yaml:"max_concurrent"`
}

// Default returns a working default configuration
func Default() *Config {
	defaultWhitelist := []string{"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	return &Config{
		Swarm: SwarmConfig{
			Name: "hive-01",
			Bind: "0.0.0.0:9700",
		},
		Engine: EngineConfig{
			XDPMode:      "generic",
			MaxPPS:       1000000,
			SynFloodPPS:  80,
			UdpFloodPPS:  200,
			IcmpFloodPPS: 50,
			RunUID:       65534, // nobody
			RunGID:       65534, // nogroup
			APIPort:      9090,
			HPSSHPort:    2222,
			HPHTTPPort:   8080,
			HPMySQLPort:  3307,
		},
		Brain: BrainConfig{
			RulesDir:               "/etc/fortress/rules.d",
			AutoCounterstrike:      false,
			CounterstrikeThreshold: 85.0,
			BanDuration:            1800,
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
			LogLevel:    "info",
		LogDir:      "logs",
		parsedCIDRs: parseCIDRList(defaultWhitelist),
	}
}

// Load reads config from YAML file
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

	// Override from environment
	if v := os.Getenv("FORTRESS_SWARM_NAME"); v != "" { cfg.Swarm.Name = v }
	if v := os.Getenv("FORTRESS_GOSSIP_KEY"); v != "" { cfg.Swarm.GossipKey = v }

	// Re-parse CIDRs in case the YAML overrode the whitelist.
	cfg.parsedCIDRs = parseCIDRList(cfg.Whitelist)

	cfg.path = path

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// OnChange registers a callback for config hot-reload
func (c *Config) OnChange(fn func(*Config)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.watchers = append(c.watchers, fn)
}

// Watch polls for config file changes and triggers callbacks
func (c *Config) Watch(interval time.Duration) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[config] file watcher panic: %v\nstack: %s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if c.path == "" {
				continue
			}
			stat, err := os.Stat(c.path)
			if err != nil {
				continue
			}
			if stat.ModTime().After(c.lastMod) {
				c.lastMod = stat.ModTime()
				if newCfg, err := Load(c.path); err == nil {
					c.mu.Lock()
					// Copy fields individually to avoid copying sync.RWMutex.
					c.Swarm = newCfg.Swarm
					c.Engine = newCfg.Engine
					c.Brain = newCfg.Brain
					c.Weapons = newCfg.Weapons
					c.Whitelist = newCfg.Whitelist
					c.parsedCIDRs = newCfg.parsedCIDRs
					c.LogDir = newCfg.LogDir
					watchers := c.watchers
					c.mu.Unlock()
					for _, w := range watchers {
						w(newCfg)
					}
				}
			}
		}
	}()
}

// targetHostnameRE matches basic hostnames for ValidateTarget.
var targetHostnameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$`)

// ValidateTarget validates a user-controlled target string before passing it
// to external binaries. Accepts valid IP addresses and basic hostnames.
// Rejects strings that start with "-" (flag injection), contain shell
// metacharacters, or fail IP/hostname parsing.
func ValidateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("config: target must not be empty")
	}

	// Reject targets starting with "-" (flag injection).
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("config: target %q must not start with '-'", target)
	}

	// Reject targets containing shell metacharacters.
	if strings.ContainsAny(target, ";|&`$(){}<>\n\r") {
		return fmt.Errorf("config: target %q contains forbidden characters", target)
	}

	// Accept valid IP addresses.
	if net.ParseIP(target) != nil {
		return nil
	}

	// Accept basic hostnames.
	if targetHostnameRE.MatchString(target) {
		return nil
	}

	return fmt.Errorf("config: target %q is not a valid IP or hostname", target)
}

// Validate checks the configuration for validity and returns all errors
// accumulated into a single error.
func (c *Config) Validate() error {
	var errs []string

	// Swarm.Bind must be valid host:port.
	if _, _, err := net.SplitHostPort(c.Swarm.Bind); err != nil {
		errs = append(errs, fmt.Sprintf("swarm.bind %q: %v", c.Swarm.Bind, err))
	}

	// Engine thresholds: must be > 0 and < 1000000.
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

	// Brain.CounterstrikeThreshold: 0-100 (0 = disabled).
	if c.Brain.CounterstrikeThreshold < 0 || c.Brain.CounterstrikeThreshold > 100 {
		errs = append(errs, fmt.Sprintf("brain.counterstrike_threshold must be 0-100, got %.1f", c.Brain.CounterstrikeThreshold))
	}

	// Brain.BanDuration must be >= 0.
	if c.Brain.BanDuration < 0 {
		errs = append(errs, fmt.Sprintf("brain.ban_duration must be >= 0, got %d", c.Brain.BanDuration))
	}

	// Weapons: if set, path must not be empty (no existence check — may be in PATH).
	if c.Weapons.NmapBin == "" {
		errs = append(errs, "weapons.nmap_bin must not be empty")
	}
	if c.Weapons.NucleiBin == "" {
		errs = append(errs, "weapons.nuclei_bin must not be empty")
	}
	if c.Weapons.HydraBin == "" {
		errs = append(errs, "weapons.hydra_bin must not be empty")
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

	// Exact string match (handles both bare IPs, IPv6 literals, and CIDR strings).
	for _, w := range c.Whitelist {
		if w == ip {
			return true
		}
	}

	// CIDR subnet match against pre-parsed network ranges.
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false // not a valid IP and no exact match — can't match CIDR
	}
	for _, cidr := range c.parsedCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}

	return false
}

// SetWhitelist replaces the whitelist and re-parses CIDR entries.
// This is the correct way to change the whitelist at runtime because
// it keeps parsedCIDRs in sync with the string entries.
func (c *Config) SetWhitelist(entries []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Whitelist = entries
	c.parsedCIDRs = parseCIDRList(entries)
}
