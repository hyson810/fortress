package config

// Config is the top-level Fortress configuration.
type Config struct {
	Engine    EngineConfig   `yaml:"engine"`
	Brain     BrainConfig    `yaml:"brain"`
	Swarm     SwarmConfig    `yaml:"swarm"`
	Weapons   WeaponsConfig  `yaml:"weapons"`
	Whitelist []string       `yaml:"whitelist"`
	LogDir    string         `yaml:"log_dir"`
	DataDir   string         `yaml:"data_dir"`
}

// EngineConfig holds XDP packet-engine settings.
type EngineConfig struct {
	XDPMode       string `yaml:"xdp_mode"`
	MaxPPS        int    `yaml:"max_pps"`
	SynFloodPPS   int    `yaml:"syn_flood_pps"`
	UDPFloodPPS   int    `yaml:"udp_flood_pps"`
	ICMPFloodPPS  int    `yaml:"icmp_flood_pps"`
	RunUID        int    `yaml:"run_uid"`
	RunGID        int    `yaml:"run_gid"`
}

// BrainConfig holds the decision-engine settings.
type BrainConfig struct {
	RulesDir             string `yaml:"rules_dir"`
	AutoCounterstrike    bool   `yaml:"auto_counterstrike"`
	CounterstrikeThreshold int  `yaml:"counterstrike_threshold"`
	BanDuration          int    `yaml:"ban_duration"`
	AggressiveMode       bool   `yaml:"aggressive_mode"`
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
