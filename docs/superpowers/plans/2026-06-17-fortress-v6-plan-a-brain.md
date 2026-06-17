# Fortress V6 Plan A: Go 大脑地基

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the complete Go brain — config, 7-layer detection pipeline, threat scoring, 4-tier response ladder, CLI entry point.

**Architecture:** Go 1.23+, single module `github.com/fortress/v6`, `internal/` packages organized by domain (engine/, brain/, config/), shared utilities in `pkg/`. All engines communicate via Go channels. YAML config + BoltDB persistence.

**Tech Stack:** Go 1.23+, gopkg.in/yaml.v3, go.etcd.io/bbolt, golang.org/x/crypto

**Dependencies:** Plan A is self-contained. Does not depend on Rust or C code. Detection engines accept `PacketContext` structs from a channel — the Rust FFI layer (Plan B) will feed this channel later.

---

## File Structure

```
fortress-v6/
├── cmd/fortress/main.go              # CLI entry, mode dispatch, signal handling
├── internal/
│   ├── config/config.go              # YAML loading, validation, hot-reload, whitelist
│   ├── engine/
│   │   ├── types.go                  # Shared: Threat, DetectionVector, PacketContext
│   │   ├── packet.go                 # L1: SYN/UDP/ICMP flood, TCP flags, port probe
│   │   ├── flow.go                   # L2: 5-tuple tracking, multi-window scan detection
│   │   ├── behavior.go               # L3: Welford online entropy, sigma deviation
│   │   ├── dns.go                    # L4: DNS tunnel (entropy + length + frequency)
│   │   ├── http.go                   # L5: TCP stream reassembly, SQLi/XSS/path traversal
│   │   ├── bruteforce.go             # L5: SSH/HTTP brute force detection
│   │   ├── anomaly.go                # L6: EMA Z-Score + Count-Min Sketch hybrid
│   │   └── fingerprint.go            # L7: JA3 TLS + passive OS fingerprinting
│   └── brain/
│       ├── scorer.go                 # 13-detector weighted fusion, per-IP ThreatRecord
│       ├── ladder.go                 # 4-tier response ladder A/B/C/D
│       ├── correlation.go            # Cross-IP coordination, subnet neighbor, DDoS
│       └── decay.go                  # Exponential score decay, lazy evaluation
├── pkg/
│   ├── welford/welford.go            # Generic Welford online variance
│   ├── cmsketch/countmin.go          # Count-Min Sketch with configurable rows/cols
│   ├── entropy/entropy.go            # Shannon entropy for byte sequences
│   └── ringbuf/ringbuf.go            # Fixed-capacity ring buffer of timestamps
├── fortress.yaml                     # Default configuration
├── go.mod
└── go.sum
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `fortress.yaml`
- Create: `cmd/fortress/main.go` (minimal skeleton)
- Create: `internal/config/config.go` (minimal skeleton)

- [ ] **Step 1: Initialize Go module**

```bash
cd C:\Users\Administrator\fortress-v6
go mod init github.com/fortress/v6
```

- [ ] **Step 2: Create default fortress.yaml**

```yaml
# Fortress V6 Configuration
engine:
  xdp_mode: generic
  max_pps: 1000000
  syn_flood_pps: 80
  udp_flood_pps: 200
  icmp_flood_pps: 50
  run_uid: 65534
  run_gid: 65534

brain:
  rules_dir: /etc/fortress/rules.d
  auto_counterstrike: false
  counterstrike_threshold: 75
  ban_duration: 1800
  aggressive_mode: false

swarm:
  name: hive-01
  bind: 0.0.0.0:9700
  peers: []
  gossip_key: ""

weapons:
  nmap_bin: /usr/bin/nmap
  nuclei_bin: /usr/local/bin/nuclei
  hydra_bin: /usr/bin/hydra
  sqlmap_bin: /usr/bin/sqlmap
  msf_bin: /usr/bin/msfconsole
  wordlists: /usr/share/wordlists
  max_concurrent: 50

whitelist:
  - 127.0.0.1
  - ::1
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16

log_dir: /var/log/fortress
data_dir: /var/lib/fortress
```

- [ ] **Step 3: Create minimal main.go skeleton**

```go
package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	configPath = flag.String("config", "/etc/fortress/fortress.yaml", "path to config file")
	mode       = flag.String("mode", "defend", "operating mode: defend, scan, fusion, counterstrike, serve-mcp")
)

func main() {
	flag.Parse()
	fmt.Fprintf(os.Stderr, "Fortress V6 — %s mode\n", *mode)
	os.Exit(0)
}
```

- [ ] **Step 4: Create minimal config skeleton**

```go
package config

type Config struct {
	Engine    EngineConfig    `yaml:"engine"`
	Brain     BrainConfig     `yaml:"brain"`
	Swarm     SwarmConfig     `yaml:"swarm"`
	Weapons   WeaponsConfig   `yaml:"weapons"`
	Whitelist []string        `yaml:"whitelist"`
	LogDir    string          `yaml:"log_dir"`
	DataDir   string          `yaml:"data_dir"`
}

type EngineConfig struct {
	XDPMode       string `yaml:"xdp_mode"`
	MaxPPS        int    `yaml:"max_pps"`
	SynFloodPPS   int    `yaml:"syn_flood_pps"`
	UdpFloodPPS   int    `yaml:"udp_flood_pps"`
	IcmpFloodPPS  int    `yaml:"icmp_flood_pps"`
	RunUID        int    `yaml:"run_uid"`
	RunGID        int    `yaml:"run_gid"`
}

type BrainConfig struct {
	RulesDir               string  `yaml:"rules_dir"`
	AutoCounterstrike      bool    `yaml:"auto_counterstrike"`
	CounterstrikeThreshold float64 `yaml:"counterstrike_threshold"`
	BanDuration            int     `yaml:"ban_duration"`
	AggressiveMode         bool    `yaml:"aggressive_mode"`
}

type SwarmConfig struct {
	Name      string   `yaml:"name"`
	Bind      string   `yaml:"bind"`
	Peers     []string `yaml:"peers"`
	GossipKey string   `yaml:"gossip_key"`
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

func Default() *Config {
	return &Config{
		Engine: EngineConfig{
			XDPMode:      "generic",
			MaxPPS:       1000000,
			SynFloodPPS:  80,
			UdpFloodPPS:  200,
			IcmpFloodPPS: 50,
			RunUID:       65534,
			RunGID:       65534,
		},
		Brain: BrainConfig{
			RulesDir:               "/etc/fortress/rules.d",
			CounterstrikeThreshold: 75,
			BanDuration:            1800,
		},
		Swarm: SwarmConfig{
			Name: "hive-01",
			Bind: "0.0.0.0:9700",
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
		Whitelist: []string{"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		LogDir:    "/var/log/fortress",
		DataDir:   "/var/lib/fortress",
	}
}
```

- [ ] **Step 5: Build and verify**

```bash
cd C:\Users\Administrator\fortress-v6
go build ./...
# Expected: builds without errors
go run ./cmd/fortress/
# Expected: "Fortress V6 — defend mode"
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: project scaffolding with config types and minimal main"
```

---

### Task 2: Shared Types and Utilities

**Files:**
- Create: `internal/engine/types.go`
- Create: `pkg/ringbuf/ringbuf.go`
- Create: `pkg/ringbuf/ringbuf_test.go`
- Create: `pkg/entropy/entropy.go`
- Create: `pkg/entropy/entropy_test.go`
- Create: `pkg/welford/welford.go`
- Create: `pkg/welford/welford_test.go`
- Create: `pkg/cmsketch/countmin.go`
- Create: `pkg/cmsketch/countmin_test.go`

- [ ] **Step 1: Write shared threat types**

`internal/engine/types.go`:
```go
package engine

import "time"

// Threat represents a detected security event.
type Threat struct {
	Type   string // Chinese threat category, e.g. "SYN洪水", "SQL注入攻击"
	IP     string // Source IP address
	Detail string // Human-readable detail
}

// DetectionVector carries scores from a single detection layer.
type DetectionVector struct {
	Layer          int     // Detection layer number (1-7)
	FloodScore     float64 // Layer 1: packet flood score
	ScanScore      float64 // Layer 1+2: scan pattern score
	EntropyScore   float64 // Layer 3: entropy deviation score
	DNSScore       float64 // Layer 4: DNS tunnel score
	HTTPScore      float64 // Layer 5: HTTP attack score
	BruteForceScore float64 // Layer 5: brute force score
	AnomalyScore   float64 // Layer 6: hybrid anomaly score
	FingerScore    float64 // Layer 7: fingerprint mismatch score
}

// PacketContext is the shared structure passed from Rust muscle to Go brain.
// In Plan A, it arrives via a Go channel (fed by a simulation loop or Rust FFI later).
type PacketContext struct {
	Timestamp    time.Time
	SrcIP        string
	DstIP        string
	SrcPort      uint16
	DstPort      uint16
	Protocol     string // "TCP", "UDP", "ICMP"
	TCPFlags     string // sorted uppercase, e.g. "S", "AS", "FPU"
	PayloadSize  uint16
	PayloadHash  uint64 // xxhash of first 64 bytes, 0 if no payload
	Direction    string // "ingress" or "egress"
}
```

- [ ] **Step 2: Write RingBuffer utility**

`pkg/ringbuf/ringbuf.go`:
```go
package ringbuf

import "time"

// RingBuffer is a fixed-capacity circular buffer of timestamps.
// Push is O(1) amortized. PruneBefore drops entries older than cutoff.
type RingBuffer struct {
	buf []time.Time
	cap int
}

func New(cap int) *RingBuffer {
	return &RingBuffer{buf: make([]time.Time, 0, cap), cap: cap}
}

func (rb *RingBuffer) Push(t time.Time) {
	if len(rb.buf) >= rb.cap {
		rb.buf = rb.buf[1:]
	}
	rb.buf = append(rb.buf, t)
}

func (rb *RingBuffer) PruneBefore(cutoff time.Time) {
	i := 0
	for i < len(rb.buf) && rb.buf[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		rb.buf = rb.buf[i:]
	}
}

func (rb *RingBuffer) Len() int { return len(rb.buf) }
```

`pkg/ringbuf/ringbuf_test.go`:
```go
package ringbuf

import (
	"testing"
	"time"
)

func TestPushCap(t *testing.T) {
	rb := New(3)
	now := time.Now()
	rb.Push(now)
	rb.Push(now.Add(time.Second))
	rb.Push(now.Add(2 * time.Second))
	if rb.Len() != 3 {
		t.Fatalf("expected len 3, got %d", rb.Len())
	}
	rb.Push(now.Add(3 * time.Second))
	if rb.Len() != 3 {
		t.Fatalf("expected len 3 after overflow, got %d", rb.Len())
	}
}

func TestPruneBefore(t *testing.T) {
	rb := New(10)
	now := time.Now()
	for i := 0; i < 5; i++ {
		rb.Push(now.Add(time.Duration(i) * time.Second))
	}
	rb.PruneBefore(now.Add(3 * time.Second))
	if rb.Len() != 2 {
		t.Fatalf("expected len 2 after prune, got %d", rb.Len())
	}
}
```

- [ ] **Step 3: Write Shannon entropy utility**

`pkg/entropy/entropy.go`:
```go
package entropy

import "math"

// Shannon computes the Shannon entropy H(X) = -sum(p(x) * log2(p(x)))
// for a slice of comparable items. Returns 0 for empty input.
func Shannon[T comparable](data []T) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[T]int)
	for _, v := range data {
		counts[v]++
	}
	n := float64(len(data))
	var h float64
	for _, count := range counts {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Bytes computes Shannon entropy of a byte slice.
func Bytes(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := [256]int{}
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}
```

- [ ] **Step 4: Write Welford online variance**

`pkg/welford/welford.go`:
```go
package welford

import "math"

// Tracker computes running mean and variance using Welford's online algorithm.
// O(1) memory, single-pass, numerically stable.
type Tracker struct {
	Mean  float64
	M2    float64
	Count int
}

func (t *Tracker) Add(value float64) {
	t.Count++
	delta := value - t.Mean
	t.Mean += delta / float64(t.Count)
	delta2 := value - t.Mean
	t.M2 += delta * delta2
}

func (t *Tracker) Std() float64 {
	if t.Count < 2 {
		return 0
	}
	return math.Sqrt(t.M2 / float64(t.Count-1))
}

func (t *Tracker) Variance() float64 {
	if t.Count < 2 {
		return 0
	}
	return t.M2 / float64(t.Count-1)
}
```

- [ ] **Step 5: Write Count-Min Sketch**

`pkg/cmsketch/countmin.go`:
```go
package cmsketch

import "hash/fnv"

// Sketch is a Count-Min Sketch with configurable rows and columns.
// Provides approximate frequency counting with probabilistic bounds.
type Sketch struct {
	rows  int
	cols  int
	table [][]uint64
}

func New(rows, cols int) *Sketch {
	t := make([][]uint64, rows)
	for i := range t {
		t[i] = make([]uint64, cols)
	}
	return &Sketch{rows: rows, cols: cols, table: t}
}

func (s *Sketch) hash(row int, data []byte) int {
	h := fnv.New32a()
	h.Write([]byte{byte(row)})
	h.Write(data)
	return int(h.Sum32()) % s.cols
}

func (s *Sketch) Add(data []byte, count uint64) {
	for r := 0; r < s.rows; r++ {
		col := s.hash(r, data)
		s.table[r][col] += count
	}
}

func (s *Sketch) Estimate(data []byte) uint64 {
	min := uint64(^uint64(0))
	for r := 0; r < s.rows; r++ {
		col := s.hash(r, data)
		if s.table[r][col] < min {
			min = s.table[r][col]
		}
	}
	return min
}

func (s *Sketch) Total() uint64 {
	var sum uint64
	for _, col := range s.table[0] {
		sum += col
	}
	return sum
}

// Decay halves all counters. Call periodically (e.g. every 10M packets)
// to prevent overflow and keep estimates fresh.
func (s *Sketch) Decay() {
	for r := range s.table {
		for c := range s.table[r] {
			s.table[r][c] >>= 1
		}
	}
}
```

- [ ] **Step 6: Run tests for all utilities**

```bash
go test ./pkg/...
# Expected: all PASS
```

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: shared types, ring buffer, entropy, Welford, Count-Min Sketch"
```

---

### Task 3: Config System (Load, Validate, Whitelist)

**Files:**
- Modify: `internal/config/config.go`

- [ ] **Step 1: Add Load function with YAML parsing**

Add to `internal/config/config.go` after existing types:

```go
import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config wraps all configuration with thread-safe access and hot-reload.
type Config struct {
	Engine      EngineConfig      `yaml:"engine"`
	Brain       BrainConfig       `yaml:"brain"`
	Swarm       SwarmConfig       `yaml:"swarm"`
	Weapons     WeaponsConfig     `yaml:"weapons"`
	Whitelist   []string          `yaml:"whitelist"`
	LogDir      string            `yaml:"log_dir"`
	DataDir     string            `yaml:"data_dir"`

	mu          sync.RWMutex
	parsedCIDRs []net.IPNet
	path        string
	lastMod     time.Time
	watchers    []func(*Config)
}

// Load reads config from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := Default()
			cfg.path = path
			cfg.parsedCIDRs = parseCIDRs(cfg.Whitelist)
			return cfg, nil
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.path = path
	cfg.parsedCIDRs = parseCIDRs(cfg.Whitelist)

	// Environment variable overrides
	if v := os.Getenv("FORTRESS_SWARM_NAME"); v != "" {
		cfg.Swarm.Name = v
	}
	if v := os.Getenv("FORTRESS_GOSSIP_KEY"); v != "" {
		cfg.Swarm.GossipKey = v
	}

	return cfg, nil
}

func parseCIDRs(entries []string) []net.IPNet {
	var result []net.IPNet
	for _, e := range entries {
		_, cidr, err := net.ParseCIDR(e)
		if err != nil {
			continue // non-CIDR entries used for exact match
		}
		result = append(result, *cidr)
	}
	return result
}
```

- [ ] **Step 2: Add Validate method**

```go
// Validate checks all config values and returns accumulated errors.
func (c *Config) Validate() error {
	var errs []string

	if c.Engine.SynFloodPPS <= 0 || c.Engine.SynFloodPPS > 1000000 {
		errs = append(errs, "engine.syn_flood_pps must be 1..1000000")
	}
	if c.Engine.UdpFloodPPS <= 0 || c.Engine.UdpFloodPPS > 1000000 {
		errs = append(errs, "engine.udp_flood_pps must be 1..1000000")
	}
	if c.Engine.IcmpFloodPPS <= 0 || c.Engine.IcmpFloodPPS > 1000000 {
		errs = append(errs, "engine.icmp_flood_pps must be 1..1000000")
	}
	if c.Engine.MaxPPS <= 0 {
		errs = append(errs, "engine.max_pps must be > 0")
	}
	if c.Brain.CounterstrikeThreshold < 0 || c.Brain.CounterstrikeThreshold > 100 {
		errs = append(errs, "brain.counterstrike_threshold must be 0..100")
	}
	if c.Brain.BanDuration < 0 {
		errs = append(errs, "brain.ban_duration must be >= 0")
	}

	if _, _, err := net.SplitHostPort(c.Swarm.Bind); err != nil {
		errs = append(errs, "swarm.bind must be host:port")
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation:\n  - %s", joinErrs(errs))
	}
	return nil
}

func joinErrs(errs []string) string {
	s := ""
	for i, e := range errs {
		if i > 0 {
			s += "\n  - "
		}
		s += e
	}
	return s
}
```

- [ ] **Step 3: Add IsWhitelisted with CIDR support**

```go
// IsWhitelisted checks if an IP is whitelisted. Supports exact string match
// and CIDR subnet matching via pre-parsed networks.
func (c *Config) IsWhitelisted(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Exact string match (handles bare IPs, IPv6 literals, and raw CIDR strings)
	for _, w := range c.Whitelist {
		if w == ip {
			return true
		}
	}

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

// SetWhitelist replaces the whitelist and re-parses CIDRs.
func (c *Config) SetWhitelist(entries []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Whitelist = entries
	c.parsedCIDRs = parseCIDRs(entries)
}

// OnChange registers a callback for config hot-reload.
func (c *Config) OnChange(fn func(*Config)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.watchers = append(c.watchers, fn)
}
```

- [ ] **Step 4: Add hot-reload Watch**

```go
func (c *Config) Watch(interval time.Duration) {
	go func() {
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
					c.Engine = newCfg.Engine
					c.Brain = newCfg.Brain
					c.Swarm = newCfg.Swarm
					c.Weapons = newCfg.Weapons
					c.Whitelist = newCfg.Whitelist
					c.parsedCIDRs = newCfg.parsedCIDRs
					c.LogDir = newCfg.LogDir
					c.DataDir = newCfg.DataDir
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
```

- [ ] **Step 5: Add ValidateTarget for command injection prevention**

```go
import "strings"

// ValidateTarget checks that a target string is safe for use with external binaries.
// Rejects flag injection, shell metacharacters, and non-IP/non-hostname values.
func ValidateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target must not be empty")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("target must not start with '-' (flag injection prevention)")
	}
	dangerous := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "\n", "\r"}
	for _, c := range dangerous {
		if strings.Contains(target, c) {
			return fmt.Errorf("target contains forbidden character %q", c)
		}
	}
	if ip := net.ParseIP(target); ip != nil {
		return nil
	}
	if len(target) > 253 {
		return fmt.Errorf("target too long for hostname")
	}
	return nil
}
```

- [ ] **Step 6: Build and verify**

```bash
go build ./...
go vet ./...
# Expected: no errors
```

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: config loading, validation, CIDR whitelist, target sanitization"
```

---

### Task 4: L1 Packet Inspector

**Files:**
- Create: `internal/engine/packet.go`
- Create: `internal/engine/packet_test.go`

- [ ] **Step 1: Write failing test**

`internal/engine/packet_test.go`:
```go
package engine

import (
	"testing"

	"github.com/fortress/v6/internal/config"
)

func TestSYNFloodDetection(t *testing.T) {
	cfg := config.Default()
	cfg.Engine.SynFloodPPS = 10 // lower threshold for faster test
	pi := NewPacketInspector(cfg)

	// 50 SYN packets from same IP — should trigger flood alert
	var alerts int
	for i := 0; i < 50; i++ {
		threats := pi.Feed("S", "203.0.113.99", 443, "TCP")
		if len(threats) > 0 {
			alerts++
		}
	}
	if alerts == 0 {
		t.Error("expected SYN flood alerts from 50 packets")
	}
	t.Logf("SYN flood: %d alerts from 50 packets (threshold=10)", alerts)
}

func TestSensitivePortProbe(t *testing.T) {
	cfg := config.Default()
	pi := NewPacketInspector(cfg)

	threats := pi.Feed("S", "203.0.113.99", 22, "TCP")
	found := false
	for _, th := range threats {
		if th.Type == "敏感端口探测" {
			found = true
		}
	}
	if !found {
		t.Error("expected sensitive port probe alert for port 22")
	}
}

func TestARPReplyIgnored(t *testing.T) {
	cfg := config.Default()
	pi := NewPacketInspector(cfg)
	threat := pi.FeedARP("192.168.1.1", "aa:bb:cc:dd:ee:ff")
	if threat.Type != "ARP应答" {
		t.Errorf("expected ARP应答, got %s", threat.Type)
	}
}
```

- [ ] **Step 2: Run test to verify failure**

```bash
go test ./internal/engine/ -run TestSYNFlood -v
# Expected: compilation error — NewPacketInspector not defined
```

- [ ] **Step 3: Implement PacketInspector**

`internal/engine/packet.go`:
```go
package engine

import (
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/pkg/ringbuf"
)

// SensitivePorts are ports commonly targeted by scanners and worms.
var SensitivePorts = map[uint16]bool{
	22: true, 23: true, 135: true, 137: true, 139: true,
	445: true, 1433: true, 3306: true, 3389: true,
	5432: true, 6379: true, 27017: true, 11211: true,
}

const MAX_RING_BUFFERS = 10000

// PacketInspector is the L1 packet-level threat detection engine.
type PacketInspector struct {
	mu             sync.Mutex
	synCounter     map[string]*ringbuf.RingBuffer
	udpCounter     map[string]*ringbuf.RingBuffer
	icmpCounter    map[string]*ringbuf.RingBuffer
	synFloodPPS    int
	udpFloodPPS    int
	icmpFloodPPS   int
	whitelisted    func(string) bool
	ringBufWarned  bool
}

func NewPacketInspector(cfg *config.Config) *PacketInspector {
	return &PacketInspector{
		synCounter:   make(map[string]*ringbuf.RingBuffer),
		udpCounter:   make(map[string]*ringbuf.RingBuffer),
		icmpCounter:  make(map[string]*ringbuf.RingBuffer),
		synFloodPPS:  cfg.Engine.SynFloodPPS,
		udpFloodPPS:  cfg.Engine.UdpFloodPPS,
		icmpFloodPPS: cfg.Engine.IcmpFloodPPS,
		whitelisted:  cfg.IsWhitelisted,
	}
}

func (pi *PacketInspector) Feed(tcpFlags, src string, dport uint16, protocol string) []Threat {
	pi.mu.Lock()
	defer pi.mu.Unlock()

	switch protocol {
	case "TCP":
		return pi.feedTCP(tcpFlags, src, dport)
	case "UDP":
		return pi.feedUDP(src)
	case "ICMP":
		return pi.feedICMP(src)
	}
	return nil
}

func (pi *PacketInspector) feedTCP(flags, src string, dport uint16) []Threat {
	var threats []Threat
	skip := pi.whitelisted != nil && pi.whitelisted(src)
	if skip {
		return nil
	}

	// SYN flood
	if containsFlag(flags, 'S') && !containsFlag(flags, 'A') {
		if pi.checkFlood(src, pi.synFloodPPS, pi.synCounter) {
			threats = append(threats, Threat{Type: "SYN洪水", IP: src, Detail: "速率 pps"})
		}
	}

	// TCP flag anomaly scan
	if name := flagPattern(flags); name != "" && !isNormalFlag(flags) {
		threats = append(threats, Threat{Type: name, IP: src, Detail: "标志位=" + flags})
	}

	// Sensitive port probe
	if SensitivePorts[dport] {
		threats = append(threats, Threat{Type: "敏感端口探测", IP: src, Detail: "目标端口"})
	}

	return threats
}

func (pi *PacketInspector) feedUDP(src string) []Threat {
	if pi.whitelisted != nil && pi.whitelisted(src) {
		return nil
	}
	if pi.checkFlood(src, pi.udpFloodPPS, pi.udpCounter) {
		return []Threat{{Type: "UDP洪水", IP: src}}
	}
	return nil
}

func (pi *PacketInspector) feedICMP(src string) []Threat {
	if pi.whitelisted != nil && pi.whitelisted(src) {
		return nil
	}
	if pi.checkFlood(src, pi.icmpFloodPPS, pi.icmpCounter) {
		return []Threat{{Type: "ICMP洪水", IP: src}}
	}
	return nil
}

func (pi *PacketInspector) FeedARP(srcIP, srcMAC string) Threat {
	return Threat{Type: "ARP应答", IP: srcIP, Detail: "MAC=" + srcMAC}
}

func (pi *PacketInspector) checkFlood(ip string, threshold int, counter map[string]*ringbuf.RingBuffer) bool {
	now := time.Now()
	rb, ok := counter[ip]
	if !ok {
		if len(counter) >= MAX_RING_BUFFERS {
			pi.evictEmptiest(counter)
		}
		rb = ringbuf.New(1000)
		counter[ip] = rb
	}
	rb.Push(now)
	rb.PruneBefore(now.Add(-time.Second))
	return rb.Len() >= threshold
}

func (pi *PacketInspector) evictEmptiest(counter map[string]*ringbuf.RingBuffer) {
	var minIP string
	minLen := int(^uint(0) >> 1)
	for ip, rb := range counter {
		if rb.Len() < minLen {
			minLen = rb.Len()
			minIP = ip
		}
	}
	if minIP != "" {
		delete(counter, minIP)
	}
}

func containsFlag(flags string, flag byte) bool {
	for i := 0; i < len(flags); i++ {
		if flags[i] == flag {
			return true
		}
	}
	return false
}

var flagPatterns = map[string]string{
	"S": "SYN扫描", "AS": "SYN-ACK", "F": "FIN扫描",
	"FPU": "Xmas扫描", "N": "NULL扫描", "FS": "SYN+FIN异常", "RS": "SYN+RST异常",
}

var normalFlags = map[string]bool{"S": true, "AS": true}

func flagPattern(flags string) string { return flagPatterns[flags] }
func isNormalFlag(flags string) bool   { return normalFlags[flags] }
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/engine/ -run "TestSYNFlood|TestSensitivePort|TestARP" -v
# Expected: all PASS
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: L1 packet inspector — SYN/UDP/ICMP flood, TCP flags, port probe, ARP"
```

---

### Task 5: L2 Flow Analyzer

**Files:**
- Create: `internal/engine/flow.go`
- Create: `internal/engine/flow_test.go`

- [ ] **Step 1: Implement FlowAnalyzer with multi-window scan detection**

`internal/engine/flow.go`:
```go
package engine

import (
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
)

type flowRecord struct {
	Time time.Time
	Port uint16
}

type scanWindow struct {
	Name     string
	Seconds  int
	Threshold int
}

var defaultScanWindows = []scanWindow{
	{"快速扫描", 5, 12},
	{"中速扫描", 30, 25},
	{"慢速扫描", 300, 50},
}

const maxFlowRecords = 500

type FlowAnalyzer struct {
	mu      sync.Mutex
	records map[string][]flowRecord
	windows []scanWindow
}

func NewFlowAnalyzer(cfg *config.Config) *FlowAnalyzer {
	return &FlowAnalyzer{
		records: make(map[string][]flowRecord),
		windows: defaultScanWindows,
	}
}

func (fa *FlowAnalyzer) Feed(srcIP string, dstPort uint16) []Threat {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	now := time.Now()
	fa.records[srcIP] = append(fa.records[srcIP], flowRecord{Time: now, Port: dstPort})

	records := fa.records[srcIP]
	if len(records) > maxFlowRecords {
		records = records[len(records)-maxFlowRecords:]
		fa.records[srcIP] = records
	}

	var threats []Threat
	for _, w := range fa.windows {
		cutoff := now.Add(-time.Duration(w.Seconds) * time.Second)
		uniquePorts := make(map[uint16]struct{})
		for i := len(records) - 1; i >= 0; i-- {
			if records[i].Time.Before(cutoff) {
				break
			}
			uniquePorts[records[i].Port] = struct{}{}
		}
		if len(uniquePorts) >= w.Threshold {
			threats = append(threats, Threat{
				Type: w.Name, IP: srcIP,
				Detail: "扫描端口数=" + itoa(len(uniquePorts)),
			})
		}
	}
	return threats
}

func (fa *FlowAnalyzer) Evict(deadline time.Time) int {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	removed := 0
	for ip, records := range fa.records {
		kept := pruneFlowRecords(records, deadline)
		if len(kept) == 0 {
			delete(fa.records, ip)
			removed++
		} else {
			fa.records[ip] = kept
		}
	}
	return removed
}

func pruneFlowRecords(records []flowRecord, cutoff time.Time) []flowRecord {
	for i, r := range records {
		if !r.Time.Before(cutoff) {
			kept := make([]flowRecord, len(records)-i)
			copy(kept, records[i:])
			return kept
		}
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 6)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
```

- [ ] **Step 2: Write flow test**

`internal/engine/flow_test.go`:
```go
package engine

import (
	"testing"

	"github.com/fortress/v6/internal/config"
)

func TestPortScanDetection(t *testing.T) {
	cfg := config.Default()
	fa := NewFlowAnalyzer(cfg)

	// Simulate 15 unique ports to one IP within 5 seconds — triggers "快速扫描"
	for port := uint16(1); port <= 15; port++ {
		threats := fa.Feed("203.0.113.99", port)
		if port >= 12 && len(threats) > 0 {
			t.Logf("port %d: detected %s", port, threats[0].Type)
			return // test passes
		}
	}
	t.Error("expected port scan detection after 12 unique ports")
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/engine/ -run TestPortScan -v
# Expected: PASS with detection log
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: L2 flow analyzer — multi-window port scan detection"
```

---

### Task 6: L3 Behavior Analyzer (Entropy Anomaly)

**Files:**
- Create: `internal/engine/behavior.go`
- Create: `internal/engine/behavior_test.go`

- [ ] **Step 1: Implement BehaviorAnalyzer**

`internal/engine/behavior.go`:
```go
package engine

import (
	"math"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/pkg/entropy"
	"github.com/fortress/v6/pkg/welford"
)

const (
	defaultEntropyWindow  = 60 * time.Second
	entropyDeviationSigma = 2.5
	baselineInterval      = 200
	maxGlobalSamples      = 2000
)

type portSample struct {
	Time time.Time
	Port uint16
}

type ipSample struct {
	Time time.Time
	IP   string
}

type BehaviorAnalyzer struct {
	mu             sync.Mutex
	globalPorts    []portSample
	globalIPs      []ipSample
	portBaseline   *welford.Tracker
	ipBaseline     *welford.Tracker
	entropyWindow  time.Duration
	devThreshold   float64
	sampleCount    int
}

func NewBehaviorAnalyzer(cfg *config.Config) *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		globalPorts:   make([]portSample, 0, maxGlobalSamples),
		globalIPs:     make([]ipSample, 0, maxGlobalSamples),
		portBaseline:  &welford.Tracker{},
		ipBaseline:    &welford.Tracker{},
		entropyWindow: defaultEntropyWindow,
		devThreshold:  entropyDeviationSigma,
	}
}

func (ba *BehaviorAnalyzer) Feed(srcIP string, dstPort uint16) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	now := time.Now()
	ba.globalPorts = append(ba.globalPorts, portSample{Time: now, Port: dstPort})
	if len(ba.globalPorts) > maxGlobalSamples {
		ba.globalPorts = ba.globalPorts[len(ba.globalPorts)-maxGlobalSamples:]
	}
	ba.globalIPs = append(ba.globalIPs, ipSample{Time: now, IP: srcIP})
	if len(ba.globalIPs) > maxGlobalSamples {
		ba.globalIPs = ba.globalIPs[len(ba.globalIPs)-maxGlobalSamples:]
	}

	ba.sampleCount++
	if ba.sampleCount%baselineInterval == 0 {
		ba.portBaseline.Add(ba.currentPortEntropy())
		ba.ipBaseline.Add(ba.currentIPEntropy())
	}
}

func (ba *BehaviorAnalyzer) Check() []Threat {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	var threats []Threat
	pe := ba.currentPortEntropy()
	ie := ba.currentIPEntropy()

	if ba.portBaseline.Std() > 0 {
		dev := math.Abs(pe-ba.portBaseline.Mean) / ba.portBaseline.Std()
		if dev > ba.devThreshold {
			threats = append(threats, Threat{
				Type: "流量异常", Detail: "端口熵偏差=" + ftoa(dev) + "σ",
			})
		}
	}
	if ba.ipBaseline.Std() > 0 {
		dev := math.Abs(ie-ba.ipBaseline.Mean) / ba.ipBaseline.Std()
		if dev > ba.devThreshold {
			threats = append(threats, Threat{
				Type: "流量异常", Detail: "IP熵偏差=" + ftoa(dev) + "σ",
			})
		}
	}
	return threats
}

func (ba *BehaviorAnalyzer) currentPortEntropy() float64 {
	cutoff := time.Now().Add(-ba.entropyWindow)
	ports := make([]uint16, 0)
	for i := len(ba.globalPorts) - 1; i >= 0; i-- {
		if ba.globalPorts[i].Time.Before(cutoff) {
			break
		}
		ports = append(ports, ba.globalPorts[i].Port)
	}
	return entropy.Shannon(ports)
}

func (ba *BehaviorAnalyzer) currentIPEntropy() float64 {
	cutoff := time.Now().Add(-ba.entropyWindow)
	ips := make([]string, 0)
	for i := len(ba.globalIPs) - 1; i >= 0; i-- {
		if ba.globalIPs[i].Time.Before(cutoff) {
			break
		}
		ips = append(ips, ba.globalIPs[i].IP)
	}
	return entropy.Shannon(ips)
}
```

- [ ] **Step 2: Build and verify**

```bash
go build ./...
# Add ftoa helper if needed, or use fmt.Sprintf in the Threat Detail
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: L3 behavior analyzer — Welford online entropy + sigma deviation"
```

---

### Task 7: L4 DNS Tunnel Detector

**Files:**
- Create: `internal/engine/dns.go`
- Create: `internal/engine/dns_test.go`

- [ ] **Step 1: Implement DnsTunnelDetector**

`internal/engine/dns.go`:
```go
package engine

import (
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/pkg/entropy"
)

const (
	dnsMaxQueryLen   = 52
	dnsEntropyThresh = 4.5
	dnsFloodThresh   = 30
	dnsFloodWindow   = 30 * time.Second
	dnsMaxHistory    = 200
)

type queryRecord struct {
	Time  time.Time
	Query string
}

type DnsTunnelDetector struct {
	mu      sync.Mutex
	history map[string][]queryRecord
}

func NewDnsTunnelDetector(cfg *config.Config) *DnsTunnelDetector {
	return &DnsTunnelDetector{
		history: make(map[string][]queryRecord),
	}
}

func (d *DnsTunnelDetector) Feed(srcIP, query string) []Threat {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	d.history[srcIP] = append(d.history[srcIP], queryRecord{Time: now, Query: query})
	if len(d.history[srcIP]) > dnsMaxHistory {
		d.history[srcIP] = d.history[srcIP][len(d.history[srcIP])-dnsMaxHistory:]
	}

	var threats []Threat

	// Heuristic 1: unusually long query
	if len(query) > dnsMaxQueryLen {
		threats = append(threats, Threat{
			Type: "DNS隧道", IP: srcIP, Detail: "查询长度异常 len=" + itoa(len(query)),
		})
	}

	// Heuristic 2: high entropy (base64-encoded payloads)
	if entropy.Bytes([]byte(query)) > dnsEntropyThresh {
		threats = append(threats, Threat{
			Type: "DNS隧道", IP: srcIP, Detail: "查询熵异常",
		})
	}

	// Heuristic 3: query flood
	count := 0
	cutoff := now.Add(-dnsFloodWindow)
	for _, r := range d.history[srcIP] {
		if r.Time.After(cutoff) {
			count++
		}
	}
	if count >= dnsFloodThresh {
		threats = append(threats, Threat{
			Type: "DNS隧道", IP: srcIP, Detail: "查询频率异常 " + itoa(count) + "次/30s",
		})
	}

	return threats
}
```

- [ ] **Step 2: Write DNS test**

`internal/engine/dns_test.go`:
```go
package engine

import (
	"strings"
	"testing"

	"github.com/fortress/v6/internal/config"
)

func TestDNSTunnelLongQuery(t *testing.T) {
	cfg := config.Default()
	d := NewDnsTunnelDetector(cfg)
	longQuery := strings.Repeat("x", 60) + ".example.com"
	threats := d.Feed("10.0.0.1", longQuery)
	if len(threats) == 0 {
		t.Error("expected DNS tunnel alert for long query")
	}
	t.Logf("long query detected: %s", threats[0].Detail)
}

func TestDNSTunnelHighEntropy(t *testing.T) {
	cfg := config.Default()
	d := NewDnsTunnelDetector(cfg)
	base64Query := "dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0IGVuY29kaW5n.exfil.com"
	threats := d.Feed("10.0.0.2", base64Query)
	if len(threats) == 0 {
		t.Error("expected DNS tunnel alert for high-entropy query")
	}
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/engine/ -run TestDNS -v
# Expected: PASS
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: L4 DNS tunnel detector — length, entropy, frequency heuristics"
```

---

### Task 8: L5 HTTP Inspector + Brute Force Detector

**Files:**
- Create: `internal/engine/http.go`
- Create: `internal/engine/bruteforce.go`
- Create: `internal/engine/http_test.go`

- [ ] **Step 1: Implement HTTP stream reassembly + attack detection**

`internal/engine/http.go`:
```go
package engine

import (
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fortress/v6/internal/config"
)

const maxHTTPStreams = 5000
const maxStreamSize = 64 * 1024
const streamIdleTimeout = 30 * time.Second

var (
	reSQLi          = regexp.MustCompile(`(?i)(\s|%20)*(or|union|select|insert|drop|--|#|/\*)`)
	reXSS           = regexp.MustCompile(`(?i)(<script|onerror=|onload=|javascript:|alert\(|eval\()`)
	rePathTraversal = regexp.MustCompile(`\.\./|\.\.\\|%2e%2e|%2f|/etc/passwd|/proc/self`)
)

type streamKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

type httpStream struct {
	Buf      []byte
	LastSeen time.Time
}

type HttpInspector struct {
	mu             sync.Mutex
	streams        map[streamKey]*httpStream
	droppedStreams atomic.Uint64
}

func NewHttpInspector(cfg *config.Config) *HttpInspector {
	return &HttpInspector{
		streams: make(map[streamKey]*httpStream),
	}
}

func (h *HttpInspector) Feed(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []Threat {
	h.mu.Lock()
	defer h.mu.Unlock()

	key := streamKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}
	s, ok := h.streams[key]
	if !ok {
		if len(h.streams) >= maxHTTPStreams {
			h.droppedStreams.Add(1)
			return nil
		}
		s = &httpStream{Buf: make([]byte, 0, 4096)}
		h.streams[key] = s
	}
	s.LastSeen = time.Now()

	if len(s.Buf)+len(payload) > maxStreamSize {
		s.Buf = nil // truncate, don't accumulate garbage
	}
	s.Buf = append(s.Buf, payload...)

	return h.scan(string(s.Buf), srcIP)
}

func (h *HttpInspector) scan(data, ip string) []Threat {
	var threats []Threat

	if loc := reSQLi.FindStringIndex(data); loc != nil {
		threats = append(threats, Threat{
			Type: "SQL注入攻击", IP: ip, Detail: "匹配位置=" + itoa(loc[0]),
		})
	}
	if loc := reXSS.FindStringIndex(data); loc != nil {
		threats = append(threats, Threat{
			Type: "XSS攻击", IP: ip, Detail: "匹配位置=" + itoa(loc[0]),
		})
	}
	if loc := rePathTraversal.FindStringIndex(data); loc != nil {
		threats = append(threats, Threat{
			Type: "路径遍历攻击", IP: ip, Detail: "匹配位置=" + itoa(loc[0]),
		})
	}
	return threats
}

func (h *HttpInspector) EvictIdle() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := time.Now().Add(-streamIdleTimeout)
	removed := 0
	for k, s := range h.streams {
		if s.LastSeen.Before(cutoff) {
			delete(h.streams, k)
			removed++
		}
	}
	return removed
}

func (h *HttpInspector) DroppedStreams() uint64 {
	return h.droppedStreams.Load()
}
```

- [ ] **Step 2: Implement BruteForceDetector**

`internal/engine/bruteforce.go`:
```go
package engine

import (
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/pkg/ringbuf"
)

const (
	sshBruteThresh  = 10
	sshBruteWindow  = 60 * time.Second
	httpBruteThresh = 15
	httpBruteWindow = 60 * time.Second
)

type BruteForceDetector struct {
	mu          sync.Mutex
	sshAttempts map[string]*ringbuf.RingBuffer
	httpErrors  map[string]*ringbuf.RingBuffer
}

func NewBruteForceDetector(cfg *config.Config) *BruteForceDetector {
	return &BruteForceDetector{
		sshAttempts: make(map[string]*ringbuf.RingBuffer),
		httpErrors:  make(map[string]*ringbuf.RingBuffer),
	}
}

func (bf *BruteForceDetector) FeedSSH(srcIP string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	rb, ok := bf.sshAttempts[srcIP]
	if !ok {
		rb = ringbuf.New(200)
		bf.sshAttempts[srcIP] = rb
	}
	rb.Push(time.Now())
	rb.PruneBefore(time.Now().Add(-sshBruteWindow))
}

func (bf *BruteForceDetector) FeedHTTPError(srcIP string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	rb, ok := bf.httpErrors[srcIP]
	if !ok {
		rb = ringbuf.New(200)
		bf.httpErrors[srcIP] = rb
	}
	rb.Push(time.Now())
	rb.PruneBefore(time.Now().Add(-httpBruteWindow))
}

func (bf *BruteForceDetector) Check() []Threat {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	var threats []Threat
	for ip, rb := range bf.sshAttempts {
		if rb.Len() >= sshBruteThresh {
			threats = append(threats, Threat{Type: "SSH爆破", IP: ip, Detail: "次数=" + itoa(rb.Len())})
		}
	}
	for ip, rb := range bf.httpErrors {
		if rb.Len() >= httpBruteThresh {
			threats = append(threats, Threat{Type: "HTTP爆破", IP: ip, Detail: "次数=" + itoa(rb.Len())})
		}
	}
	return threats
}
```

- [ ] **Step 3: Write HTTP test**

`internal/engine/http_test.go`:
```go
package engine

import (
	"testing"

	"github.com/fortress/v6/internal/config"
)

func TestSQLiDetection(t *testing.T) {
	cfg := config.Default()
	h := NewHttpInspector(cfg)
	payload := []byte("GET /search?q=1' OR '1'='1 HTTP/1.1\r\nHost: test\r\n\r\n")
	threats := h.Feed("10.0.0.1", "10.0.0.2", 12345, 80, payload)
	found := false
	for _, th := range threats {
		if th.Type == "SQL注入攻击" {
			found = true
			t.Logf("SQLi detected at position %s", th.Detail)
		}
	}
	if !found {
		t.Error("expected SQL injection detection")
	}
}

func TestXSSDetection(t *testing.T) {
	cfg := config.Default()
	h := NewHttpInspector(cfg)
	payload := []byte("GET /page?msg=<script>alert(1)</script> HTTP/1.1\r\n\r\n")
	threats := h.Feed("10.0.0.1", "10.0.0.2", 12345, 80, payload)
	for _, th := range threats {
		if th.Type == "XSS攻击" {
			t.Log("XSS detected")
			return
		}
	}
	t.Error("expected XSS detection")
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/engine/ -run "TestSQLi|TestXSS" -v
# Expected: PASS
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: L5 HTTP inspector (stream reassembly, SQLi/XSS/path-traversal) + brute force detector"
```

---

### Task 9: L6 Hybrid Anomaly Detector (EMA + CMS)

**Files:**
- Create: `internal/engine/anomaly.go`
- Create: `internal/engine/anomaly_test.go`

- [ ] **Step 1: Implement EMA Z-Score + Count-Min Sketch hybrid**

`internal/engine/anomaly.go`:
```go
package engine

import (
	"math"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/pkg/cmsketch"
	"github.com/fortress/v6/pkg/welford"
)

const maxFlows = 10000
const cmsRows = 4
const cmsCols = 65536
const emaAlpha = 0.1
const zThresholdL1 = 4.0
const anomalyThresholdL2 = 6.0
const minSamplesForZ = 5

type featureStats struct {
	EMA    float64
	Mean   float64
	M2     float64
	N      int
	DevEMA float64
}

type FlowStats struct {
	IP         string
	LastSeen   time.Time
	Features   [6]featureStats // pkt_size, iat, flags_bitmask, payload_entropy, burst_count, symmetry
}

type HybridAnomalyDetector struct {
	mu       sync.Mutex
	flows    map[string]*FlowStats
	cms      *cmsketch.Sketch
	packetCount uint64
	ZThresh  float64
	L2Thresh float64
}

func NewHybridAnomalyDetector(cfg *config.Config) *HybridAnomalyDetector {
	return &HybridAnomalyDetector{
		flows:    make(map[string]*FlowStats),
		cms:      cmsketch.New(cmsRows, cmsCols),
		ZThresh:  zThresholdL1,
		L2Thresh: anomalyThresholdL2,
	}
}

func (ha *HybridAnomalyDetector) Feed(pkt PacketContext) []Threat {
	ha.mu.Lock()
	defer ha.mu.Unlock()

	ha.packetCount++
	if ha.packetCount%10000000 == 0 {
		ha.cms.Decay()
	}

	// Layer 1: EMA Z-Score (6 features)
	fs, ok := ha.flows[pkt.SrcIP]
	if !ok {
		if len(ha.flows) >= maxFlows {
			ha.evictOldest()
		}
		fs = &FlowStats{IP: pkt.SrcIP}
		ha.flows[pkt.SrcIP] = fs
	}
	fs.LastSeen = time.Now()

	featVals := [6]float64{
		float64(pkt.PayloadSize),               // pkt_size
		0,                                        // iat (would need last timestamp from Rust)
		float64(len(pkt.TCPFlags)),                // flags_bitmask
		0,                                        // payload_entropy (computed by Rust)
		1,                                        // burst_count
		1,                                        // symmetry
	}

	var l1Score float64
	for i, val := range featVals {
		st := &fs.Features[i]
		if st.N < minSamplesForZ {
			st.EMA = val
			st.N++
			continue
		}
		delta := val - st.EMA
		st.EMA += emaAlpha * delta
		oldMean := st.Mean
		st.N++
		st.Mean += (val - st.Mean) / float64(st.N)
		st.M2 += (val - oldMean) * (val - st.Mean)

		stddev := float64(0)
		if st.N >= 2 {
			stddev = math.Sqrt(st.M2 / float64(st.N-1))
		}
		if stddev > 0 {
			z := math.Abs(val-st.EMA) / stddev
			if z > ha.ZThresh {
				l1Score += z / ha.ZThresh
			}
		}
	}

	// Layer 2: Count-Min Sketch structural anomaly
	fp := []byte(pkt.SrcIP + pkt.Protocol + string(rune(pkt.DstPort)))
	ha.cms.Add(fp, 1)
	estimate := ha.cms.Estimate(fp)
	total := ha.cms.Total()
	var l2Score float64
	if total > 0 && estimate > 0 {
		l2Score = -math.Log(float64(estimate) / float64(total))
	}

	var threats []Threat
	if l1Score >= 2.0 || l2Score > ha.L2Thresh {
		threats = append(threats, Threat{
			Type: "混合异常", IP: pkt.SrcIP,
			Detail: "L1=" + ftoa(l1Score) + " L2=" + ftoa(l2Score),
		})
	}
	return threats
}

func (ha *HybridAnomalyDetector) evictOldest() {
	var oldestIP string
	var oldestTime time.Time
	for ip, fs := range ha.flows {
		if oldestIP == "" || fs.LastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = fs.LastSeen
		}
	}
	if oldestIP != "" {
		delete(ha.flows, oldestIP)
	}
}

func (ha *HybridAnomalyDetector) EvictIdle(idle time.Duration) int {
	ha.mu.Lock()
	defer ha.mu.Unlock()
	cutoff := time.Now().Add(-idle)
	removed := 0
	for ip, fs := range ha.flows {
		if fs.LastSeen.Before(cutoff) {
			delete(ha.flows, ip)
			removed++
		}
	}
	return removed
}

func ftoa(f float64) string {
	// minimal float formatter — use fmt.Sprintf in production
	return string([]byte{
		byte('0' + int(f)/10),
		'.',
		byte('0' + int(f*10)%10),
	})
}
```

- [ ] **Step 2: Build and verify**

```bash
go build ./...
# Fix any compilation issues (ftoa may need fmt import)
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: L6 hybrid anomaly detector — EMA Z-Score + Count-Min Sketch"
```

---

### Task 10: L7 Fingerprinting (JA3 + OS)

**Files:**
- Create: `internal/engine/fingerprint.go`
- Create: `internal/engine/fingerprint_test.go`

- [ ] **Step 1: Implement JA3 and OS fingerprinting skeletons**

`internal/engine/fingerprint.go`:
```go
package engine

import (
	"crypto/md5"
	"fmt"
	"sync"

	"github.com/fortress/v6/internal/config"
)

type osSignature struct {
	Name string
	TTL  int
	Win  int
	DF   bool
}

var osSignatures = []osSignature{
	{"Linux 5.x/6.x", 64, 65535, true},
	{"Linux 3.x", 64, 29200, true},
	{"Windows 10/11", 128, 65535, true},
	{"Windows 7/8", 128, 8192, true},
	{"macOS", 64, 65535, true},
	{"FreeBSD", 64, 65535, true},
}

type FingerprintEngine struct {
	mu          sync.Mutex
	osDetected  map[string]string
}

func NewFingerprintEngine(cfg *config.Config) *FingerprintEngine {
	return &FingerprintEngine{
		osDetected: make(map[string]string),
	}
}

// FeedTLS processes a raw TLS ClientHello and returns threats if JA3 is suspicious.
// tlsData should be the raw ClientHello bytes starting from the handshake type.
func (fe *FingerprintEngine) FeedTLS(srcIP string, tlsData []byte) []Threat {
	if len(tlsData) < 50 {
		return nil
	}
	ja3Hash := computeJA3(tlsData)
	if ja3Hash == "" {
		return nil
	}
	// TODO: Match against real JA3 database (populated in Plan C)
	_ = ja3Hash
	return nil
}

// FeedSYN processes initial SYN packet characteristics for passive OS detection.
func (fe *FingerprintEngine) FeedSYN(srcIP string, ttl int, win uint16, df bool) []Threat {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	for _, sig := range osSignatures {
		score := 0
		if ttl == sig.TTL || (sig.TTL == 64 && ttl <= 64) || (sig.TTL == 128 && ttl <= 128) {
			score += 3
		}
		if win == uint16(sig.Win) {
			score += 1
		}
		if df == sig.DF {
			score += 1
		}
		if score >= 4 {
			fe.osDetected[srcIP] = sig.Name
			return nil // normal match, not a threat
		}
	}
	return []Threat{{
		Type: "OS指纹异常", IP: srcIP,
		Detail: "TTL=" + itoa(ttl) + " Win=" + itoa(int(win)),
	}}
}

func computeJA3(data []byte) string {
	// Simplified JA3: extract cipher suites + extensions + EC curves
	// Full implementation requires manual TLS parsing (Plan C)
	if len(data) < 50 {
		return ""
	}
	hash := md5.Sum(data[:min(len(data), 200)])
	return fmt.Sprintf("%x", hash)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
```

- [ ] **Step 2: Write fingerprint test**

`internal/engine/fingerprint_test.go`:
```go
package engine

import (
	"testing"

	"github.com/fortress/v6/internal/config"
)

func TestOSDetectionLinux(t *testing.T) {
	cfg := config.Default()
	fe := NewFingerprintEngine(cfg)
	// Linux SYN: TTL=64, Window=65535, DF set
	threats := fe.FeedSYN("10.0.0.1", 64, 65535, true)
	if len(threats) > 0 {
		t.Errorf("expected no threat for normal Linux SYN, got %v", threats)
	}
}

func TestOSDetectionUnknown(t *testing.T) {
	cfg := config.Default()
	fe := NewFingerprintEngine(cfg)
	// Spoofed: TTL=32 (unusual), Window=12345, no DF
	threats := fe.FeedSYN("10.0.0.2", 32, 12345, false)
	if len(threats) == 0 {
		t.Error("expected OS fingerprint threat for unusual SYN")
	}
	t.Logf("OS anomaly: %s", threats[0].Detail)
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/engine/ -run TestOS -v
# Expected: PASS
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: L7 fingerprint engine — JA3 TLS + passive OS detection"
```

---

### Task 11: Brain Scorer + Response Ladder

**Files:**
- Create: `internal/brain/scorer.go`
- Create: `internal/brain/ladder.go`
- Create: `internal/brain/correlation.go`
- Create: `internal/brain/decay.go`
- Create: `internal/brain/scorer_test.go`

- [ ] **Step 1: Implement scorer with 13 detector weights**

`internal/brain/scorer.go`:
```go
package brain

import (
	"math"
	"sync"
	"time"

	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/engine"
)

// DetectorWeights defines the contribution of each detector to the total score.
type DetectorWeights struct {
	PacketFlood     float64
	PacketScan      float64
	FlowScan        float64
	BehaviorEntropy float64
	DNSTunnel       float64
	HTTPAttack      float64
	BruteForce      float64
	AnomalyL1       float64
	AnomalyL2       float64
	JA3Malicious    float64
	OSAnomaly       float64
	HoneypotHit     float64
	ARPSpoof        float64
}

// DefaultWeights returns the standard detector weight configuration.
func DefaultWeights() DetectorWeights {
	return DetectorWeights{
		PacketFlood: 0.10, PacketScan: 0.10, FlowScan: 0.10,
		BehaviorEntropy: 0.08, DNSTunnel: 0.07, HTTPAttack: 0.10,
		BruteForce: 0.08, AnomalyL1: 0.07, AnomalyL2: 0.07,
		JA3Malicious: 0.05, OSAnomaly: 0.03,
		HoneypotHit: 0.30, ARPSpoof: 0.08,
	}
}

// AggressiveWeights returns higher weights for predator mode.
func AggressiveWeights() DetectorWeights {
	w := DefaultWeights()
	w.PacketFlood = 0.15
	w.HTTPAttack = 0.15
	w.HoneypotHit = 0.35
	w.BruteForce = 0.12
	return w
}

// ThreatLevel represents the severity classification of a threat.
type ThreatLevel int

const (
	ThreatNone     ThreatLevel = iota
	ThreatLow
	ThreatMedium
	ThreatHigh
	ThreatCritical
)

// ResponseLevel maps to the 4-tier response ladder.
type ResponseLevel int

const (
	ResponseA ResponseLevel = iota // Silent observation
	ResponseB                       // Active recon
	ResponseC                       // Predator mode
	ResponseD                       // Black hole counterstrike
)

// IPRecord tracks all scoring data for a single IP address.
type IPRecord struct {
	IP              string
	FirstSeen       time.Time
	LastSeen        time.Time
	TotalScore      float64
	ScanScore       float64
	FloodScore      float64
	AnomalyScore    float64
	HoneypotScore   float64
	IntelScore      float64
	ThreatCount     int
	HoneypotTripped bool
	Banned          bool
	ResponseLevel   ResponseLevel
}

// Scorer is the central threat scoring engine.
type Scorer struct {
	mu           sync.RWMutex
	records      map[string]*IPRecord
	weights      DetectorWeights
	banDuration  time.Duration
	maxRecords   int
	aggressive   bool
}

func NewScorer(weights DetectorWeights, banDurationSec int, maxRecords int) *Scorer {
	return &Scorer{
		records:     make(map[string]*IPRecord),
		weights:     weights,
		banDuration: time.Duration(banDurationSec) * time.Second,
		maxRecords:  maxRecords,
	}
}

// getOrCreate returns the IPRecord for an IP, creating one if needed.
func (s *Scorer) getOrCreate(ip string) *IPRecord {
	r, ok := s.records[ip]
	if !ok {
		if len(s.records) >= s.maxRecords {
			s.evictOldest()
		}
		r = &IPRecord{IP: ip, FirstSeen: time.Now()}
		s.records[ip] = r
	}
	r.LastSeen = time.Now()
	return r
}

func (s *Scorer) evictOldest() {
	var oldest string
	var oldestTime time.Time
	for ip, r := range s.records {
		if oldest == "" || r.LastSeen.Before(oldestTime) {
			oldest = ip
			oldestTime = r.LastSeen
		}
	}
	if oldest != "" {
		delete(s.records, oldest)
	}
}

// AddThreat incorporates an engine threat into the scoring system.
func (s *Scorer) AddThreat(threat engine.Threat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.getOrCreate(threat.IP)
	r.ThreatCount++

	switch threat.Type {
	case "SYN洪水", "UDP洪水", "ICMP洪水":
		r.FloodScore += s.weights.PacketFlood * 100
	case "SYN扫描", "FIN扫描", "Xmas扫描", "NULL扫描", "快速扫描", "中速扫描", "慢速扫描":
		r.ScanScore += s.weights.PacketScan * 100
	case "流量异常":
		r.AnomalyScore += s.weights.BehaviorEntropy * 100
	case "DNS隧道":
		r.AnomalyScore += s.weights.DNSTunnel * 100
	case "SQL注入攻击", "XSS攻击", "路径遍历攻击":
		r.AnomalyScore += s.weights.HTTPAttack * 100
	case "SSH爆破", "HTTP爆破":
		r.AnomalyScore += s.weights.BruteForce * 100
	case "混合异常":
		r.AnomalyScore += s.weights.AnomalyL1 * 100
	case "ARP应答":
		r.AnomalyScore += s.weights.ARPSpoof * 100
	}

	s.recalc(r)
}

func (s *Scorer) AddHoneypotTrip(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.getOrCreate(ip)
	r.HoneypotScore += s.weights.HoneypotHit * 100
	r.HoneypotTripped = true
	s.recalc(r)
}

func (s *Scorer) AddIntelMatch(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.getOrCreate(ip)
	r.IntelScore += 10
	s.recalc(r)
}

func (s *Scorer) recalc(r *IPRecord) {
	r.TotalScore = r.ScanScore + r.FloodScore + r.AnomalyScore + r.HoneypotScore + r.IntelScore
}

// GetScore returns the current score and response level for an IP.
func (s *Scorer) GetScore(ip string) (float64, ResponseLevel) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[ip]
	if !ok {
		return 0, ResponseA
	}
	return r.TotalScore, r.ResponseLevel
}

// ShouldCounterstrike checks if an IP's score exceeds the threshold.
func (s *Scorer) ShouldCounterstrike(ip string, threshold float64) bool {
	score, _ := s.GetScore(ip)
	return score >= threshold
}
```

- [ ] **Step 2: Implement response ladder**

`internal/brain/ladder.go`:
```go
package brain

type ladderTier struct {
	MaxScore float64
	Level    ResponseLevel
	Name     string
	Desc     string
}

var defaultLadder = []ladderTier{
	{25, ResponseA, "A·静默", "Silent observation — log only"},
	{50, ResponseB, "B·侦查", "Active recon — WHOIS, rate limit, abuse report draft"},
	{75, ResponseC, "C·掠食者", "Predator — tarpit, honeypot, ban, OSINT, attack scan"},
	{100, ResponseD, "D·黑洞", "Black hole — LLM deception, full weapon chain, swarm immunity"},
}

var aggressiveLadder = []ladderTier{
	{15, ResponseA, "A·静默", "Silent observation"},
	{30, ResponseB, "B·侦查", "Active recon"},
	{55, ResponseC, "C·掠食者", "Predator"},
	{100, ResponseD, "D·黑洞", "Black hole"},
}

// DetermineResponse returns the appropriate response level for a score.
func DetermineResponse(score float64, aggressive bool) (ResponseLevel, string, string) {
	ladder := defaultLadder
	if aggressive {
		ladder = aggressiveLadder
	}
	for _, tier := range ladder {
		if score <= tier.MaxScore {
			return tier.Level, tier.Name, tier.Desc
		}
	}
	return ResponseD, "D·黑洞", "Black hole"
}

// UpdateResponseLevel recomputes the response level for an IP record.
func UpdateResponseLevel(r *IPRecord, aggressive bool) {
	level, _, _ := DetermineResponse(r.TotalScore, aggressive)
	r.ResponseLevel = level
}
```

- [ ] **Step 3: Implement correlation and decay**

`internal/brain/correlation.go`:
```go
package brain

import (
	"strings"
	"sync"
	"time"
)

type alertEntry struct {
	Time time.Time
	IP   string
	Type string
}

type CorrelationEngine struct {
	mu     sync.Mutex
	alerts []alertEntry
}

const maxCorrelationAlerts = 100
const correlationWindow = 60 * time.Second
const minCorrelatedIPs = 3

func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{alerts: make([]alertEntry, 0, maxCorrelationAlerts)}
}

func (ce *CorrelationEngine) Feed(ip, alertType string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.alerts = append(ce.alerts, alertEntry{Time: time.Now(), IP: ip, Type: alertType})
	if len(ce.alerts) > maxCorrelationAlerts {
		ce.alerts = ce.alerts[len(ce.alerts)-maxCorrelationAlerts:]
	}
}

func (ce *CorrelationEngine) Check() ([]string, float64) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-correlationWindow)
	ipSet := make(map[string]struct{})
	typeSet := make(map[string]struct{})

	for i := len(ce.alerts) - 1; i >= 0; i-- {
		a := ce.alerts[i]
		if a.Time.Before(cutoff) {
			break
		}
		ipSet[a.IP] = struct{}{}
		typeSet[a.Type] = struct{}{}
	}

	if len(ipSet) >= minCorrelatedIPs && len(typeSet) <= 3 {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		multiplier := 1.0 + 0.1*float64(len(ipSet))
		if multiplier > 1.5 {
			multiplier = 1.5
		}
		return ips, multiplier
	}
	return nil, 0
}

func subnetOf(ip string) string {
	lastDot := strings.LastIndex(ip, ".")
	if lastDot == -1 {
		return ip
	}
	return ip[:lastDot] + ".0/24"
}
```

`internal/brain/decay.go`:
```go
package brain

import (
	"math"
	"time"
)

const defaultHalfLife = 30 * time.Minute

// DecayScore applies exponential decay to a score.
// score(t) = score_0 * 2^(-t / half_life)
func DecayScore(score float64, lastSeen time.Time, halfLife time.Duration) float64 {
	if halfLife <= 0 {
		halfLife = defaultHalfLife
	}
	elapsed := time.Since(lastSeen)
	if elapsed <= 0 {
		return score
	}
	lambda := math.Ln2 / float64(halfLife)
	return score * math.Exp(-lambda*float64(elapsed))
}

// CleanupStale removes IPs that haven't been seen and have decayed below the floor.
func (s *Scorer) CleanupStale(floor float64, maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for ip, r := range s.records {
		if time.Since(r.LastSeen) > maxAge {
			decayed := DecayScore(r.TotalScore, r.LastSeen, defaultHalfLife)
			if decayed < floor {
				delete(s.records, ip)
				removed++
			}
		}
	}
	return removed
}
```

- [ ] **Step 4: Write scorer test**

`internal/brain/scorer_test.go`:
```go
package brain

import (
	"testing"

	"github.com/fortress/v6/internal/engine"
)

func TestSYNFloodScoring(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 10000)

	// 100 SYN flood threats from one IP
	for i := 0; i < 100; i++ {
		s.AddThreat(engine.Threat{Type: "SYN洪水", IP: "203.0.113.99"})
	}

	score, level := s.GetScore("203.0.113.99")
	t.Logf("Score: %.1f, Level: %d", score, level)
	if score < 50 {
		t.Error("expected score >= 50 for 100 SYN flood threats")
	}
}

func TestResponseLadder(t *testing.T) {
	tests := []struct {
		score      float64
		aggressive bool
		expectName string
	}{
		{10, false, "A·静默"},
		{35, false, "B·侦查"},
		{60, false, "C·掠食者"},
		{85, false, "D·黑洞"},
		{10, true, "A·静默"},
		{20, true, "B·侦查"},
		{45, true, "C·掠食者"},
		{80, true, "D·黑洞"},
	}

	for _, tt := range tests {
		_, name, _ := DetermineResponse(tt.score, tt.aggressive)
		if name != tt.expectName {
			t.Errorf("score=%.0f aggressive=%v: expected %s, got %s",
				tt.score, tt.aggressive, tt.expectName, name)
		}
	}
}

func TestHoneypotTripTriggersB(t *testing.T) {
	s := NewScorer(DefaultWeights(), 1800, 10000)
	s.AddHoneypotTrip("10.0.0.99")
	score, _ := s.GetScore("10.0.0.99")
	t.Logf("Honeypot trip score: %.1f", score)
	if score < 20 {
		t.Error("honeypot trip should push score above 20 (B阶)")
	}
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/brain/ -v
# Expected: all PASS
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: brain — scorer (13 weights), 4-tier ladder, correlation, decay"
```

---

### Task 12: Main Entry Point — Wire Everything Together

**Files:**
- Modify: `cmd/fortress/main.go`

- [ ] **Step 1: Full main.go with defense mode pipeline**

`cmd/fortress/main.go`:
```go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/engine"
)

var (
	configPath = flag.String("config", "/etc/fortress/fortress.yaml", "path to config file")
	mode       = flag.String("mode", "defend", "operating mode: defend, scan, fusion, counterstrike, serve-mcp")
	target     = flag.String("target", "", "target IP/URL for scan/fusion modes")
	topN       = flag.Int("top", 10, "show top N threats")
)

func main() {
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	log.Printf("Fortress V6 — %s mode", *mode)
	log.Printf("Engine thresholds: SYN=%d pps UDP=%d pps ICMP=%d pps",
		cfg.Engine.SynFloodPPS, cfg.Engine.UdpFloodPPS, cfg.Engine.IcmpFloodPPS)

	switch *mode {
	case "defend":
		runDefense(cfg)
	case "scan":
		runScan(cfg, *target)
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}

func runDefense(cfg *config.Config) {
	log.Println("[defense] initializing detection pipeline...")

	// L1-L7 engines
	pi := engine.NewPacketInspector(cfg)
	fa := engine.NewFlowAnalyzer(cfg)
	ba := engine.NewBehaviorAnalyzer(cfg)
	dd := engine.NewDnsTunnelDetector(cfg)
	hi := engine.NewHttpInspector(cfg)
	bf := engine.NewBruteForceDetector(cfg)
	ha := engine.NewHybridAnomalyDetector(cfg)
	fe := engine.NewFingerprintEngine(cfg)

	// Brain
	weights := brain.DefaultWeights()
	if cfg.Brain.AggressiveMode {
		weights = brain.AggressiveWeights()
	}
	scorer := brain.NewScorer(weights, cfg.Brain.BanDuration, 50000)
	corr := brain.NewCorrelationEngine()

	log.Println("[defense] all engines initialized")
	log.Println("[defense] running simulation loop (1 pkt/sec) — awaiting Rust AF_XDP feed (Plan B)")

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Simulation ticker — feeds one synthetic packet per second
	simTicker := time.NewTicker(1 * time.Second)
	defer simTicker.Stop()

	// Periodic tasks
	evictTicker := time.NewTicker(60 * time.Second)
	defer evictTicker.Close()

	checkTicker := time.NewTicker(5 * time.Second)
	defer checkTicker.Close()

	packetCount := 0

	for {
		select {
		case <-sigCh:
			log.Println("[defense] shutting down...")
			return

		case <-simTicker.C:
			// Simulation: feed one benign packet per second
			// In production, this is replaced by Rust AF_XDP feed (Plan B)
			packetCount++
			srcIP := "192.168.1.100"
			dstPort := uint16(80 + packetCount%100)

			// L1
			for _, th := range pi.Feed("AS", srcIP, dstPort, "TCP") {
				scorer.AddThreat(th)
				corr.Feed(th.IP, th.Type)
			}
			// L2
			for _, th := range fa.Feed(srcIP, dstPort) {
				scorer.AddThreat(th)
				corr.Feed(th.IP, th.Type)
			}
			// L3
			ba.Feed(srcIP, dstPort)
			// L5
			bf.FeedSSH(srcIP)
			// L6
			ha.Feed(engine.PacketContext{
				SrcIP: srcIP, DstIP: "10.0.0.1",
				SrcPort: 12345, DstPort: dstPort,
				Protocol: "TCP", TCPFlags: "AS", PayloadSize: 64,
			})
			// L7
			fe.FeedSYN(srcIP, 64, 65535, true)

		case <-checkTicker.C:
			// L3 behavior check
			for _, th := range ba.Check() {
				corr.Feed("", th.Type)
			}
			// L5 brute force check
			for _, th := range bf.Check() {
				scorer.AddThreat(th)
			}
			// Correlation
			ips, mult := corr.Check()
			if len(ips) > 0 {
				log.Printf("[correlation] %d IPs coordinated, multiplier=%.1f", len(ips), mult)
			}

		case <-evictTicker.C:
			hi.EvictIdle()
			ha.EvictIdle(10 * time.Minute)
			scorer.CleanupStale(1.0, 30*time.Minute)
		}
	}
}

func runScan(cfg *config.Config, target string) {
	if target == "" {
		log.Fatal("scan mode requires --target")
	}
	log.Printf("[scan] scanning %s...", target)
	if err := config.ValidateTarget(target); err != nil {
		log.Fatalf("invalid target: %v", err)
	}
	log.Println("[scan] target validated — Kali nmap/nuclei integration in Plan C")
}
```

- [ ] **Step 2: Build and verify**

```bash
go build ./... && go vet ./...
# Expected: no errors
go run ./cmd/fortress/ --mode defend &
sleep 3
kill %1
# Expected: engine init, simulation loop running, graceful shutdown
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: main entry point — defense pipeline wiring, simulation loop, signal handling"
```

---

### Task 13: Integration Test — Full Pipeline

**Files:**
- Create: `internal/engine/pipeline_test.go`

- [ ] **Step 1: Write end-to-end pipeline test**

`internal/engine/pipeline_test.go`:
```go
package engine

import (
	"testing"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
)

func TestFullPipeline(t *testing.T) {
	cfg := config.Default()
	cfg.Engine.SynFloodPPS = 10

	pi := NewPacketInspector(cfg)
	fa := NewFlowAnalyzer(cfg)
	ba := NewBehaviorAnalyzer(cfg)
	dd := NewDnsTunnelDetector(cfg)
	hi := NewHttpInspector(cfg)
	bf := NewBruteForceDetector(cfg)
	ha := NewHybridAnomalyDetector(cfg)
	fe := NewFingerprintEngine(cfg)

	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)

	attackIP := "203.0.113.99"

	// Simulate an attack: SYN flood + port scan + SQLi
	for i := 0; i < 50; i++ {
		// L1
		for _, th := range pi.Feed("S", attackIP, uint16(100+i), "TCP") {
			scorer.AddThreat(th)
		}
		// L2
		for _, th := range fa.Feed(attackIP, uint16(100+i)) {
			scorer.AddThreat(th)
		}
		// L3
		ba.Feed(attackIP, uint16(100+i))
	}
	// L5 SQLi
	for _, th := range hi.Feed(attackIP, "192.168.1.1", 12345, 80,
		[]byte("GET /?q=1' OR '1'='1 HTTP/1.1\r\n\r\n")) {
		scorer.AddThreat(th)
	}
	// L7
	for _, th := range fe.FeedSYN(attackIP, 32, 1234, false) {
		scorer.AddThreat(th)
	}

	score, level := scorer.GetScore(attackIP)
	t.Logf("Attack IP %s: score=%.1f level=%d", attackIP, score, level)

	if score < 20 {
		t.Errorf("expected score > 20 for multi-vector attack, got %.1f", score)
	}

	_, name, _ := brain.DetermineResponse(score, false)
	t.Logf("Response level: %s", name)
}
```

- [ ] **Step 2: Run integration test**

```bash
go test ./internal/engine/ -run TestFullPipeline -v
# Expected: multi-vector attack detected, score > 20, B阶 or higher
```

- [ ] **Step 3: Full test suite**

```bash
go test ./... -count=1
# Expected: all tests pass
go build ./... && go vet ./...
# Expected: no errors
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "test: full pipeline integration test — 50 SYN + port scan + SQLi + OS anomaly"
```

---

## Appendix: After Plan A

When Plan A is complete, the Go brain can:
- Accept PacketContext from a channel (currently simulation)
- Run all 7 detection layers
- Score threats and determine response tier
- Handle config, whitelist, and graceful shutdown

**Next: Plan B — Rust Muscle + C Dagger** adds AF_XDP zero-copy packet capture and feeds the Go channel for real.

**Next: Plan C — Defense + Swarm + Deception** adds counterstrike capabilities, Kali weapon fusion, swarm networking, and LLM deception.

**Next: Plan D — Integration + Testing + Container** links Go↔Rust, runs 20 E2E scenarios, and builds the OCI image.
