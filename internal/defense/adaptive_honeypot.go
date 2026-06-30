// Package defense — Adaptive Honeypot™
//
// Hot technique #5: Dynamically adjusts honeypot responses based on attacker
// fingerprint and behavior. Traditional honeypots send static banners —
// adaptive ones change personality to keep attackers engaged longer.
//
// Features:
// - Attacker profiling (tool, skill level, intent)
// - Dynamic banner rotation based on attacker's expected target
// - Speed-bump challenges (slow auth handshake to waste attacker time)
// - Fake data planted per attacker (unique fake credentials, configs, DBs)
package defense

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// AttackerProfile classifies an attacker based on their interaction pattern.
type AttackerProfile struct {
	IP           string    `json:"ip"`
	Tool         string    `json:"tool"`          // "nmap", "masscan", "hydra", "metasploit", "manual"
	SkillLevel   string    `json:"skill_level"`   // "script_kiddie", "intermediate", "advanced", "apt"
	Targets      []string  `json:"targets"`       // services they probed
	Engagement   float64   `json:"engagement"`    // 0-1, how long they stayed
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	BannersShown []string  `json:"banners_shown"`
}

// AdaptiveHoneypotManager wraps HoneypotManager with adaptive response logic.
type AdaptiveHoneypotManager struct {
	base      *HoneypotManager
	mu        sync.Mutex
	profiles  map[string]*AttackerProfile
	bannerMap map[string][]string // service → banner pool

	// Speed bump counter: how many ms to wait before responding
	speedBumps map[string]time.Duration
}

// NewAdaptiveHoneypotManager creates an adaptive honeypot layer.
func NewAdaptiveHoneypotManager(base *HoneypotManager) *AdaptiveHoneypotManager {
	return &AdaptiveHoneypotManager{
		base:       base,
		profiles:   make(map[string]*AttackerProfile),
		bannerMap:  defaultBannerPool(),
		speedBumps: make(map[string]time.Duration),
	}
}

// defaultBannerPool provides rotating banners per service.
func defaultBannerPool() map[string][]string {
	return map[string][]string{
		"ssh": {
			"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
			"SSH-2.0-OpenSSH_9.3p1 Debian-1",
			"SSH-2.0-OpenSSH_7.4p1 CentOS-7",
			"SSH-2.0-OpenSSH_9.6p1 Ubuntu-4",
			"SSH-2.0-dropbear_2022.83",
		},
		"http": {
			"nginx/1.24.0",
			"nginx/1.25.3",
			"Apache/2.4.57 (Ubuntu)",
			"Apache/2.4.41 (Ubuntu)",
			"Microsoft-IIS/10.0",
			"cloudflare",
		},
		"mysql": {
			"8.0.35-0ubuntu0.22.04.1",
			"5.7.44-log",
			"10.11.6-MariaDB-0+deb12u1",
			"8.0.36",
		},
	}
}

// RecordHit classifies attacker and selects optimal banner.
// Returns a handler function that implements the adaptive response.
func (am *AdaptiveHoneypotManager) RecordHit(hit HitRecord) *AttackerProfile {
	am.mu.Lock()
	defer am.mu.Unlock()

	if hit.Type == "" {
		hit.Type = "ssh"
	}

	now := time.Now()
	profile, exists := am.profiles[hit.IP]
	if !exists {
		profile = &AttackerProfile{
			IP:        hit.IP,
			FirstSeen: now,
			Tool:      classifyTool(hit),
		}
		am.profiles[hit.IP] = profile
	}

	profile.LastSeen = now
	profile.Targets = append(profile.Targets, string(hit.Type))

	// Classify skill level based on behavior
	attempts := len(profile.Targets)
	switch {
	case attempts <= 2:
		profile.SkillLevel = "unknown"
	case attempts <= 5:
		profile.SkillLevel = "script_kiddie"
	case attempts <= 10:
		profile.SkillLevel = "intermediate"
	default:
		profile.SkillLevel = "advanced"
	}

	// Select banner based on profile
	bannerPool := am.bannerMap[string(hit.Type)]
		if len(bannerPool) == 0 {
			log.Printf("[adaptive-honeypot] %s → %s (no banners available)", hit.IP, hit.Type)
			return profile
		}
	selectedBanner := bannerPool[rand.Intn(len(bannerPool))]

	// Adjust speed bump — slow down aggressive scanners
	if profile.Tool == "masscan" || profile.Tool == "hydra" {
		am.speedBumps[hit.IP] = time.Duration(500+rand.Intn(2000)) * time.Millisecond
	} else if profile.SkillLevel == "script_kiddie" {
		am.speedBumps[hit.IP] = time.Duration(100+rand.Intn(500)) * time.Millisecond
	} else {
		am.speedBumps[hit.IP] = time.Duration(10+rand.Intn(100)) * time.Millisecond
	}

	profile.BannersShown = append(profile.BannersShown, selectedBanner)
	log.Printf("[adaptive-honeypot] %s → %s (tool=%s skill=%s banner=%s speedbump=%v)",
		hit.IP, hit.Type, profile.Tool, profile.SkillLevel, selectedBanner, am.speedBumps[hit.IP])

	return profile
}

// classifyTool attempts to identify the tool from the interaction.
func classifyTool(hit HitRecord) string {
	data := strings.ToLower(hit.Data)

	// Masscan — single packet, no follow-up
	if len(data) < 20 {
		return "masscan"
	}
	// Nmap — specific probe patterns
	if strings.Contains(data, "nmap") || strings.Contains(data, "Nmap") {
		return "nmap"
	}
	// Hydra — repeated auth attempts
	if strings.Contains(data, "user") && strings.Contains(data, "pass") {
		return "hydra"
	}
	// Metasploit — specific module fingerprints
	if strings.Contains(data, "metasploit") || strings.Contains(data, "zmq") {
		return "metasploit"
	}
	// Manual browser
	if strings.Contains(data, "mozilla") || strings.Contains(data, "chrome") || strings.Contains(data, "safari") {
		return "manual"
	}
	return "unknown"
}

// GetBanner returns an appropriate banner for the attacker and service.
func (am *AdaptiveHoneypotManager) GetBanner(ip string, serviceType string) string {
	am.mu.Lock()
	defer am.mu.Unlock()

	pool, ok := am.bannerMap[serviceType]
	if !ok {
		return fmt.Sprintf("Unknown service on port")
	}

	profile, exists := am.profiles[ip]
	if exists && len(profile.BannersShown) > 0 {
		// Return last shown banner for consistency
		return profile.BannersShown[len(profile.BannersShown)-1]
	}

	return pool[rand.Intn(len(pool))]
}

// GetSpeedBump returns how long to delay before responding to this IP.
func (am *AdaptiveHoneypotManager) GetSpeedBump(ip string) time.Duration {
	am.mu.Lock()
	defer am.mu.Unlock()
	if bump, ok := am.speedBumps[ip]; ok {
		return bump
	}
	return 0
}

// GenerateFakeData creates convincing fake data for an attacker to find.
func (am *AdaptiveHoneypotManager) GenerateFakeData(ip string) map[string]string {
	am.mu.Lock()
	defer am.mu.Unlock()

	profile, exists := am.profiles[ip]
	if !exists {
		return nil
	}

	fakeData := make(map[string]string)
	uniqueID := fmt.Sprintf("%x", rand.Int63())

	// Fake credentials based on what they probed
	for _, target := range profile.Targets {
		switch target {
		case "ssh":
			fakeData["ssh_credentials"] = fmt.Sprintf("root:FortressAdmin!%s", uniqueID[:8])
		case "mysql":
			fakeData["mysql_credentials"] = fmt.Sprintf("root:DB_Secret_%s", uniqueID[:12])
		case "http":
			fakeData["admin_panel"] = fmt.Sprintf("/admin/login.php (admin:Admin%s)", uniqueID[:6])
			fakeData["config_file"] = fmt.Sprintf("/var/www/html/config.php (DB_PASS=%s)", uniqueID[:16])
		}
	}

	return fakeData
}

// Profile returns the attacker profile for an IP.
func (am *AdaptiveHoneypotManager) Profile(ip string) *AttackerProfile {
	am.mu.Lock()
	defer am.mu.Unlock()
	return am.profiles[ip]
}
