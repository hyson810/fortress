package deception

import (
	"testing"
	"time"
)

func TestNewCounterIntelEngine(t *testing.T) {
	ce := NewCounterIntelEngine()
	if ce == nil {
		t.Fatal("NewCounterIntelEngine() returned nil")
	}
	// Verify internal state is initialized
	if len(ce.GetAllProfiles()) != 0 {
		t.Errorf("expected 0 profiles, got %d", len(ce.GetAllProfiles()))
	}
}

func TestTrackAttackerBehavior_Basic(t *testing.T) {
	ce := NewCounterIntelEngine()
	now := time.Now()

	event := AttackerEvent{
		IP:        "10.0.0.1",
		Tool:      "nmap",
		Port:      22,
		UserAgent: "Mozilla/5.0",
		Timestamp: now,
		Technique: "T1046",
	}

	profile := ce.TrackAttackerBehavior("10.0.0.1", event)

	if profile.IP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", profile.IP)
	}
	if !profile.FirstSeen.Equal(now) {
		t.Errorf("expected FirstSeen %v, got %v", now, profile.FirstSeen)
	}
	if !profile.LastSeen.Equal(now) {
		t.Errorf("expected LastSeen %v, got %v", now, profile.LastSeen)
	}
	if len(profile.Tools) != 1 || profile.Tools[0] != "nmap" {
		t.Errorf("expected Tools [nmap], got %v", profile.Tools)
	}
	if len(profile.PortsScanned) != 1 || profile.PortsScanned[0] != 22 {
		t.Errorf("expected PortsScanned [22], got %v", profile.PortsScanned)
	}
	if len(profile.UserAgents) != 1 || profile.UserAgents[0] != "Mozilla/5.0" {
		t.Errorf("expected UserAgents [Mozilla/5.0], got %v", profile.UserAgents)
	}
	if len(profile.Techniques) != 1 || profile.Techniques[0] != "T1046" {
		t.Errorf("expected Techniques [T1046], got %v", profile.Techniques)
	}
}

func TestTrackAttackerBehavior_MultipleEvents(t *testing.T) {
	ce := NewCounterIntelEngine()
	base := time.Now()
	ip := "10.0.0.2"

	events := []struct {
		tool      string
		port      int
		technique string
		offsetSec int
	}{
		{"nmap", 22, "T1046", 0},
		{"nmap", 80, "T1046", 1},
		{"nmap", 443, "T1046", 2},
		{"nmap", 3306, "T1046", 3},
		{"nmap", 8080, "T1046", 4},
	}

	for _, e := range events {
		ce.TrackAttackerBehavior(ip, AttackerEvent{
			IP:        ip,
			Tool:      e.tool,
			Port:      e.port,
			Timestamp: base.Add(time.Duration(e.offsetSec) * time.Second),
			Technique: e.technique,
		})
	}

	profile, ok := ce.GetProfile(ip)
	if !ok {
		t.Fatal("expected to find profile")
	}

	// 5 unique ports scanned
	if len(profile.PortsScanned) != 5 {
		t.Errorf("expected 5 ports scanned, got %d: %v", len(profile.PortsScanned), profile.PortsScanned)
	}

	// Single tool repeated — should still be 1 unique tool
	if len(profile.Tools) != 1 {
		t.Errorf("expected 1 unique tool, got %d: %v", len(profile.Tools), profile.Tools)
	}

	// RequestRate should be > 0
	if profile.RequestRate <= 0 {
		t.Errorf("expected positive RequestRate, got %f", profile.RequestRate)
	}

	// All 5 events in the same hour — Persistence should be false
	if profile.Persistence {
		t.Errorf("expected Persistence false for single-hour activity, got true")
	}

	// SkillLevel should be "novice" (only 1 tool, not enough ports for intermediate)
	if profile.SkillLevel != "novice" {
		t.Errorf("expected SkillLevel novice, got %s", profile.SkillLevel)
	}

	// FirstSeen should match earliest event
	expectedFirst := base
	if !profile.FirstSeen.Equal(expectedFirst) {
		t.Errorf("expected FirstSeen %v, got %v", expectedFirst, profile.FirstSeen)
	}

	// LastSeen should match latest event
	expectedLast := base.Add(4 * time.Second)
	if !profile.LastSeen.Equal(expectedLast) {
		t.Errorf("expected LastSeen %v, got %v", expectedLast, profile.LastSeen)
	}
}

func TestClassifyAttacker_ScriptKiddie(t *testing.T) {
	ce := NewCounterIntelEngine()
	ip := "10.0.0.3"
	now := time.Now()

	// A "script kiddie" — few ports, few tools, no advanced techniques
	ce.TrackAttackerBehavior(ip, AttackerEvent{
		IP: ip, Tool: "nmap", Port: 22, Timestamp: now, Technique: "T1046",
	})

	skill, nationState, aptGroup := ce.ClassifyAttacker(ip)
	if skill != "novice" {
		t.Errorf("expected novice, got %s", skill)
	}
	if nationState {
		t.Errorf("expected nationState false for script kiddie, got true")
	}
	if aptGroup != "unknown" {
		t.Errorf("expected aptGroup unknown, got %s", aptGroup)
	}
}

func TestClassifyAttacker_Advanced(t *testing.T) {
	ce := NewCounterIntelEngine()
	ip := "10.0.0.4"
	now := time.Now()

	// Build an advanced attacker: 4+ techniques, 6+ tools
	tools := []string{"nmap", "metasploit", "cobalt", "mimikatz", "sqlmap", "burpsuite"}
	techniques := []string{"T1046", "T1210", "T1003", "T1573"}

	for i, tool := range tools {
		ce.TrackAttackerBehavior(ip, AttackerEvent{
			IP:        ip,
			Tool:      tool,
			Port:      22 + i,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Technique: techniques[i%len(techniques)],
		})
	}

	skill, nationState, aptGroup := ce.ClassifyAttacker(ip)
	if skill != "advanced" {
		t.Errorf("expected advanced, got %s", skill)
	}
	// Nation-state requires persistence (activeHours > 6) or long dwell time
	// All events are in same hour so Persistence is false
	if nationState {
		t.Errorf("expected nationState false (low persistence), got true")
	}
	_ = aptGroup // APT group classification is secondary here
}

func TestGetProfile_NotFound(t *testing.T) {
	ce := NewCounterIntelEngine()

	_, ok := ce.GetProfile("192.168.1.99")
	if ok {
		t.Error("expected false for unknown IP, got true")
	}
}

func TestDeployTargetedDeception(t *testing.T) {
	ce := NewCounterIntelEngine()
	now := time.Now()

	// Track an attacker first so we have a profile
	ce.TrackAttackerBehavior("10.0.0.5", AttackerEvent{
		IP: "10.0.0.5", Tool: "nmap", Port: 22, Timestamp: now,
	})

	profile, _ := ce.GetProfile("10.0.0.5")
	deceptions := ce.DeployTargetedDeception(profile)

	if len(deceptions) == 0 {
		t.Fatal("DeployTargetedDeception returned empty slice")
	}

	for _, d := range deceptions {
		if d.ID == "" {
			t.Error("deception has empty ID")
		}
		if d.TargetIP != "10.0.0.5" {
			t.Errorf("expected TargetIP 10.0.0.5, got %s", d.TargetIP)
		}
		if d.Content == "" {
			t.Error("deception has empty content")
		}
		if d.DeployedAt.IsZero() {
			t.Error("deception has zero DeployedAt")
		}
	}
}

func TestDeployTargetedDeception_BySkillLevel(t *testing.T) {
	ce := NewCounterIntelEngine()
	now := time.Now()
	ip := "10.0.0.6"

	// Use many tools & ports to trigger "intermediate"
	ports := make([]int, 10)
	for i := 0; i < 10; i++ {
		ports[i] = 1000 + i
	}
	for i, p := range ports {
		ce.TrackAttackerBehavior(ip, AttackerEvent{
			IP: ip, Tool: "nmap", Port: p, Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}
	// Add two more tools to get toolCount >= 3
	ce.TrackAttackerBehavior(ip, AttackerEvent{IP: ip, Tool: "curl", Port: 80, Timestamp: now})
	ce.TrackAttackerBehavior(ip, AttackerEvent{IP: ip, Tool: "wget", Port: 443, Timestamp: now})

	profile, _ := ce.GetProfile(ip)
	if profile.SkillLevel != "intermediate" {
		t.Fatalf("expected intermediate, got %s — adjust test setup", profile.SkillLevel)
	}

	deceptions := ce.DeployTargetedDeception(profile)
	if len(deceptions) != 2 {
		t.Errorf("expected 2 deceptions for intermediate, got %d", len(deceptions))
	}
}

func TestFeedFalseIntel(t *testing.T) {
	ce := NewCounterIntelEngine()
	now := time.Now()
	ip := "10.0.0.7"

	// Must track attacker first so profile exists
	ce.TrackAttackerBehavior(ip, AttackerEvent{
		IP: ip, Tool: "nmap", Port: 22, Timestamp: now,
	})

	deceptions := ce.FeedFalseIntel(ip)
	if len(deceptions) == 0 {
		t.Fatal("FeedFalseIntel returned empty slice")
	}

	for _, d := range deceptions {
		if d.ID == "" {
			t.Error("false intel deception has empty ID")
		}
		if d.TargetIP != ip {
			t.Errorf("expected TargetIP %s, got %s", ip, d.TargetIP)
		}
		if d.Content == "" {
			t.Error("false intel deception has empty content")
		}
		if d.DeployedAt.IsZero() {
			t.Error("false intel deception has zero DeployedAt")
		}
	}

	// Also verify the deceptions are tracked internally
	ids := ce.GetDeceptions(ip)
	if len(ids) != len(deceptions) {
		t.Errorf("expected %d stored deception IDs, got %d", len(deceptions), len(ids))
	}
}

func TestFeedFalseIntel_NoProfile(t *testing.T) {
	ce := NewCounterIntelEngine()

	deceptions := ce.FeedFalseIntel("10.0.0.99")
	if deceptions != nil {
		t.Errorf("expected nil for untracked IP, got %v", deceptions)
	}
}

func TestPlantAttributionClues(t *testing.T) {
	ce := NewCounterIntelEngine()
	ip := "10.0.0.8"
	falseTarget := "APT-nation-state-alpha"

	clues := ce.PlantAttributionClues(ip, falseTarget)

	if len(clues) == 0 {
		t.Fatal("PlantAttributionClues returned empty slice")
	}

	for _, c := range clues {
		if c.Content == "" {
			t.Error("clue has empty content")
		}
		if c.ClueType == "" {
			t.Error("clue has empty ClueType")
		}
		if c.TargetIP != ip {
			t.Errorf("expected TargetIP %s, got %s", ip, c.TargetIP)
		}
		if c.PointsTo != falseTarget {
			t.Errorf("expected PointsTo %s, got %s", falseTarget, c.PointsTo)
		}
		if c.PlantedAt.IsZero() {
			t.Error("clue has zero PlantedAt")
		}
	}
}

func TestGetAllProfiles(t *testing.T) {
	ce := NewCounterIntelEngine()
	now := time.Now()
	ips := []string{"10.0.0.10", "10.0.0.11", "10.0.0.12"}

	for _, ip := range ips {
		ce.TrackAttackerBehavior(ip, AttackerEvent{
			IP: ip, Tool: "nmap", Port: 22, Timestamp: now,
		})
	}

	profiles := ce.GetAllProfiles()
	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d", len(profiles))
	}

	// Verify each IP is represented
	seen := make(map[string]bool)
	for _, p := range profiles {
		seen[p.IP] = true
	}
	for _, ip := range ips {
		if !seen[ip] {
			t.Errorf("profile missing for IP %s", ip)
		}
	}
}

func TestGetAllProfiles_Empty(t *testing.T) {
	ce := NewCounterIntelEngine()

	profiles := ce.GetAllProfiles()
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles for new engine, got %d", len(profiles))
	}
}

func TestTrackAttackerBehavior_Deduplicates(t *testing.T) {
	ce := NewCounterIntelEngine()
	ip := "10.0.0.20"
	now := time.Now()

	// Track the same tool and port twice
	ce.TrackAttackerBehavior(ip, AttackerEvent{
		IP: ip, Tool: "nmap", Port: 22, Timestamp: now,
	})
	ce.TrackAttackerBehavior(ip, AttackerEvent{
		IP: ip, Tool: "nmap", Port: 22, Timestamp: now.Add(time.Second),
	})

	profile, ok := ce.GetProfile(ip)
	if !ok {
		t.Fatal("expected to find profile")
	}

	if len(profile.Tools) != 1 {
		t.Errorf("expected 1 unique tool after dedup, got %d: %v", len(profile.Tools), profile.Tools)
	}
	if len(profile.PortsScanned) != 1 {
		t.Errorf("expected 1 unique port after dedup, got %d: %v", len(profile.PortsScanned), profile.PortsScanned)
	}
}

func TestGetProfile_ReturnsCopy(t *testing.T) {
	ce := NewCounterIntelEngine()
	ip := "10.0.0.30"
	now := time.Now()

	ce.TrackAttackerBehavior(ip, AttackerEvent{
		IP: ip, Tool: "nmap", Port: 22, Timestamp: now,
	})

	profile1, ok := ce.GetProfile(ip)
	if !ok {
		t.Fatal("expected to find profile")
	}

	// Mutate the returned profile — should not affect internal state
	profile1.Tools = append(profile1.Tools, "mutated")

	profile2, _ := ce.GetProfile(ip)
	if len(profile2.Tools) != 1 {
		t.Errorf("GetProfile did not return a copy: expected 1 tool, got %d", len(profile2.Tools))
	}
}
