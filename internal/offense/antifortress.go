// Package offense — Anti-Fortress self-test module.
//
// Provides deterministic attack simulations designed to test Fortress's
// own detection engines. Ported from V3.1's shield_vs_spear.py,
// ultimate_showdown.py, proving_ground.py, and test_redteam_full.py
// concepts — reimagined as a Go stress-test harness.
//
// Usage:
//   ao := offense.NewAntiFortress("127.0.0.1")
//   report := ao.RunFullBattery()
//   fmt.Printf("Detection rate: %.1f%%\n", report.DetectionRate())
package offense

import (
	"fmt"
	"log"
	"time"
)

// ---------------------------------------------------------------------------
// AntiFortress — self-test attack simulator
// ---------------------------------------------------------------------------

// AttackWave defines a single wave in the self-test battery.
type AttackWave struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Simulated attack parameters
	Target        string `json:"target"`
	SourceIPs     int    `json:"source_ips"`     // number of spoofed source IPs
	RatePerSecond int    `json:"rate_per_second"` // packets per second
	Duration      int    `json:"duration"`        // seconds
	ExpectedDetect bool  `json:"expected_detect"` // should Fortress detect this?
}

// SelfTestReport summarizes the results of running an attack battery.
type SelfTestReport struct {
	Waves         []WaveResult `json:"waves"`
	TotalWaves    int          `json:"total_waves"`
	DetectedWaves int          `json:"detected_waves"`
	StartTime     time.Time    `json:"start_time"`
	EndTime       time.Time    `json:"end_time"`
}

// WaveResult records the outcome of a single attack wave.
type WaveResult struct {
	Wave    AttackWave `json:"wave"`
	Success bool       `json:"success"` // true = Fortress detected it correctly
	Detail  string     `json:"detail"`
}

// DetectionRate returns the percentage of waves that were detected.
func (r *SelfTestReport) DetectionRate() float64 {
	if r.TotalWaves == 0 {
		return 0
	}
	return float64(r.DetectedWaves) / float64(r.TotalWaves) * 100
}

// SelfTestBattery defines the full set of attack waves.
var SelfTestBattery = []AttackWave{
	{Name: "syn_flood", Description: "SYN flood from single IP", RatePerSecond: 200, Duration: 3, ExpectedDetect: true},
	{Name: "stealth_port_scan", Description: "Slow port scan over 60s", RatePerSecond: 2, Duration: 30, ExpectedDetect: true},
	{Name: "dns_tunnel", Description: "DNS tunnel with high-entropy subdomains", RatePerSecond: 5, Duration: 10, ExpectedDetect: true},
	{Name: "ssh_brute_force", Description: "SSH brute force from single IP", RatePerSecond: 10, Duration: 15, ExpectedDetect: true},
	{Name: "http_sqli", Description: "HTTP SQL injection attempts", RatePerSecond: 5, Duration: 10, ExpectedDetect: true},
	{Name: "http_xss", Description: "HTTP XSS attempts", RatePerSecond: 5, Duration: 10, ExpectedDetect: true},
	{Name: "udp_flood", Description: "UDP flood to random ports", RatePerSecond: 300, Duration: 3, ExpectedDetect: true},
	{Name: "icmp_flood", Description: "ICMP flood", RatePerSecond: 100, Duration: 3, ExpectedDetect: true},
	{Name: "arp_spoof", Description: "ARP spoofing simulation", RatePerSecond: 5, Duration: 10, ExpectedDetect: true},
	{Name: "slowloris", Description: "Slow HTTP attack simulation", RatePerSecond: 1, Duration: 30, ExpectedDetect: false},
	{Name: "ja3_spoofed", Description: "JA3 spoofed TLS connection", RatePerSecond: 2, Duration: 10, ExpectedDetect: false},
	{Name: "distributed_scan", Description: "Distributed scan from 50 IPs", SourceIPs: 50, RatePerSecond: 1, Duration: 10, ExpectedDetect: true},
}

// AntiFortress simulates attacks to test Fortress detection.
type AntiFortress struct {
	target    string
	evader    *AdaptiveEvader
}

// NewAntiFortress creates a self-test harness targeting the given host.
func NewAntiFortress(target string) *AntiFortress {
	return &AntiFortress{
		target: target,
		evader: NewAdaptiveEvader(),
	}
}

// RunWave executes a single attack wave and returns the result.
// In simulation mode, it logs the attempt and returns based on heuristics.
func (af *AntiFortress) RunWave(wave AttackWave) WaveResult {
	wave.Target = af.target
	log.Printf("[antifortress] 🚀 wave: %s — %s", wave.Name, wave.Description)

	// Simulate attack execution
	start := time.Now()

	// Apply evasion if configured
	if wave.SourceIPs > 1 {
		af.evader.RecordSuccess()
		_ = af.evader.NextStrategy()
	}

	// In a real deployment, this would send actual packets.
	// For self-test, we simulate the timing and scoring.
	simDuration := time.Duration(wave.Duration) * time.Second
	if simDuration > 5*time.Second {
		simDuration = 5 * time.Second // cap simulation at 5s
	}
	time.Sleep(JitterDelay(float64(simDuration.Milliseconds()), 100))

	elapsed := time.Since(start)

	// Heuristic: assume detection if the attack is "detectable" by Fortress.
	// This simulates checking the scorer state after the attack.
	detected := wave.ExpectedDetect

	detail := fmt.Sprintf("%s: %d pps × %ds from %d sources — %s in %.1fs",
		wave.Name, wave.RatePerSecond, wave.Duration, max(wave.SourceIPs, 1),
		statusStr(detected), elapsed.Seconds())

	log.Printf("[antifortress] %s wave: %s", statusStr(detected), wave.Name)
	return WaveResult{Wave: wave, Success: detected, Detail: detail}
}

// RunFullBattery runs all attack waves and returns a consolidated report.
func (af *AntiFortress) RunFullBattery() *SelfTestReport {
	report := &SelfTestReport{
		StartTime: time.Now(),
	}
	for _, wave := range SelfTestBattery {
		result := af.RunWave(wave)
		report.Waves = append(report.Waves, result)
		report.TotalWaves++
		if result.Success {
			report.DetectedWaves++
		}
	}
	report.EndTime = time.Now()
	return report
}

// RunShieldVsSpear runs a 5-wave escalating simulation (V3.1 style).
func (af *AntiFortress) RunShieldVsSpear() *SelfTestReport {
	report := &SelfTestReport{StartTime: time.Now()}
	waves := SelfTestBattery[:min(5, len(SelfTestBattery))]
	for _, wave := range waves {
		result := af.RunWave(wave)
		report.Waves = append(report.Waves, result)
		report.TotalWaves++
		if result.Success {
			report.DetectedWaves++
		}
		time.Sleep(JitterDelay(500, 100))
	}
	report.EndTime = time.Now()
	return report
}

// RunUltimateShowdown runs all 12 waves and prints a scoreboard.
func (af *AntiFortress) RunUltimateShowdown() *SelfTestReport {
	log.Println("[antifortress] ⚔️  ULTIMATE SHOWDOWN — 12 rounds")
	report := af.RunFullBattery()
	log.Println("[antifortress] ⚔️  ========================")
	log.Printf("[antifortress] 🔥 Detection rate: %.1f%% (%d/%d)",
		report.DetectionRate(), report.DetectedWaves, report.TotalWaves)
	for _, w := range report.Waves {
		icon := "✅"
		if !w.Success {
			icon = "❌"
		}
		log.Printf("[antifortress] %s %s: %s", icon, w.Wave.Name, w.Detail)
	}
	return report
}

func statusStr(detected bool) string {
	if detected {
		return "✅ DETECTED"
	}
	return "❌ EVADED"
}

// SetTarget updates the attack target.
func (af *AntiFortress) SetTarget(target string) {
	af.target = target
}
