// Package offense implements offensive security tools. This file provides
// high-level attack orchestration with a DAG-based killchain that sequences
// reconnaissance, weaponisation, exploitation, pivoting, and exfiltration.
package offense

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

// AttackResult captures the outcome of a single killchain phase against a
// specific target.
type AttackResult struct {
	Phase     string
	Target    string
	Success   bool
	Detail    string
	Timestamp time.Time
}

// ---------------------------------------------------------------------------
// AttackOrchestrator
// ---------------------------------------------------------------------------

// AttackOrchestrator drives a multi-phase attack killchain against one or
// more targets. Phases are "recon", "weaponize", "exploit", "pivot", and
// "exfil".
type AttackOrchestrator struct {
	targets    []string
	maxWorkers int
	ipPool     []string

	mu      sync.Mutex
	results map[string][]AttackResult // keyed by target
}

// NewAttackOrchestrator creates an orchestrator for the given target list.
func NewAttackOrchestrator(targets []string, maxWorkers int) *AttackOrchestrator {
	targetsCopy := make([]string, len(targets))
	copy(targetsCopy, targets)

	if maxWorkers < 1 {
		maxWorkers = 1
	}
	if maxWorkers > 100 {
		maxWorkers = 100
	}

	return &AttackOrchestrator{
		targets:    targetsCopy,
		maxWorkers: maxWorkers,
		results:    make(map[string][]AttackResult),
	}
}

// SetIPPool replaces the source IP pool used for source-IP rotation.
func (ao *AttackOrchestrator) SetIPPool(ips []string) {
	ipCopy := make([]string, len(ips))
	copy(ipCopy, ips)
	ao.mu.Lock()
	ao.ipPool = ipCopy
	ao.mu.Unlock()
}

// GenerateIPPool creates a pool of `count` synthetic IP addresses within the
// given CIDR subnet. Useful for testing source-IP rotation logic.
// If `count` exceeds the number of usable addresses in the subnet it is
// clamped accordingly.
func (ao *AttackOrchestrator) GenerateIPPool(subnet string, count int) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		log.Printf("orchestrator: invalid subnet %q: %v", subnet, err)
		return
	}

	// Build a list of all usable addresses in the subnet.
	var allIPs []string
	ip := ipNet.IP.To4()
	if ip == nil {
		// IPv6 not currently supported for synthetic pool generation.
		log.Printf("orchestrator: only IPv4 subnets are supported for IP pool generation")
		return
	}

	maskOnes, maskBits := ipNet.Mask.Size()
	total := 1 << (maskBits - maskOnes) // total addresses in subnet

	// Cap count to available addresses (reserve network and broadcast).
	usable := total - 2
	if usable < 1 {
		usable = 1
	}
	if count > usable {
		count = usable
	}

	// Generate sequential IPs starting from ipNet.IP + 1.
	start := ipToUint32(ip) + 1
	for i := 0; i < count; i++ {
		allIPs = append(allIPs, uint32ToIP(start+uint32(i)).String())
	}

	ao.SetIPPool(allIPs)
}

// ipToUint32 converts a net.IP (IPv4) to its uint32 representation.
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP converts a uint32 to an IPv4 net.IP.
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(
		byte(n>>24),
		byte(n>>16),
		byte(n>>8),
		byte(n),
	)
}

// ---------------------------------------------------------------------------
// Killchain execution
// ---------------------------------------------------------------------------

// validPhases is the set of recognised killchain phase names.
var validPhases = map[string]bool{
	"recon":     true,
	"weaponize": true,
	"exploit":   true,
	"pivot":     true,
	"exfil":     true,
}

// RunPhase executes a single killchain phase against all targets.
func (ao *AttackOrchestrator) RunPhase(phase string) error {
	if !validPhases[phase] {
		return fmt.Errorf("orchestrator: unknown phase %q (valid: recon, weaponize, exploit, pivot, exfil)", phase)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, ao.maxWorkers)

	for _, target := range ao.targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			result := ao.executePhase(phase, t)
			ao.mu.Lock()
			ao.results[t] = append(ao.results[t], result)
			ao.mu.Unlock()
		}(target)
	}

	wg.Wait()
	return nil
}

// RunFullKillchain executes the complete killchain (recon -> weaponize ->
// exploit -> pivot -> exfil) for a single target and returns the results in
// order.
func (ao *AttackOrchestrator) RunFullKillchain(target string) []AttackResult {
	phases := []string{"recon", "weaponize", "exploit", "pivot", "exfil"}
	var results []AttackResult

	for _, phase := range phases {
		result := ao.executePhase(phase, target)
		results = append(results, result)
		ao.mu.Lock()
		ao.results[target] = append(ao.results[target], result)
		ao.mu.Unlock()

		// If a phase fails, the killchain stops (dependencies not met).
		if !result.Success {
			break
		}
	}

	return results
}

// executePhase runs the logic for a single phase against a single target.
func (ao *AttackOrchestrator) executePhase(phase, target string) AttackResult {
	result := AttackResult{
		Phase:     phase,
		Target:    target,
		Timestamp: time.Now(),
	}

	switch phase {
	case "recon":
		result.Success, result.Detail = ao.runRecon(target)
	case "weaponize":
		result.Success, result.Detail = ao.runWeaponize(target)
	case "exploit":
		result.Success, result.Detail = ao.runExploit(target)
	case "pivot":
		result.Success, result.Detail = ao.runPivot(target)
	case "exfil":
		result.Success, result.Detail = ao.runExfil(target)
	default:
		result.Success = false
		result.Detail = fmt.Sprintf("unknown phase: %s", phase)
	}

	return result
}

// ---------------------------------------------------------------------------
// Phase implementations
// ---------------------------------------------------------------------------

// runRecon performs reconnaissance: quick TCP port scan and service
// fingerprinting on interesting ports.
func (ao *AttackOrchestrator) runRecon(target string) (bool, string) {
	scanner := NewPortScanner(2*time.Second, 50)
	openPorts := scanner.QuickScan(target)

	if len(openPorts) == 0 {
		return false, "no open ports found"
	}

	fingerprinter := NewServiceFingerprinter()
	var services []string
	for _, port := range openPorts {
		service, version := fingerprinter.Fingerprint(target, port)
		if version != "" {
			services = append(services, fmt.Sprintf("%d/%s(%s)", port, service, version))
		} else {
			services = append(services, fmt.Sprintf("%d/%s", port, service))
		}
	}

	detail := fmt.Sprintf("%d open ports: %v", len(openPorts), services)
	return true, detail
}

// runWeaponize analyses recon data to select and prepare exploits.
// In a full implementation this would build targeted payloads; the stub here
// simulates weaponisation readiness.
func (ao *AttackOrchestrator) runWeaponize(target string) (bool, string) {
	ao.mu.Lock()
	prevResults := ao.results[target]
	ao.mu.Unlock()

	// Check that recon was successful.
	hasRecon := false
	for _, r := range prevResults {
		if r.Phase == "recon" && r.Success {
			hasRecon = true
			break
		}
	}
	if !hasRecon {
		return false, "recon phase did not succeed — cannot weaponize"
	}

	// Simulate payload selection based on discovered services.
	detail := "weaponisation complete — payloads staged"
	return true, detail
}

// runExploit delivers the weaponised payloads against the target.
// It runs the WebAttacker injection tests against common web ports if
// available, and simulates other exploit delivery.
func (ao *AttackOrchestrator) runExploit(target string) (bool, string) {
	scanner := NewPortScanner(1*time.Second, 20)

	// Check for web ports.
	webPorts := []int{80, 443, 8080, 8443, 3000, 5000, 8000, 8888}
	var exploited int
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

		// Run SQLi test against a common parameter name.
		for _, param := range []string{"id", "q", "search", "page"} {
			results := attacker.TestSQLInjection(baseURL, param)
			for _, r := range results {
				if r.Vulnerable {
					exploited++
				}
			}
		}
	}

	if exploited > 0 {
		return true, fmt.Sprintf("exploited %d injection points across web services", exploited)
	}

	// Fall back to testing SSH brute if port 22 is open.
	if scanner.ScanPort(target, 22) {
		return true, "SSH service detected — brute-force vector available"
	}

	return false, "no exploitable services found"
}

// runPivot attempts lateral movement from the compromised target.
// Stub implementation — in production this would scan the internal network
// from the compromised host.
func (ao *AttackOrchestrator) runPivot(target string) (bool, string) {
	ao.mu.Lock()
	prevResults := ao.results[target]
	ao.mu.Unlock()

	hasExploit := false
	for _, r := range prevResults {
		if r.Phase == "exploit" && r.Success {
			hasExploit = true
			break
		}
	}
	if !hasExploit {
		return false, "exploit phase did not succeed — cannot pivot"
	}

	// Simulate scanning the internal network from the compromised host.
	// In a real implementation this would use the target as a jump box.
	detail := "pivot staged — internal network enumeration ready"
	return true, detail
}

// runExfil simulates data exfiltration from the target.
// Stub implementation — in production this would extract files, databases,
// or memory contents.
func (ao *AttackOrchestrator) runExfil(target string) (bool, string) {
	ao.mu.Lock()
	prevResults := ao.results[target]
	ao.mu.Unlock()

	hasPivot := false
	for _, r := range prevResults {
		if r.Phase == "pivot" && r.Success {
			hasPivot = true
			break
		}
	}
	if !hasPivot {
		return false, "pivot phase did not succeed — cannot exfiltrate"
	}

	// Simulate data extraction.
	detail := fmt.Sprintf("exfiltration complete — %d bytes staged", rand.Intn(1<<20)+1<<10)
	return true, detail
}
