package brain

import (
	"fmt"
	"time"
)

// CountermeasureType categorizes defensive actions.
type CountermeasureType int

const (
	CmLog     CountermeasureType = iota // record only
	CmThrottle                           // rate limit
	CmIntel                              // gather intelligence
	CmTarpit                             // TCP tarpit
	CmHoneypot                           // dynamic honeypot
	CmBlock                              // IP block (nftables/eBPF)
	CmScan                               // active recon scan
	CmChain                              // full weapon chain
	CmImmunity                           // swarm immunity broadcast
	CmAbyss                              // LLM recursive abyss
	CmXDP                                // XDP kernel blackhole
)

func (ct CountermeasureType) String() string {
	switch ct {
	case CmLog:
		return "log"
	case CmThrottle:
		return "throttle"
	case CmIntel:
		return "intel-gather"
	case CmTarpit:
		return "tarpit"
	case CmHoneypot:
		return "honeypot"
	case CmBlock:
		return "block"
	case CmScan:
		return "active-scan"
	case CmChain:
		return "weapon-chain"
	case CmImmunity:
		return "swarm-immunity"
	case CmAbyss:
		return "llm-abyss"
	case CmXDP:
		return "xdp-blackhole"
	default:
		return "unknown"
	}
}

// Countermeasure is a recommended defensive action with risk assessment.
type Countermeasure struct {
	ID          string
	Name        string
	Description string
	Type        CountermeasureType
	TargetIP    string
	RiskLevel   float64 // 0=safe, 1=high-risk
	AutoApprove bool    // safe enough to execute without human approval
	Reversible  bool    // can be undone
	Duration    time.Duration
	Evidence    string // justification for audit trail
}

// RiskAssessment evaluates the safety and appropriateness of a countermeasure.
type RiskAssessment struct {
	Score        float64 // 0=safe, 1=extreme risk
	Justification string
	Preconditions []string
	SideEffects   []string
	Mitigations   []string
}

// CountermeasureEngine maps threat levels to recommended countermeasures.
type CountermeasureEngine struct {
	history       []Countermeasure
	maxHistory    int
	cmCount       map[string]int // counters by IP for escalation tracking
	preApproved   map[CountermeasureType]bool
}

// NewCountermeasureEngine creates a countermeasure recommendation engine.
func NewCountermeasureEngine() *CountermeasureEngine {
	return &CountermeasureEngine{
		maxHistory:  1000,
		cmCount:     make(map[string]int),
		preApproved: defaultPreApproved(),
	}
}

// defaultPreApproved returns countermeasure types safe for automatic execution.
func defaultPreApproved() map[CountermeasureType]bool {
	return map[CountermeasureType]bool{
		CmLog:      true,
		CmThrottle: true,
		CmIntel:    true,
		CmBlock:    true,
		CmTarpit:   true,
		CmXDP:      true,
		// These REQUIRE explicit authorization:
		// CmScan, CmChain, CmImmunity, CmAbyss, CmHoneypot
	}
}

// Recommend returns countermeasures appropriate for the given threat level.
func (ce *CountermeasureEngine) Recommend(ip string, score float64, level ResponseLevel, isWhitelisted bool) []Countermeasure {
	if isWhitelisted && level >= ResponseC {
		level = ResponseB // whitelist cap per design spec
	}

	var measures []Countermeasure

	// Always: log
	measures = append(measures, Countermeasure{
		ID: fmt.Sprintf("log-%s-%d", ip, time.Now().Unix()),
		Name: "ThreatLog", Description: "Record threat observation",
		Type: CmLog, TargetIP: ip, RiskLevel: 0, AutoApprove: true, Reversible: true,
	})

	// --- A阶: Silent observation ---
	if level >= ResponseA {
		// Log only — already added above
	}

	// --- B阶: Active reconnaissance ---
	if level >= ResponseB {
		measures = append(measures,
			Countermeasure{
				ID: fmt.Sprintf("intel-%s-%d", ip, time.Now().Unix()),
				Name: "IntelGather", Description: "WHOIS/ASN/Shodan lookup",
				Type: CmIntel, TargetIP: ip, RiskLevel: 0.05, AutoApprove: true, Reversible: true,
				Duration: 5 * time.Second,
			},
			Countermeasure{
				ID: fmt.Sprintf("throttle-%s-%d", ip, time.Now().Unix()),
				Name: "RateLimit", Description: "nftables rate limit 10 req/min",
				Type: CmThrottle, TargetIP: ip, RiskLevel: 0.1, AutoApprove: true, Reversible: true,
				Duration: 30 * time.Minute,
			},
		)
	}

	// --- C阶: Predator mode ---
	if level >= ResponseC {
		measures = append(measures,
			Countermeasure{
				ID: fmt.Sprintf("block-%s-%d", ip, time.Now().Unix()),
				Name: "IPBlock", Description: "nftables permanent block + eBPF blacklist",
				Type: CmBlock, TargetIP: ip, RiskLevel: 0.15, AutoApprove: true, Reversible: true,
				Duration: 1 * time.Hour,
			},
			Countermeasure{
				ID: fmt.Sprintf("tarpit-%s-%d", ip, time.Now().Unix()),
				Name: "TarpitRedirect", Description: "TCP zero-window tarpit",
				Type: CmTarpit, TargetIP: ip, RiskLevel: 0.2, AutoApprove: true, Reversible: true,
				Duration: 1 * time.Hour,
			},
			Countermeasure{
				ID: fmt.Sprintf("honeypot-%s-%d", ip, time.Now().Unix()),
				Name: "HoneypotDeploy", Description: "Deploy targeted honeypot for attacker",
				Type: CmHoneypot, TargetIP: ip, RiskLevel: 0.3, AutoApprove: false, Reversible: true,
				Duration: 1 * time.Hour,
			},
			Countermeasure{
				ID: fmt.Sprintf("scan-%s-%d", ip, time.Now().Unix()),
				Name: "ActiveRecon", Description: "nmap + nuclei scan of attacker",
				Type: CmScan, TargetIP: ip, RiskLevel: 0.5, AutoApprove: false, Reversible: true,
				Duration: 2 * time.Minute,
			},
		)
	}

	// --- D阶: Black hole counterstrike ---
	if level >= ResponseD {
		measures = append(measures,
			Countermeasure{
				ID: fmt.Sprintf("xdp-%s-%d", ip, time.Now().Unix()),
				Name: "XDPBlackhole", Description: "XDP_DROP at kernel level — wire speed",
				Type: CmXDP, TargetIP: ip, RiskLevel: 0.1, AutoApprove: true, Reversible: true,
			},
			Countermeasure{
				ID: fmt.Sprintf("chain-%s-%d", ip, time.Now().Unix()),
				Name: "FullWeaponChain", Description: "nmap→nuclei→hydra→sqlmap→msf — full Kali chain",
				Type: CmChain, TargetIP: ip, RiskLevel: 0.85, AutoApprove: false, Reversible: false,
				Duration: 5 * time.Minute,
				Evidence: "D阶全武器链 — 需Raft >N/2共识",
			},
			Countermeasure{
				ID: fmt.Sprintf("immunity-%s-%d", ip, time.Now().Unix()),
				Name: "SwarmImmunity", Description: "Ed25519-signed swarm immunity broadcast",
				Type: CmImmunity, TargetIP: ip, RiskLevel: 0.3, AutoApprove: false, Reversible: true,
			},
			Countermeasure{
				ID: fmt.Sprintf("abyss-%s-%d", ip, time.Now().Unix()),
				Name: "LLMAbyss", Description: "LLM-driven recursive depth honeypot",
				Type: CmAbyss, TargetIP: ip, RiskLevel: 0.4, AutoApprove: false, Reversible: true,
				Duration: 30 * time.Minute,
			},
		)
	}

	// Track history
	ce.history = append(ce.history, measures...)
	if len(ce.history) > ce.maxHistory {
		ce.history = ce.history[len(ce.history)-ce.maxHistory:]
	}
	ce.cmCount[ip]++

	return measures
}

// AssessRisk evaluates the risk of executing a countermeasure.
func (ce *CountermeasureEngine) AssessRisk(cm Countermeasure) RiskAssessment {
	switch cm.Type {
	case CmChain:
		return RiskAssessment{
			Score: 0.85, Justification: "Full weapon chain — offensive action, legal exposure",
			Preconditions: []string{"Raft consensus >N/2", "D阶 confirmed", "Not whitelisted", "Human pre-auth"},
			SideEffects:   []string{"Attacker infrastructure damage", "Attribution risk"},
			Mitigations:   []string{"Require explicit authorization", "Log all actions", "Encrypt evidence"},
		}
	case CmScan:
		return RiskAssessment{
			Score: 0.5, Justification: "Active reconnaissance — may alert attacker",
			Preconditions: []string{"C阶 or higher", "Not whitelisted"},
			SideEffects:   []string{"Attacker may detect scan", "May escalate conflict"},
			Mitigations:   []string{"Use decoy source IP if available", "Throttle scan rate"},
		}
	case CmAbyss:
		return RiskAssessment{
			Score: 0.4, Justification: "LLM-driven deception — low risk, high reward",
			Preconditions: []string{"D阶 confirmed", "LLM backend available"},
			SideEffects:   []string{"May consume significant resources"},
			Mitigations:   []string{"Resource limits", "Timeout after 30min"},
		}
	case CmXDP:
		return RiskAssessment{
			Score: 0.1, Justification: "Kernel-level drop — very safe, very fast",
			Preconditions: []string{"eBPF loaded", "IP validated"},
			SideEffects:   []string{"Complete network block for target IP"},
			Mitigations:   []string{"Auto-expire after ban duration", "Whitelist bypass"},
		}
	default:
		return RiskAssessment{
			Score: cm.RiskLevel, Justification: "Standard countermeasure",
		}
	}
}

// IsPreApproved returns true if the countermeasure type is safe for auto-execution.
func (ce *CountermeasureEngine) IsPreApproved(ct CountermeasureType) bool {
	return ce.preApproved[ct]
}

// EscalationCount returns how many times countermeasures have been taken against an IP.
func (ce *CountermeasureEngine) EscalationCount(ip string) int {
	return ce.cmCount[ip]
}

// History returns recent countermeasures for an IP.
func (ce *CountermeasureEngine) History(ip string) []Countermeasure {
	var result []Countermeasure
	for _, cm := range ce.history {
		if cm.TargetIP == ip {
			result = append(result, cm)
		}
	}
	return result
}

// RecentHistory returns the last N countermeasures regardless of target.
func (ce *CountermeasureEngine) RecentHistory(n int) []Countermeasure {
	if n >= len(ce.history) {
		return append([]Countermeasure{}, ce.history...)
	}
	start := len(ce.history) - n
	return append([]Countermeasure{}, ce.history[start:]...)
}
