package fusion

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"

	"github.com/fortress/v6/internal/config"
)

// --- Shared types ---

type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version,omitempty"`
}

type ScanResult struct {
	Target string     `json:"target"`
	Ports  []PortInfo `json:"ports"`
	OS     string     `json:"os,omitempty"`
	Raw    string     `json:"-"`
}

type VulnFinding struct {
	Template string `json:"template"`
	Name     string `json:"name"`
	Severity string `json:"severity"` // critical, high, medium, low, info
	URL      string `json:"url"`
}

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Service  string `json:"service"`
}

// --- Nmap wrapper ---

type NmapScanner struct {
	bin string
}

func NewNmapScanner(cfg *config.WeaponsConfig) *NmapScanner {
	return &NmapScanner{bin: cfg.NmapBin}
}

func (n *NmapScanner) QuickScan(target string) (*ScanResult, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("nmap: %w", err)
	}
	cmd := exec.Command(n.bin, "-T4", "-Pn", "--top-ports", "100", "--", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap quick scan: %w: %s", err, string(out))
	}
	return &ScanResult{Target: target, Raw: string(out)}, nil
}

func (n *NmapScanner) DeepScan(target string) (*ScanResult, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("nmap: %w", err)
	}
	cmd := exec.Command(n.bin, "-sS", "-sV", "-sC", "-O", "-T4", "-Pn", "-oX", "-", "--", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap deep scan: %w: %s", err, string(out))
	}
	result := &ScanResult{Target: target, Raw: string(out)}
	n.parseXML(out, result)
	return result, nil
}

func (n *NmapScanner) VulnScan(target string) (*ScanResult, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("nmap: %w", err)
	}
	cmd := exec.Command(n.bin, "-sS", "-sV", "--script", "vuln", "-T4", "-Pn", "-oX", "-", "--", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap vuln scan: %w: %s", err, string(out))
	}
	result := &ScanResult{Target: target, Raw: string(out)}
	n.parseXML(out, result)
	return result, nil
}

func (n *NmapScanner) parseXML(data []byte, r *ScanResult) {
	type xmlPort struct {
		PortID   int    `xml:"portid,attr"`
		Protocol string `xml:"protocol,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name    string `xml:"name,attr"`
			Product string `xml:"product,attr"`
			Version string `xml:"version,attr"`
		} `xml:"service"`
	}
	type xmlResult struct {
		Ports []xmlPort `xml:"host>ports>port"`
		OS    struct {
			Match []struct {
				Name     string `xml:"name,attr"`
				Accuracy string `xml:"accuracy,attr"`
			} `xml:"osmatch"`
		} `xml:"host>os"`
	}
	var xr xmlResult
	if err := xml.Unmarshal(data, &xr); err != nil {
		return // XML parse failure, keep Raw
	}
	for _, p := range xr.Ports {
		if p.State.State == "open" {
			r.Ports = append(r.Ports, PortInfo{
				Port: p.PortID, Protocol: p.Protocol,
				Service: p.Service.Name, Version: p.Service.Product + " " + p.Service.Version,
			})
		}
	}
	if len(xr.OS.Match) > 0 {
		r.OS = xr.OS.Match[0].Name
	}
}

// --- Nuclei wrapper ---

type NucleiScanner struct {
	bin string
}

func NewNucleiScanner(cfg *config.WeaponsConfig) *NucleiScanner {
	return &NucleiScanner{bin: cfg.NucleiBin}
}

func (n *NucleiScanner) Scan(target string) ([]VulnFinding, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}
	urls := []string{target}
	if !strings.HasPrefix(target, "http") {
		urls = []string{"http://" + target, "https://" + target}
	}
	var allFindings []VulnFinding
	for _, u := range urls {
		cmd := exec.Command(n.bin, "-u", u, "-jsonl", "-silent")
		out, _ := cmd.CombinedOutput()
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var f VulnFinding
			if err := json.Unmarshal([]byte(line), &f); err == nil {
				f.URL = u
				allFindings = append(allFindings, f)
			}
		}
	}
	return allFindings, nil
}

// --- Hydra wrapper ---

type HydraBruteForcer struct {
	bin       string
	wordlists string
}

func NewHydraBruteForcer(cfg *config.WeaponsConfig) *HydraBruteForcer {
	return &HydraBruteForcer{bin: cfg.HydraBin, wordlists: cfg.Wordlists}
}

func (h *HydraBruteForcer) BruteSSH(target string) ([]Credential, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("hydra: %w", err)
	}
	userList := h.wordlists + "/top-usernames-shortlist.txt"
	passList := h.wordlists + "/rockyou.txt"
	cmd := exec.Command(h.bin, "-L", userList, "-P", passList, "-t", "4", "-f", "ssh://"+target)
	out, _ := cmd.CombinedOutput()
	var creds []Credential
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "login:") {
			parts := strings.Fields(line)
			for i, p := range parts {
				if p == "login:" && i+1 < len(parts) {
					creds = append(creds, Credential{Username: parts[i+1], Password: "found", Service: "ssh"})
				}
			}
		}
	}
	return creds, nil
}
