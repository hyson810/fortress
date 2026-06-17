package weapons

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/fortress/v6/internal/config"
)

// NmapResult mirrors the nmap XML output we care about
type NmapResult struct {
	Target    string        `json:"target"`
	OpenPorts []PortInfo    `json:"open_ports"`
	OS        string        `json:"os,omitempty"`
	Duration  time.Duration `json:"duration"`
	Raw       string        `json:"-"`
}

type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Nmap wraps the nmap binary
type Nmap struct {
	BinPath string
	Timeout time.Duration
}

// NewNmap creates an nmap weapon with the given binary path
func NewNmap(binPath string) *Nmap {
	return &Nmap{BinPath: binPath, Timeout: 120 * time.Second}
}

// QuickScan runs a fast top-1000 port scan
func (n *Nmap) QuickScan(target string) (*NmapResult, error) {
	return n.scan(target, []string{
		"-T4", "-Pn", "--max-retries", "1",
		"--top-ports", "1000",
		"-oX", "-",
	})
}

// DeepScan runs full service detection + OS fingerprint
func (n *Nmap) DeepScan(target string) (*NmapResult, error) {
	return n.scan(target, []string{
		"-T4", "-Pn", "-sV", "-O",
		"--script", "http-title,ssl-cert,ssh-hostkey",
		"-p", "1-10000",
		"-oX", "-",
	})
}

// VulnScan runs vulnerability detection scripts
func (n *Nmap) VulnScan(target string) (*NmapResult, error) {
	return n.scan(target, []string{
		"-T4", "-Pn", "-sV",
		"--script", "vuln",
		"-p", "1-1000",
		"-oX", "-",
	})
}

func (n *Nmap) scan(target string, extraArgs []string) (*NmapResult, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("nmap: %w", err)
	}

	args := append([]string{}, extraArgs...)
	args = append(args, "--", target)

	start := time.Now()
	cmd := exec.Command(n.BinPath, args...)
	output, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("nmap failed: %w", err)
	}

	return parseNmapXML(string(output), target, elapsed), nil
}

// parseNmapXML extracts port info from nmap XML output
func parseNmapXML(raw, target string, elapsed time.Duration) *NmapResult {
	result := &NmapResult{
		Target:   target,
		Duration: elapsed,
		Raw:      raw,
	}

	type nmaprun struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts   []struct {
			Address struct {
				Addr string `xml:"addr,attr"`
			} `xml:"address"`
			Ports []struct {
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
			} `xml:"ports>port"`
		} `xml:"host"`
	}

	var data nmaprun
	if err := xml.Unmarshal([]byte(raw), &data); err != nil {
		// XML parse failed — try basic regex fallback
		return parseNmapText(raw, target, elapsed)
	}

	for _, host := range data.Hosts {
		for _, port := range host.Ports {
			if port.State.State == "open" {
				result.OpenPorts = append(result.OpenPorts, PortInfo{
					Port:     port.PortID,
					Protocol: port.Protocol,
					Service:  port.Service.Name,
					Product:  port.Service.Product,
					Version:  port.Service.Version,
				})
			}
		}
	}
	return result
}

// parseNmapText is a fallback regex parser for nmap text output
func parseNmapText(raw, target string, elapsed time.Duration) *NmapResult {
	result := &NmapResult{
		Target:   target,
		Duration: elapsed,
		Raw:      raw,
	}

	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				var port int
				fmt.Sscanf(parts[0], "%d/tcp", &port)
				result.OpenPorts = append(result.OpenPorts, PortInfo{
					Port:     port,
					Protocol: "tcp",
					Service:  parts[2],
				})
			}
		}
	}
	return result
}

// PortCount returns total number of open ports
func (r *NmapResult) PortCount() int { return len(r.OpenPorts) }

// HasService checks if a service is present
func (r *NmapResult) HasService(name string) bool {
	for _, p := range r.OpenPorts {
		if strings.EqualFold(p.Service, name) {
			return true
		}
	}
	return false
}
