// Package engines — Living-off-the-Land (LotL) Detection Engine
//
// Detects attacks that use ONLY built-in OS tools (no malware dropped).
// Hot technique #4: LotL attacks are the #1 evasion method in 2025-2026
// because traditional AV/EDR struggles to distinguish admin work from
// malicious ps, wmic, certutil, bitsadmin, regsvr32, mshta, wscript usage.
package engines

import (
	"math"
	"strings"
	"sync"
)

// LotLPattern describes a living-off-the-land detection pattern.
type LotLPattern struct {
	Name        string   `json:"name"`
	Tool        string   `json:"tool"` // ps, wmic, certutil, etc.
	Indicators  []string `json:"indicators"`  // suspicious arguments/flags
	Severity    float64  `json:"severity"`    // 0-10
	Description string   `json:"description"`
}

// LotLPatterns is the database of known LotL abuse patterns.
var LotLPatterns = []LotLPattern{
	// PowerShell abuse
	{Name: "PS-DownloadCradle", Tool: "powershell", Severity: 8.0,
		Indicators: []string{"-enc", "-e ", "frombase64string", "downloadstring", "downloadfile", "invoke-expression", "iex", "webclient", "net.webclient"},
		Description: "PowerShell download cradle — common initial access vector"},
	{Name: "PS-InMemoryExecution", Tool: "powershell", Severity: 9.0,
		Indicators: []string{"-w hidden", "-windowstyle hidden", "-nop", "-noprofile", "-noninteractive", "bypass", "exec bypass"},
		Description: "PowerShell in-memory execution — no disk artifacts"},
	{Name: "PS-C2Communication", Tool: "powershell", Severity: 9.0,
		Indicators: []string{"-c", "tcpclient", "socket", "send", "receive", "stream", "memorystream", "sslstream"},
		Description: "PowerShell C2 channel — beacon communication"},

	// WMIC abuse
	{Name: "WMI-ProcessCreate", Tool: "wmic", Severity: 7.0,
		Indicators: []string{"process", "call", "create", "wmic", "node:"},
		Description: "WMI remote process creation — lateral movement classic"},
	{Name: "WMI-DataExfil", Tool: "wmic", Severity: 6.0,
		Indicators: []string{"/node:", "output:", "get", "/format:"},
		Description: "WMI data exfiltration via format redirection"},

	// Certutil abuse
	{Name: "Certutil-Decode", Tool: "certutil", Severity: 7.0,
		Indicators: []string{"-decode", "-encode", "base64", "download"},
		Description: "Certutil used for base64 decode/malware download"},
	{Name: "Certutil-Download", Tool: "certutil", Severity: 8.0,
		Indicators: []string{"-urlcache", "-split", "-f", "http:", "https:"},
		Description: "Certutil used as downloader"},

	// Bitsadmin abuse
	{Name: "Bitsadmin-Download", Tool: "bitsadmin", Severity: 7.0,
		Indicators: []string{"/transfer", "download", "/download", "http:", "https:"},
		Description: "Bitsadmin used to download files — fileless delivery"},

	// Regsvr32 abuse
	{Name: "Regsvr32-Squiblydoo", Tool: "regsvr32", Severity: 8.0,
		Indicators: []string{"/s", "/u", "/i:", "http:", "https:", "scrobj.dll"},
		Description: "Regsvr32 Squiblydoo — bypass application whitelisting"},

	// Mshta abuse
	{Name: "Mshta-Exec", Tool: "mshta", Severity: 8.0,
		Indicators: []string{"javascript:", "http:", "https:", "vbscript:"},
		Description: "Mshta executing remote HTA — classic social engineering"},

	// Rundll32 abuse
	{Name: "Rundll32-Download", Tool: "rundll32", Severity: 7.0,
		Indicators: []string{"javascript:", "http:", "https:", "url.dll,fileprotocolhandler"},
		Description: "Rundll32 used as LOLbin — remote code execution"},

	// SSH tunneling
	{Name: "SSH-Tunnel", Tool: "ssh", Severity: 6.0,
		Indicators: []string{"-L", "-R", "-D", "-N", "-f", "dynamic"},
		Description: "SSH tunneling — potential data exfiltration or C2 proxy"},

	// Curl/Wget abuse (Unix)
	{Name: "Curl-PipeBash", Tool: "curl", Severity: 9.0,
		Indicators: []string{"| bash", "| sh", "-o-", "http:", "https:"},
		Description: "Curl pipe to bash — classic fileless execution"},
	{Name: "Wget-Download", Tool: "wget", Severity: 7.0,
		Indicators: []string{"-O-", "-q -O", "| bash", "| sh"},
		Description: "Wget used for fileless malware delivery"},
}

// LotLDetector monitors process/command execution for LotL abuse patterns.
type LotLDetector struct {
	mu       sync.Mutex
	alerts   map[string]int // IP → alert count
	maxAlerts int
}

// NewLotLDetector creates a LotL detection engine.
func NewLotLDetector() *LotLDetector {
	return &LotLDetector{
		alerts:   make(map[string]int),
		maxAlerts: 1000,
	}
}

// Analyze checks a command line or log line for LotL abuse.
// Returns matched patterns and severity scores.
func (ld *LotLDetector) Analyze(sourceIP, commandLine string) (matched []LotLPattern, maxSeverity float64) {
	lower := strings.ToLower(commandLine)

	for _, pattern := range LotLPatterns {
		if !strings.Contains(lower, pattern.Tool) {
			continue
		}

		matchesForTool := 0
		for _, indicator := range pattern.Indicators {
			if strings.Contains(lower, indicator) {
				matchesForTool++
			}
		}

		// At least one indicator must match for the same tool
		if matchesForTool >= 1 {
			matched = append(matched, pattern)
			if pattern.Severity > maxSeverity {
				maxSeverity = pattern.Severity
			}
		}
	}

	// Track alerts per source
	if maxSeverity >= 5.0 {
		ld.mu.Lock()
		ld.alerts[sourceIP]++
		if ld.alerts[sourceIP] > ld.maxAlerts {
			ld.alerts[sourceIP] = ld.maxAlerts
		}
		ld.mu.Unlock()
	}

	return
}

// EscalationScore returns a per-IP escalation score based on LotL alert frequency.
func (ld *LotLDetector) EscalationScore(ip string) float64 {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	count := ld.alerts[ip]
	if count == 0 {
		return 0
	}
	return math.Min(float64(count)*0.5, 50) // max 50 points from LotL
}

// GetAlertCount returns the number of LotL alerts for an IP.
func (ld *LotLDetector) GetAlertCount(ip string) int {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	return ld.alerts[ip]
}

// Reset clears tracking for an IP (after counterstrike action).
func (ld *LotLDetector) Reset(ip string) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	delete(ld.alerts, ip)
}
