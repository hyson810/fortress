package fusion

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/fortress/v6/internal/config"
)

// MsfSession represents a Metasploit session opened against a target.
type MsfSession struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Target  string `json:"target"`
	Exploit string `json:"exploit"`
	Info    string `json:"info"`
}

// MsfConsole wraps the msfconsole binary for programmatic exploit
// execution via XMLRPC-style command scripting.
type MsfConsole struct {
	bin string
}

// NewMsfConsole creates a new MsfConsole using the binary path from the
// supplied WeaponsConfig.
func NewMsfConsole(cfg *config.WeaponsConfig) *MsfConsole {
	return &MsfConsole{bin: cfg.MsfBin}
}

// Exploit launches the given exploit against target with the specified
// payload and returns the resulting session. The target is validated for
// basic safety before the command is executed.
func (m *MsfConsole) Exploit(target, exploit, payload string) (*MsfSession, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("msf: %w", err)
	}

	rcScript := fmt.Sprintf(
		"use %s\nset RHOSTS %s\nset PAYLOAD %s\nexploit -j\nexit\n",
		exploit, target, payload,
	)

	cmd := exec.Command(m.bin, "-q", "-x", rcScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("msf exploit %s: %w (%s)", target, err, string(out))
	}

	// Parse session info from msfconsole output.
	session := &MsfSession{Target: target, Exploit: exploit, Info: string(out)}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "session") && strings.Contains(line, "opened") {
			session.Type = "meterpreter"
			//nolint:errcheck // best-effort parse
			fmt.Sscanf(line, "session %d", &session.ID)
		}
	}

	log.Printf("[msf] exploit %s against %s → session %d", exploit, target, session.ID)
	return session, nil
}

// ScanModules runs an Nmap scan through msfconsole's database and returns
// any exploit module paths found in the output.
func (m *MsfConsole) ScanModules(target string) []string {
	if err := config.ValidateTarget(target); err != nil {
		return nil
	}

	cmd := exec.Command(m.bin, "-q", "-x",
		fmt.Sprintf("db_nmap %s\nexit\n", target))
	out, _ := cmd.CombinedOutput()

	var modules []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "exploit/") {
			modules = append(modules, strings.TrimSpace(line))
		}
	}
	return modules
}
