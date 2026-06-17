package fusion

import (
	"testing"

	"github.com/fortress/v6/internal/config"
)

func TestValidateTargetSafe(t *testing.T) {
	if err := config.ValidateTarget("192.168.1.1"); err != nil {
		t.Errorf("valid IP should not error: %v", err)
	}
}

func TestValidateTargetRejectFlagInjection(t *testing.T) {
	if err := config.ValidateTarget("-T4"); err == nil {
		t.Error("flag injection should be rejected")
	}
}

func TestValidateTargetRejectShellMeta(t *testing.T) {
	if err := config.ValidateTarget("1.1.1.1; ls"); err == nil {
		t.Error("shell metacharacters should be rejected")
	}
}

func TestNewNmapScanner(t *testing.T) {
	cfg := config.Default()
	n := NewNmapScanner(&cfg.Weapons)
	if n.bin != "/usr/bin/nmap" {
		t.Errorf("expected /usr/bin/nmap, got %s", n.bin)
	}
}
