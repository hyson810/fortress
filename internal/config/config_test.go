package config

import (
	"testing"
)

func TestLoad_MinimalConfig(t *testing.T) {
	cfg, err := Load("../../fortress.yaml")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Swarm.Name == "" {
		t.Error("Swarm.Name should not be empty")
	}
	if cfg.Engine.SynFloodPPS == 0 {
		t.Error("SynFloodPPS should have default > 0")
	}
}

func TestIsWhitelisted_ExactIP(t *testing.T) {
	cfg := &Config{
		Whitelist: []string{"127.0.0.1", "::1"},
	}
	// Load would normally parse the whitelist; we test SetWhitelist
	cfg.SetWhitelist(cfg.Whitelist)
	if !cfg.IsWhitelisted("127.0.0.1") {
		t.Error("127.0.0.1 should be whitelisted")
	}
	if cfg.IsWhitelisted("8.8.8.8") {
		t.Error("8.8.8.8 should NOT be whitelisted")
	}
}

func TestIsWhitelisted_CIDR(t *testing.T) {
	cfg := &Config{
		Whitelist: []string{"10.0.0.0/8"},
	}
	cfg.SetWhitelist(cfg.Whitelist)

	if !cfg.IsWhitelisted("10.0.0.1") {
		t.Error("10.0.0.1 should match 10.0.0.0/8")
	}
	if !cfg.IsWhitelisted("10.255.255.255") {
		t.Error("10.255.255.255 should match 10.0.0.0/8")
	}
	if cfg.IsWhitelisted("11.0.0.1") {
		t.Error("11.0.0.1 should NOT match 10.0.0.0/8")
	}
}

func TestIsWhitelisted_IPv6(t *testing.T) {
	cfg := &Config{
		Whitelist: []string{"::1"},
	}
	cfg.SetWhitelist(cfg.Whitelist)
	if !cfg.IsWhitelisted("::1") {
		t.Error("::1 should be whitelisted")
	}
}

func TestValidateTarget_Safe(t *testing.T) {
	if err := ValidateTarget("192.168.1.1"); err != nil {
		t.Errorf("safe IP should pass validation: %v", err)
	}
	if err := ValidateTarget("example.com"); err != nil {
		t.Errorf("safe domain should pass validation: %v", err)
	}
}

func TestValidateTarget_Dangerous(t *testing.T) {
	if err := ValidateTarget("192.168.1.1; rm -rf /"); err == nil {
		t.Error("shell injection should be rejected")
	}
	if err := ValidateTarget("--help"); err == nil {
		t.Error("flag injection should be rejected")
	}
	if err := ValidateTarget("$(whoami)"); err == nil {
		t.Error("command substitution should be rejected")
	}
}

func TestSetWhitelist(t *testing.T) {
	cfg := &Config{}
	cfg.SetWhitelist([]string{"10.0.0.0/8"})
	if !cfg.IsWhitelisted("10.1.2.3") {
		t.Error("after SetWhitelist, 10.1.2.3 should be whitelisted")
	}
	cfg.SetWhitelist(nil)
	if cfg.IsWhitelisted("10.1.2.3") {
		t.Error("after SetWhitelist(nil), no IP should be whitelisted")
	}
}
