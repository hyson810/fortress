package dashboard

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("default should be disabled")
	}
	if cfg.Port != 9091 {
		t.Errorf("expected port 9091, got %d", cfg.Port)
	}
	if cfg.RefreshInterval != 1000 {
		t.Errorf("expected RefreshInterval 1000, got %d", cfg.RefreshInterval)
	}
}

func TestConfigYAML(t *testing.T) {
	yamlData := "enabled: true\nport: 9092\nrefresh_interval: 500\n"
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlData), &cfg); err != nil {
		t.Fatalf("yaml unmarshal failed: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected enabled true")
	}
	if cfg.Port != 9092 {
		t.Errorf("expected port 9092, got %d", cfg.Port)
	}
	if cfg.RefreshInterval != 500 {
		t.Errorf("expected RefreshInterval 500, got %d", cfg.RefreshInterval)
	}
}
