package engine

import (
	"testing"

	"github.com/fortress/v6/internal/config"
)

func TestDetectionPipeline_EnableSuricata(t *testing.T) {
	cfg := &config.Config{}
	cfg.Suricata.Enabled = false // default: disabled
	p := NewDetectionPipeline(cfg)
	if p.suricataEngine != nil {
		t.Error("expected nil suricata engine when disabled")
	}
	p.Stop()
}

func TestDetectionPipeline_EnableSuricataWithRules(t *testing.T) {
	cfg := &config.Config{}
	cfg.Suricata.Enabled = true
	cfg.Suricata.RulesPath = "../../rules/"
	cfg.Suricata.WorkerPool = 2
	cfg.Capture.Mode = "inject"

	p := NewDetectionPipeline(cfg)
	if p.suricataEngine == nil {
		t.Fatal("expected suricata engine to be initialized")
	}
	if p.suricataEngine.RuleCount() == 0 {
		t.Error("expected rules to be loaded from ../rules/")
	}

	p.Stop()
}

func TestDetectionPipeline_EnableCrowdSec(t *testing.T) {
	cfg := &config.Config{}
	cfg.CrowdSec.Enabled = false
	p := NewDetectionPipeline(cfg)
	if p.crowdSec != nil {
		t.Error("expected nil crowdsec when disabled")
	}
	p.Stop()
}

func TestDetectionPipeline_EnableCrowdSecEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.CrowdSec.Enabled = true
	p := NewDetectionPipeline(cfg)
	if p.crowdSec == nil {
		t.Fatal("expected crowdsec to be initialized")
	}
	p.Stop()
}
