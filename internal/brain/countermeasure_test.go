package brain

import (
	"testing"
)

func TestCountermeasureEngine_Recommend_ResponseA(t *testing.T) {
	ce := NewCountermeasureEngine()
	cms := ce.Recommend("10.0.0.1", 10.0, ResponseA, false)
	if len(cms) == 0 {
		t.Fatal("expected at least CmLog for A阶")
	}
	// A阶 should only have CmLog
	for _, cm := range cms {
		if cm.Type != CmLog {
			t.Errorf("A阶 should only have CmLog, got %s", cm.Type.String())
		}
	}
}

func TestCountermeasureEngine_Recommend_ResponseB(t *testing.T) {
	ce := NewCountermeasureEngine()
	cms := ce.Recommend("10.0.0.2", 35.0, ResponseB, false)

	hasIntel := false
	hasThrottle := false
	for _, cm := range cms {
		if cm.Type == CmIntel {
			hasIntel = true
		}
		if cm.Type == CmThrottle {
			hasThrottle = true
		}
	}
	if !hasIntel {
		t.Error("B阶 should include CmIntel")
	}
	if !hasThrottle {
		t.Error("B阶 should include CmThrottle")
	}
}

func TestCountermeasureEngine_Recommend_ResponseC(t *testing.T) {
	ce := NewCountermeasureEngine()
	cms := ce.Recommend("10.0.0.3", 60.0, ResponseC, false)

	hasBlock := false
	hasTarpit := false
	hasScan := false
	for _, cm := range cms {
		if cm.Type == CmBlock {
			hasBlock = true
		}
		if cm.Type == CmTarpit {
			hasTarpit = true
		}
		if cm.Type == CmScan {
			hasScan = true
		}
	}
	if !hasBlock {
		t.Error("C阶 should include CmBlock")
	}
	if !hasTarpit {
		t.Error("C阶 should include CmTarpit")
	}
	if !hasScan {
		t.Error("C阶 should include CmScan")
	}
}

func TestCountermeasureEngine_Recommend_ResponseD(t *testing.T) {
	ce := NewCountermeasureEngine()
	cms := ce.Recommend("10.0.0.4", 90.0, ResponseD, false)

	hasXDP := false
	hasChain := false
	hasImmunity := false
	hasAbyss := false
	for _, cm := range cms {
		switch cm.Type {
		case CmXDP:
			hasXDP = true
		case CmChain:
			hasChain = true
		case CmImmunity:
			hasImmunity = true
		case CmAbyss:
			hasAbyss = true
		}
	}
	if !hasXDP {
		t.Error("D阶 should include CmXDP")
	}
	if !hasChain {
		t.Error("D阶 should include CmChain")
	}
	if !hasImmunity {
		t.Error("D阶 should include CmImmunity")
	}
	if !hasAbyss {
		t.Error("D阶 should include CmAbyss")
	}
}

func TestCountermeasureEngine_WhitelistCap(t *testing.T) {
	ce := NewCountermeasureEngine()
	// Whitelisted IP should be capped at B阶 even with C-level score
	cms := ce.Recommend("10.0.0.5", 60.0, ResponseC, true)

	for _, cm := range cms {
		if cm.Type == CmBlock || cm.Type == CmScan || cm.Type == CmTarpit {
			t.Errorf("whitelisted IP should not get %s (should be capped at B階)", cm.Type.String())
		}
	}
	// Should still get B阶 items (CmIntel, CmThrottle)
	hasB := false
	for _, cm := range cms {
		if cm.Type == CmIntel {
			hasB = true
		}
	}
	if !hasB {
		t.Error("whitelisted IP should still get B階 countermeasures")
	}
}

func TestCountermeasureEngine_AssessRisk_Chain(t *testing.T) {
	ce := NewCountermeasureEngine()
	cm := Countermeasure{
		Type: CmChain, TargetIP: "10.0.0.6",
		RiskLevel: 0.85,
	}
	risk := ce.AssessRisk(cm)
	if risk.Score != 0.85 {
		t.Errorf("expected risk=0.85 for weapon chain, got %.2f", risk.Score)
	}
	if len(risk.Preconditions) == 0 {
		t.Error("weapon chain should have preconditions")
	}
}

func TestCountermeasureEngine_IsPreApproved(t *testing.T) {
	ce := NewCountermeasureEngine()
	if !ce.IsPreApproved(CmLog) {
		t.Error("CmLog should be pre-approved")
	}
	if !ce.IsPreApproved(CmThrottle) {
		t.Error("CmThrottle should be pre-approved")
	}
	if !ce.IsPreApproved(CmBlock) {
		t.Error("CmBlock should be pre-approved")
	}
	if ce.IsPreApproved(CmChain) {
		t.Error("CmChain should NOT be pre-approved")
	}
	if ce.IsPreApproved(CmAbyss) {
		t.Error("CmAbyss should NOT be pre-approved")
	}
}

func TestCountermeasureEngine_EscalationCount(t *testing.T) {
	ce := NewCountermeasureEngine()
	ce.Recommend("10.0.0.7", 10.0, ResponseA, false)
	ce.Recommend("10.0.0.7", 40.0, ResponseB, false)
	ce.Recommend("10.0.0.7", 70.0, ResponseD, false)

	if ce.EscalationCount("10.0.0.7") != 3 {
		t.Errorf("expected escalation count=3, got %d", ce.EscalationCount("10.0.0.7"))
	}
	if ce.EscalationCount("99.99.99.99") != 0 {
		t.Error("unknown IP should have escalation count=0")
	}
}
