package brain

import (
	"testing"
)

func TestEvidenceCollector_Collect(t *testing.T) {
	ec := NewEvidenceCollector(100, "/tmp/test_evidence.json")
	r := ec.Collect("10.0.0.1", "SYN洪水", 85.0, ResponseD, []string{"block", "tarpit"})

	if r == nil {
		t.Fatal("Collect returned nil")
	}
	if r.IP != "10.0.0.1" {
		t.Errorf("expected IP=10.0.0.1, got %s", r.IP)
	}
	if r.Score != 85.0 {
		t.Errorf("expected Score=85.0, got %.1f", r.Score)
	}
	if r.ResponseLevel != "D·黑洞" {
		t.Errorf("expected D·黑洞, got %s", r.ResponseLevel)
	}
	if len(r.Actions) != 2 {
		t.Errorf("expected 2 actions, got %d", len(r.Actions))
	}
	if r.Hash == "" {
		t.Error("Hash should not be empty")
	}
}

func TestEvidenceCollector_VerifyChain_Valid(t *testing.T) {
	ec := NewEvidenceCollector(100, "/tmp/test_evidence_chain.json")
	ec.Collect("10.0.0.1", "端口扫描", 15.0, ResponseB, []string{"log"})
	ec.Collect("10.0.0.2", "SYN洪水", 55.0, ResponseC, []string{"block"})
	ec.Collect("10.0.0.3", "SQL注入", 90.0, ResponseD, []string{"chain", "xdp"})

	if !ec.VerifyChain() {
		t.Error("evidence chain should be valid")
	}
}

func TestEvidenceCollector_Count(t *testing.T) {
	ec := NewEvidenceCollector(100, "/tmp/test_evidence_count.json")
	if ec.Count() != 0 {
		t.Errorf("expected 0, got %d", ec.Count())
	}
	ec.Collect("10.0.0.1", "test", 10.0, ResponseA, nil)
	if ec.Count() != 1 {
		t.Errorf("expected 1, got %d", ec.Count())
	}
	ec.Collect("10.0.0.2", "test", 20.0, ResponseB, nil)
	ec.Collect("10.0.0.3", "test", 30.0, ResponseC, nil)
	if ec.Count() != 3 {
		t.Errorf("expected 3, got %d", ec.Count())
	}
}

func TestEvidenceCollector_LastRecord(t *testing.T) {
	ec := NewEvidenceCollector(100, "/tmp/test_evidence_last.json")
	if ec.LastRecord() != nil {
		t.Error("LastRecord should be nil for empty collector")
	}

	ec.Collect("10.0.0.1", "test", 10.0, ResponseA, nil)
	last := ec.LastRecord()
	if last == nil || last.IP != "10.0.0.1" {
		t.Error("LastRecord should return most recent")
	}
}

func TestEvidenceCollector_ForIP(t *testing.T) {
	ec := NewEvidenceCollector(100, "/tmp/test_evidence_forip.json")
	ec.Collect("10.0.0.1", "A事件", 10.0, ResponseA, nil)
	ec.Collect("10.0.0.1", "B事件", 20.0, ResponseB, nil)
	ec.Collect("10.0.0.2", "C事件", 30.0, ResponseC, nil)

	records := ec.ForIP("10.0.0.1")
	if len(records) != 2 {
		t.Errorf("expected 2 records for 10.0.0.1, got %d", len(records))
	}

	records = ec.ForIP("99.99.99.99")
	if len(records) != 0 {
		t.Errorf("expected 0 records for unknown IP, got %d", len(records))
	}
}

func TestEvidenceCollector_Clear(t *testing.T) {
	ec := NewEvidenceCollector(100, "/tmp/test_evidence_clear.json")
	ec.Collect("10.0.0.1", "test", 10.0, ResponseA, nil)
	ec.Collect("10.0.0.2", "test", 20.0, ResponseB, nil)

	ec.Clear()
	if ec.Count() != 0 {
		t.Errorf("expected 0 after Clear, got %d", ec.Count())
	}
	if ec.ChainHead() != "" {
		t.Error("ChainHead should be empty after Clear")
	}
}

func TestEvidenceCollector_ChainHead(t *testing.T) {
	ec := NewEvidenceCollector(100, "/tmp/test_evidence_head.json")
	if ec.ChainHead() != "" {
		t.Error("ChainHead should be empty initially")
	}

	r := ec.Collect("10.0.0.1", "test", 10.0, ResponseA, nil)
	if ec.ChainHead() != r.Hash {
		t.Error("ChainHead should match last record's hash")
	}
}
