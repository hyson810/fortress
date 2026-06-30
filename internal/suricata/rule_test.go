package suricata

import (
	"testing"
)

func TestParseRule_Basic(t *testing.T) {
	ruleStr := `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET TROJAN Test"; content:"GET"; nocase; http_method; classtype:trojan-activity; sid:12345; rev:1;)`
	rule, err := ParseRule(ruleStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule == nil {
		t.Fatal("expected rule, got nil")
	}
	if rule.Action != ActionAlert {
		t.Errorf("expected ActionAlert, got %s", rule.Action)
	}
	if rule.Proto != ProtoTCP {
		t.Errorf("expected ProtoTCP, got %s", rule.Proto)
	}
	if rule.SrcNet != "$HOME_NET" {
		t.Errorf("expected $HOME_NET, got %s", rule.SrcNet)
	}
	if rule.SrcPort != "any" {
		t.Errorf("expected any, got %s", rule.SrcPort)
	}
	if rule.DstNet != "$EXTERNAL_NET" {
		t.Errorf("expected $EXTERNAL_NET, got %s", rule.DstNet)
	}
	if rule.DstPort != "$HTTP_PORTS" {
		t.Errorf("expected $HTTP_PORTS, got %s", rule.DstPort)
	}
	if rule.Meta.SID != 12345 {
		t.Errorf("expected SID 12345, got %d", rule.Meta.SID)
	}
	if rule.Meta.Rev != 1 {
		t.Errorf("expected Rev 1, got %d", rule.Meta.Rev)
	}
	if rule.Meta.Msg != "ET TROJAN Test" {
		t.Errorf("expected msg 'ET TROJAN Test', got '%s'", rule.Meta.Msg)
	}
	if rule.Meta.Classtype != "trojan-activity" {
		t.Errorf("expected classtype 'trojan-activity', got '%s'", rule.Meta.Classtype)
	}
	if len(rule.Contents) != 1 {
		t.Fatalf("expected 1 content match, got %d", len(rule.Contents))
	}
	if string(rule.Contents[0].Pattern) != "GET" {
		t.Errorf("expected pattern 'GET', got '%s'", string(rule.Contents[0].Pattern))
	}
	if !rule.Contents[0].Nocase {
		t.Errorf("expected nocase to be true")
	}
}

func TestParseRule_Comment(t *testing.T) {
	rule, err := ParseRule("# This is a comment")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule != nil {
		t.Fatal("expected nil for comment line")
	}
}

func TestParseRule_Empty(t *testing.T) {
	rule, err := ParseRule("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule != nil {
		t.Fatal("expected nil for empty line")
	}
}

func TestParseRule_DSize(t *testing.T) {
	ruleStr := `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Test DSize"; dsize:100<>200; sid:1; rev:1;)`
	rule, err := ParseRule(ruleStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule == nil {
		t.Fatal("expected rule, got nil")
	}
	if rule.DSize == nil {
		t.Fatal("expected DSize to be set")
	}
	if len(rule.DSize) != 2 {
		t.Fatalf("expected DSize to have 2 elements, got %d", len(rule.DSize))
	}
	if rule.DSize[0] != 100 {
		t.Errorf("expected DSize min 100, got %d", rule.DSize[0])
	}
	if rule.DSize[1] != 200 {
		t.Errorf("expected DSize max 200, got %d", rule.DSize[1])
	}
}

func TestParseRule_HexContent(t *testing.T) {
	ruleStr := `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"NOP Sled"; content:"|90 90 90|"; sid:2; rev:1;)`
	rule, err := ParseRule(ruleStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule == nil {
		t.Fatal("expected rule, got nil")
	}
	if len(rule.Contents) != 1 {
		t.Fatalf("expected 1 content match, got %d", len(rule.Contents))
	}
	expected := []byte{0x90, 0x90, 0x90}
	if len(rule.Contents[0].Pattern) != len(expected) {
		t.Fatalf("expected pattern length %d, got %d", len(expected), len(rule.Contents[0].Pattern))
	}
	for i, b := range expected {
		if rule.Contents[0].Pattern[i] != b {
			t.Errorf("at index %d: expected 0x%02x, got 0x%02x", i, b, rule.Contents[0].Pattern[i])
		}
	}
}

func TestParseRule_MixedContent(t *testing.T) {
	ruleStr := `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Mixed Content"; content:"union|20|select"; sid:3; rev:1;)`
	rule, err := ParseRule(ruleStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule == nil {
		t.Fatal("expected rule, got nil")
	}
	if len(rule.Contents) != 1 {
		t.Fatalf("expected 1 content match, got %d", len(rule.Contents))
	}
	expected := []byte("union")
	expected = append(expected, 0x20)
	expected = append(expected, "select"...)
	if len(rule.Contents[0].Pattern) != len(expected) {
		t.Fatalf("expected pattern length %d, got %d", len(expected), len(rule.Contents[0].Pattern))
	}
	for i, b := range expected {
		if rule.Contents[0].Pattern[i] != b {
			t.Errorf("at index %d: expected 0x%02x, got 0x%02x", i, b, rule.Contents[0].Pattern[i])
		}
	}
}

func TestParseRule_TCPFlags(t *testing.T) {
	ruleStr := `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"TCP Flags"; flags:S; sid:4; rev:1;)`
	rule, err := ParseRule(ruleStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule == nil {
		t.Fatal("expected rule, got nil")
	}
	if rule.Flags != "S" {
		t.Errorf("expected flags 'S', got '%s'", rule.Flags)
	}
}

func TestParseRule_MalformedHeader(t *testing.T) {
	_, err := ParseRule("invalid header no arrow")
	if err == nil {
		t.Fatal("expected error for malformed header, got nil")
	}
}

func TestParseRule_MultipleContent(t *testing.T) {
	ruleStr := `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Multi Content"; content:"first"; content:"second"; nocase; sid:5; rev:1;)`
	rule, err := ParseRule(ruleStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule == nil {
		t.Fatal("expected rule, got nil")
	}
	if len(rule.Contents) != 2 {
		t.Fatalf("expected 2 content matches, got %d", len(rule.Contents))
	}
	if string(rule.Contents[0].Pattern) != "first" {
		t.Errorf("expected pattern 'first', got '%s'", string(rule.Contents[0].Pattern))
	}
	if string(rule.Contents[1].Pattern) != "second" {
		t.Errorf("expected pattern 'second', got '%s'", string(rule.Contents[1].Pattern))
	}
	if !rule.Contents[1].Nocase {
		t.Errorf("expected nocase on second content match")
	}
	if rule.Contents[0].Nocase {
		t.Errorf("expected no nocase on first content match")
	}
}

func TestParseRule_AllActions(t *testing.T) {
	tests := []struct {
		actionStr string
		expected  Action
	}{
		{"alert", ActionAlert},
		{"pass", ActionPass},
		{"drop", ActionDrop},
		{"reject", ActionReject},
	}
	for _, tt := range tests {
		ruleStr := tt.actionStr + ` tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; rev:1;)`
		rule, err := ParseRule(ruleStr)
		if err != nil {
			t.Fatalf("unexpected error for action %s: %v", tt.actionStr, err)
		}
		if rule == nil {
			t.Fatalf("expected rule for action %s, got nil", tt.actionStr)
		}
		if rule.Action != tt.expected {
			t.Errorf("expected action %s, got %s", tt.expected, rule.Action)
		}
	}
}
