package suricata

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRuleset_NewEmpty(t *testing.T) {
	_, err := NewRuleset(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestRuleset_LoadAndMatch(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `alert tcp any any -> any 80 (msg:"Test HTTP Rule"; content:"GET"; nocase; sid:1000001; rev:1;)
alert udp any any -> any 53 (msg:"Test DNS Rule"; content:"|01 00 00 01|"; sid:1000002; rev:1;)`
	ruleFile := filepath.Join(dir, "test.rules")
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	rs, err := NewRuleset(dir)
	if err != nil {
		t.Fatal(err)
	}

	if rs.RuleCount() != 2 {
		t.Fatalf("expected 2 rules, got %d", rs.RuleCount())
	}

	matches := rs.MatchAC([]byte("GET /index.html HTTP/1.1"))
	if len(matches) == 0 {
		t.Fatal("expected at least one match for GET content")
	}

	matches = rs.MatchAC([]byte("no match here"))
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for unrelated data, got %d", len(matches))
	}
}

func TestRuleset_Reload(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `alert tcp any any -> any 80 (msg:"Rule 1"; content:"GET"; sid:1000001; rev:1;)`
	ruleFile := filepath.Join(dir, "test.rules")
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	rs, err := NewRuleset(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rs.RuleCount() != 1 {
		t.Fatalf("expected 1 rule, got %d", rs.RuleCount())
	}

	// Add another rule and reload.
	newContent := ruleContent + "\nalert udp any any -> any 53 (msg:\"Rule 2\"; content:\"dns\"; sid:1000002; rev:1;)"
	if err := os.WriteFile(ruleFile, []byte(newContent), 0644); err != nil {
		t.Fatal(err)
	}

	if err := rs.Reload(); err != nil {
		t.Fatal(err)
	}
	if rs.RuleCount() != 2 {
		t.Fatalf("expected 2 rules after reload, got %d", rs.RuleCount())
	}
}

func TestRuleset_ConcurrentRead(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `alert tcp any any -> any 80 (msg:"Test"; content:"GET"; sid:1000001; rev:1;)`
	ruleFile := filepath.Join(dir, "test.rules")
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	rs, err := NewRuleset(dir)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup

	// Start 10 reader goroutines.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				rs.RuleCount()
				rs.Candidates(ProtoTCP, 0, 80)
				rs.MatchAC([]byte("GET / HTTP/1.1"))
				rs.Rules()
			}
		}()
	}

	// Simultaneously reload.
	wg.Add(1)
	go func() {
		defer wg.Done()
		newContent := ruleContent + "\nalert udp any any -> any 53 (msg:\"DNS Test\"; content:\"dns\"; sid:1000002; rev:1;)"
		if err := os.WriteFile(ruleFile, []byte(newContent), 0644); err != nil {
			t.Errorf("failed to write updated rules: %v", err)
		}
		if err := rs.Reload(); err != nil {
			t.Errorf("reload failed: %v", err)
		}
	}()

	wg.Wait()
}

func TestRuleset_RuleCount(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `alert tcp any any -> any 80 (msg:"Rule 1"; content:"GET"; sid:1000001; rev:1;)
alert udp any any -> any 53 (msg:"Rule 2"; content:"dns"; sid:1000002; rev:1;)
alert icmp any any -> any any (msg:"Rule 3"; dsize:8<>100; sid:1000003; rev:1;)`
	ruleFile := filepath.Join(dir, "test.rules")
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	rs, err := NewRuleset(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rs.RuleCount() != 3 {
		t.Fatalf("expected 3 rules, got %d", rs.RuleCount())
	}
}

func TestRuleset_Candidates(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `alert tcp any any -> any 80 (msg:"HTTP Rule"; content:"GET"; sid:1000001; rev:1;)
alert udp any any -> any 53 (msg:"DNS Rule"; content:"dns"; sid:1000002; rev:1;)
alert ip any any -> any any (msg:"IP Rule"; content:"|ff|"; sid:1000003; rev:1;)`
	ruleFile := filepath.Join(dir, "test.rules")
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	rs, err := NewRuleset(dir)
	if err != nil {
		t.Fatal(err)
	}

	// TCP on port 80 should return at least the HTTP rule.
	candidates := rs.Candidates(ProtoTCP, 0, 80)
	if len(candidates) == 0 {
		t.Fatal("expected at least one TCP candidate on port 80")
	}

	// UDP on port 53 should return at least the DNS rule.
	candidates = rs.Candidates(ProtoUDP, 0, 53)
	if len(candidates) == 0 {
		t.Fatal("expected at least one UDP candidate on port 53")
	}

	// ICMP (any port) should return IP rules as fallback candidates.
	candidates = rs.Candidates(ProtoICMP, 0, 0)
	if len(candidates) == 0 {
		t.Fatal("expected IP rules as candidates for any protocol")
	}
}
