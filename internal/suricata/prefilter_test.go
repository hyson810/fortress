package suricata

import (
	"slices"
	"testing"
)

func makePortRules() []*Rule {
	return []*Rule{
		// Index 0: TCP rule on port 80
		{
			Proto:   ProtoTCP,
			DstPort: "80",
			Meta:    RuleMeta{SID: 1},
		},
		// Index 1: UDP rule from port 53
		{
			Proto:   ProtoUDP,
			SrcPort: "53",
			Meta:    RuleMeta{SID: 2},
		},
		// Index 2: IP (any protocol) rule
		{
			Proto: ProtoIP,
			Meta:  RuleMeta{SID: 3},
		},
		// Index 3: TCP rule on port 8080
		{
			Proto:   ProtoTCP,
			DstPort: "8080",
			Meta:    RuleMeta{SID: 4},
		},
		// Index 4: UDP rule with "any" port (should be skipped)
		{
			Proto:   ProtoUDP,
			DstPort: "any",
			Meta:    RuleMeta{SID: 5},
		},
		// Index 5: TCP rule with empty src port (should be skipped)
		{
			Proto:   ProtoTCP,
			SrcPort: "",
			DstPort: "443",
			Meta:    RuleMeta{SID: 6},
		},
	}
}

func TestPrefilter_PortMatch(t *testing.T) {
	rules := makePortRules()
	pf := NewPrefilter(rules)

	candidates := pf.CandidateRules(ProtoTCP, 0, 80)

	if len(candidates) == 0 {
		t.Fatal("expected at least one candidate for TCP port 80, got none")
	}

	// Should include rule index 0 (TCP dstPort 80) and index 2 (IP rule)
	expected := []int{0, 2}
	for _, e := range expected {
		if !slices.Contains(candidates, e) {
			t.Errorf("expected candidate rule index %d (SID %d) to match TCP port 80", e, rules[e].Meta.SID)
		}
	}

	// Should NOT include rule 1 (UDP), 3 (TCP 8080), 4 (UDP any), 5 (TCP 443)
	notExpected := []int{1, 3, 4, 5}
	for _, ne := range notExpected {
		if slices.Contains(candidates, ne) {
			t.Errorf("did not expect candidate rule index %d (SID %d) for TCP port 80", ne, rules[ne].Meta.SID)
		}
	}
}

func TestPrefilter_SrcPortMatch(t *testing.T) {
	rules := makePortRules()
	pf := NewPrefilter(rules)

	candidates := pf.CandidateRules(ProtoUDP, 53, 0)

	if len(candidates) == 0 {
		t.Fatal("expected at least one candidate for UDP src port 53, got none")
	}

	// Should include rule index 1 (UDP srcPort 53) and index 2 (IP rule)
	expected := []int{1, 2}
	for _, e := range expected {
		if !slices.Contains(candidates, e) {
			t.Errorf("expected candidate rule index %d (SID %d) to match UDP src port 53", e, rules[e].Meta.SID)
		}
	}

	// Should NOT include TCP rules or unrelated UDP rules
	notExpected := []int{0, 3, 4, 5}
	for _, ne := range notExpected {
		if slices.Contains(candidates, ne) {
			t.Errorf("did not expect candidate rule index %d (SID %d) for UDP src port 53", ne, rules[ne].Meta.SID)
		}
	}
}

func TestPrefilter_IPRulesAlwaysMatch(t *testing.T) {
	rules := makePortRules()
	pf := NewPrefilter(rules)

	// IP rules should be returned regardless of protocol or ports
	candidates := pf.CandidateRules(ProtoICMP, 0, 0)

	if len(candidates) == 0 {
		t.Fatal("expected at least one candidate for ICMP, got none")
	}

	// Should include IP rule (index 2) but not any port-specific rules
	if !slices.Contains(candidates, 2) {
		t.Error("expected IP rule index 2 to always be a candidate")
	}

	// Should NOT include TCP or UDP specific rules
	for _, idx := range []int{0, 1, 3} {
		if slices.Contains(candidates, idx) {
			t.Errorf("did not expect port-specific rule index %d for ICMP", idx)
		}
	}
}

func TestPrefilter_PortMismatch(t *testing.T) {
	rules := makePortRules()
	pf := NewPrefilter(rules)

	// UDP packet to port 80 should NOT match TCP rule on port 80
	candidates := pf.CandidateRules(ProtoUDP, 0, 80)

	if slices.Contains(candidates, 0) {
		t.Error("TCP rule should not match UDP packet even on same port")
	}
}

func TestPrefilter_Empty(t *testing.T) {
	pf := NewPrefilter(nil)

	candidates := pf.CandidateRules(ProtoTCP, 0, 80)
	if len(candidates) != 0 {
		t.Errorf("expected empty candidates, got %v", candidates)
	}

	pf2 := NewPrefilter([]*Rule{})
	candidates2 := pf2.CandidateRules(ProtoTCP, 0, 80)
	if len(candidates2) != 0 {
		t.Errorf("expected empty candidates, got %v", candidates2)
	}
}

func TestPrefilter_MultipleRulesSamePort(t *testing.T) {
	rules := []*Rule{
		{Proto: ProtoTCP, DstPort: "80", Meta: RuleMeta{SID: 1}},
		{Proto: ProtoTCP, DstPort: "80", Meta: RuleMeta{SID: 2}},
		{Proto: ProtoTCP, DstPort: "443", Meta: RuleMeta{SID: 3}},
	}
	pf := NewPrefilter(rules)

	candidates := pf.CandidateRules(ProtoTCP, 0, 80)

	if len(candidates) != 2 {
		t.Errorf("expected 2 candidates for TCP port 80, got %d: %v", len(candidates), candidates)
	}

	if !slices.Contains(candidates, 0) || !slices.Contains(candidates, 1) {
		t.Error("expected both rule indices 0 and 1 for TCP port 80")
	}
}

func TestPrefilter_NoPortRules(t *testing.T) {
	rules := []*Rule{
		{Proto: ProtoTCP, DstPort: "any", SrcPort: "any", Meta: RuleMeta{SID: 1}},
		{Proto: ProtoUDP, DstPort: "", SrcPort: "", Meta: RuleMeta{SID: 2}},
	}
	pf := NewPrefilter(rules)

	// These rules have "any"/"" ports so they should not be indexed.
	// Only IP rules would always match. For TCP/UDP, no port-indexed rules exist.
	candidates := pf.CandidateRules(ProtoTCP, 0, 80)
	if len(candidates) != 0 {
		t.Errorf("expected no candidates for no-port TCP rules, got %d: %v", len(candidates), candidates)
	}

	candidates2 := pf.CandidateRules(ProtoUDP, 0, 80)
	if len(candidates2) != 0 {
		t.Errorf("expected no candidates for no-port UDP rules, got %d: %v", len(candidates2), candidates2)
	}
}
