package suricata

import (
	"slices"
	"testing"
)

func TestACAutomaton_Basic(t *testing.T) {
	rules := []*Rule{
		{Contents: []ContentMatch{{Pattern: []byte("hello")}}},
		{Contents: []ContentMatch{{Pattern: []byte("world")}}},
	}
	a := newACAutomaton()
	a.build(rules)

	indices := a.matchAll([]byte("say hello world"))
	if !slices.Contains(indices, 0) {
		t.Error("expected rule 0 (hello) to match")
	}
	if !slices.Contains(indices, 1) {
		t.Error("expected rule 1 (world) to match")
	}
}

func TestACAutomaton_MultiplePatterns(t *testing.T) {
	rules := []*Rule{
		{Contents: []ContentMatch{{Pattern: []byte("foo")}}},
		{Contents: []ContentMatch{{Pattern: []byte("bar")}}},
		{Contents: []ContentMatch{{Pattern: []byte("baz")}}},
	}
	a := newACAutomaton()
	a.build(rules)

	indices := a.matchAll([]byte("foo and bar and baz"))
	expected := []int{0, 1, 2}
	for _, e := range expected {
		if !slices.Contains(indices, e) {
			t.Errorf("expected rule %d to match", e)
		}
	}
	if len(indices) != 3 {
		t.Errorf("expected 3 matches, got %d: %v", len(indices), indices)
	}
}

func TestACAutomaton_NoMatch(t *testing.T) {
	rules := []*Rule{
		{Contents: []ContentMatch{{Pattern: []byte("hello")}}},
		{Contents: []ContentMatch{{Pattern: []byte("world")}}},
	}
	a := newACAutomaton()
	a.build(rules)

	indices := a.matchAll([]byte("goodbye universe"))
	if len(indices) != 0 {
		t.Errorf("expected no matches, got %v", indices)
	}
}

func TestACAutomaton_OverlappingPatterns(t *testing.T) {
	// Classic Aho-Corasick test: "he", "she", "his", "hers"
	rules := []*Rule{
		{Contents: []ContentMatch{{Pattern: []byte("he")}}},
		{Contents: []ContentMatch{{Pattern: []byte("she")}}},
		{Contents: []ContentMatch{{Pattern: []byte("his")}}},
		{Contents: []ContentMatch{{Pattern: []byte("hers")}}},
	}
	a := newACAutomaton()
	a.build(rules)

	indices := a.matchAll([]byte("ushers"))
	// "ushers" contains "she" (at pos 1) and "he" (at pos 2), "hers" (at pos 1)
	expected := []int{0, 1, 3}
	for _, e := range expected {
		if !slices.Contains(indices, e) {
			t.Errorf("expected rule %d to match in 'ushers'", e)
		}
	}
	if len(indices) != len(expected) {
		t.Errorf("expected %d matches in 'ushers', got %d: %v", len(expected), len(indices), indices)
	}
}

func TestACAutomaton_HexPattern(t *testing.T) {
	// Binary pattern: NOP sled \x90\x90\x90
	rules := []*Rule{
		{Contents: []ContentMatch{{Pattern: []byte{0x90, 0x90, 0x90}}}},
		{Contents: []ContentMatch{{Pattern: []byte("GET")}}},
	}
	a := newACAutomaton()
	a.build(rules)

	data := []byte{0x01, 0x90, 0x90, 0x90, 0x02}
	indices := a.matchAll(data)
	if !slices.Contains(indices, 0) {
		t.Error("expected rule 0 (NOP sled) to match")
	}
	if len(indices) != 1 {
		t.Errorf("expected exactly 1 match, got %d: %v", len(indices), indices)
	}
}

func TestACAutomaton_EmptyPattern(t *testing.T) {
	rules := []*Rule{
		{Contents: []ContentMatch{{Pattern: []byte("")}}},
		{Contents: []ContentMatch{{Pattern: []byte("hello")}}},
	}
	a := newACAutomaton()
	a.build(rules)

	indices := a.matchAll([]byte("hello"))
	// Empty pattern should not crash; should still match "hello"
	if !slices.Contains(indices, 1) {
		t.Error("expected rule 1 (hello) to match")
	}
}

func TestACAutomaton_BuiltinDedup(t *testing.T) {
	// Same rule matched multiple times should return single entry
	rules := []*Rule{
		{Contents: []ContentMatch{{Pattern: []byte("aa")}}},
	}
	a := newACAutomaton()
	a.build(rules)

	indices := a.matchAll([]byte("aaaa"))
	if len(indices) != 1 {
		t.Errorf("expected dedup: 1 match, got %d: %v", len(indices), indices)
	}
	if indices[0] != 0 {
		t.Errorf("expected rule index 0, got %d", indices[0])
	}
}

func TestACAutomaton_MultipleRulesSamePattern(t *testing.T) {
	// Two different rules with the same pattern should both match
	rules := []*Rule{
		{Contents: []ContentMatch{{Pattern: []byte("test")}}},
		{Contents: []ContentMatch{{Pattern: []byte("test")}}},
	}
	a := newACAutomaton()
	a.build(rules)

	indices := a.matchAll([]byte("this is a test"))
	if len(indices) != 2 {
		t.Errorf("expected both rules (0 and 1) to match, got %d: %v", len(indices), indices)
	}
	if !slices.Contains(indices, 0) {
		t.Error("expected rule 0 to match")
	}
	if !slices.Contains(indices, 1) {
		t.Error("expected rule 1 to match")
	}
}

func TestACAutomaton_LargeInput(t *testing.T) {
	// Verify O(n) behavior doesn't blow up on larger input
	rules := []*Rule{
		{Contents: []ContentMatch{{Pattern: []byte("needle")}}},
	}
	a := newACAutomaton()
	a.build(rules)

	data := make([]byte, 100000)
	for i := 0; i < len(data); i++ {
		data[i] = 'a'
	}
	copy(data[50000:], []byte("needle"))

	indices := a.matchAll(data)
	if len(indices) != 1 {
		t.Errorf("expected 1 match, got %d", len(indices))
	}
}
