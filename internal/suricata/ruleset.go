package suricata

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Ruleset manages a collection of Suricata rules with hot-reload support.
type Ruleset struct {
	mu        sync.RWMutex
	rules     []*Rule
	prefilter *Prefilter
	automaton *acAutomaton
	path      string
}

// NewRuleset creates a new Ruleset by loading rules from the given directory.
func NewRuleset(path string) (*Ruleset, error) {
	rs := &Ruleset{path: path}
	if err := rs.Load(); err != nil {
		return nil, fmt.Errorf("suricata: NewRuleset: %w", err)
	}
	return rs, nil
}

// Load reads all .rules files from the directory, parses each line,
// and builds the prefilter and automaton indices.
func (rs *Ruleset) Load() error {
	info, err := os.Stat(rs.path)
	if err != nil {
		return fmt.Errorf("cannot access rules directory %q: %w", rs.path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", rs.path)
	}

	entries, err := os.ReadDir(rs.path)
	if err != nil {
		return fmt.Errorf("failed to read rules directory %q: %w", rs.path, err)
	}

	var allRules []*Rule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rules") {
			continue
		}
		filePath := filepath.Join(rs.path, entry.Name())
		fileRules, loadErr := loadRuleFile(filePath)
		if loadErr != nil {
			// Log and skip — don't abort on a single bad rule file.
			continue
		}
		allRules = append(allRules, fileRules...)
	}

	// Build indices.
	prefilter := NewPrefilter(allRules)
	automaton := newACAutomaton()
	automaton.build(allRules)

	rs.mu.Lock()
	rs.rules = allRules
	rs.prefilter = prefilter
	rs.automaton = automaton
	rs.mu.Unlock()
	return nil
}

// Reload re-reads all .rules files from the directory and rebuilds indices.
// Intended for hot-reload (SIGHUP equivalent).
func (rs *Ruleset) Reload() error {
	return rs.Load()
}

// Candidates returns rule indices that could match the given protocol and ports.
// Thread-safe — holds RLock during lookup.
func (rs *Ruleset) Candidates(proto Proto, srcPort, dstPort uint16) []int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if rs.prefilter == nil {
		return nil
	}
	return rs.prefilter.CandidateRules(proto, srcPort, dstPort)
}

// MatchAC runs the Aho-Corasick automaton against data and returns matching
// rule indices. Thread-safe — holds RLock during matching.
func (rs *Ruleset) MatchAC(data []byte) []int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if rs.automaton == nil {
		return nil
	}
	return rs.automaton.matchAll(data)
}

// RuleCount returns the number of currently loaded rules.
func (rs *Ruleset) RuleCount() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return len(rs.rules)
}

// Rules returns a snapshot of the currently loaded rules (for engine use).
func (rs *Ruleset) Rules() []*Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	result := make([]*Rule, len(rs.rules))
	copy(result, rs.rules)
	return result
}

// loadRuleFile reads a single .rules file and returns all successfully parsed rules.
// Lines that fail to parse are silently skipped.
func loadRuleFile(path string) ([]*Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []*Rule
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		rule, parseErr := ParseRule(line)
		if parseErr != nil {
			// Skip individual bad lines.
			continue
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}
	if err := scanner.Err(); err != nil {
		return rules, err
	}
	return rules, nil
}
