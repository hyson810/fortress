package suricata

import (
	"testing"
)

// BenchmarkACAutomaton_1000Rules benchmarks Aho-Corasick matching against an
// automaton built with 1000 rules, each containing a 2-byte pattern.
func BenchmarkACAutomaton_1000Rules(b *testing.B) {
	rules := make([]*Rule, 1000)
	for i := range rules {
		rules[i] = &Rule{
			Contents: []ContentMatch{
				{Pattern: []byte{byte(i % 256), byte((i + 1) % 256)}},
			},
			Meta: RuleMeta{SID: i + 1},
		}
	}

	a := newACAutomaton()
	a.build(rules)

	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.matchAll(data)
	}
}

// BenchmarkACAutomaton_10000Rules benchmarks Aho-Corasick matching against an
// automaton built with 10000 rules, each containing a 2-byte pattern.
func BenchmarkACAutomaton_10000Rules(b *testing.B) {
	rules := make([]*Rule, 10000)
	for i := range rules {
		rules[i] = &Rule{
			Contents: []ContentMatch{
				{Pattern: []byte{byte(i % 256), byte((i + 1) % 256)}},
			},
			Meta: RuleMeta{SID: i + 1},
		}
	}

	a := newACAutomaton()
	a.build(rules)

	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.matchAll(data)
	}
}

// BenchmarkPrefilter_10000Rules benchmarks CandidateRules lookup against a
// prefilter built with 10000 rules (5000 TCP on port 80, 5000 ProtoIP).
func BenchmarkPrefilter_10000Rules(b *testing.B) {
	rules := make([]*Rule, 10000)
	for i := range rules {
		if i < 5000 {
			rules[i] = &Rule{Proto: ProtoTCP, DstPort: "80", Meta: RuleMeta{SID: i}}
		} else {
			rules[i] = &Rule{Proto: ProtoIP, Meta: RuleMeta{SID: i}}
		}
	}
	p := NewPrefilter(rules)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.CandidateRules(ProtoTCP, 12345, 80)
	}
}

// BenchmarkParseRule benchmarks parsing a realistic Suricata rule string.
func BenchmarkParseRule(b *testing.B) {
	ruleStr := `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; content:"union|20|select"; nocase; classtype:web-application-attack; sid:2024210; rev:4;)`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseRule(ruleStr)
	}
}
