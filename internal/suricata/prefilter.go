package suricata

import (
	"strconv"
)

// Prefilter provides O(1) candidate filtering of Suricata rules by protocol
// and port, reducing the number of rules that need expensive pattern matching.
type Prefilter struct {
	tcpDstPort map[uint16][]int // dstPort -> rule indices
	tcpSrcPort map[uint16][]int // srcPort -> rule indices
	udpDstPort map[uint16][]int
	udpSrcPort map[uint16][]int
	ipRules    []int // protocol-agnostic (IP) rules always returned
}

// NewPrefilter builds a prefilter index from rules.
func NewPrefilter(rules []*Rule) *Prefilter {
	p := &Prefilter{
		tcpDstPort: make(map[uint16][]int),
		tcpSrcPort: make(map[uint16][]int),
		udpDstPort: make(map[uint16][]int),
		udpSrcPort: make(map[uint16][]int),
	}

	for idx, rule := range rules {
		switch rule.Proto {
		case ProtoTCP:
			if port := parsePort(rule.SrcPort); port != 0 {
				p.tcpSrcPort[port] = append(p.tcpSrcPort[port], idx)
			}
			if port := parsePort(rule.DstPort); port != 0 {
				p.tcpDstPort[port] = append(p.tcpDstPort[port], idx)
			}
		case ProtoUDP:
			if port := parsePort(rule.SrcPort); port != 0 {
				p.udpSrcPort[port] = append(p.udpSrcPort[port], idx)
			}
			if port := parsePort(rule.DstPort); port != 0 {
				p.udpDstPort[port] = append(p.udpDstPort[port], idx)
			}
		case ProtoIP:
			p.ipRules = append(p.ipRules, idx)
		case ProtoICMP:
			p.ipRules = append(p.ipRules, idx)
		}
	}

	return p
}

// CandidateRules returns rule indices that COULD match a packet with the given
// protocol, source port, and destination port. This is used before the
// expensive AC automaton to filter out irrelevant rules.
func (p *Prefilter) CandidateRules(proto Proto, srcPort, dstPort uint16) []int {
	seen := make(map[int]struct{})
	var result []int

	// Protocol-agnostic (IP) rules always match.
	for _, idx := range p.ipRules {
		if _, ok := seen[idx]; !ok {
			seen[idx] = struct{}{}
			result = append(result, idx)
		}
	}

	switch proto {
	case ProtoTCP:
		if indices, ok := p.tcpDstPort[dstPort]; ok {
			for _, idx := range indices {
				if _, ok := seen[idx]; !ok {
					seen[idx] = struct{}{}
					result = append(result, idx)
				}
			}
		}
		if indices, ok := p.tcpSrcPort[srcPort]; ok {
			for _, idx := range indices {
				if _, ok := seen[idx]; !ok {
					seen[idx] = struct{}{}
					result = append(result, idx)
				}
			}
		}
	case ProtoUDP:
		if indices, ok := p.udpDstPort[dstPort]; ok {
			for _, idx := range indices {
				if _, ok := seen[idx]; !ok {
					seen[idx] = struct{}{}
					result = append(result, idx)
				}
			}
		}
		if indices, ok := p.udpSrcPort[srcPort]; ok {
			for _, idx := range indices {
				if _, ok := seen[idx]; !ok {
					seen[idx] = struct{}{}
					result = append(result, idx)
				}
			}
		}
	default:
		// ICMP and other protocols: only protocol-agnostic rules are returned.
	}

	return result
}

// parsePort converts a port string to uint16.
// Returns 0 for "any" or "" (meaning not set).
func parsePort(s string) uint16 {
	if s == "" || s == "any" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(v)
}
