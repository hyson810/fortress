// Package suricata provides a parser for Suricata-compatible rules.
package suricata

import (
	"fmt"
	"strconv"
	"strings"
)

// Action represents the action a rule takes when matched.
type Action string

const (
	ActionAlert  Action = "alert"
	ActionPass   Action = "pass"
	ActionDrop   Action = "drop"
	ActionReject Action = "reject"
)

// Proto represents the network protocol a rule matches.
type Proto string

const (
	ProtoTCP  Proto = "tcp"
	ProtoUDP  Proto = "udp"
	ProtoICMP Proto = "icmp"
	ProtoIP   Proto = "ip"
)

// ContentMatch describes a content match pattern and its modifiers.
type ContentMatch struct {
	Pattern  []byte
	Nocase   bool
	Offset   int // -1 = not set
	Depth    int // -1 = not set
	Distance int // -1 = not set
	Within   int // -1 = not set
}

// RuleMeta holds metadata fields parsed from a rule.
type RuleMeta struct {
	SID       int
	Rev       int
	GID       int
	Msg       string
	Classtype string
	Reference string
}

// Rule represents a single Suricata rule.
type Rule struct {
	Action   Action
	Proto    Proto
	SrcNet   string
	SrcPort  string
	DstNet   string
	DstPort  string
	Contents []ContentMatch
	DSize    []int // [min, max] or nil
	Flags    string
	Meta     RuleMeta
}

// ParseRule parses a single Suricata rule line into a Rule struct.
// Empty lines and comment lines (starting with #) return nil, nil.
func ParseRule(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	// Locate the options block between '(' and the matching ')'.
	// Use a paren-balancing scanner that skips quoted regions to handle
	// parentheses inside quoted option values (e.g. msg:"Something (TEST)").
	parenStart := strings.Index(line, "(")
	var parenEnd int = -1
	if parenStart >= 0 {
		parenEnd = findClosingParen(line, parenStart)
	}

	var headerPart string
	var optionsPart string

	if parenStart >= 0 && parenEnd > parenStart {
		headerPart = strings.TrimSpace(line[:parenStart])
		optionsPart = line[parenStart+1 : parenEnd]
	} else {
		headerPart = line
	}

	// Parse the rule header.
	action, proto, srcNet, srcPort, dstNet, dstPort, err := parseHeader(headerPart)
	if err != nil {
		return nil, err
	}

	r := &Rule{
		Action:  action,
		Proto:   proto,
		SrcNet:  srcNet,
		SrcPort: srcPort,
		DstNet:  dstNet,
		DstPort: dstPort,
	}

	if optionsPart != "" {
		if err := r.parseOptions(optionsPart); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// parseHeader parses the 7-token rule header.
func parseHeader(h string) (Action, Proto, string, string, string, string, error) {
	parts := strings.Fields(h)
	if len(parts) < 7 {
		return "", "", "", "", "", "", fmt.Errorf("suricata: malformed rule header: %q", h)
	}

	action := Action(parts[0])
	proto := Proto(parts[1])
	srcNet := parts[2]
	srcPort := parts[3]
	direction := parts[4]
	dstNet := parts[5]
	dstPort := parts[6]

	if direction != "->" && direction != "<>" {
		return "", "", "", "", "", "", fmt.Errorf("suricata: invalid direction %q in header: %q", direction, h)
	}

	return action, proto, srcNet, srcPort, dstNet, dstPort, nil
}

// parseOptions processes the options string (content between parens).
func (r *Rule) parseOptions(optsStr string) error {
	opts := splitOptions(optsStr)

	for _, opt := range opts {
		if err := r.applyOption(opt); err != nil {
			return err
		}
	}
	return nil
}

// applyOption applies a single key:value or flag option to the Rule.
func (r *Rule) applyOption(opt string) error {
	// Check for key:value vs flag option.
	colonIdx := strings.Index(opt, ":")
	var key, value string
	if colonIdx >= 0 {
		key = strings.TrimSpace(opt[:colonIdx])
		value = strings.TrimSpace(opt[colonIdx+1:])
	} else {
		key = strings.TrimSpace(opt)
		value = ""
	}

	switch key {
	case "msg":
		r.Meta.Msg = strings.Trim(value, `"`)
	case "sid":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("suricata: invalid sid %q", value)
		}
		r.Meta.SID = v
	case "rev":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("suricata: invalid rev %q", value)
		}
		r.Meta.Rev = v
	case "gid":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("suricata: invalid gid %q", value)
		}
		r.Meta.GID = v
	case "classtype":
		r.Meta.Classtype = value
	case "reference":
		r.Meta.Reference = value
	case "content":
		cm := ContentMatch{
			Offset:   -1,
			Depth:    -1,
			Distance: -1,
			Within:   -1,
		}
		cm.Pattern = parseContentPattern(value)
		r.Contents = append(r.Contents, cm)
	case "nocase":
		if len(r.Contents) > 0 {
			r.Contents[len(r.Contents)-1].Nocase = true
		}
	case "offset":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("suricata: invalid offset %q", value)
		}
		if len(r.Contents) > 0 {
			r.Contents[len(r.Contents)-1].Offset = v
		}
	case "depth":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("suricata: invalid depth %q", value)
		}
		if len(r.Contents) > 0 {
			r.Contents[len(r.Contents)-1].Depth = v
		}
	case "distance":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("suricata: invalid distance %q", value)
		}
		if len(r.Contents) > 0 {
			r.Contents[len(r.Contents)-1].Distance = v
		}
	case "within":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("suricata: invalid within %q", value)
		}
		if len(r.Contents) > 0 {
			r.Contents[len(r.Contents)-1].Within = v
		}
	case "dsize":
		parts := strings.Split(value, "<>")
		if len(parts) == 2 {
			min, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			max, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				return fmt.Errorf("suricata: invalid dsize range %q", value)
			}
			r.DSize = []int{min, max}
		} else {
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("suricata: invalid dsize %q", value)
			}
			r.DSize = []int{v, v}
		}
	case "flags":
		r.Flags = value
	// Ignore unknown options (content modifiers, flow, etc.)
	default:
	}

	return nil
}

// splitOptions splits the options string on semicolons, respecting
// quoted strings so semicolons inside quotes are not treated as delimiters.
func splitOptions(optsStr string) []string {
	var opts []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(optsStr); i++ {
		c := optsStr[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			current.WriteByte(c)
		case c == ';' && !inQuote:
			s := strings.TrimSpace(current.String())
			if s != "" {
				opts = append(opts, s)
			}
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	// Handle last segment.
	s := strings.TrimSpace(current.String())
	if s != "" {
		opts = append(opts, s)
	}
	return opts
}

// findClosingParen finds the matching ')' for a '(' at position start in line,
// skipping over quoted strings so parentheses inside quotes are ignored.
func findClosingParen(line string, start int) int {
	depth := 1
	inQuote := false
	for i := start + 1; i < len(line); i++ {
		switch {
		case line[i] == '"':
			inQuote = !inQuote
		case line[i] == '(' && !inQuote:
			depth++
		case line[i] == ')' && !inQuote:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// parseContentPattern parses a content pattern string (with surrounding quotes removed)
// that may contain hex segments delimited by |...|.
//
// Examples:
//
//	"GET"             -> []byte("GET")
//	"|90 90 90|"      -> []byte{0x90, 0x90, 0x90}
//	"union|20|select" -> []byte("union") + []byte{0x20} + []byte("select")
func parseContentPattern(quoted string) []byte {
	// Strip surrounding quotes.
	v := strings.Trim(quoted, `"`)

	// Split by | to handle hex segments.
	parts := strings.Split(v, "|")

	var result []byte
	for i, part := range parts {
		if i%2 == 0 {
			// Even index: text segment.
			result = append(result, []byte(part)...)
		} else {
			// Odd index: hex segment.
			hexStr := strings.TrimSpace(part)
			if hexStr != "" {
				hexBytes := strings.Fields(hexStr)
				for _, h := range hexBytes {
					b, err := strconv.ParseUint(h, 16, 8)
					if err == nil {
						result = append(result, byte(b))
					}
				}
			}
		}
	}
	return result
}
