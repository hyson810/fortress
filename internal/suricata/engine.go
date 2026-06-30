package suricata

import (
	"bytes"
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fortress/v6/internal/capture"
)

// Alert represents a rule match forwarded to the scoring engine.
type Alert struct {
	SID       int
	Msg       string
	Classtype string
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Timestamp time.Time
	Severity  int
}

// EngineStats tracks engine performance counters using atomic access.
type EngineStats struct {
	PacketsProcessed atomic.Uint64
	PacketsFiltered  atomic.Uint64
	RulesMatched     atomic.Uint64
}

// StatsSnapshot is a point-in-time copy of engine performance counters.
type StatsSnapshot struct {
	PacketsProcessed uint64
	PacketsFiltered  uint64
	RulesMatched     uint64
}

// engineTask holds work for a worker goroutine.
type engineTask struct {
	dp        *capture.DecodedPacket
	payload   []byte
	matchedAC []int // rule indices from AC automaton
	proto     Proto
}

// Engine wraps the Suricata-compatible rule detection pipeline.
// It wires together: capture handler -> dispatcher (prefilter + AC match)
// -> worker pool (full rule matching) -> alert channel.
type Engine struct {
	ruleset *Ruleset
	alertCh chan *Alert
	taskCh  chan *engineTask
	stats   EngineStats
	workers int
	wg      sync.WaitGroup
}

// NewEngine creates an engine, loads the ruleset, and returns a ready engine.
// If workers is <= 0, runtime.NumCPU() is used as the default.
func NewEngine(rulesPath string, workers int) (*Engine, error) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	rs, err := NewRuleset(rulesPath)
	if err != nil {
		return nil, err
	}

	return &Engine{
		ruleset: rs,
		alertCh: make(chan *Alert, 1000),
		taskCh:  make(chan *engineTask, 1000),
		workers: workers,
	}, nil
}

// Start launches the dispatcher goroutine and worker goroutines.
// The engine runs until ctx is cancelled or handler.Packets() is closed.
func (e *Engine) Start(ctx context.Context, handler capture.CaptureHandler) {
	// Start worker goroutines.
	for i := 0; i < e.workers; i++ {
		e.wg.Add(1)
		go e.worker(ctx)
	}

	// Start dispatcher goroutine.
	e.wg.Add(1)
	go e.dispatcher(ctx, handler)
}

// dispatcher reads packets from the capture handler, runs prefiltering and
// AC matching, and dispatches candidate matches to the worker pool.
func (e *Engine) dispatcher(ctx context.Context, handler capture.CaptureHandler) {
	defer close(e.taskCh)
	defer e.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case dp, ok := <-handler.Packets():
			if !ok {
				return
			}

			e.stats.PacketsProcessed.Add(1)

			// Map protocol number to Proto type.
			proto := protoToString(dp.Protocol)

			// Prefilter: narrow candidates by protocol and port.
			candidates := e.ruleset.Candidates(proto, dp.SrcPort, dp.DstPort)
			if len(candidates) == 0 {
				e.stats.PacketsFiltered.Add(1)
				continue
			}

			// Extract application-layer payload.
			payload := extractPayload(dp.Raw)
			if payload == nil {
				continue
			}

			// Run Aho-Corasick multi-pattern matching.
			matchedAC := e.ruleset.MatchAC(payload)
			if len(matchedAC) == 0 {
				e.stats.PacketsFiltered.Add(1)
				continue
			}

			// Dispatch to worker pool (non-blocking).
			task := &engineTask{
				dp:        dp,
				payload:   payload,
				matchedAC: matchedAC,
				proto:     proto,
			}

			select {
			case e.taskCh <- task:
			default:
				// Worker pool saturated — drop packet silently.
			}
		}
	}
}

// worker reads tasks from the dispatcher channel and performs full rule
// matching (dsize, flags, content constraints). On a full match, it sends
// an Alert to the alert channel (non-blocking).
func (e *Engine) worker(ctx context.Context) {
	defer e.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-e.taskCh:
			if !ok {
				return
			}

			rules := e.ruleset.Rules()

			for _, ruleIdx := range task.matchedAC {
				if ruleIdx >= len(rules) {
					continue
				}
				rule := rules[ruleIdx]

				if !ruleFullMatch(rule, task.payload, task.dp.TCPFlags) {
					continue
				}

				e.stats.RulesMatched.Add(1)

				alert := &Alert{
					SID:       rule.Meta.SID,
					Msg:       rule.Meta.Msg,
					Classtype: rule.Meta.Classtype,
					SrcIP:     task.dp.SrcIP,
					DstIP:     task.dp.DstIP,
					SrcPort:   task.dp.SrcPort,
					DstPort:   task.dp.DstPort,
					Protocol:  task.dp.Protocol,
					Timestamp: task.dp.Timestamp,
					Severity:  1,
				}

				// Non-blocking send to alert channel.
				select {
				case e.alertCh <- alert:
				default:
					// Alert channel full — drop alert silently.
				}
			}
		}
	}
}

// Alerts returns a read-only channel of alerts produced by the engine.
func (e *Engine) Alerts() <-chan *Alert {
	return e.alertCh
}

// Stats returns a point-in-time snapshot of the engine's performance counters.
func (e *Engine) Stats() StatsSnapshot {
	return StatsSnapshot{
		PacketsProcessed: e.stats.PacketsProcessed.Load(),
		PacketsFiltered:  e.stats.PacketsFiltered.Load(),
		RulesMatched:     e.stats.RulesMatched.Load(),
	}
}

// RuleCount returns the number of currently loaded rules.
func (e *Engine) RuleCount() int {
	return e.ruleset.RuleCount()
}

// Wait blocks until all dispatcher and worker goroutines have exited.
func (e *Engine) Wait() {
	e.wg.Wait()
}

// protoToString maps IP protocol numbers to the Proto type used by rules.
func protoToString(p uint8) Proto {
	switch p {
	case 6:
		return ProtoTCP
	case 17:
		return ProtoUDP
	case 1:
		return ProtoICMP
	default:
		return ProtoIP
	}
}

// extractPayload extracts the application-layer payload from a raw ethernet
// frame. Skips the ethernet header (14 bytes) and reads the IPv4 header
// length from the IHL field (lower 4 bits of byte 14), which can be 20-60
// bytes. Returns nil if the raw frame is too short.
func extractPayload(raw []byte) []byte {
	const ethHeaderLen = 14
	if len(raw) < ethHeaderLen+20 { // minimum: ethernet + IPv4
		return nil
	}
	// IHL is the lower 4 bits of byte 14 (start of IPv4 header)
	ihl := int(raw[ethHeaderLen]&0x0f) * 4
	if ihl < 20 || ihl > 60 || len(raw) < ethHeaderLen+ihl {
		return nil
	}
	return raw[ethHeaderLen+ihl:]
}

// matchFlags checks whether the packet's TCP flags satisfy the rule's flag
// requirements. Flag characters: S=SYN, A=ACK, F=FIN, R=RST.
// The rule flags string is a set of required flags (e.g. "SA" means both
// SYN and ACK must be set).
func matchFlags(packetFlags uint8, ruleFlags string) bool {
	for i := 0; i < len(ruleFlags); i++ {
		switch ruleFlags[i] {
		case 'S': // SYN = bit 1 (value 0x02)
			if packetFlags&0x02 == 0 {
				return false
			}
		case 'A': // ACK = bit 4 (value 0x10)
			if packetFlags&0x10 == 0 {
				return false
			}
		case 'F': // FIN = bit 0 (value 0x01)
			if packetFlags&0x01 == 0 {
				return false
			}
		case 'R': // RST = bit 2 (value 0x04)
			if packetFlags&0x04 == 0 {
				return false
			}
		}
	}
	return true
}

// ruleFullMatch performs comprehensive rule matching against a packet.
// It verifies dsize bounds, flags, and content constraints (offset/depth).
// All content patterns must be present for the rule to match.
func ruleFullMatch(rule *Rule, payload []byte, tcpFlags uint8) bool {
	// Check dsize bounds.
	if rule.DSize != nil && len(rule.DSize) == 2 {
		if len(payload) < rule.DSize[0] || len(payload) > rule.DSize[1] {
			return false
		}
	}

	// Check flags.
	if rule.Flags != "" {
		if !matchFlags(tcpFlags, rule.Flags) {
			return false
		}
	}

	// Check all content patterns with constraints.
	for _, cm := range rule.Contents {
		if !matchContent(payload, cm) {
			return false
		}
	}

	return true
}

// matchContent checks if a content pattern exists in the payload subject
// to its offset and depth constraints.
func matchContent(payload []byte, cm ContentMatch) bool {
	if len(cm.Pattern) == 0 {
		return true // empty pattern always matches
	}

	// Determine search window.
	start := 0
	end := len(payload)

	if cm.Offset >= 0 {
		start = cm.Offset
	}
	if cm.Depth >= 0 {
		end = cm.Depth
	}

	if start >= len(payload) || start >= end {
		return false
	}
	if end > len(payload) {
		end = len(payload)
	}

	searchSpace := payload[start:end]

	if cm.Nocase {
		return bytes.Contains(bytes.ToLower(searchSpace), bytes.ToLower(cm.Pattern))
	}
	return bytes.Contains(searchSpace, cm.Pattern)
}
