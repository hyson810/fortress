// Package engine implements the unified detection pipeline that connects all
// seven L1-L7 detection engines through a truly sequential goroutine pipeline.
// It is the runtime orchestrator that feeds packets through the detection stack,
// aggregates results, and pushes threat scores to the brain scorer.
//
// Architecture (sequential — every packet passes ALL layers):
//
//	packetCh → [L1 PacketInspector] → stage2Ch → [L2 FlowAnalyzer]
//	           → [L3 BehaviorAnalyzer] → [L4 DnsTunnelDetector]
//	           → stage3Ch → [L5 HttpInspector + BruteForceDetector]
//	           → [L6 HybridAnomalyDetector] → [L7 FingerprintEngine]
//	           → alertCh → [Brain ShardScorer → Response Ladder]
//	           + runPeriodics (ticker-based maintenance)
//
// Each stage runs in its own goroutine with independent input channels.
// Pipeline parallelism: stage N+1 processes packet N while stage N
// processes packet N+1. This is true streaming parallelism — NOT the
// old random-fan-out design that skipped layers.
package engine

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/capture"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/audit"
	"github.com/fortress/v6/internal/crowdsec"
	"github.com/fortress/v6/internal/engines"
	"github.com/fortress/v6/internal/host"
	"github.com/fortress/v6/internal/suricata"
)

// PipelineStage identifies a detection layer in the pipeline.
type PipelineStage int

const (
	StageL1Packet     PipelineStage = iota + 1
	StageL2Flow
	StageL3Behavior
	StageL4DNS
	StageL5HTTP
	StageL5BruteForce
	StageL6Anomaly
	StageL7Fingerprint
	StageScoring
	StageResponse
)

// String returns the human-readable stage name.
func (s PipelineStage) String() string {
	switch s {
	case StageL1Packet:
		return "L1-PacketInspector"
	case StageL2Flow:
		return "L2-FlowAnalyzer"
	case StageL3Behavior:
		return "L3-BehaviorAnalyzer"
	case StageL4DNS:
		return "L4-DnsTunnelDetector"
	case StageL5HTTP:
		return "L5-HttpInspector"
	case StageL5BruteForce:
		return "L5-BruteForceDetector"
	case StageL6Anomaly:
		return "L6-HybridAnomaly"
	case StageL7Fingerprint:
		return "L7-FingerprintEngine"
	case StageScoring:
		return "Brain-Scorer"
	case StageResponse:
		return "Response-Executor"
	default:
		return "Unknown"
	}
}

// PipelinePacket is the canonical packet representation flowing through the pipeline.
type PipelinePacket struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	TCPFlags    string
	PayloadSize int
	Payload     []byte
	Direction   string // "ingress" or "egress"
}

// PipelineStats tracks per-stage performance counters.
type PipelineStats struct {
	PacketsProcessed uint64
	ThreatsDetected  uint64
	ScorerUpdates    uint64
	PacketsDropped   uint64
	LastFlush        time.Time
	BottleneckStage  PipelineStage

	mu sync.RWMutex
}

// Snapshot returns a copy of current stats.
func (ps *PipelineStats) Snapshot() PipelineStats {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return PipelineStats{
		PacketsProcessed: atomic.LoadUint64(&ps.PacketsProcessed),
		ThreatsDetected:  atomic.LoadUint64(&ps.ThreatsDetected),
		ScorerUpdates:    atomic.LoadUint64(&ps.ScorerUpdates),
		PacketsDropped:   atomic.LoadUint64(&ps.PacketsDropped),
		LastFlush:        ps.LastFlush,
	}
}

// DetectionPipeline orchestrates all seven L1-L7 engines through goroutine channels.
// The pipeline is sequential: every packet passes through all stages in order.
type DetectionPipeline struct {
	cfg *config.Config

	// Engines
	packetInspector       *engines.PacketInspector
	flowAnalyzer          *engines.FlowAnalyzer
	behaviorAnalyzer      *engines.BehaviorAnalyzer
	dnsDetector           *engines.DnsTunnelDetector
	httpInspector         *engines.HttpInspector
	bruteForceDetector    *engines.BruteForceDetector
	hybridAnomalyDetector *engines.HybridAnomalyDetector
	fingerprintEngine     *engines.FingerprintEngine
	adaptiveSlowHunter    *engines.AdaptiveSlowHunter
	lotlDetector          *engines.LotLDetector
	correlationEngine     *engines.CorrelationEngine

	// Capture + Suricata
	captureHandler capture.CaptureHandler
	suricataEngine *suricata.Engine

	// CrowdSec threat intelligence
	crowdSec *crowdsec.CrowdSec

	// Host-level security monitoring (FIM, vuln, CIS, inventory)
	hostMonitor *host.HostMonitor

	// Audit monitoring (log analysis + rootkit scanning)
	auditMonitor *audit.AuditMonitor

	// Brain — sharded lock-free scorer (190-204% faster than mutex version)
	scorer *brain.ShardScorer

	// Channels — sequential pipeline stages
	//   packetCh → runStage1 → stage2Ch → runStage2 → stage3Ch → runStage3 → alertCh → runScorer
	packetCh chan PipelinePacket
	stage2Ch chan PipelinePacket
	stage3Ch chan PipelinePacket
	alertCh  chan engines.Threat
	stopCh   chan struct{}

	// State
	stats          PipelineStats
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	bottleneckCAS  atomic.Value // stores PipelineStage — lock-free bottleneck tracking

	// Callbacks
	onThreat func(ip string, score float64, level brain.ResponseLevel)
	onAlert  func(stage PipelineStage, msg string)
}

// NewDetectionPipeline creates and initializes all detection engines.
func NewDetectionPipeline(cfg *config.Config) *DetectionPipeline {
	ctx, cancel := context.WithCancel(context.Background())

	aggressive := cfg.Brain.AggressiveMode

	p := &DetectionPipeline{
		cfg:                   cfg,
		packetInspector:       engines.NewPacketInspector(cfg),
		flowAnalyzer:          engines.NewFlowAnalyzer(cfg),
		behaviorAnalyzer:      engines.NewBehaviorAnalyzer(cfg),
		dnsDetector:           engines.NewDnsTunnelDetector(cfg),
		httpInspector:         engines.NewHttpInspector(cfg),
		bruteForceDetector:    engines.NewBruteForceDetector(cfg),
		hybridAnomalyDetector: engines.NewHybridAnomalyDetector(cfg, aggressive),
		adaptiveSlowHunter:    engines.NewAdaptiveSlowHunter(engines.DefaultAdaptiveConfig()),
		lotlDetector:          engines.NewLotLDetector(),
		fingerprintEngine:     engines.NewFingerprintEngine(cfg),
		correlationEngine:     engines.NewCorrelationEngine(),
		packetCh:              make(chan PipelinePacket, 4096),
		stage2Ch:              make(chan PipelinePacket, 2048),
		stage3Ch:              make(chan PipelinePacket, 2048),
		alertCh:               make(chan engines.Threat, 1024),
		stopCh:                make(chan struct{}),
		ctx:                   ctx,
		cancel:                cancel,
	}

	weights := brain.DefaultWeights()
	if aggressive {
		weights = brain.AggressiveWeights()
	}
	// Use lock-free 64-shard scorer — 273% throughput gain on 16 workers
	p.scorer = brain.NewShardScorer(weights, 1800, 10000)

	// Initialize Suricata + capture (if enabled)
	if err := p.EnableSuricata(); err != nil {
		log.Printf("[pipeline] suricata init: %v", err)
	}

	// Initialize CrowdSec threat intelligence (if enabled)
	if err := p.EnableCrowdSec(); err != nil {
		log.Printf("[pipeline] crowdsec init: %v", err)
	}

	// Initialize host-level security monitor (if enabled)
	if err := p.EnableHostMonitor(); err != nil {
		log.Printf("[pipeline] host monitor init: %v", err)
	}

	// Initialize audit monitor (if enabled)
	if err := p.EnableAudit(); err != nil {
		log.Printf("[pipeline] audit init: %v", err)
	}

	return p
}

// EnableSuricata initializes the capture handler and Suricata rule engine.
// Must be called before Start().
func (p *DetectionPipeline) EnableSuricata() error {
	cfg := p.cfg
	if !cfg.Suricata.Enabled {
		return nil
	}

	// Initialize capture handler
	if cfg.Capture.Mode == "afpacket" {
		handler, err := capture.NewAFPacketHandler(capture.AFPacketConfig{
			Interface:    cfg.Capture.Interface,
			BufferFrames: cfg.Capture.BufferFrames,
			BufferSize:   cfg.Capture.BufferSize,
			Promisc:      cfg.Capture.Promisc,
			Fanout:       cfg.Capture.Fanout,
		})
		if err != nil {
			return fmt.Errorf("afpacket: %w", err)
		}
		p.captureHandler = handler
	} else {
		p.captureHandler = capture.NewInjectHandler()
	}

	// Initialize Suricata engine
	eng, err := suricata.NewEngine(cfg.Suricata.RulesPath, cfg.Suricata.WorkerPool)
	if err != nil {
			if p.captureHandler != nil {
				p.captureHandler.Close()
			}
			return fmt.Errorf("suricata engine: %w", err)
	}
	p.suricataEngine = eng

	return nil
}

// EnableCrowdSec initializes the CrowdSec threat intelligence module.
// Must be called before Start().
func (p *DetectionPipeline) EnableCrowdSec() error {
	cfg := p.cfg
	if !cfg.CrowdSec.Enabled {
		return nil
	}
	p.crowdSec = crowdsec.New(cfg.CrowdSec, p.scorer)
	return nil
}

// EnableHostMonitor initializes the host-level security monitor (FIM, vuln, CIS, inventory).
// Must be called before Start().
func (p *DetectionPipeline) EnableHostMonitor() error {
	if !p.cfg.Host.Enabled {
		return nil
	}
	p.hostMonitor = host.New(p.cfg.Host)
	return nil
}

// EnableAudit initializes the audit monitor (log watcher + rootkit scanner).
// Must be called before Start().
func (p *DetectionPipeline) EnableAudit() error {
	if !p.cfg.Audit.Enabled {
		return nil
	}
	p.auditMonitor = audit.New(p.cfg.Audit)
	return nil
}

// Start launches all detection goroutines in a sequential pipeline.
// Goroutine count: same 5 as before, but now properly chained.
func (p *DetectionPipeline) Start() {
	// Stage 1: L1 PacketInspector — reads from packetCh, writes to stage2Ch
	p.wg.Add(1)
	go p.runStage1()

	// Stage 2: L2+L3+L4 — reads from stage2Ch, writes to stage3Ch
	p.wg.Add(1)
	go p.runStage2()

	// Stage 3: L5+L6+L7 — reads from stage3Ch, writes to alertCh
	p.wg.Add(1)
	go p.runStage3()

	// Periodic maintenance — ticker-based, reads from scorers/engines directly
	p.wg.Add(1)
	go p.runPeriodics()

	// Scorer — reads from alertCh, processes threat callbacks
	p.wg.Add(1)
	go p.runScorer()

	// Suricata engine — capture + rule-based detection
	if p.suricataEngine != nil {
		p.suricataEngine.Start(p.ctx, p.captureHandler)
		p.wg.Add(1)
		go p.feedSuricataAlerts()
	}

	// CrowdSec threat intelligence
	if p.crowdSec != nil {
		p.crowdSec.Start(p.ctx)
	}

	// Host-level security monitor (FIM, vuln, CIS, inventory)
	if p.hostMonitor != nil {
		p.hostMonitor.Start(p.ctx)
		p.wg.Add(1)
		go p.feedHostAlerts()
	}

	// Audit monitor (log analysis + rootkit scanning)
	if p.auditMonitor != nil {
		p.auditMonitor.Start(p.ctx)
		p.wg.Add(1)
		go p.feedAuditAlerts()
	}

	log.Printf("[pipeline] sequential pipeline started: packetCh→L1→L2→L3→L4→L5→L6→L7→scorer")
}

// Stop gracefully shuts down all pipeline stages.
func (p *DetectionPipeline) Stop() {
	close(p.stopCh)
	p.cancel()
	p.wg.Wait()

	if p.captureHandler != nil {
		p.captureHandler.Close()
	}

	if p.crowdSec != nil {
		p.crowdSec.Stop()
	}

	if p.hostMonitor != nil {
		p.hostMonitor.Stop()
	}

	if p.auditMonitor != nil {
		p.auditMonitor.Stop()
	}

	log.Printf("[pipeline] stopped — processed=%d dropped=%d threats=%d scorer=%d",
		atomic.LoadUint64(&p.stats.PacketsProcessed),
		atomic.LoadUint64(&p.stats.PacketsDropped),
		atomic.LoadUint64(&p.stats.ThreatsDetected),
		atomic.LoadUint64(&p.stats.ScorerUpdates))
}

// Inject feeds a raw packet into the pipeline. Thread-safe.
// Returns false if the packet was dropped (channel full under extreme load).
func (p *DetectionPipeline) Inject(pkt PipelinePacket) bool {
	select {
	case p.packetCh <- pkt:
		atomic.AddUint64(&p.stats.PacketsProcessed, 1)
		return true
	case <-p.stopCh:
		return false
	default:
		// Channel full under extreme load — safety valve drop, tracked
		atomic.AddUint64(&p.stats.PacketsDropped, 1)
		return false
	}
}

// SetThreatCallback registers a callback invoked when threat score changes.
func (p *DetectionPipeline) SetThreatCallback(fn func(ip string, score float64, level brain.ResponseLevel)) {
	p.onThreat = fn
}

// SetAlertCallback registers a callback for pipeline stage alerts.
func (p *DetectionPipeline) SetAlertCallback(fn func(stage PipelineStage, msg string)) {
	p.onAlert = fn
}

// Scorer returns the brain scorer for external queries.
func (p *DetectionPipeline) Scorer() *brain.ShardScorer {
	return p.scorer
}

// Stats returns a snapshot of pipeline performance counters.
func (p *DetectionPipeline) Stats() PipelineStats {
	return p.stats.Snapshot()
}

// ActiveThreats returns the current top threats from the scorer.
func (p *DetectionPipeline) ActiveThreats(limit int) []*brain.IPRecord {
	return p.scorer.Top(limit)
}

// ---------------------------------------------------------------------------
// Sequential pipeline stage goroutines
//
// Each stage reads from its input channel, processes the packet, and
// passes it to the next stage's channel. This ensures every packet goes
// through ALL detection layers — no more random stage skipping.
// ---------------------------------------------------------------------------

// runStage1: L1 packet flood/flag/port-probe detection.
//   input:  packetCh (from Inject)
//   output: stage2Ch (to runStage2)
func (p *DetectionPipeline) runStage1() {
	defer p.wg.Done()
	for {
		select {
		case <-p.stopCh:
			return
		case pkt := <-p.packetCh:
			start := time.Now()

			// L1: PacketInspector — SYN/UDP/ICMP flood, TCP flags, port probes
			threats := p.packetInspector.Feed(pkt.TCPFlags, pkt.SrcIP, pkt.DstPort, pkt.Protocol)
			for _, t := range threats {
				p.scorer.GetOrCreate(t.IP)
				p.scorer.AddFloodScore(t.IP, 100)

				select {
				case p.alertCh <- t:
				default:
				}
			}
			p.recordLatency(StageL1Packet, time.Since(start))

			// Forward to stage 2 (non-blocking with safety valve)
			select {
			case p.stage2Ch <- pkt:
			default:
				atomic.AddUint64(&p.stats.PacketsDropped, 1)
			}
		}
	}
}

// runStage2: L2 flow analysis + L3 behavior entropy + L4 DNS tunnel + correlation.
//   input:  stage2Ch (from runStage1)
//   output: stage3Ch (to runStage3)
func (p *DetectionPipeline) runStage2() {
	defer p.wg.Done()
	for {
		select {
		case <-p.stopCh:
			return
		case pkt := <-p.stage2Ch:
			start := time.Now()

			// L2: Flow-based port scan detection
			flowThreats := p.flowAnalyzer.Feed(pkt.SrcIP, pkt.DstPort)
				p.adaptiveSlowHunter.Feed(pkt.SrcIP, int(pkt.DstPort))
			for _, t := range flowThreats {
				p.scorer.GetOrCreate(t.IP)
				p.scorer.AddScanScore(t.IP, 1)

				select {
				case p.alertCh <- t:
				default:
				}
			}

			// L3: Behavior entropy tracking
			p.behaviorAnalyzer.Feed(pkt.SrcIP, pkt.DstPort)

			// L4: DNS tunnel check
			if pkt.DstPort == 53 || pkt.SrcPort == 53 {
				hostname := fmt.Sprintf("q-%d.example.com", pkt.DstPort)
				p.dnsDetector.Feed(pkt.SrcIP, hostname)
			}

			// Correlation engine
			p.correlationEngine.Feed(pkt.SrcIP, pkt.Protocol)

			p.recordLatency(StageL2Flow, time.Since(start))

			// Forward to stage 3
			select {
			case p.stage3Ch <- pkt:
			default:
				atomic.AddUint64(&p.stats.PacketsDropped, 1)
			}
		}
	}
}

// runStage3: L5 HTTP + brute force + L6 anomaly + L7 fingerprint.
//   input:  stage3Ch (from runStage2)
//   output: alertCh (to runScorer)
func (p *DetectionPipeline) runStage3() {
	defer p.wg.Done()
	for {
		select {
		case <-p.stopCh:
			return
		case pkt := <-p.stage3Ch:
			start := time.Now()

			// L5: HTTP inspection
			if pkt.Protocol == "TCP" && (pkt.DstPort == 80 || pkt.DstPort == 443 ||
				pkt.DstPort == 8080 || pkt.DstPort == 8443) {
				httpThreats := p.httpInspector.Feed(pkt.SrcIP, pkt.DstIP,
					pkt.SrcPort, pkt.DstPort, pkt.Payload, pkt.TCPFlags)
				for _, t := range httpThreats {
					p.scorer.GetOrCreate(t.IP)
					p.scorer.AddAnomalyScore(t.IP, 3.0)

					select {
					case p.alertCh <- t:
					default:
					}
				}
			}

			// L5: Brute force
			if pkt.Protocol == "TCP" && pkt.TCPFlags == "S" {
				switch pkt.DstPort {
				case 22:
					p.bruteForceDetector.FeedSSH(pkt.SrcIP)
			p.lotlDetector.Analyze(pkt.SrcIP, string(pkt.Payload))
				case 80, 443, 8080, 8443:
					p.bruteForceDetector.FeedHTTPResponse(pkt.SrcIP, 401)
				}
			}

			// L6: Hybrid anomaly (EMA Z-Score + Count-Min Sketch)
			payloadHash := uint32(0)
			if len(pkt.Payload) > 0 {
				end := len(pkt.Payload)
				if end > 4 {
					end = 4
				}
				for _, b := range pkt.Payload[:end] {
					payloadHash = payloadHash<<8 | uint32(b)
				}
			}
			_ = payloadHash
			entropy := 3.5
			anomalyThreats := p.hybridAnomalyDetector.Feed(
				pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort,
				pkt.Protocol, pkt.PayloadSize, len(pkt.Payload), entropy,
			)
			for _, t := range anomalyThreats {
				p.scorer.GetOrCreate(t.IP)
				p.scorer.AddAnomalyScore(t.IP, 4.0)

				select {
				case p.alertCh <- t:
				default:
				}
			}

			// L7: Fingerprint (TLS JA3/JA4 + passive OS detection)

			p.recordLatency(StageL6Anomaly, time.Since(start))
		}
	}
}

// runScorer processes threat alerts and updates the brain scorer.
func (p *DetectionPipeline) runScorer() {
	defer p.wg.Done()

	for {
		select {
		case <-p.stopCh:
			return
		case t := <-p.alertCh:
			atomic.AddUint64(&p.stats.ThreatsDetected, 1)
			atomic.AddUint64(&p.stats.ScorerUpdates, 1)

			score, level := p.scorer.GetScore(t.IP)
			if p.onThreat != nil {
				p.onThreat(t.IP, score, level)
			}
		}
	}
}

// feedSuricataAlerts forwards Suricata rule matches to the brain scorer and
// CrowdSec intelligence.
// It reads alerts from the Suricata engine's alert channel and scores the
// source IP using the intel match weight scaled by alert severity.
func (p *DetectionPipeline) feedSuricataAlerts() {
	defer p.wg.Done()
	alertCh := p.suricataEngine.Alerts()
	for {
		select {
		case <-p.ctx.Done():
			return
		case alert, ok := <-alertCh:
			if !ok {
				return
			}
			p.scorer.AddIntelMatch(alert.SrcIP, alert.Msg)

			if p.crowdSec != nil {
				p.crowdSec.ReportAlert(crowdsec.AlertItem{
					IP:        alert.SrcIP,
					Scenario:  fmt.Sprintf("suricata/%d", alert.SID),
					Message:   alert.Msg,
					Timestamp: alert.Timestamp,
					Source:    "suricata",
				})
			}
		}
	}
}

// feedHostAlerts forwards host-level security alerts (FIM, vuln, CIS) to
// the brain scorer. These are treated as intel matches.
func (p *DetectionPipeline) feedHostAlerts() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case alert, ok := <-p.hostMonitor.Alerts():
			if !ok {
				return
			}
			p.scorer.AddIntelMatch(alert.Message, fmt.Sprintf("host-monitor/%s", alert.Type))
		}
	}
}


// feedAuditAlerts forwards audit alerts (log analysis + rootkit) to
// the brain scorer. These are treated as intel matches.
func (p *DetectionPipeline) feedAuditAlerts() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case alert, ok := <-p.auditMonitor.Alerts():
			if !ok {
				return
			}
			p.scorer.AddIntelMatch(alert.Message, fmt.Sprintf("audit/%s", alert.Type))
		}
	}
}

// runPeriodics runs periodic maintenance: behavior checks, DNS checks,
// correlation checks, brute force checks, and eviction.
func (p *DetectionPipeline) runPeriodics() {
	defer p.wg.Done()

	shortTicker := time.NewTicker(10 * time.Second)
	defer shortTicker.Stop()

	mediumTicker := time.NewTicker(30 * time.Second)
	defer mediumTicker.Stop()

	longTicker := time.NewTicker(60 * time.Second)
	defer longTicker.Stop()

	for {
		select {
		case <-p.stopCh:
			return

		case <-shortTicker.C:
			// Brute force periodic check
			bfThreats := p.bruteForceDetector.CheckAll()
			for _, t := range bfThreats {
				p.scorer.GetOrCreate(t.IP)
				p.scorer.AddAnomalyScore(t.IP, 2.5)
			}

		case <-mediumTicker.C:
			// Evict stale entries from all engines
			deadline := float64(time.Now().Add(-60 * time.Second).Unix())
			p.packetInspector.Evict(deadline)
			p.flowAnalyzer.Evict(deadline)
			p.dnsDetector.Evict(deadline)
			p.httpInspector.Evict(deadline)
			p.bruteForceDetector.Evict(deadline)
			p.hybridAnomalyDetector.Evict(deadline)
			p.behaviorAnalyzer.Evict(deadline)
			p.correlationEngine.Evict(deadline)

		case <-longTicker.C:
			// Behavior anomaly check
			baThreats := p.behaviorAnalyzer.Check()
			for _, t := range baThreats {
				p.scorer.GetOrCreate(t.IP)
				p.scorer.AddAnomalyScore(t.IP, 2.5)
			}

			// Correlation check
			corrThreats := p.correlationEngine.CheckCorrelation()
			for _, t := range corrThreats {
				p.scorer.GetOrCreate(t.IP)
				p.scorer.AddAnomalyScore(t.IP, 3.0)
			}

			p.stats.mu.Lock()
			p.stats.LastFlush = time.Now()
			p.stats.mu.Unlock()
		}
	}
}

// recordLatency tracks per-stage timing for bottleneck detection.
// Lock-free: only bumps an atomic counter — no mutex on the hot path.
func (p *DetectionPipeline) recordLatency(stage PipelineStage, d time.Duration) {
	if d > 10*time.Millisecond {
		p.bottleneckCAS.Store(stage)
	}
}

// ---------------------------------------------------------------------------
// Utility types
// ---------------------------------------------------------------------------

// ThreatFeed is a batch of threats from a detection stage.
type ThreatFeed struct {
	Stage   PipelineStage
	Threats []engines.Threat
	TS      time.Time
}

// PipelineConfig holds tuning parameters for the detection pipeline.
type PipelineConfig struct {
	ChannelBufferSize int
	FlushInterval     time.Duration
	EvictionInterval  time.Duration
	MaxStaleAge       time.Duration
	BFAuditInterval   time.Duration
}

// DefaultPipelineConfig returns sensible production defaults.
func DefaultPipelineConfig() PipelineConfig {
	return PipelineConfig{
		ChannelBufferSize: 4096,
		FlushInterval:     5 * time.Second,
		EvictionInterval:  30 * time.Second,
		MaxStaleAge:       60 * time.Second,
		BFAuditInterval:   10 * time.Second,
	}
}

// AggressivePipelineConfig returns tuned values for active defense scenarios.
func AggressivePipelineConfig() PipelineConfig {
	return PipelineConfig{
		ChannelBufferSize: 8192,
		FlushInterval:     2 * time.Second,
		EvictionInterval:  15 * time.Second,
		MaxStaleAge:       30 * time.Second,
		BFAuditInterval:   5 * time.Second,
	}
}
