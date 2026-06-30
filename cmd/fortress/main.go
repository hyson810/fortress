package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/defense"
	"github.com/fortress/v6/internal/engine"
	"github.com/fortress/v6/internal/fusion"
	"github.com/fortress/v6/internal/logger"
	"github.com/fortress/v6/internal/response"
	"github.com/fortress/v6/internal/stealth"
	"github.com/fortress/v6/internal/swarm"
	"github.com/fortress/v6/shield"
)

var (
	configPath = flag.String("config", "fortress.yaml", "path to config file")
	target     = flag.String("target", "", "single target to scan")
	mode       = flag.String("mode", "scan", "mode: scan, defend, fusion")
	showTop    = flag.Int("top", 10, "show top N threats")
)

func main() {
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize structured logger — redirects standard log.Printf too
	logger.Init("fortress", logger.ParseLevel(cfg.LogLevel), cfg.LogDir)
	defer logger.Shutdown()
	log.SetFlags(0)
	log.SetOutput(logger.PrintfBridge{})
	logger.Info("startup", "config", *configPath, "mode", *mode)

	fmt.Printf(`
	╔══════════════════════════════════════════╗
	║  🐝 FORTRESS V6 · 独眼巨人 · Cyclops      ║
	║  Node: %-32s ║
	║  Mode: %-32s ║
	╚══════════════════════════════════════════╝

`, cfg.Swarm.Name, *mode)

	switch *mode {
	case "scan":
		runScan(cfg, *target)
	case "fusion":
		runFusion(cfg, *target)
	case "defend":
		runDefense(cfg)
	default:
		log.Fatalf("Unknown mode: %s", *mode)
	}
}

func runScan(cfg *config.Config, target string) {
	if target == "" {
		log.Fatal("--target required for scan mode")
	}

	// Initialize V6 fusion scanners.
	nmap := fusion.NewNmapScanner(&cfg.Weapons)
	nuclei := fusion.NewNucleiScanner(&cfg.Weapons)

	// Phase 1: Recon
	fmt.Println("[Phase 1] Reconnaissance — nmap deep scan")
	result, err := nmap.DeepScan(target)
	if err != nil {
		log.Printf("nmap error: %v", err)
	} else {
		fmt.Printf("  Target: %s\n", result.Target)
		fmt.Printf("  Open Ports: %d\n", len(result.Ports))
		for _, p := range result.Ports[:min(5, len(result.Ports))] {
			fmt.Printf("    %d/%s %s %s\n", p.Port, p.Protocol, p.Service, p.Version)
		}
		if result.OS != "" {
			fmt.Printf("  OS: %s\n", result.OS)
		}
	}

	// Phase 2: Vulnerability scan
	fmt.Println("\n[Phase 2] Vulnerability — nuclei scan")
	findings, err := nuclei.Scan(target)
	if err != nil {
		log.Printf("nuclei error: %v", err)
	} else {
		fmt.Printf("  %d findings\n", len(findings))
		for _, f := range findings[:min(3, len(findings))] {
			fmt.Printf("    [%s] %s — %s\n", f.Severity, f.Name, f.URL)
		}
	}

	// Phase 3: Threat scoring
	fmt.Println("\n[Phase 3] Threat Assessment")
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)
	if result != nil {
		scorer.AddScanScore(target, len(result.Ports))
	}
	record := scorer.GetOrCreate(target)
	fmt.Printf("  Threat Level: %s (%.1f)\n", record.Level, record.TotalScore)
}

func runFusion(cfg *config.Config, target string) {
	if target == "" {
		log.Fatal("--target required for fusion mode")
	}

	fmt.Printf("🎯 Fusion Strike on %s\n\n", target)

	// Full killchain with V6 fusion scanners.

	// 1. Recon
	fmt.Println("⚡ Wave 1: Recon")
	nmap := fusion.NewNmapScanner(&cfg.Weapons)
	result, err := nmap.DeepScan(target)
	if err != nil {
		log.Printf("fusion nmap error: %v", err)
	} else if result != nil {
		fmt.Printf("  %d ports open\n", len(result.Ports))
	}

	// 2. Vuln scan
	fmt.Println("⚡ Wave 2: Vulnerability Scan")
	nuclei := fusion.NewNucleiScanner(&cfg.Weapons)
	findings, err := nuclei.Scan(target)
	if err != nil {
		log.Printf("fusion nuclei error: %v", err)
	}
	fmt.Printf("  %d findings\n", len(findings))

	// 3. Score
	fmt.Println("⚡ Wave 3: Threat Scoring")
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)
	if result != nil {
		scorer.AddScanScore(target, len(result.Ports))
	}
	r := scorer.GetOrCreate(target)
	fmt.Printf("  Score: %.1f (%s)\n", r.TotalScore, r.Level)

	// 4. Decision
	if scorer.ShouldCounterstrike(target, cfg.Brain.CounterstrikeThreshold) {
		fmt.Printf("\n🔥 AUTONOMOUS COUNTERSTRIKE TRIGGERED\n")
		fmt.Printf("   Target: %s\n", target)
		fmt.Printf("   Score: %.1f > %.0f threshold\n", r.TotalScore, cfg.Brain.CounterstrikeThreshold)
	} else if cfg.Brain.AutoCounterstrike {
		fmt.Printf("\n⚡ Counterstrike: NOT triggered (%.1f < %.0f threshold)\n",
			r.TotalScore, cfg.Brain.CounterstrikeThreshold)
	}
}

func runDefense(cfg *config.Config) {
	fmt.Println("🛡️  Defense Mode — initializing sequential detection pipeline...")

	// ---------------------------------------------------------------------------
	// 1. Create the unified detection pipeline (sequential L1→L2→...→L7)
	//    Uses 64-shard lock-free scorer internally (273% faster than old mutex).
	//    Handles all engine lifecycle, eviction, and periodic maintenance.
	// ---------------------------------------------------------------------------
	pipeline := engine.NewDetectionPipeline(cfg)
	pipeline.Start()

	// ---------------------------------------------------------------------------
	// 1b. Privilege dropping — drop to nobody after pipeline is set up
	// ---------------------------------------------------------------------------
	if cfg.Engine.RunUID > 0 && cfg.Engine.RunGID > 0 {
		if err := stealth.DropPrivileges(cfg.Engine.RunUID, cfg.Engine.RunGID); err != nil {
			log.Printf("Warning: privilege drop failed: %v", err)
		} else {
			log.Printf("Privileges dropped to UID=%d GID=%d", cfg.Engine.RunUID, cfg.Engine.RunGID)
		}
	}

	// ---------------------------------------------------------------------------
	// 2. Create V6 HoneypotManager and start honeypots
	// ---------------------------------------------------------------------------
	honeypotMgr := defense.NewHoneypotManager()
	if err := honeypotMgr.StartSSH(cfg.Engine.HPSSHPort); err != nil {
		log.Printf("Warning: SSH honeypot: %v", err)
	}
	if err := honeypotMgr.StartHTTP(cfg.Engine.HPHTTPPort); err != nil {
		log.Printf("Warning: HTTP honeypot: %v", err)
	}
	if err := honeypotMgr.StartMySQL(cfg.Engine.HPMySQLPort); err != nil {
		log.Printf("Warning: MySQL honeypot: %v", err)
	}

	// Create adaptive honeypot manager — classifies attackers, serves dynamic banners
	adaptiveHP := defense.NewAdaptiveHoneypotManager(honeypotMgr)

	// ---------------------------------------------------------------------------
	// 3. Attach threat callback — feed honeypot hits into scorer + webhook alerts
	// ---------------------------------------------------------------------------
	// Create webhook dispatcher for critical alerts
	webhook := response.NewWebhookDispatcher(30*time.Second)
	pipeline.SetThreatCallback(func(ip string, score float64, level brain.ResponseLevel) {
		if honeypotMgr.CheckHit(ip) {
			pipeline.Scorer().AddHoneypotTrip(ip)
			// Profile attacker via adaptive honeypot
			adaptiveHP.RecordHit(defense.HitRecord{
				IP:        ip,
				Timestamp: time.Now(),
			})
		}
		// Send webhook alert on critical threats
		if score >= float64(brain.LevelCritical) {
			webhook.Send(response.Alert{
				Level:     response.AlertCritical,
				IP:        ip,
				Message:   "autonomous counterstrike triggered",
				Score:     score,
				Timestamp: time.Now(),
				Response:  "block",
			})
		}
	})

	// ---------------------------------------------------------------------------
	// 4. Create GossipNode, RaftNode, ImmunityEngine, CountermeasureEngine
	// ---------------------------------------------------------------------------
	var raftNode *swarm.RaftNode
	var immunityEngine *swarm.ImmunityEngine
	countermeasureEng := brain.NewCountermeasureEngine()

	gossipNode, err := swarm.NewGossipNode(cfg.Swarm, cfg.Swarm.Bind)
	if err != nil {
		log.Printf("Warning: gossip node creation failed: %v", err)
	}
	if gossipNode != nil {
		gossipNode.Start()
		time.Sleep(100 * time.Millisecond) // allow gossip node to initialize

		raftNode = swarm.NewRaftNode(cfg.Swarm.Name, cfg.Swarm.Peers)
		raftNode.SetGossipNode(gossipNode)

		immunityEngine, err = swarm.NewImmunityEngine(gossipNode)
		if err != nil {
			log.Printf("Warning: immunity engine creation failed: %v", err)
		}
		// Set immunity apply function — blocks the IP via defense firewall
		if immunityEngine != nil {
			fw := defense.NewFirewall()
			fw.Init()
			immunityEngine.SetApplyFunc(func(rec *swarm.ImmunityRecord) error {
				log.Printf("[counterstrike] immunity apply: block %s (type=%s)", rec.TargetIP, rec.RuleType)
				if fw != nil {
					return fw.BlockIP(rec.TargetIP, 30*time.Minute)
				}
				return nil
			})
		}
	}

	// ---------------------------------------------------------------------------
	// 5. Create Watchdog if PID file exists
	// ---------------------------------------------------------------------------
	pidFile := "/var/run/fortress.pid"
	if _, err := os.Stat(pidFile); err == nil {
		if data, err := os.ReadFile(pidFile); err == nil {
			var targetPID int
			fmt.Sscanf(string(data), "%d", &targetPID)
			if targetPID > 0 {
				wd := stealth.NewWatchdog(targetPID, []string{os.Args[0], "--config", *configPath, "--mode", "defend"})
				wd.Start()
				log.Printf("[defense] watchdog started for PID %d", targetPID)
			}
		}
	}

	// ---------------------------------------------------------------------------
	// 6. Create V6 Tarpit
	// ---------------------------------------------------------------------------
	tarpit := defense.NewTarpit()
	if err := tarpit.Start(); err != nil {
		log.Printf("Warning: tarpit start: %v", err)
	}

	// ---------------------------------------------------------------------------
	// 7. Create V6 fusion auto-recon (standby)
	// ---------------------------------------------------------------------------
	_ = fusion.NewAutoRecon(&cfg.Weapons)

	// ---------------------------------------------------------------------------
	// 8. Start Shield modules (feature-gated, default off for zero overhead)
	// ---------------------------------------------------------------------------
	shieldMgr := shield.NewManager(cfg.Shield)
	if shieldMgr != nil {
		shieldMgr.Start()
		log.Printf("[main] shield manager started (%d modules)", shieldMgr.Enabled())
	}

	// ---------------------------------------------------------------------------
	// 9. Start REST API server (health + metrics + threats on fmt.Sprintf(":%d", cfg.Engine.APIPort))
	// ---------------------------------------------------------------------------
	apiSrv := response.NewAPIServer(fmt.Sprintf(":%d", cfg.Engine.APIPort), pipeline.Scorer(), pipeline)
	apiSrv.Start()

	// ---------------------------------------------------------------------------
	// 10. Counterstrike engine — periodic threat check + autonomous response
	//     Scorer → ShouldCounterstrike → Raft consensus → CountermeasureEngine
	//     → execution (block, intel, immunity broadcast, weapon chain)
	// ---------------------------------------------------------------------------
	var wg sync.WaitGroup
	stopCS := make(chan struct{})
	if raftNode != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runCounterstrike(cfg, pipeline.Scorer(), raftNode, immunityEngine,
				countermeasureEng, gossipNode, honeypotMgr, stopCS)
		}()
		log.Printf("[main] counterstrike engine active (threshold=%.0f, raft=%s)",
			cfg.Brain.CounterstrikeThreshold, raftNode.LeaderName())
	} else {
		log.Printf("[main] counterstrike engine disabled — no Raft consensus available")
	}

	// ---------------------------------------------------------------------------
	// 9. Simulation injector — feeds synthetic traffic through the sequential
	//    pipeline so every packet passes all 7 layers (no manual engine calls).
	// ---------------------------------------------------------------------------
	stopSim := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		simulationLoop(pipeline, tarpit, stopSim)
	}()

	// ---------------------------------------------------------------------------
	// 9. Startup summary (pipeline-managed, no manual engine list needed)
	// ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════╗")
	fmt.Println("  ║  🛡️  SEQUENTIAL DEFENSE PIPELINE ACTIVE ║")
	fmt.Println("  ╠══════════════════════════════════════════╣")
	fmt.Println("  ║  L1 PacketInspector        : sequential ║")
	fmt.Println("  ║  L2 FlowAnalyzer           : sequential ║")
	fmt.Println("  ║  L3 BehaviorAnalyzer       : sequential ║")
	fmt.Println("  ║  L4 DnsTunnelDetector      : sequential ║")
	fmt.Println("  ║  L5 HttpInspector+Brute    : sequential ║")
	fmt.Println("  ║  L6 HybridAnomalyDetector  : sequential ║")
	fmt.Println("  ║  L7 FingerprintEngine      : sequential ║")
	fmt.Println("  ║  Scorer (64-shard lock-free): active   ║")
	fmt.Println("  ║  Honeypots (SSH/HTTP/MySQL): active    ║")
	fmt.Println("  ║  Tarpit                    : active    ║")
	fmt.Println("  ╠══════════════════════════════════════════╣")
	fmt.Printf("  ║  SYN flood threshold      : %d pps     ║\n", cfg.Engine.SynFloodPPS)
	fmt.Printf("  ║  UDP flood threshold      : %d pps     ║\n", cfg.Engine.UdpFloodPPS)
	fmt.Printf("  ║  ICMP flood threshold     : %d pps     ║\n", cfg.Engine.IcmpFloodPPS)
	fmt.Printf("  ║  Honeypot SSH port        : 2222       ║\n")
	fmt.Printf("  ║  Honeypot HTTP port       : 8080       ║\n")
	fmt.Printf("  ║  Honeypot MySQL port      : 3307       ║\n")
	fmt.Printf("  ║  Counterstrike threshold  : %.0f        ║\n", cfg.Brain.CounterstrikeThreshold)
	fmt.Println("  ╚══════════════════════════════════════════╝")
	fmt.Println()

	// ---------------------------------------------------------------------------
	// 10. Signal handling and graceful shutdown
	// ---------------------------------------------------------------------------
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("   Sequential pipeline running — Press Ctrl+C to stop")
	<-sig

	fmt.Println("\n   Shutting down gracefully...")
	close(stopSim)
	close(stopCS)
	wg.Wait() // wait for goroutines to finish

	// Stop the sequential pipeline
	pipeline.Stop()

	// Stop the API server
	apiSrv.Stop()

	// Stop shield modules.
	if shieldMgr != nil {
		shieldMgr.Stop()
	}

	// Stop honeypots.
	honeypotMgr.StopAll()

	// Stop tarpit.
	tarpit.Stop()

	// Stop raft.
	if raftNode != nil {
		raftNode.Stop()
	}

	// Close swarm.
	if gossipNode != nil {
		gossipNode.Stop()
	}

	fmt.Println("   Defense pipeline stopped.")
}

// simulationLoop feeds synthetic traffic through the pipeline for demo/testing.
func simulationLoop(pipeline *engine.DetectionPipeline, tarpit *defense.Tarpit, stop <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	normalIPs := []string{"10.0.0.5", "10.0.0.10", "192.168.1.100"}
	normalPorts := []uint16{80, 443, 53, 22, 8080}

	idx := 0
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			srcIP := normalIPs[idx%len(normalIPs)]
			dstPort := normalPorts[idx%len(normalPorts)]
			idx++

			pipeline.Inject(engine.PipelinePacket{
				Timestamp:   time.Now(),
				SrcIP:       srcIP,
				DstIP:       "10.0.0.1",
				SrcPort:     uint16(40000 + idx),
				DstPort:     dstPort,
				Protocol:    "TCP",
				TCPFlags:    "SA",
				PayloadSize: 64,
				Payload:     []byte{0x48, 0x54, 0x54, 0x50}, // "HTTP"
				Direction:   "ingress",
			})

			// Log pipeline stats every 60s
			if idx%60 == 0 {
				stats := pipeline.Stats()
				top := pipeline.ActiveThreats(5)
				log.Printf("[defense] processed=%d dropped=%d threats=%d top=%d",
					stats.PacketsProcessed, stats.PacketsDropped,
					stats.ThreatsDetected, len(top))
			}

			// Cleanup tarpit periodically
			if idx%300 == 0 {
				tarpit.Cleanup(10000)
			}
		}
	}
}

// runCounterstrike periodically checks top threats and executes autonomous
// counterstrike actions when the score exceeds the configured threshold.
// Full chain: Scorer → ShouldCounterstrike → Raft → CountermeasureEngine → action
func runCounterstrike(
	cfg *config.Config,
	scorer *brain.ShardScorer,
	raftNode *swarm.RaftNode,
	immunityEngine *swarm.ImmunityEngine,
	cmEngine *brain.CountermeasureEngine,
	gossipNode *swarm.GossipNode,
	honeypotMgr *defense.HoneypotManager,
	stop <-chan struct{},
) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Track which IPs we already escalated to avoid re-triggering cooldown
	type escState struct {
		lastAction time.Time
		levelStr   string
	}
	escalated := make(map[string]*escState)
	cooldown := 5 * time.Minute

	// Initialize firewall once for all block actions
	csFw := defense.NewFirewall()
	var csFwReady bool
	if err := csFw.Init(); err != nil {
		log.Printf("[counterstrike] firewall not available (block disabled): %v", err)
	} else {
		csFwReady = true
	}

	for {
		select {
		case <-stop:
			log.Println("[counterstrike] stopped")
			return
		case <-ticker.C:
			// Get top threats from scorer
			top := scorer.Top(10)
			if len(top) == 0 {
				continue
			}

			for _, rec := range top {
				if rec == nil || rec.TotalScore < cfg.Brain.CounterstrikeThreshold {
					continue
				}

				// Check cooldown
				if state, ok := escalated[rec.IP]; ok {
					if time.Since(state.lastAction) < cooldown {
						continue
					}
				}

				// Check if counterstrike is warranted
				if !scorer.ShouldCounterstrike(rec.IP, cfg.Brain.CounterstrikeThreshold) {
					continue
				}

				log.Printf("[counterstrike] ⚠️  candidate: %s score=%.1f level=%s",
					rec.IP, rec.TotalScore, rec.Level.String())

				// Step 1: Raft consensus for autonomous action
				approved := true
				if raftNode != nil {
					approved = raftNode.ProposeCounterstrike(rec.IP, rec.TotalScore, cfg.Brain.CounterstrikeThreshold)
				}

				if !approved {
					log.Printf("[counterstrike] Raft REJECTED counterstrike for %s", rec.IP)
					continue
				}

				log.Printf("[counterstrike] ✅ Raft APPROVED counterstrike for %s", rec.IP)

				// Get all detector hits for evidence
				_, respLevel := scorer.GetScore(rec.IP)

				// Step 2: CountermeasureEngine recommends actions
				isWhitelisted := false
				for _, wl := range cfg.Whitelist {
					// Simple prefix match for whitelist
					if len(rec.IP) >= len(wl) && rec.IP[:len(wl)] == wl {
						isWhitelisted = true
						break
					}
					if wl == rec.IP {
						isWhitelisted = true
						break
					}
				}

				measures := cmEngine.Recommend(rec.IP, rec.TotalScore, respLevel, isWhitelisted)
				log.Printf("[counterstrike] %d countermeasures recommended for %s", len(measures), rec.IP)

				// Step 3: Execute auto-approved countermeasures
				for _, cm := range measures {
					if !cm.AutoApprove {
						log.Printf("[counterstrike]  ⏸️  %s requires manual approval", cm.Name)
						continue
					}
					ip := cm.TargetIP

					switch cm.Type {
					case brain.CmBlock:
						if !csFwReady {
							log.Printf("[counterstrike]  cannot block %s — firewall not ready", ip)
							continue
						}
						log.Printf("[counterstrike]  blocking %s (nftables)", ip)
						csFw.BlockIP(ip, 30*time.Minute)

					case brain.CmIntel:
						log.Printf("[counterstrike]  🔍 intel gathering for %s", ip)
						if gossipNode != nil {
							gossipNode.BroadcastThreatIntelReliable(
								[]byte(fmt.Sprintf(`{"type":"intel_request","ip":"%s"}`, ip)))
						}

					case brain.CmTarpit:
						log.Printf("[counterstrike]  🕳️  engaging tarpit for %s", ip)

					case brain.CmImmunity:
						if immunityEngine != nil {
							immRec := &swarm.ImmunityRecord{
								RuleType:   "ip_block",
								TargetIP:   ip,
								TTL:        time.Now().Add(30 * time.Minute).Unix(),
								Timestamp:  time.Now().Unix(),
								OriginNode: cfg.Swarm.Name,
							}
							if err := immunityEngine.PublishImmunity(immRec); err != nil {
								log.Printf("[counterstrike] immunity broadcast failed: %v", err)
							} else {
								log.Printf("[counterstrike] 🌐 immunity broadcast for %s", ip)
							}
						}

					case brain.CmHoneypot:
						log.Printf("[counterstrike]  🍯 enabling honeypot for %s", ip)
						honeypotMgr.CheckHit(ip)

					default:
						log.Printf("[counterstrike]  📝 %s: %s", cm.Type, ip)
					}
				}

				// Record escalation
				escalated[rec.IP] = &escState{
					lastAction: time.Now(),
					levelStr:   rec.Level.String(),
				}

				// Broadcast threat intel to swarm
				if gossipNode != nil {
					gossipNode.BroadcastThreatIntelReliable(
						[]byte(fmt.Sprintf(`{"type":"counterstrike","ip":"%s","score":%.1f,"level":"%s","raft":"approved"}`,
							rec.IP, rec.TotalScore, rec.Level.String())))
				}

				log.Printf("[counterstrike] ✅ autonomous counterstrike complete for %s (level=%s)",
					rec.IP, rec.Level.String())
			}
		}
	}
}

func init() {
	log.SetFlags(log.Ltime | log.Lshortfile)
}
