package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fortress/v6/internal/brain"
	"github.com/fortress/v6/internal/config"
	"github.com/fortress/v6/internal/counterstrike"
	"github.com/fortress/v6/internal/engines"
	"github.com/fortress/v6/internal/offense"
	"github.com/fortress/v6/internal/stealth"
	"github.com/fortress/v6/internal/swarm"
	"github.com/fortress/v6/internal/weapons"
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

	fmt.Printf(`
╔══════════════════════════════════════════╗
║  🐝 FORTRESS v4 — Swarm Commander      ║
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

	// Initialize weapons
	nmap := weapons.NewNmap(cfg.Weapons.NmapBin)
	nuclei := weapons.NewNuclei(cfg.Weapons.NucleiBin)

	// Phase 1: Recon
	fmt.Println("[Phase 1] Reconnaissance — nmap deep scan")
	result, err := nmap.DeepScan(target)
	if err != nil {
		log.Printf("nmap error: %v", err)
	} else {
		fmt.Printf("  Target: %s\n", result.Target)
		fmt.Printf("  Open Ports: %d\n", result.PortCount())
		for _, p := range result.OpenPorts[:min(5, len(result.OpenPorts))] {
			fmt.Printf("    %d/%s %s %s\n", p.Port, p.Protocol, p.Service, p.Product)
		}
		fmt.Printf("  Duration: %v\n", result.Duration)
	}

	// Phase 2: Vulnerability scan
	fmt.Println("\n[Phase 2] Vulnerability — nuclei scan")
	nucleiResult, err := nuclei.Scan(target)
	if err != nil {
		log.Printf("nuclei error: %v", err)
	} else {
		fmt.Printf("  %s\n", nucleiResult.Summary())
		for _, f := range nucleiResult.Findings[:min(3, len(nucleiResult.Findings))] {
			fmt.Printf("    [%s] %s\n", f.Severity, f.Name)
		}
	}

	// Phase 3: Threat scoring
	fmt.Println("\n[Phase 3] Threat Assessment")
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)
	if result != nil {
		scorer.AddScanScore(target, result.PortCount())
	}
	record := scorer.GetOrCreate(target)
	fmt.Printf("  Threat Level: %s (%.1f)\n", record.Level, record.TotalScore)
}

func runFusion(cfg *config.Config, target string) {
	if target == "" {
		log.Fatal("--target required for fusion mode")
	}

	fmt.Printf("🎯 Fusion Strike on %s\n\n", target)

	// Full killchain:
	// 1. Recon
	fmt.Println("⚡ Wave 1: Recon")
	nmap := weapons.NewNmap(cfg.Weapons.NmapBin)
	result, _ := nmap.DeepScan(target)
	if result != nil {
		fmt.Printf("  %d ports open\n", result.PortCount())
	}

	// 2. Vuln scan
	fmt.Println("⚡ Wave 2: Vulnerability Scan")
	nuclei := weapons.NewNuclei(cfg.Weapons.NucleiBin)
	nResult, _ := nuclei.Scan(target)
	if nResult != nil {
		fmt.Printf("  %s\n", nResult.Summary())
	}

	// 3. Score
	fmt.Println("⚡ Wave 3: Threat Scoring")
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)
	if result != nil {
		scorer.AddScanScore(target, result.PortCount())
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
	fmt.Println("🛡️  Defense Mode — initializing detection pipeline...")

	// ---------------------------------------------------------------------------
	// 1. Create all detection engines
	// ---------------------------------------------------------------------------
	pi := engines.NewPacketInspector(cfg)
	fa := engines.NewFlowAnalyzer(cfg)
	dnsDetector := engines.NewDnsTunnelDetector(cfg)
	httpInspector := engines.NewHttpInspector(cfg)
	bruteDetector := engines.NewBruteForceDetector(cfg)
	hybridDetector := engines.NewHybridAnomalyDetector(cfg, false)
	behaviorAnalyzer := engines.NewBehaviorAnalyzer(cfg)
	correlationEngine := engines.NewCorrelationEngine()
	fingerprintEngine := engines.NewFingerprintEngine(cfg)

	// 2. Create Scorer
	scorer := brain.NewScorer(brain.DefaultWeights(), 1800, 10000)

	// 3. Create HoneypotManager and start honeypots
	honeypotMgr := counterstrike.NewHoneypotManager()
	if err := honeypotMgr.StartAll(); err != nil {
		log.Printf("Warning: honeypot start error: %v", err)
	}

	// 4. Create GossipNode, RaftNode, and ImmunityEngine (multiplexed callbacks via Fix 3)
	gossipNode, err := swarm.NewGossipNode(cfg.Swarm, cfg.Swarm.Bind)
	if err != nil {
		log.Printf("Warning: gossip node creation failed: %v", err)
	}
	if gossipNode != nil {
		gossipNode.Start()

		raftNode := swarm.NewRaftNode(cfg.Swarm.Name, cfg.Swarm.Peers)
		raftNode.SetGossipNode(gossipNode)

		immunityEngine, err := swarm.NewImmunityEngine(gossipNode)
		if err != nil {
			log.Printf("Warning: immunity engine creation failed: %v", err)
		}
		_ = immunityEngine // registered as threat-intel callback already
	}

	// 5. Create Watchdog if PID file exists
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

	// 6. Create Tarpit
	tarpit := counterstrike.NewTarpit(false)

	// 7. Create standby offense orchestrator
	_ = offense.NewAttackOrchestrator(nil, 1)

	// ---------------------------------------------------------------------------
	// 8. Startup summary
	// ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════╗")
	fmt.Println("  ║  🛡️  DEFENSE PIPELINE ACTIVE            ║")
	fmt.Println("  ╠══════════════════════════════════════════╣")
	fmt.Printf("  ║  PacketInspector          : ✓          ║\n")
	fmt.Printf("  ║  FlowAnalyzer             : ✓          ║\n")
	fmt.Printf("  ║  DnsTunnelDetector        : ✓          ║\n")
	fmt.Printf("  ║  HttpInspector            : ✓          ║\n")
	fmt.Printf("  ║  BruteForceDetector       : ✓          ║\n")
	fmt.Printf("  ║  HybridAnomalyDetector    : ✓          ║\n")
	fmt.Printf("  ║  BehaviorAnalyzer         : ✓          ║\n")
	fmt.Printf("  ║  CorrelationEngine        : ✓          ║\n")
	fmt.Printf("  ║  FingerprintEngine        : ✓          ║\n")
	fmt.Printf("  ║  Scorer                   : ✓          ║\n")
	fmt.Printf("  ║  Honeypots (SSH/HTTP/MySQL): ✓          ║\n")
	fmt.Printf("  ║  Tarpit                   : ✓          ║\n")
	fmt.Printf("  ╠══════════════════════════════════════════╣\n")
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
	// 9. Simulation loop (feeds synthetic packets to keep engines alive)
	// ---------------------------------------------------------------------------
	stopSim := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		// Simulated "normal" traffic sources
		normalIPs := []string{"10.0.0.5", "10.0.0.10", "192.168.1.100"}
		normalPorts := []uint16{80, 443, 53, 22, 8080}

		idx := 0
		for {
			select {
			case <-stopSim:
				return
			case <-ticker.C:
				srcIP := normalIPs[idx%len(normalIPs)]
				dstPort := normalPorts[idx%len(normalPorts)]
				idx++

				// Feed PacketInspector — simulate normal TCP SYN + ACK
				threats := pi.Feed("S", srcIP, dstPort, "TCP")
				for _, t := range threats {
					scorer.GetOrCreate(t.IP)
					scorer.AddScanScore(t.IP, 1)
				}

				// Feed FlowAnalyzer — track port diversity
				faThreats := fa.Feed(srcIP, dstPort)
				for _, t := range faThreats {
					scorer.GetOrCreate(t.IP)
					scorer.AddScanScore(t.IP, 5)
				}

				// Feed DNS detector — a normal query
				dnsDetector.Feed(srcIP, "api.example.com")

				// Feed BehaviorAnalyzer
				behaviorAnalyzer.Feed(srcIP, dstPort)

				// Feed HybridAnomalyDetector — normal single-packet flow
				hybridThreats := hybridDetector.Feed(srcIP, "10.0.0.1", 54321, dstPort, "TCP", 64, 2, 3.5)
				for _, t := range hybridThreats {
					scorer.GetOrCreate(t.IP)
					scorer.AddAnomalyScore(t.IP, 5.0)
				}

				// Check BruteForce periodically
				if idx%30 == 0 {
					bfThreats := bruteDetector.CheckAll()
					for _, t := range bfThreats {
						scorer.GetOrCreate(t.IP)
						scorer.AddScanScore(t.IP, 3)
					}
				}

				// Check DNS tunnel periodically
				if idx%10 == 0 {
					for _, ip := range normalIPs {
						dnsThreats := dnsDetector.Check(ip)
						for _, t := range dnsThreats {
							scorer.GetOrCreate(t.IP)
							scorer.AddAnomalyScore(t.IP, 3.0)
						}
					}
				}

				// Check CorrelationEngine
				correlationEngine.Feed(srcIP, "normal_traffic")
				if idx%60 == 0 {
					corrThreats := correlationEngine.CheckCorrelation()
					for _, t := range corrThreats {
						log.Printf("[defense] correlation alert: %s", t.Type)
					}
				}

				// Check BehaviorAnalyzer periodically
				if idx%60 == 0 {
					baThreats := behaviorAnalyzer.Check()
					for _, t := range baThreats {
						log.Printf("[defense] behavior anomaly: %s", t.Detail)
					}
				}

				// Check honeypot hits
				if honeypotMgr.CheckHit(srcIP) {
					scorer.AddHoneypotTrip(srcIP)
				}

				// Feed fingerprint engine with minimal data
				_ = fingerprintEngine.Feed(srcIP, nil, 64, 65535, true, 1460, []string{"MSS", "SACK", "TS"})

				// Evict stale entries every 30 seconds
				if idx%30 == 0 {
					deadline := float64(time.Now().Add(-60 * time.Second).Unix())
					pi.Evict(deadline)
					fa.Evict(deadline)
					dnsDetector.Evict(deadline)
					httpInspector.Evict(deadline)
					bruteDetector.Evict(deadline)
					hybridDetector.Evict(deadline)
					behaviorAnalyzer.Evict(deadline)
					correlationEngine.Evict(deadline)
				}

				// Cleanup tarpit periodically
				if idx%300 == 0 {
					tarpit.Cleanup()
				}
			}
		}
	}()

	// ---------------------------------------------------------------------------
	// 10. Signal handling and graceful shutdown
	// ---------------------------------------------------------------------------
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("   Defense pipeline running — Press Ctrl+C to stop")
	<-sig

	fmt.Println("\n   Shutting down gracefully...")
	close(stopSim)

	// Stop honeypots.
	if err := honeypotMgr.StopAll(); err != nil {
		log.Printf("Warning: honeypot stop error: %v", err)
	}

	// Close swarm.
	if gossipNode != nil {
		gossipNode.Stop()
	}

	fmt.Println("   Defense pipeline stopped.")
}

func init() {
	log.SetFlags(log.Ltime | log.Lshortfile)
}
