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
	"github.com/fortress/v6/internal/engine"
)

var (
	configPath = flag.String("config", "/etc/fortress/fortress.yaml", "path to config file")
	mode       = flag.String("mode", "defend", "operating mode: defend, scan")
	target     = flag.String("target", "", "target IP/URL for scan mode")
	topN       = flag.Int("top", 10, "show top N threats")
)

func main() {
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	log.Printf("Fortress V6 — %s mode", *mode)
	log.Printf("Engine: SYN=%dpps UDP=%dpps ICMP=%dpps",
		cfg.Engine.SynFloodPPS, cfg.Engine.UdpFloodPPS, cfg.Engine.IcmpFloodPPS)

	switch *mode {
	case "defend":
		runDefense(cfg)
	case "scan":
		runScan(cfg, *target)
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}

func runDefense(cfg *config.Config) {
	log.Println("[defense] initializing detection pipeline...")

	// L1-L7 Engines
	pi := engine.NewPacketInspector(cfg)
	fa := engine.NewFlowAnalyzer(cfg)
	ba := engine.NewBehaviorAnalyzer(cfg)
	dd := engine.NewDnsTunnelDetector(cfg)
	hi := engine.NewHttpInspector(cfg)
	bf := engine.NewBruteForceDetector(cfg)
	ha := engine.NewHybridAnomalyDetector(cfg)
	fe := engine.NewFingerprintEngine(cfg)

	// Brain
	weights := brain.DefaultWeights()
	if cfg.Brain.AggressiveMode {
		weights = brain.AggressiveWeights()
	}
	scorer := brain.NewScorer(weights, cfg.Brain.BanDuration, 50000)
	corr := brain.NewCorrelationEngine()

	log.Println("[defense] all engines initialized")
	log.Printf("[defense] response mode: %s", map[bool]string{false: "normal", true: "aggressive"}[cfg.Brain.AggressiveMode])

	// Try Rust FFI muscle layer
	ffiActive := false
	if err := engine.InitFFI("eth0"); err != nil {
		log.Printf("[defense] Rust muscle not available: %v — using simulation mode", err)
	} else {
		log.Println("[defense] Rust muscle engine loaded — AF_XDP active")
		ffiActive = true
		defer engine.CloseFFI()
	}
	log.Println("[defense] awaiting packets...")

	// Signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	simTicker := time.NewTicker(1 * time.Second)
	defer simTicker.Stop()
	checkTicker := time.NewTicker(5 * time.Second)
	defer checkTicker.Stop()
	evictTicker := time.NewTicker(60 * time.Second)
	defer evictTicker.Stop()
	reportTicker := time.NewTicker(30 * time.Second)
	defer reportTicker.Stop()

	packetCount := 0

	for {
		select {
		case <-sigCh:
			log.Println("[defense] shutting down...")
			log.Printf("[defense] session stats: %d packets processed, %d IPs tracked",
				packetCount, scorer.RecordCount())
			return

		case <-simTicker.C:
			// Try Rust FFI muscle first
			if ffiActive {
				if pkt, ok := engine.ReadFFI(); ok {
					packetCount++
					// L1: packet inspection
					for _, th := range pi.Feed(pkt.TCPFlags, pkt.SrcIP, pkt.DstPort, pkt.Protocol) {
						scorer.AddThreat(th)
						corr.Feed(th.IP, th.Type)
					}
					// L2: flow analysis
					for _, th := range fa.Feed(pkt.SrcIP, pkt.DstPort) {
						scorer.AddThreat(th)
						corr.Feed(th.IP, th.Type)
					}
					// L3: behavior
					ba.Feed(pkt.SrcIP, pkt.DstPort)
					// L4: DNS (periodic)
					if packetCount%10 == 0 {
						for _, th := range dd.Feed(pkt.SrcIP, "api.example.com") {
							scorer.AddThreat(th)
						}
					}
					// L5: brute force
					bf.FeedSSH(pkt.SrcIP)
					// L6: hybrid anomaly
					ha.Feed(pkt)
					// L7: fingerprint
					fe.FeedSYN(pkt.SrcIP, int(pkt.PayloadSize), 65535, true)
					continue
				}
				// No FFI packet available, inject a test packet
				engine.InjectFFI(
					fmt.Sprintf("192.168.1.%d", packetCount%254+1),
					"10.0.0.1",
					uint16(12345+packetCount%1000),
					80,
					"TCP",
					"S",
					64,
				)
			}

			packetCount++
			srcIP := fmt.Sprintf("192.168.1.%d", packetCount%254+1)
			dstPort := uint16(80 + packetCount%100)

			// L1
			for _, th := range pi.Feed("AS", srcIP, dstPort, "TCP") {
				scorer.AddThreat(th)
				corr.Feed(th.IP, th.Type)
			}
			// L2
			for _, th := range fa.Feed(srcIP, dstPort) {
				scorer.AddThreat(th)
				corr.Feed(th.IP, th.Type)
			}
			// L3
			ba.Feed(srcIP, dstPort)
			// L4 (periodic)
			if packetCount%10 == 0 {
				for _, th := range dd.Feed(srcIP, "api.example.com") {
					scorer.AddThreat(th)
				}
			}
			// L5
			bf.FeedSSH(srcIP)
			// L6
			ha.Feed(engine.PacketContext{
				Timestamp:   time.Now(),
				SrcIP:       srcIP,
				DstIP:       "10.0.0.1",
				SrcPort:     12345,
				DstPort:     dstPort,
				Protocol:    "TCP",
				TCPFlags:    "AS",
				PayloadSize: 64,
			})
			// L7
			fe.FeedSYN(srcIP, 64, 65535, true)

		case <-checkTicker.C:
			for _, th := range ba.Check() {
				corr.Feed("", th.Type)
			}
			for _, th := range bf.Check() {
				scorer.AddThreat(th)
			}
			if ips, mult := corr.Check(); len(ips) > 0 {
				log.Printf("[correlation] %d IPs coordinated, multiplier=%.1f", len(ips), mult)
			}

		case <-reportTicker.C:
			if scorer.RecordCount() > 0 {
				log.Printf("[status] tracking %d IPs", scorer.RecordCount())
			}

		case <-evictTicker.C:
			hi.EvictIdle()
			ha.EvictIdle(10 * time.Minute)
			fa.Evict(time.Now().Add(-10 * time.Minute))
			scorer.CleanupStale(1.0, 30*time.Minute)
		}
	}
}

func runScan(cfg *config.Config, target string) {
	if target == "" {
		log.Fatal("scan mode requires --target")
	}
	if err := config.ValidateTarget(target); err != nil {
		log.Fatalf("invalid target: %v", err)
	}
	log.Printf("[scan] target validated: %s", target)
	log.Println("[scan] Kali nmap/nuclei integration in Plan C")
}
