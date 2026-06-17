package engine

import (
	"testing"
	"time"

	"github.com/fortress/v6/internal/config"
)

func TestHybridAnomalyFeed(t *testing.T) {
	ha := NewHybridAnomalyDetector(config.Default())
	pkt := PacketContext{
		Timestamp:   time.Now(),
		SrcIP:       "203.0.113.99",
		DstIP:       "10.0.0.1",
		SrcPort:     12345,
		DstPort:     443,
		Protocol:    "TCP",
		TCPFlags:    "S",
		PayloadSize: 1500,
	}
	for i := 0; i < 10; i++ {
		ha.Feed(pkt)
	}
	threats := ha.Feed(pkt)
	t.Logf("Hybrid anomaly threats: %d", len(threats))
}

func TestOSDetectionLinux(t *testing.T) {
	fe := NewFingerprintEngine(config.Default())
	threats := fe.FeedSYN("10.0.0.1", 64, 65535, true)
	if len(threats) > 0 {
		t.Errorf("expected no threat for normal Linux SYN, got %v", threats)
	}
}

func TestOSDetectionSpoofed(t *testing.T) {
	fe := NewFingerprintEngine(config.Default())
	threats := fe.FeedSYN("10.0.0.2", 32, 12345, false)
	if len(threats) == 0 {
		t.Error("expected OS anomaly for spoofed SYN")
	}
	t.Logf("OS anomaly: %s", threats[0].Detail)
}
