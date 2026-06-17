package engine

import (
	"testing"

	"github.com/fortress/v6/internal/config"
)

func TestSYNFloodDetection(t *testing.T) {
	cfg := config.Default()
	cfg.Engine.SynFloodPPS = 10
	pi := NewPacketInspector(cfg)
	var alerts int
	for i := 0; i < 50; i++ {
		if len(pi.Feed("S", "203.0.113.99", 443, "TCP")) > 0 { alerts++ }
	}
	if alerts == 0 { t.Error("expected SYN flood alerts") }
	t.Logf("SYN flood: %d alerts from 50 packets", alerts)
}

func TestSensitivePortProbe(t *testing.T) {
	pi := NewPacketInspector(config.Default())
	threats := pi.Feed("S", "203.0.113.99", 22, "TCP")
	found := false
	for _, th := range threats {
		if th.Type == "敏感端口探测" { found = true }
	}
	if !found { t.Error("expected sensitive port probe alert for port 22") }
}

func TestARP(t *testing.T) {
	pi := NewPacketInspector(config.Default())
	th := pi.FeedARP("192.168.1.1", "aa:bb:cc:dd:ee:ff")
	if th.Type != "ARP应答" { t.Errorf("expected ARP应答, got %s", th.Type) }
}
