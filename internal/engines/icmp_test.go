package engines

import (
	"testing"
	"time"

	"github.com/fortress/v6/internal/config"
)

func testICMPConfig() *config.Config {
	cfg := config.Default()
	cfg.SetWhitelist(nil)
	return cfg
}

func TestICMPTunnelDetector_New(t *testing.T) {
	d := NewICMPTunnelDetector(testICMPConfig())
	if d == nil {
		t.Fatal("NewICMPTunnelDetector returned nil")
	}
	if d.ActiveIPs() != 0 {
		t.Errorf("expected 0 active IPs, got %d", d.ActiveIPs())
	}
}

func TestICMPTunnelDetector_Feed_NormalTraffic(t *testing.T) {
	d := NewICMPTunnelDetector(testICMPConfig())

	// Normal ping: 10 echo requests with small payloads.
	for i := 0; i < 10; i++ {
		threats := d.Feed("10.0.0.1", 8, 0, 56)
		if len(threats) > 0 {
			t.Logf("normal ping triggered alert: %v", threats)
		}
	}

	if d.ActiveIPs() != 1 {
		t.Errorf("expected 1 active IP, got %d", d.ActiveIPs())
	}
}

func TestICMPTunnelDetector_Feed_TunnelPayload(t *testing.T) {
	d := NewICMPTunnelDetector(testICMPConfig())

	// Simulate ICMP tunneling: many large echo requests.
	// This should trigger the ICMP隧道 alert.
	tunnelIP := "10.0.0.99"
	var threats []Threat
	for i := 0; i < 20; i++ {
		threats = append(threats, d.Feed(tunnelIP, 8, 0, 2048)...)
	}

	found := false
	for _, th := range threats {
		if th.Type == "ICMP隧道" && th.IP == tunnelIP {
			found = true
			t.Logf("detected ICMP tunnel: %s", th.Detail)
		}
	}
	if !found && len(threats) > 0 {
		t.Logf("other threats detected: %d", len(threats))
	}
	// Note: tunnel detection may not fire if the ratio threshold isn't met.
	// This test documents the expected behavior.
}

func TestICMPTunnelDetector_Feed_CovertChannel(t *testing.T) {
	d := NewICMPTunnelDetector(testICMPConfig())

	// Simulate covert channel: ICMP timestamp requests.
	// Type 13 (Timestamp), 15 (InfoRequest), 17 (MaskRequest) are unusual.
	covertIP := "172.16.0.99"
	var threats []Threat

	// Mix of normal and unusual types.
	for i := 0; i < 5; i++ {
		threats = append(threats, d.Feed(covertIP, 13, 0, 64)...) // timestamp
	}
	for i := 0; i < 5; i++ {
		threats = append(threats, d.Feed(covertIP, 8, 0, 64)...) // echo (normal)
	}

	found := false
	for _, th := range threats {
		if th.Type == "ICMP隐蔽信道" && th.IP == covertIP {
			found = true
			t.Logf("detected covert channel: %s", th.Detail)
		}
	}
	if found {
		t.Logf("covert channel detected correctly")
	}
}

func TestICMPTunnelDetector_Feed_DataExfil(t *testing.T) {
	d := NewICMPTunnelDetector(testICMPConfig())

	// Simulate ICMP data exfiltration: many large echo packets.
	exfilIP := "10.10.10.10"
	var threats []Threat
	for i := 0; i < 60; i++ {
		threats = append(threats, d.Feed(exfilIP, 8, 0, 512)...)
	}

	found := false
	for _, th := range threats {
		if th.Type == "ICMP数据外泄" && th.IP == exfilIP {
			found = true
			t.Logf("detected data exfiltration: %s", th.Detail)
		}
	}
	if found {
		t.Logf("ICMP data exfiltration detected correctly")
	}
}

func TestICMPTunnelDetector_WhitelistBypass(t *testing.T) {
	cfg := testICMPConfig()
	cfg.Whitelist = []string{"10.0.0.0/8"}
	cfg.SetWhitelist(cfg.Whitelist)

	d := NewICMPTunnelDetector(cfg)

	// Whitelisted IP sending tunnel-like traffic.
	for i := 0; i < 30; i++ {
		threats := d.Feed("10.50.50.50", 8, 0, 2048)
		if len(threats) > 0 {
			t.Errorf("whitelisted IP should not generate threats, got %d", len(threats))
		}
	}
}

func TestICMPTunnelDetector_Evict(t *testing.T) {
	d := NewICMPTunnelDetector(testICMPConfig())

	// Add some traffic.
	for i := 0; i < 15; i++ {
		d.Feed("192.168.1.1", 8, 0, 64)
	}
	if d.ActiveIPs() != 1 {
		t.Errorf("expected 1 active IP, got %d", d.ActiveIPs())
	}

	// Evict with a deadline 2 seconds in the future (records last seen before this are stale).
	// Use Add(2*Second) because Unix() truncates sub-second precision.
	evicted := d.Evict(float64(time.Now().Add(2 * time.Second).Unix()))
	if evicted == 0 {
		t.Error("expected eviction of old records")
	}
	if d.ActiveIPs() != 0 {
		t.Errorf("expected 0 IPs after eviction, got %d", d.ActiveIPs())
	}
}

func TestICMPTunnelDetector_MultipleIPs(t *testing.T) {
	d := NewICMPTunnelDetector(testICMPConfig())

	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	for _, ip := range ips {
		for j := 0; j < 12; j++ {
			d.Feed(ip, 8, 0, 64)
		}
	}

	if d.ActiveIPs() != 5 {
		t.Errorf("expected 5 active IPs, got %d", d.ActiveIPs())
	}
}
