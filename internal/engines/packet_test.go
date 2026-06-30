package engines

import (
	"testing"
	"time"

	"github.com/fortress/v6/internal/config"
)

func testPacketConfig() *config.Config {
	return &config.Config{
		Engine: config.EngineConfig{
			SynFloodPPS:  100,
			UdpFloodPPS:  150,
			IcmpFloodPPS: 30,
		},
		Whitelist: []string{},
	}
}

func TestPacketInspector_New(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())
	if pi == nil {
		t.Fatal("NewPacketInspector returned nil")
	}
}

func TestPacketInspector_Feed_SYNFlood(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())
	ip := "192.168.1.100"

	var threats []Threat
	for i := 0; i < 120; i++ {
		threats = pi.Feed("S", ip, 80, "TCP")
	}
	if len(threats) == 0 {
		t.Error("expected SYN flood threats after 120 packets")
	}
	found := false
	for _, th := range threats {
		if th.Type == "SYN洪水" && th.IP == ip {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SYN洪水 threat, got %d threats", len(threats))
	}
}

func TestPacketInspector_Feed_FINScan(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())
	ip := "10.10.10.50"

	threats := pi.Feed("F", ip, 22, "TCP")
	if len(threats) == 0 {
		t.Fatal("expected FIN scan threat")
	}
	if threats[0].Type != "FIN扫描" {
		t.Errorf("expected FIN扫描, got %s", threats[0].Type)
	}
}

func TestPacketInspector_Feed_XmasScan(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())
	ip := "10.10.10.60"

	threats := pi.Feed("FPU", ip, 80, "TCP")
	if len(threats) == 0 {
		t.Fatal("expected Xmas scan threat")
	}
	if threats[0].Type != "Xmas扫描" {
		t.Errorf("expected Xmas扫描, got %s", threats[0].Type)
	}
}

func TestPacketInspector_Feed_NullScan(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())
	ip := "10.10.10.70"

	threats := pi.Feed("N", ip, 443, "TCP")
	if len(threats) == 0 {
		t.Fatal("expected NULL scan threat")
	}
}

func TestPacketInspector_Feed_SensitivePort(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())
	ip := "10.10.10.80"

	threats := pi.Feed("S", ip, 22, "TCP")
	found := false
	for _, th := range threats {
		if th.Type == "敏感端口探测" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 敏感端口探测 for port 22")
	}
}

func TestPacketInspector_Feed_UDPFlood(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())
	ip := "10.10.10.90"

	var threats []Threat
	for i := 0; i < 200; i++ {
		threats = pi.Feed("", ip, 53, "UDP")
	}
	found := false
	for _, th := range threats {
		if th.Type == "UDP洪水" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected UDP洪水 after 200 UDP packets")
	}
}

func TestPacketInspector_FeedARP(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())
	ip := "10.10.10.100"

	threat := pi.FeedARP(ip, "aa:bb:cc:dd:ee:ff")
	if threat.Type != "ARP应答" {
		t.Errorf("expected ARP应答, got %s", threat.Type)
	}
	if threat.Detail == "" {
		t.Errorf("expected MAC in detail, got empty")
	}
}

func TestPacketInspector_WhitelistBypass(t *testing.T) {
	cfg := testPacketConfig()
	cfg.SetWhitelist([]string{"10.0.0.0/8"})
	pi := NewPacketInspector(cfg)
	ip := "10.0.0.55"

	threats := pi.Feed("F", ip, 22, "TCP")
	if len(threats) != 0 {
		t.Errorf("whitelisted IP should have 0 threats, got %d", len(threats))
	}

	// ARP should still fire even for whitelisted
	arpThreat := pi.FeedARP(ip, "aa:bb:cc:dd:ee:ff")
	if arpThreat.Type == "" {
		t.Error("ARP should still fire for whitelisted IP")
	}
}

func TestPacketInspector_Evict(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())
	ip := "10.10.10.200"

	for i := 0; i < 50; i++ {
		pi.Feed("S", ip, 80, "TCP")
	}

	removed := pi.Evict(float64(time.Now().Add(1 * time.Hour).Unix()))
	_ = removed
}

func TestPacketInspector_DetectSMSScan(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())

	// SMB port 445 probe should trigger SMB scan detection.
	threat := pi.DetectSMSScan("10.0.0.99", 445)
	if threat == nil {
		t.Fatal("expected SMB scan threat on port 445")
	}
	if threat.Type != "SMB扫描" {
		t.Errorf("expected SMB扫描, got %s", threat.Type)
	}

	// SMB port 139 probe.
	threat2 := pi.DetectSMSScan("10.0.0.99", 139)
	if threat2 == nil {
		t.Fatal("expected SMB scan threat on port 139")
	}

	// Non-SMB port should not trigger.
	threat3 := pi.DetectSMSScan("10.0.0.99", 80)
	if threat3 != nil {
		t.Errorf("expected nil threat for non-SMB port, got %v", threat3)
	}

	// Whitelisted IP should not trigger.
	cfg := testPacketConfig()
	cfg.SetWhitelist([]string{"10.0.0.0/8"})
	piWL := NewPacketInspector(cfg)
	threat4 := piWL.DetectSMSScan("10.0.0.99", 445)
	if threat4 != nil {
		t.Errorf("whitelisted IP should not trigger SMB scan, got %v", threat4)
	}
	t.Log("SMB scan detection verified")
}

func TestPacketInspector_DetectICSScan(t *testing.T) {
	pi := NewPacketInspector(testPacketConfig())

	// Modbus (502) scan.
	threat := pi.DetectICSScan("192.168.1.100", 502)
	if threat == nil {
		t.Fatal("expected ICS scan threat on Modbus port 502")
	}
	if threat.Type != "ICS/SCADA扫描" {
		t.Errorf("expected ICS/SCADA扫描, got %s", threat.Type)
	}
	if threat.Detail == "" {
		t.Error("ICS scan detail should not be empty")
	}

	// EtherNet/IP (44818) scan.
	threat2 := pi.DetectICSScan("192.168.1.100", 44818)
	if threat2 == nil {
		t.Fatal("expected ICS scan threat on EtherNet/IP port 44818")
	}

	// BACnet (47808) scan.
	threat3 := pi.DetectICSScan("192.168.1.100", 47808)
	if threat3 == nil {
		t.Fatal("expected ICS scan threat on BACnet port 47808")
	}

	// IEC 104 (2404) scan.
	threat4 := pi.DetectICSScan("192.168.1.100", 2404)
	if threat4 == nil {
		t.Fatal("expected ICS scan threat on IEC-104 port 2404")
	}

	// Normal port should not trigger.
	threat5 := pi.DetectICSScan("192.168.1.100", 80)
	if threat5 != nil {
		t.Errorf("expected nil threat for non-ICS port, got %v", threat5)
	}
	t.Log("ICS/SCADA scan detection verified")
}

func TestSensitivePorts_NewPorts(t *testing.T) {
	// Verify newly added sensitive ports are in the map.
	newPorts := []uint16{1521, 389, 636, 3268, 3269, 5985, 5986, 502, 44818, 47808, 2404}
	for _, port := range newPorts {
		if !SensitivePorts[port] {
			t.Errorf("port %d should be in SensitivePorts", port)
		}
	}
	t.Logf("SensitivePorts has %d entries", len(SensitivePorts))
}
