package brain

import (
	"testing"
)

func makeThreat(ip string) Threat {
	return Threat{
		IPRecord: &IPRecord{IP: ip},
	}
}

func TestClassifyAttack_SYNFlood(t *testing.T) {
	threats := []Threat{
		{
			IPRecord:      &IPRecord{IP: "10.0.0.1", FloodScore: 40, TotalScore: 50},
			PacketRate:    600,
			ProtocolHints: []string{"syn"},
		},
	}
	at, conf := ClassifyAttack(threats)
	if at == AttackUnknown {
		t.Error("should classify as something, got Unknown")
	}
	t.Logf("SYNFlood test: type=%s confidence=%.2f", at.String(), conf)
}

func TestClassifyAttack_PortScan(t *testing.T) {
	threats := []Threat{
		{
			IPRecord:     &IPRecord{IP: "10.0.0.2", ScanScore: 20},
			PortsScanned: 50,
			PacketRate:   10,
		},
	}
	at, conf := ClassifyAttack(threats)
	t.Logf("PortScan test: type=%s confidence=%.2f", at.String(), conf)
}

func TestClassifyAttack_DNSTunnel(t *testing.T) {
	threats := []Threat{
		{
			IPRecord:       &IPRecord{IP: "10.0.0.3", AnomalyScore: 8},
			DNSQueries:     200,
			PayloadSamples: []string{"very-long-query-name-that-exceeds-normal-dns-length-limit"},
		},
	}
	at, _ := ClassifyAttack(threats)
	t.Logf("DNSTunnel test: type=%s", at.String())
}

func TestClassifyAttack_SQLInjection(t *testing.T) {
	threats := []Threat{
		{
			IPRecord:  &IPRecord{IP: "10.0.0.4"},
			HTTPPaths: []string{"/products?id=1 UNION SELECT password FROM users"},
		},
	}
	at, _ := ClassifyAttack(threats)
	t.Logf("SQLInjection test: type=%s", at.String())
}

func TestClassifyAttack_XSS(t *testing.T) {
	threats := []Threat{
		{
			IPRecord:       &IPRecord{IP: "10.0.0.5"},
			PayloadSamples: []string{"<script>alert(document.cookie)</script>"},
		},
	}
	at, _ := ClassifyAttack(threats)
	t.Logf("XSS test: type=%s", at.String())
}

func TestClassifyAttack_PathTraversal(t *testing.T) {
	threats := []Threat{
		{
			IPRecord:  &IPRecord{IP: "10.0.0.6"},
			HTTPPaths: []string{"/download?file=../../etc/passwd"},
		},
	}
	at, _ := ClassifyAttack(threats)
	t.Logf("PathTraversal test: type=%s", at.String())
}

func TestClassifyAttack_SSHBruteForce(t *testing.T) {
	threats := []Threat{
		{
			IPRecord:      &IPRecord{IP: "10.0.0.7", AnomalyScore: 15},
			ProtocolHints: []string{"ssh:22"},
			PacketRate:    30,
		},
	}
	at, _ := ClassifyAttack(threats)
	t.Logf("SSHBrute test: type=%s", at.String())
}

func TestClassifyAttack_CobaltStrike(t *testing.T) {
	threats := []Threat{
		{
			IPRecord:       &IPRecord{IP: "10.0.0.8"},
			PayloadSamples: []string{"MZ", "beacon", "windows/meterpreter"},
			ProtocolHints:  []string{"tls", "ja3_match"},
		},
	}
	at, _ := ClassifyAttack(threats)
	t.Logf("CobaltStrike test: type=%s", at.String())
}

func TestClassifyAttack_DataExfiltration(t *testing.T) {
	threats := []Threat{
		{
			IPRecord:    &IPRecord{IP: "10.0.0.9", AnomalyScore: 8},
			PacketRate:  300,
			Intensity:   70,
		},
	}
	at, _ := ClassifyAttack(threats)
	t.Logf("DataExfil test: type=%s", at.String())
}

func TestClassifyAttack_ARPSpoof(t *testing.T) {
	threats := []Threat{
		{
			IPRecord:      &IPRecord{IP: "10.0.0.10"},
			ProtocolHints: []string{"arp"},
		},
	}
	at, _ := ClassifyAttack(threats)
	t.Logf("ARPSpoof test: type=%s", at.String())
}

func TestClassifyAttack_EmptyThreats(t *testing.T) {
	at, conf := ClassifyAttack(nil)
	if at != AttackUnknown {
		t.Errorf("nil input should yield Unknown, got %s", at.String())
	}
	if conf != 0 {
		t.Errorf("nil input confidence should be 0, got %.2f", conf)
	}

	at, conf = ClassifyAttack([]Threat{})
	if at != AttackUnknown {
		t.Errorf("empty input should yield Unknown, got %s", at.String())
	}
}

func TestClassifyAttack_MultipleIPs(t *testing.T) {
	threats := []Threat{
		{IPRecord: &IPRecord{IP: "10.0.0.1", FloodScore: 30}, PacketRate: 500, ProtocolHints: []string{"syn"}},
		{IPRecord: &IPRecord{IP: "10.0.0.2", FloodScore: 30}, PacketRate: 500, ProtocolHints: []string{"syn"}},
		{IPRecord: &IPRecord{IP: "10.0.0.3", FloodScore: 30}, PacketRate: 500, ProtocolHints: []string{"syn"}},
	}
	at, conf := ClassifyAttack(threats)
	t.Logf("Multi-IP test: type=%s confidence=%.2f", at.String(), conf)
	if at == AttackUnknown {
		t.Error("3 coordinated SYN flooders should be classified")
	}
}

func TestAttackType_String(t *testing.T) {
	tests := []AttackType{
		AttackUnknown, AttackSYNFlood, AttackUDPFlood, AttackPortScan,
		AttackDNSTunnel, AttackSQLInjection, AttackXSS, AttackPathTraversal,
		AttackSSHBruteForce, AttackHTTPBruteForce, AttackARPSpoof,
		AttackCobaltStrike, AttackMetasploit, AttackAPT, AttackDataExfiltration,
	}
	for _, at := range tests {
		s := at.String()
		if s == "" {
			t.Errorf("AttackType %d has empty string", at)
		}
	}
}

func TestSeverityByType(t *testing.T) {
	if len(SeverityByType) == 0 {
		t.Fatal("SeverityByType should be non-empty")
	}
	for at, sev := range SeverityByType {
		if sev < 0 || sev > 1.0 {
			t.Errorf("AttackType %s has out-of-range severity %.2f", at.String(), sev)
		}
	}
}

func TestNewThreat(t *testing.T) {
	r := &IPRecord{IP: "10.0.0.99", TotalScore: 45.0}
	th := NewThreat(r)
	if th == nil {
		t.Fatal("NewThreat returned nil")
	}
	if th.IP != "10.0.0.99" {
		t.Errorf("expected IP=10.0.0.99, got %s", th.IP)
	}
	if th.Intensity != 45.0 {
		t.Errorf("expected Intensity=45.0, got %.1f", th.Intensity)
	}
}
