package engine

import (
	"strings"
	"testing"

	"github.com/fortress/v6/internal/config"
)

func TestBehaviorBaseline(t *testing.T) {
	ba := NewBehaviorAnalyzer(config.Default())
	// Feed enough samples to establish baseline (200+)
	for i := 0; i < 250; i++ {
		ba.Feed("10.0.0.1", uint16(80+i%10))
	}
	threats := ba.Check()
	t.Logf("Baseline check: %d threats (expected 0, normal traffic)", len(threats))
}

func TestDNSTunnelLongQuery(t *testing.T) {
	d := NewDnsTunnelDetector(config.Default())
	longQuery := strings.Repeat("x", 60) + ".example.com"
	threats := d.Feed("10.0.0.1", longQuery)
	if len(threats) == 0 {
		t.Error("expected DNS tunnel alert for long query")
	}
}

func TestDNSTunnelHighEntropy(t *testing.T) {
	d := NewDnsTunnelDetector(config.Default())
	highEntropy := "dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0.exfil.com"
	threats := d.Feed("10.0.0.2", highEntropy)
	if len(threats) == 0 {
		t.Error("expected DNS tunnel alert for high-entropy query")
	}
}
