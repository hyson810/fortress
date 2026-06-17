package engine

import (
	"testing"
	"time"

	"github.com/fortress/v6/internal/config"
)

func TestPortScanFastDetection(t *testing.T) {
	fa := NewFlowAnalyzer(config.Default())
	// 15 unique ports to same IP triggers fast scan (threshold 12 in 5s)
	for port := uint16(1); port <= 15; port++ {
		threats := fa.Feed("203.0.113.99", port)
		if port >= 12 && len(threats) > 0 {
			t.Logf("port %d: detected %s", port, threats[0].Type)
			return
		}
	}
	t.Error("expected fast scan detection after 12 unique ports")
}

func TestFlowEviction(t *testing.T) {
	fa := NewFlowAnalyzer(config.Default())
	fa.Feed("10.0.0.1", 80)
	fa.Feed("10.0.0.1", 443)
	removed := fa.Evict(time.Now().Add(time.Hour)) // evict everything
	if removed != 1 {
		t.Errorf("expected 1 IP evicted, got %d", removed)
	}
}
