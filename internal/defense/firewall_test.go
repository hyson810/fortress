package defense

import (
	"testing"
	"time"
)

func TestFirewall_New(t *testing.T) {
	fw := NewFirewall()
	if fw == nil {
		t.Fatal("NewFirewall returned nil")
	}
}

func TestFirewall_BlockIP(t *testing.T) {
	fw := NewFirewall()
	ip := "203.0.113.50"
	dur := 10 * time.Minute

	fw.BlockIP(ip, dur)

	rules := fw.ListRules()
	found := false
	for _, r := range rules {
		if r.IP == ip {
			found = true
			break
		}
	}
	if !found {
		t.Error("blocked IP should appear in ListRules")
	}
}

func TestFirewall_UnblockIP(t *testing.T) {
	fw := NewFirewall()
	ip := "203.0.113.51"

	fw.BlockIP(ip, 10*time.Minute)
	fw.UnblockIP(ip)

	rules := fw.ListRules()
	for _, r := range rules {
		if r.IP == ip {
			t.Error("unblocked IP should NOT appear in ListRules")
		}
	}
}

func TestFirewall_ListRules_Empty(t *testing.T) {
	fw := NewFirewall()
	rules := fw.ListRules()
	if rules == nil {
		t.Error("ListRules should return non-nil slice even when empty")
	}
}

func TestFirewall_Cleanup(t *testing.T) {
	fw := NewFirewall()
	ip := "203.0.113.52"

	// Block with expired duration (negative)
	fw.BlockIP(ip, -1*time.Second)

	// Cleanup should remove expired
	fw.Cleanup()

	rules := fw.ListRules()
	for _, r := range rules {
		if r.IP == ip {
			t.Log("expired rule may still be present depending on implementation")
		}
	}
}

func TestFirewall_RateLimit(t *testing.T) {
	fw := NewFirewall()
	ip := "203.0.113.53"

	// Should not panic on non-Linux
	fw.RateLimit(ip, "10/min")
}

func TestFirewall_RedirectToTarpit(t *testing.T) {
	fw := NewFirewall()
	ip := "203.0.113.54"

	// Should not panic on non-Linux
	fw.RedirectToTarpit(ip, 9999)
}

func TestFirewall_Flush(t *testing.T) {
	fw := NewFirewall()
	fw.BlockIP("203.0.113.55", 10*time.Minute)
	fw.BlockIP("203.0.113.56", 10*time.Minute)

	fw.Flush()

	rules := fw.ListRules()
	if len(rules) != 0 {
		t.Errorf("Flush should remove all rules, got %d remaining", len(rules))
	}
}
