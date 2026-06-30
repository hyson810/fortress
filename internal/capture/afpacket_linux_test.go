//go:build linux

package capture

import "testing"

func TestAFPacketCreate(t *testing.T) {
	// Test that NewAFPacketHandler with invalid interface returns error.
	_, err := NewAFPacketHandler(AFPacketConfig{Interface: "nonexistent0"})
	if err == nil {
		t.Error("expected error for nonexistent interface")
	}
}
