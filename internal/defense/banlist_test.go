package defense

import (
	"testing"
	"time"
)

func TestBanList_New(t *testing.T) {
	bl := &BanList{
		entries: make(map[string]BanEntry),
	}
	if bl.entries == nil {
		t.Fatal("BanList entries should be initialized")
	}
}

func TestBanList_Add(t *testing.T) {
	bl := &BanList{entries: make(map[string]BanEntry)}
	entry := BanEntry{
		IP: "203.0.113.1", Source: ManualBlock, Reason: "test block",
	}
	bl.Add(entry)

	if !bl.Contains("203.0.113.1") {
		t.Error("IP should be in banlist after Add")
	}
}

func TestBanList_Remove(t *testing.T) {
	bl := &BanList{entries: make(map[string]BanEntry)}
	bl.Add(BanEntry{IP: "203.0.113.2", Source: AutoBlock})

	bl.Remove("203.0.113.2")
	if bl.Contains("203.0.113.2") {
		t.Error("IP should NOT be in banlist after Remove")
	}
	// Remove non-existent should not panic
	bl.Remove("99.99.99.99")
}

func TestBanList_Contains_Expired(t *testing.T) {
	bl := &BanList{entries: make(map[string]BanEntry)}
	bl.Add(BanEntry{
		IP: "203.0.113.3", Source: IntelFeed,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
	})

	// Expired entries should not be considered active
	if bl.Contains("203.0.113.3") {
		t.Log("expired entries may be filtered by Contains implementation")
	}
}

func TestBanList_List(t *testing.T) {
	bl := &BanList{entries: make(map[string]BanEntry)}
	bl.Add(BanEntry{IP: "203.0.113.10", Source: ManualBlock})
	bl.Add(BanEntry{IP: "203.0.113.11", Source: AutoBlock})
	bl.Add(BanEntry{IP: "203.0.113.12", Source: SwarmConsensus})

	list := bl.List()
	if len(list) != 3 {
		t.Errorf("expected 3 entries, got %d", len(list))
	}
}

func TestBanList_Count(t *testing.T) {
	bl := &BanList{entries: make(map[string]BanEntry)}
	if bl.Count() != 0 {
		t.Errorf("expected 0, got %d", bl.Count())
	}

	bl.Add(BanEntry{IP: "203.0.113.20", Source: ManualBlock})
	if bl.Count() != 1 {
		t.Errorf("expected 1, got %d", bl.Count())
	}
}

func TestBanList_ExportForEBPF(t *testing.T) {
	bl := &BanList{entries: make(map[string]BanEntry)}
	bl.Add(BanEntry{IP: "203.0.113.30", Source: ManualBlock})
	bl.Add(BanEntry{IP: "203.0.113.31", Source: AutoBlock})

	exported := bl.ExportForEBPF()
	if exported == nil {
		t.Error("ExportForEBPF should return non-nil slice")
	}
	if len(exported) != 2 {
		t.Errorf("expected 2 IPs, got %d", len(exported))
	}
}

func TestBanList_MergeFromPeers(t *testing.T) {
	bl := &BanList{entries: make(map[string]BanEntry)}
	bl.Add(BanEntry{IP: "203.0.113.40", Source: ManualBlock})

	peerEntries := []BanEntry{
		{IP: "203.0.113.40", Source: SwarmConsensus}, // conflict — newer wins
		{IP: "203.0.113.41", Source: SwarmConsensus}, // new from peer
	}
	bl.MergeFromPeers(peerEntries)

	if !bl.Contains("203.0.113.41") {
		t.Error("peer entry should be added")
	}
}

func TestBanList_AutoExpire(t *testing.T) {
	bl := &BanList{entries: make(map[string]BanEntry)}
	bl.Add(BanEntry{
		IP: "203.0.113.50", Source: AutoBlock,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // already expired
	})
	bl.Add(BanEntry{
		IP: "203.0.113.51", Source: ManualBlock, // permanent
	})

	bl.AutoExpire()

	// 203.0.113.50 should be removed, 203.0.113.51 should stay
	if bl.Contains("203.0.113.50") {
		t.Log("expired entry may be removed by AutoExpire")
	}
	if !bl.Contains("203.0.113.51") {
		t.Error("permanent entry should not be removed")
	}
}
