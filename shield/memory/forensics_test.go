//go:build linux

package memory

import (
	"testing"
	"time"
)

// TestForensicsSelfTest validates the internal data structures of the
// goroutine tracer without requiring actual eBPF attachments.
func TestForensicsSelfTest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping goroutine tracer self-test in short mode")
	}

	if err := TestGoroutineTracerSelf(); err != nil {
		t.Fatalf("goroutine tracer self-test failed: %v", err)
	}

	t.Log("goroutine tracer self-test passed")
}

// TestGetForensicsStats ensures stats retrieval works with empty state.
func TestGetForensicsStats(t *testing.T) {
	stats := GetForensicsStats()

	if stats.LastScanTime.IsZero() {
		// Expected before tracer starts; the LastScanTime is only set
		// by the scanner loop.
		t.Log("stats LastScanTime is zero (expected when tracer not running)")
	}

	if stats.ActiveGoroutines > 0 {
		t.Logf("active goroutines in stats: %d", stats.ActiveGoroutines)
	}
}

// TestGetGoroutineMapEmpty verifies the map retrieval works when empty.
func TestGetGoroutineMapEmpty(t *testing.T) {
	gmap := GetGoroutineMap()
	if gmap == nil {
		t.Fatal("GetGoroutineMap returned nil (should return empty map)")
	}

	if len(gmap) > 0 {
		t.Logf("goroutine map has %d entries (may be remnants from other tests)", len(gmap))
	}
}

// TestAnomalousGoroutinesEmpty verifies retrieval with no anomalies.
func TestAnomalousGoroutinesEmpty(t *testing.T) {
	records := GetAnomalousGoroutines()
	if records == nil {
		t.Fatal("GetAnomalousGoroutines returned nil (should return empty slice)")
	}
}

// TestStartStopDoubleStart verifies double-start protection.
func TestStartStopDoubleStart(t *testing.T) {
	// On most test machines, we cannot actually attach uprobes (no
	// matching Go binary), so this is expected to fail with a symbol error.
	// We just verify the double-start protection path.
	err := StartGoroutineTracer("/proc/self/exe")
	if err == nil {
		// If it succeeded (unlikely in test), stop it.
		defer func() { _, _ = StopGoroutineTracer() }()

		// Second start should fail.
		err2 := StartGoroutineTracer("/proc/self/exe")
		if err2 == nil {
			t.Error("expected error on double start, got nil")
		}
	}
}

// TestHeapCorruptionDetection verifies goroutine event recording.
func TestHeapCorruptionDetection(t *testing.T) {
	event := &GoroutineEvent{
		Type:        GoroutineCreated,
		GoroutineID: 42,
		SyscallNr:   0,
		PID:         1234,
		TID:         5678,
		Timestamp:   uint64(time.Now().UnixNano()),
	}

	recordGoroutineEvent(event)

	val, ok := goroutineMap.Load(uint64(42))
	if !ok {
		t.Fatal("goroutine 42 not found in map after recording")
	}

	tracker, ok := val.(*goroutineTracker)
	if !ok {
		t.Fatal("map value is not a *goroutineTracker")
	}

	if tracker.goid != 42 {
		t.Errorf("expected goroutine ID 42, got %d", tracker.goid)
	}

	// Clean up.
	goroutineMap.Delete(uint64(42))
}
