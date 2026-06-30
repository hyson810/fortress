package mcp

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// AuthCheck tests
// ---------------------------------------------------------------------------

func TestAuthCheck_Administrator(t *testing.T) {
	tools := []string{
		"fortress_status",
		"fortress_list_threats",
		"fortress_intel_lookup",
		"fortress_swarm_status",
		"fortress_block_ip",
		"fortress_unblock_ip",
		"fortress_scan_target",
		"fortress_launch_counterstrike",
		"fortress_toggle_mode",
	}
	for _, tool := range tools {
		if err := AuthCheck(tool, AuthAdministrator); err != nil {
			t.Errorf("AuthAdministrator should be able to access %s, got: %v", tool, err)
		}
	}
}

func TestAuthCheck_Operator(t *testing.T) {
	// Operator should be able to access read-only and operator-level tools.
	allowed := []string{
		"fortress_status",
		"fortress_list_threats",
		"fortress_intel_lookup",
		"fortress_swarm_status",
		"fortress_block_ip",
		"fortress_unblock_ip",
		"fortress_scan_target",
	}
	for _, tool := range allowed {
		if err := AuthCheck(tool, AuthOperator); err != nil {
			t.Errorf("AuthOperator should be able to access %s, got: %v", tool, err)
		}
	}

	// Operator should NOT be able to access administrator tools.
	denied := []string{
		"fortress_launch_counterstrike",
		"fortress_toggle_mode",
	}
	for _, tool := range denied {
		if err := AuthCheck(tool, AuthOperator); err == nil {
			t.Errorf("AuthOperator should be denied access to %s", tool)
		}
	}
}

func TestAuthCheck_Viewer(t *testing.T) {
	// Use AuthReadOnly (the actual constant name) for viewer-level tests.
	allowed := []string{
		"fortress_status",
		"fortress_list_threats",
		"fortress_intel_lookup",
		"fortress_swarm_status",
	}
	for _, tool := range allowed {
		if err := AuthCheck(tool, AuthReadOnly); err != nil {
			t.Errorf("AuthReadOnly should be able to access %s, got: %v", tool, err)
		}
	}

	denied := []string{
		"fortress_block_ip",
		"fortress_unblock_ip",
		"fortress_scan_target",
		"fortress_launch_counterstrike",
		"fortress_toggle_mode",
	}
	for _, tool := range denied {
		if err := AuthCheck(tool, AuthReadOnly); err == nil {
			t.Errorf("AuthReadOnly should be denied access to %s", tool)
		}
	}
}

func TestAuthCheck_InvalidTool(t *testing.T) {
	err := AuthCheck("nonexistent_tool", AuthAdministrator)
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("expected 'unknown tool' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RateLimiter tests
// ---------------------------------------------------------------------------

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(60, 10)
	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}
	if rl.burst != 10 {
		t.Errorf("expected burst 10, got %d", rl.burst)
	}
	if rl.rate != 1.0 {
		t.Errorf("expected rate 1.0 (60/min), got %f", rl.rate)
	}
	if rl.buckets == nil {
		t.Error("buckets map should be initialized")
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(60, 5)
	// First call should always be allowed (initializes the bucket).
	if !rl.Allow("test_tool") {
		t.Error("first call to Allow should return true")
	}
	// Subsequent calls within burst should be allowed.
	for i := 0; i < 4; i++ {
		if !rl.Allow("test_tool") {
			t.Errorf("call %d within burst should be allowed", i+2)
		}
	}
}

func TestRateLimiter_BurstExceeded(t *testing.T) {
	rl := NewRateLimiter(60, 3)
	// Consume all burst tokens.
	for i := 0; i < 3; i++ {
		if !rl.Allow("burst_tool") {
			t.Fatal("unexpected rejection within burst")
		}
	}
	// Next call should be rejected (tokens exhausted).
	if rl.Allow("burst_tool") {
		t.Error("call beyond burst should be rejected")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(60, 2)
	// Exhaust the bucket.
	rl.Allow("reset_tool")
	rl.Allow("reset_tool")
	if rl.Allow("reset_tool") {
		t.Error("should be rejected after exhausting burst")
	}

	// Reset and verify.
	rl.Reset()
	if !rl.Allow("reset_tool") {
		t.Error("should be allowed after reset")
	}
}

// ---------------------------------------------------------------------------
// Dispatcher tests
// ---------------------------------------------------------------------------

func TestNewDispatcher(t *testing.T) {
	hr := NewHandlerRegistry()
	d := NewDispatcher(hr)
	if d == nil {
		t.Fatal("NewDispatcher returned nil")
	}
	if d.handlers != hr {
		t.Error("dispatcher should use the provided handler registry")
	}
	if d.limiter == nil {
		t.Error("dispatcher should have a default rate limiter")
	}
}

// ---------------------------------------------------------------------------
// AuditLogger tests
// ---------------------------------------------------------------------------

func TestNewAuditLogger(t *testing.T) {
	path := t.TempDir() + "/audit.log"
	al, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer al.Close()

	if al.writer == nil {
		t.Error("audit logger should have an open file writer")
	}

	// Verify the file exists.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("audit log file not created: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected empty file, got size %d", info.Size())
	}
}

func TestAuditLogger_Log(t *testing.T) {
	path := t.TempDir() + "/audit.log"
	al, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer al.Close()

	entry := AuditLog{
		Timestamp: time.Now(),
		Tool:      "fortress_status",
		Params:    `{}`,
		Result:    `{"status":"ok"}`,
		Status:    "success",
	}
	if err := al.Log(entry); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	// Verify the file contents.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}

	var decoded AuditLog
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to decode audit log entry: %v", err)
	}

	if decoded.Tool != "fortress_status" {
		t.Errorf("expected tool 'fortress_status', got %q", decoded.Tool)
	}
	if decoded.Params != `{}` {
		t.Errorf("expected params '{}', got %q", decoded.Params)
	}
	if decoded.Result != `{"status":"ok"}` {
		t.Errorf("expected result, got %q", decoded.Result)
	}
	if decoded.Status != "success" {
		t.Errorf("expected status 'success', got %q", decoded.Status)
	}
	if decoded.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

// ---------------------------------------------------------------------------
// randomID tests
// ---------------------------------------------------------------------------

func TestRandomID(t *testing.T) {
	id := randomID()
	if id == "" {
		t.Fatal("randomID returned empty string")
	}
	if len(id) != 12 {
		t.Errorf("expected length 12, got %d", len(id))
	}
	// Verify it only contains allowed characters.
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			t.Errorf("unexpected character %c in randomID", r)
		}
	}
	// Verify uniqueness across multiple calls.
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := randomID()
		if seen[id] {
			t.Errorf("duplicate randomID: %s", id)
		}
		seen[id] = true
	}
}
