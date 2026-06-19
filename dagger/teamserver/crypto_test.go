package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateServerKeys(t *testing.T) {
	keys, err := GenerateServerKeys()
	if err != nil {
		t.Fatalf("GenerateServerKeys: %v", err)
	}
	if keys.Public == [32]byte{} {
		t.Error("public key is zero")
	}
	if keys.Private == [32]byte{} {
		t.Error("private key is zero")
	}
	if keys.Public == keys.Private {
		t.Error("public and private keys are equal (impossible)")
	}
}

func TestLoadOrGenerateKeysCreates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-server.key")

	keys1, err := LoadOrGenerateKeys(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("key file not created")
	}

	// Load the same key file — should return the same private key
	keys2, err := LoadOrGenerateKeys(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if keys1.Private != keys2.Private {
		t.Error("key changed between loads")
	}
	if keys1.Public != keys2.Public {
		t.Error("public key changed between loads")
	}
}

func TestLoadOrGenerateKeysEmptyPath(t *testing.T) {
	// Should use default path "server.key"
	keys, err := LoadOrGenerateKeys("")
	if err != nil {
		t.Fatalf("LoadOrGenerateKeys(\"\"): %v", err)
	}
	if keys.Public == [32]byte{} {
		t.Error("public key is zero")
	}
	os.Remove("server.key") // cleanup
}

func TestEncryptTaskRoundtrip(t *testing.T) {
	task := &Task{
		ID:   [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Type: TaskShell,
		Data: []byte("whoami"),
	}
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{0x7F}, 32))

	ct, err := EncryptTask(task, &key)
	if err != nil {
		t.Fatalf("EncryptTask: %v", err)
	}
	if len(ct) == 0 {
		t.Error("ciphertext is empty")
	}
}

func TestTaskManagerEnqueueDequeue(t *testing.T) {
	tm := NewTaskManager()

	task, err := tm.Enqueue("abc123", TaskShell, []byte("id"), 60)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if task.Type != TaskShell {
		t.Errorf("expected TaskShell, got %d", task.Type)
	}

	dequeued := tm.Dequeue("abc123")
	if dequeued == nil {
		t.Fatal("Dequeue returned nil")
	}
	if dequeued.ID != task.ID {
		t.Error("task ID mismatch")
	}

	// Second dequeue should be nil
	dequeued = tm.Dequeue("abc123")
	if dequeued != nil {
		t.Error("expected nil after dequeuing last task")
	}
}

func TestTaskManagerDifferentSessions(t *testing.T) {
	tm := NewTaskManager()
	tm.Enqueue("session-a", TaskShell, []byte("a"), 60)
	tm.Enqueue("session-b", TaskDownload, []byte("b"), 60)

	if tm.Dequeue("session-a") == nil {
		t.Error("session-a should have a task")
	}
	if tm.Dequeue("session-b") == nil {
		t.Error("session-b should have a task")
	}
	if tm.Dequeue("session-a") != nil {
		t.Error("session-a should be empty")
	}
}

func TestSessionManagerRegister(t *testing.T) {
	keys, _ := GenerateServerKeys()
	sm := NewSessionManager(keys)

	pubkey := make([]byte, KeySize)
	copy(pubkey, bytes.Repeat([]byte{0x33}, KeySize))

	session, err := sm.Register(pubkey, "test-implant", "linux")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if session.Hostname != "test-implant" {
		t.Errorf("expected hostname 'test-implant', got %q", session.Hostname)
	}
	if session.OS != "linux" {
		t.Errorf("expected OS 'linux', got %q", session.OS)
	}
}

func TestSessionManagerRegisterInvalidPubkey(t *testing.T) {
	keys, _ := GenerateServerKeys()
	sm := NewSessionManager(keys)

	_, err := sm.Register([]byte{0, 1, 2}, "bad", "none")
	if err == nil {
		t.Error("expected error for invalid public key size")
	}
}
