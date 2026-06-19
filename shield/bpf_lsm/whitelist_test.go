package bpf_lsm

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func generateTestKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return pub, priv
}

func TestNewBPFWhitelist(t *testing.T) {
	pub, _ := generateTestKey()
	w := NewBPFWhitelist(pub)
	if w == nil {
		t.Fatal("NewBPFWhitelist returned nil")
	}
	if w.Count() != 0 {
		t.Errorf("expected 0 entries, got %d", w.Count())
	}
}

func TestAddToWhitelist(t *testing.T) {
	pub, priv := generateTestKey()
	w := NewBPFWhitelist(pub)

	hash := sha256.Sum256([]byte("test bpf program"))
	signedData := append(hash[:], []byte("xdp:test_prog")...)
	sig := ed25519.Sign(priv, signedData)

	err := w.AddToWhitelist(hash, sig, "xdp", "test_prog", "test program")
	if err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}
	if w.Count() != 1 {
		t.Errorf("expected 1 entry, got %d", w.Count())
	}
	if !w.IsWhitelisted(hash) {
		t.Error("hash should be whitelisted")
	}
}

func TestAddToWhitelistBadSignature(t *testing.T) {
	pub, _ := generateTestKey()
	_, otherPriv := generateTestKey()
	w := NewBPFWhitelist(pub)

	hash := sha256.Sum256([]byte("evil bpf program"))
	signedData := append(hash[:], []byte("xdp:evil")...)
	sig := ed25519.Sign(otherPriv, signedData) // wrong key

	err := w.AddToWhitelist(hash, sig, "xdp", "evil", "")
	if err == nil {
		t.Error("expected signature verification failure")
	}
}

func TestAddToWhitelistDuplicate(t *testing.T) {
	pub, priv := generateTestKey()
	w := NewBPFWhitelist(pub)

	hash := sha256.Sum256([]byte("dup"))
	signedData := append(hash[:], []byte("tc:dup")...)
	sig := ed25519.Sign(priv, signedData)

	w.AddToWhitelist(hash, sig, "tc", "dup", "")
	err := w.AddToWhitelist(hash, sig, "tc", "dup", "")
	if err == nil {
		t.Error("expected duplicate error")
	}
}

func TestLoadWhitelist(t *testing.T) {
	pub, priv := generateTestKey()

	// Build whitelist content
	hash1 := sha256.Sum256([]byte("program-1"))
	sig1 := ed25519.Sign(priv, append(hash1[:], []byte("xdp:prog1")...))
	hash2 := sha256.Sum256([]byte("program-2"))
	sig2 := ed25519.Sign(priv, append(hash2[:], []byte("tc:prog2")...))

	content := hex.EncodeToString(hash1[:]) + ":" + hex.EncodeToString(sig1) + ":xdp:prog1:first program\n"
	content += hex.EncodeToString(hash2[:]) + ":" + hex.EncodeToString(sig2) + ":tc:prog2:second program\n"

	path := filepath.Join(t.TempDir(), "whitelist.txt")
	os.WriteFile(path, []byte(content), 0644)

	w := NewBPFWhitelist(pub)
	if err := w.LoadWhitelist(path); err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	if w.Count() != 2 {
		t.Errorf("expected 2 entries, got %d", w.Count())
	}
	if !w.IsWhitelisted(hash1) {
		t.Error("hash1 should be whitelisted")
	}
	if !w.IsWhitelisted(hash2) {
		t.Error("hash2 should be whitelisted")
	}
}

func TestVerifyBPFProgram(t *testing.T) {
	pub, priv := generateTestKey()
	w := NewBPFWhitelist(pub)

	prog := []byte("legitimate bpf program")
	hash := sha256.Sum256(prog)
	signedData := append(hash[:], []byte("tracing:legit")...)
	sig := ed25519.Sign(priv, signedData)

	w.AddToWhitelist(hash, sig, "tracing", "legit", "")

	entry, ok := w.VerifyBPFProgram(prog, sig)
	if !ok {
		t.Fatal("VerifyBPFProgram should succeed")
	}
	if entry.Name != "legit" {
		t.Errorf("expected name 'legit', got %q", entry.Name)
	}
}

func TestVerifyBPFProgramFailsWithUnknown(t *testing.T) {
	pub, _ := generateTestKey()
	w := NewBPFWhitelist(pub)

	_, ok := w.VerifyBPFProgram([]byte("unknown"), []byte("fake-signature"))
	if ok {
		t.Error("should not verify unknown program")
	}
}

func TestList(t *testing.T) {
	pub, priv := generateTestKey()
	w := NewBPFWhitelist(pub)

	hash := sha256.Sum256([]byte("p1"))
	sig := ed25519.Sign(priv, append(hash[:], []byte("xdp:p1")...))
	w.AddToWhitelist(hash, sig, "xdp", "p1", "")

	list := w.List()
	if len(list) != 1 {
		t.Errorf("expected 1 in list, got %d", len(list))
	}
}

func TestStrictMode(t *testing.T) {
	pub, _ := generateTestKey()
	w := NewBPFWhitelist(pub)

	if !w.StrictMode() {
		t.Error("strict mode should be on by default")
	}
	w.SetStrictMode(false)
	if w.StrictMode() {
		t.Error("strict mode should be off")
	}
}
