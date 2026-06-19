package shared

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if kp.Public == [32]byte{} {
		t.Error("public key is zero")
	}
	if kp.Private == [32]byte{} {
		t.Error("private key is zero")
	}
}

func TestSharedSecretSymmetry(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	s1, err := SharedSecret(&alice.Private, &bob.Public)
	if err != nil {
		t.Fatalf("alice→bob: %v", err)
	}
	s2, err := SharedSecret(&bob.Private, &alice.Public)
	if err != nil {
		t.Fatalf("bob→alice: %v", err)
	}
	if s1 != s2 {
		t.Error("shared secrets don't match")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	msg := []byte("the quick brown fox jumps over the lazy dog")
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{0x42}, 32))

	ct, err := EncryptMessage(&key, msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct) <= NonceSize {
		t.Fatal("ciphertext too short")
	}

	pt, err := DecryptMessage(&key, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Errorf("roundtrip failed: got %q, want %q", pt, msg)
	}
}

func TestDecryptMessageWrongKey(t *testing.T) {
	var k1, k2 [32]byte
	copy(k1[:], bytes.Repeat([]byte{0x11}, 32))
	copy(k2[:], bytes.Repeat([]byte{0x22}, 32))

	ct, _ := EncryptMessage(&k1, []byte("secret"))
	_, err := DecryptMessage(&k2, ct)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestDecryptMessageTooShort(t *testing.T) {
	var key [32]byte
	_, err := DecryptMessage(&key, []byte("short"))
	if err == nil {
		t.Error("decrypt too-short should fail")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	var secret [32]byte
	copy(secret[:], bytes.Repeat([]byte{0xAA}, 32))
	sessionID := []byte("test-session-001")

	k1 := DeriveSessionKey(&secret, sessionID)
	k2 := DeriveSessionKey(&secret, sessionID)
	if k1 != k2 {
		t.Error("deterministic derivation failed")
	}
}

func TestDeriveSessionKeyDifferentInputs(t *testing.T) {
	var secret [32]byte
	k1 := DeriveSessionKey(&secret, []byte("session-1"))
	k2 := DeriveSessionKey(&secret, []byte("session-2"))
	if k1 == k2 {
		t.Error("different inputs should produce different keys")
	}
}
