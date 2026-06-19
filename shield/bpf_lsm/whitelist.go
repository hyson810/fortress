// Package bpf_lsm implements BPF LSM (Linux Security Module) whitelisting.
// It verifies loaded BPF programs against an Ed25519-signed whitelist,
// preventing unauthorized eBPF program execution.
//
// Defends against: malicious BPF program loading (VoidLink, eBPF rootkits)
// Reference: Elastic Security 2026 — "BPF LSM Whitelisting for Kubernetes"

package bpf_lsm

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	ProgramHashSize = 32
	SignatureSize   = ed25519.SignatureSize
	PublicKeySize   = ed25519.PublicKeySize
)

// WhitelistEntry represents a single authorized BPF program.
type WhitelistEntry struct {
	Name    string
	Hash    [ProgramHashSize]byte
	Program string // xdp, tc, tracing, cgroup, etc.
	Comment string
}

// BPFWhitelist maintains the set of authorized BPF programs.
type BPFWhitelist struct {
	mu         sync.RWMutex
	entries    map[string]*WhitelistEntry
	pubKey     ed25519.PublicKey
	strictMode bool
}

// NewBPFWhitelist creates a new whitelist with the given public key.
func NewBPFWhitelist(pubKey ed25519.PublicKey) *BPFWhitelist {
	return &BPFWhitelist{
		entries:    make(map[string]*WhitelistEntry),
		pubKey:     pubKey,
		strictMode: true,
	}
}

// LoadWhitelist reads a signed whitelist file.
// Format: one entry per line: hash(hex):signature(hex):type:name:comment
func (w *BPFWhitelist) LoadWhitelist(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read whitelist: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	w.mu.Lock()
	defer w.mu.Unlock()

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		parts := strings.SplitN(line, ":", 5)
		if len(parts) < 5 {
			return fmt.Errorf("line %d: expected 5 fields, got %d", i+1, len(parts))
		}

		hashStr, sigStr, progType, name, comment := parts[0], parts[1], parts[2], parts[3], parts[4]

		hashBytes, err := hex.DecodeString(hashStr)
		if err != nil || len(hashBytes) != ProgramHashSize {
			return fmt.Errorf("line %d: invalid hash", i+1)
		}
		sigBytes, err := hex.DecodeString(sigStr)
		if err != nil || len(sigBytes) != SignatureSize {
			return fmt.Errorf("line %d: invalid signature", i+1)
		}

		var hash [ProgramHashSize]byte
		copy(hash[:], hashBytes)

		signedData := append(hashBytes, []byte(progType+":"+name)...)
		if !ed25519.Verify(w.pubKey, signedData, sigBytes) {
			return fmt.Errorf("line %d (%s): signature verification failed", i+1, name)
		}

		key := hex.EncodeToString(hash[:])
		w.entries[key] = &WhitelistEntry{
			Name:    name,
			Hash:    hash,
			Program: progType,
			Comment: comment,
		}
	}
	return nil
}

// VerifyBPFProgram checks whether a BPF program is whitelisted with a valid signature.
func (w *BPFWhitelist) VerifyBPFProgram(progBytes []byte, signature []byte) (*WhitelistEntry, bool) {
	hash := sha256.Sum256(progBytes)
	w.mu.RLock()
	defer w.mu.RUnlock()
	key := hex.EncodeToString(hash[:])
	entry, exists := w.entries[key]
	if !exists {
		return nil, false
	}
	signedData := append(hash[:], []byte(entry.Program+":"+entry.Name)...)
	if !ed25519.Verify(w.pubKey, signedData, signature) {
		return nil, false
	}
	return entry, true
}

// AddToWhitelist adds a new entry with signature verification.
func (w *BPFWhitelist) AddToWhitelist(hash [ProgramHashSize]byte, signature []byte, progType, name, comment string) error {
	signedData := append(hash[:], []byte(progType+":"+name)...)
	if !ed25519.Verify(w.pubKey, signedData, signature) {
		return errors.New("signature verification failed")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	key := hex.EncodeToString(hash[:])
	if _, exists := w.entries[key]; exists {
		return fmt.Errorf("program already whitelisted: %s", name)
	}
	w.entries[key] = &WhitelistEntry{Name: name, Hash: hash, Program: progType, Comment: comment}
	return nil
}

// IsWhitelisted checks a hash without requiring a signature.
func (w *BPFWhitelist) IsWhitelisted(hash [ProgramHashSize]byte) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, exists := w.entries[hex.EncodeToString(hash[:])]
	return exists
}

// List returns all whitelisted entries.
func (w *BPFWhitelist) List() []*WhitelistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	r := make([]*WhitelistEntry, 0, len(w.entries))
	for _, e := range w.entries {
		r = append(r, e)
	}
	return r
}

// StrictMode returns whether the whitelist rejects unknown programs.
func (w *BPFWhitelist) StrictMode() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.strictMode
}

// SetStrictMode controls whether unknown programs are rejected.
func (w *BPFWhitelist) SetStrictMode(s bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.strictMode = s
}

// Count returns the number of whitelisted entries.
func (w *BPFWhitelist) Count() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.entries)
}
