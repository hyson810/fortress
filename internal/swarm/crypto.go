// Package swarm implements the Fortress distributed protocol for peer
// discovery, threat intel sharing, and consensus-based counterstrikes.
//
// crypto.go provides NaCl secretbox (XSalsa20-Poly1305) encryption for
// the gossip wire protocol. All swarm messages can be encrypted end-to-end
// with a pre-shared symmetric key.
package swarm

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// KeySize is the length of a NaCl secretbox key in bytes.
	KeySize = 32

	// NonceSize is the length of a NaCl secretbox nonce in bytes.
	NonceSize = 24
)

// GenerateKey creates a new random NaCl secretbox key.
func GenerateKey() ([KeySize]byte, error) {
	var key [KeySize]byte
	_, err := rand.Read(key[:])
	return key, err
}

// EncryptMessage encrypts plaintext with NaCl secretbox (XSalsa20-Poly1305).
// Returns the base64-encoded ciphertext (nonce prepended).
func EncryptMessage(plaintext []byte, key *[KeySize]byte) (string, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("crypto: nonce: %w", err)
	}
	encrypted := secretbox.Seal(nonce[:], plaintext, &nonce, key)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptMessage decrypts a NaCl secretbox ciphertext (base64-encoded,
// nonce prepended). Returns the original plaintext.
func DecryptMessage(encoded string, key *[KeySize]byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode: %w", err)
	}
	if len(ciphertext) < NonceSize {
		return nil, fmt.Errorf("crypto: ciphertext too short")
	}
	var nonce [NonceSize]byte
	copy(nonce[:], ciphertext[:NonceSize])
	decrypted, ok := secretbox.Open(nil, ciphertext[NonceSize:], &nonce, key)
	if !ok {
		return nil, fmt.Errorf("crypto: decryption failed (wrong key or tampered)")
	}
	return decrypted, nil
}

// KeyFromString decodes a base64-encoded key string into a [KeySize]byte.
func KeyFromString(s string) ([KeySize]byte, error) {
	var key [KeySize]byte
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("crypto: invalid key: %w", err)
	}
	if len(data) != KeySize {
		return key, fmt.Errorf("crypto: key must be %d bytes, got %d", KeySize, len(data))
	}
	copy(key[:], data)
	return key, nil
}

// KeyToString encodes a [KeySize]byte key as a base64 string.
func KeyToString(key *[KeySize]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}
