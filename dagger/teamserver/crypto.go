package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

const KeySize = 32

// keyFileLayout: X25519_priv (32) || Ed25519_priv (64) || Ed25519_pub (32) = 128 bytes
const keyFileSize = KeySize + ed25519.PrivateKeySize + ed25519.PublicKeySize // 32 + 64 + 32 = 128

type ServerKeys struct {
	// X25519 for ENCRYPTION (key exchange)
	Public  [KeySize]byte
	Private [KeySize]byte

	// Ed25519 for AUTHENTICATION (signing handshake messages)
	SignPublic  [ed25519.PublicKeySize]byte
	SignPrivate [ed25519.PrivateKeySize]byte
}

func GenerateServerKeys() (*ServerKeys, error) {
	keys := &ServerKeys{}
	if _, err := rand.Read(keys.Private[:]); err != nil {
		return nil, fmt.Errorf("generate x25519 private key: %w", err)
	}
	curve25519.ScalarBaseMult(&keys.Public, &keys.Private)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	copy(keys.SignPublic[:], edPub)
	copy(keys.SignPrivate[:], edPriv)
	return keys, nil
}

func LoadOrGenerateKeys(path string) (*ServerKeys, error) {
	if path == "" {
		path = "server.key"
	}
	data, err := os.ReadFile(path)
	if err == nil && len(data) == keyFileSize {
		keys := &ServerKeys{}
		// X25519 private key
		copy(keys.Private[:], data[0:KeySize])
		curve25519.ScalarBaseMult(&keys.Public, &keys.Private)
		// Ed25519 signing key pair
		copy(keys.SignPublic[:], data[KeySize:KeySize+ed25519.PublicKeySize])
		copy(keys.SignPrivate[:], data[KeySize+ed25519.PublicKeySize:])
		return keys, nil
	}
	keys, err := GenerateServerKeys()
	if err != nil {
		return nil, err
	}
	// Write full key material: X25519_priv || Ed25519_pub || Ed25519_priv
	fileData := make([]byte, 0, keyFileSize)
	fileData = append(fileData, keys.Private[:]...)
	fileData = append(fileData, keys.SignPublic[:]...)
	fileData = append(fileData, keys.SignPrivate[:]...)
	if err := os.WriteFile(path, fileData, 0600); err != nil {
		return nil, fmt.Errorf("save key: %w", err)
	}
	return keys, nil
}
