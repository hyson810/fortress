package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

const KeySize = 32

type ServerKeys struct {
	Public  [KeySize]byte
	Private [KeySize]byte
}

func GenerateServerKeys() (*ServerKeys, error) {
	keys := &ServerKeys{}
	if _, err := rand.Read(keys.Private[:]); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	curve25519.ScalarBaseMult(&keys.Public, &keys.Private)
	return keys, nil
}

func LoadOrGenerateKeys(path string) (*ServerKeys, error) {
	if path == "" {
		path = "server.key"
	}
	data, err := os.ReadFile(path)
	if err == nil && len(data) == KeySize {
		keys := &ServerKeys{}
		copy(keys.Private[:], data)
		curve25519.ScalarBaseMult(&keys.Public, &keys.Private)
		return keys, nil
	}
	keys, err := GenerateServerKeys()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, keys.Private[:], 0600); err != nil {
		return nil, fmt.Errorf("save key: %w", err)
	}
	return keys, nil
}
