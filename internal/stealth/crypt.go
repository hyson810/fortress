package stealth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// DeriveKey performs key derivation using iterated SHA-256 (PKCS#5 PBKDF2-like).
// For production use, replace with golang.org/x/crypto/argon2.
//
// If salt is empty, a random 32-byte salt is generated internally but is NOT
// returned — the caller must manage salt separately. For new derivations,
// use DeriveKeyWithSalt which returns the salt alongside the key.
func DeriveKey(passphrase string, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("crypt: salt: %w", err)
		}
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("crypt: passphrase required")
	}
	iterations := 600000
	dk := append([]byte(passphrase), salt...)
	for i := 0; i < iterations; i++ {
		h := sha256.Sum256(dk)
		dk = h[:]
	}
	return dk, nil
}

// DeriveKeyWithSalt derives a key and returns the salt used.
// The caller should store the salt alongside the ciphertext.
func DeriveKeyWithSalt(passphrase string) (key, salt []byte, err error) {
	salt, err = GenerateSalt()
	if err != nil {
		return nil, nil, err
	}
	key, err = DeriveKey(passphrase, salt)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

// GenerateSalt creates a cryptographically random 32-byte salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("crypt: generate salt: %w", err)
	}
	return salt, nil
}

// EncryptConfig encrypts plaintext using AES-256-GCM with the given 32-byte key.
// The returned string is base64-encoded and contains: salt (32) + nonce (12) + ciphertext.
func EncryptConfig(plaintext []byte, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("crypt: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("crypt: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypt: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypt: nonce: %w", err)
	}
	salt, err := GenerateSalt()
	if err != nil {
		return "", fmt.Errorf("crypt: salt: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	result := append(salt, nonce...)
	result = append(result, ciphertext...)
	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptConfig decrypts a base64-encoded ciphertext produced by EncryptConfig
// using the given 32-byte key.
func DecryptConfig(encoded string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypt: key must be 32 bytes")
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("crypt: decode: %w", err)
	}
	if len(data) < 44 {
		return nil, fmt.Errorf("crypt: data too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypt: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypt: gcm: %w", err)
	}
	// salt occupies bytes 0:32; stored for future key-rotation use
	_ = data[:32]
	nonce := data[32 : 32+gcm.NonceSize()]
	ciphertext := data[32+gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypt: decrypt: %w", err)
	}
	return plaintext, nil
}

// HashSHA256 returns the hex-encoded SHA-256 digest of data.
func HashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}
