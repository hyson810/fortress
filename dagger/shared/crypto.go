package shared

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	KeySize   = 32 // X25519 public/private key size
	NonceSize = 24 // XChaCha20-Poly1305 nonce
	TagSize   = 16 // Poly1305 tag overhead
)

type KeyPair struct {
	Public  [KeySize]byte
	Private [KeySize]byte
}

func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)
	return kp, nil
}

func SharedSecret(private, peerPublic *[KeySize]byte) ([KeySize]byte, error) {
	var secret [KeySize]byte
	curve25519.ScalarMult(&secret, private, peerPublic)
	return secret, nil
}

func EncryptMessage(key *[KeySize]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func DecryptMessage(key *[KeySize]byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:aead.NonceSize()]
	payload := ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, payload, nil)
}

func DeriveSessionKey(sharedSecret *[KeySize]byte, sessionID []byte) [KeySize]byte {
	// HKDF-SHA256 — matches Rust implant's crypto::derive_session_key
	// IKM = shared secret, salt = session ID, info = "dagger-session-v1"
	hkdfReader := hkdf.New(sha256.New, sharedSecret[:], sessionID, []byte("dagger-session-v1"))
	var key [KeySize]byte
	if _, err := io.ReadFull(hkdfReader, key[:]); err != nil {
		panic("hkdf: " + err.Error())
	}
	return key
}
