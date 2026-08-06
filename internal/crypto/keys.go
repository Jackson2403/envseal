// Package crypto implements EnvSeal's hybrid encryption: secrets are wrapped
// in an AES-256-GCM session key, and that session key is encrypted to each
// recipient's X25519 public key. Secrets are never stored in plaintext.
package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// KeyLength is the X25519 key size in bytes.
const KeyLength = 32

// GeneratePrivateKey returns a new random X25519 private key encoded as raw
// bytes. The raw bytes are suitable for persistence.
func GeneratePrivateKey() ([]byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	return priv.Bytes(), nil
}

// PublicFromPrivate derives the public key bytes from a raw private key.
func PublicFromPrivate(priv []byte) ([]byte, error) {
	p, err := newPrivate(priv)
	if err != nil {
		return nil, err
	}
	return p.PublicKey().Bytes(), nil
}

// newPrivate parses raw private key bytes into an ecdh private key.
func newPrivate(raw []byte) (*ecdh.PrivateKey, error) {
	p, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	return p, nil
}

// newPublic parses raw public key bytes into an ecdh public key.
func newPublic(raw []byte) (*ecdh.PublicKey, error) {
	p, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	return p, nil
}

// sharedSecret computes the ECDH secret between our private key and a peer's
// public key, then collapses it to a 32-byte AES key via SHA-256.
func sharedSecret(privRaw, peerPubRaw []byte) ([]byte, error) {
	priv, err := newPrivate(privRaw)
	if err != nil {
		return nil, err
	}
	peerPub, err := newPublic(peerPubRaw)
	if err != nil {
		return nil, err
	}
	secret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}
	sum := sha256.Sum256(secret)
	return sum[:], nil
}

// Fingerprint returns a short, stable identifier for a public key, used to
// match recipient seals during decryption.
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ParsePublicKey confirms raw bytes are a valid X25519 public key.
func ParsePublicKey(raw []byte) error {
	_, err := newPublic(raw)
	return err
}

// PublicKeyString base64-encodes a public key for storage in a .toml.
func PublicKeyString(pub []byte) string {
	return stdB64(pub)
}

// DecodePublicKey decodes a base64 public key string.
func DecodePublicKey(s string) ([]byte, error) {
	return stdUnB64(s)
}

// EqualPublicKeys checks byte equality of two public keys.
func EqualPublicKeys(a, b []byte) bool {
	return bytes.Equal(a, b)
}
