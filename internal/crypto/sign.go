package crypto

import (
	"crypto/ed25519"
	"fmt"
)

// EnvSeal uses a single long-term identity private key for both encryption
// (X25519) and, when enabled, for signing audit/history entries. The signing
// key is an Ed25519 key derived deterministically from the same 32-byte
// identity scalar, so no extra key material needs to be stored.
func SigningKeyFromIdentity(x25519Priv []byte) (ed25519.PrivateKey, error) {
	if len(x25519Priv) != KeyLength {
		return nil, fmt.Errorf("invalid identity private key length %d", len(x25519Priv))
	}
	return ed25519.NewKeyFromSeed(x25519Priv), nil
}

// SignIdentity signs a message with the Ed25519 key derived from the X25519
// identity private key.
func SignIdentity(x25519Priv, msg []byte) ([]byte, error) {
	key, err := SigningKeyFromIdentity(x25519Priv)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, msg), nil
}

// VerifyIdentity verifies a signature against the Ed25519 key derived from
// the identity private key. Because verification is local-only, the private
// key is used to recompute the expected public key.
func VerifyIdentity(x25519Priv, msg, sig []byte) bool {
	key, err := SigningKeyFromIdentity(x25519Priv)
	if err != nil {
		return false
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}
