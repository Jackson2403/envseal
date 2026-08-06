package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"time"
)

// Envelope version marker for forward compatibility.
const envelopeVersion = 1

// aad is the authenticated data bound to the payload, preventing ciphertext
// from being mixed between different envelopes.
var aad = []byte("envseal-v1-payload")

// RecipientSeal holds the wrapped session key for a single recipient.
type RecipientSeal struct {
	Fingerprint string `json:"fingerprint"`
	Ephemeral   []byte `json:"ephemeral"`   // 32-byte ephemeral public key
	Nonce       []byte `json:"nonce"`       // 12-byte GCM nonce
	WrappedKey  []byte `json:"wrapped_key"` // AES-256 sealed session key
}

// Envelope is the serialized secret bundle. Public keys and ciphertext are
// stored, but no plaintext secret material ever appears here.
type Envelope struct {
	Version    int             `json:"version"`
	CreatedAt  string          `json:"created_at"`
	EnvName    string          `json:"env_name"`
	Recipients []RecipientSeal `json:"recipients"`
	Nonce      []byte          `json:"nonce"`      // 12-byte payload nonce
	Ciphertext []byte          `json:"ciphertext"` // AES-256-GCM sealed payload
}

// Encrypt wraps plaintext so that it can only be opened by one of the
// provided recipient public keys. envName records which environment the
// ciphertext corresponds to (e.g. "staging").
func Encrypt(plaintext []byte, envName string, recipientPubs [][]byte) (*Envelope, error) {
	if len(recipientPubs) == 0 {
		return nil, fmt.Errorf("at least one recipient public key is required")
	}

	// 1. Random 32-byte AES-256 session key.
	sessionKey := make([]byte, KeyLength)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}

	// 2. AES-256-GCM encrypt the payload.
	payloadNonce := make([]byte, 12)
	if _, err := rand.Read(payloadNonce); err != nil {
		return nil, fmt.Errorf("generate payload nonce: %w", err)
	}
	gcm, err := newGCM(sessionKey)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, payloadNonce, plaintext, aad)

	env := &Envelope{
		Version:    envelopeVersion,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		EnvName:    envName,
		Nonce:      payloadNonce,
		Ciphertext: ciphertext,
	}

	// 3. Wrap the session key for each recipient.
	for _, pub := range recipientPubs {
		seal, err := sealTo(pub, sessionKey)
		if err != nil {
			return nil, err
		}
		env.Recipients = append(env.Recipients, seal)
	}

	return env, nil
}

// sealTo wraps sessionKey for a single recipient public key using ECDH key
// agreement followed by AES-256-GCM key wrapping.
func sealTo(pubRaw, sessionKey []byte) (RecipientSeal, error) {
	ephemeralPub, ephemeralPriv, err := ephemeralKeypair()
	if err != nil {
		return RecipientSeal{}, err
	}
	wrapKey, err := sharedSecret(ephemeralPriv.Bytes(), pubRaw)
	if err != nil {
		return RecipientSeal{}, err
	}
	gcm, err := newGCM(wrapKey)
	if err != nil {
		return RecipientSeal{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return RecipientSeal{}, err
	}
	wrapped := gcm.Seal(nil, nonce, sessionKey, nil)

	return RecipientSeal{
		Fingerprint: Fingerprint(pubRaw),
		Ephemeral:   ephemeralPub.Bytes(),
		Nonce:       nonce,
		WrappedKey:  wrapped,
	}, nil
}

// ephemeralKeypair generates an X25519 ephemeral keypair used to give each
// recipient an independent shared secret (forward secrecy).
func ephemeralKeypair() (*ecdh.PublicKey, *ecdh.PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	return priv.PublicKey(), priv, nil
}

// newGCM builds an AES-256-GCM cipher for the given 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLength {
		return nil, fmt.Errorf("invalid AES key length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("build GCM: %w", err)
	}
	return gcm, nil
}
