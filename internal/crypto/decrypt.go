package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Decrypt opens an envelope using the operator's private key. Only one of
// the sealed recipients needs to match the key. It returns the recovered
// plaintext and the recorded environment name.
func Decrypt(env *Envelope, privRaw []byte) ([]byte, string, error) {
	if env.Version != envelopeVersion {
		return nil, "", fmt.Errorf("unsupported envelope version %d", env.Version)
	}
	myPub, err := PublicFromPrivate(privRaw)
	if err != nil {
		return nil, "", err
	}
	myFp := Fingerprint(myPub)

	// 4. Find our recipient seal and recover the session key.
	var sessionKey []byte
	found := false
	for _, seal := range env.Recipients {
		if seal.Fingerprint != myFp {
			continue
		}
		sessionKey, err = openSeal(privRaw, seal)
		if err != nil {
			return nil, "", err
		}
		found = true
		break
	}
	if !found {
		return nil, "", fmt.Errorf(
			"this envelope was not sealed for your key (fingerprint %s)", myFp)
	}

	// 5. AES-256-GCM decrypt the payload.
	gcm, err := newGCM(sessionKey)
	if err != nil {
		return nil, "", err
	}
	if len(env.Ciphertext) < gcm.Overhead() {
		return nil, "", fmt.Errorf("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt payload (authentication failed): %w", err)
	}
	return plaintext, env.EnvName, nil
}

// openSeal recovers the session key from a recipient seal.
func openSeal(privRaw []byte, seal RecipientSeal) ([]byte, error) {
	if len(seal.Ephemeral) != KeyLength {
		return nil, fmt.Errorf("invalid ephemeral key length")
	}
	wrapKey, err := sharedSecret(privRaw, seal.Ephemeral)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(wrapKey)
	if err != nil {
		return nil, err
	}
	sessionKey, err := gcm.Open(nil, seal.Nonce, seal.WrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap session key: %w", err)
	}
	return sessionKey, nil
}

// Encode serializes an envelope to pretty-printed JSON bytes. Binary fields
// are base64-encoded automatically by JSON.
func (e *Envelope) Encode() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// DecodeEnvelope parses JSON bytes back into an Envelope.
func DecodeEnvelope(data []byte) (*Envelope, error) {
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}
	if len(env.Recipients) == 0 {
		return nil, fmt.Errorf("envelope has no recipients")
	}
	return &env, nil
}
