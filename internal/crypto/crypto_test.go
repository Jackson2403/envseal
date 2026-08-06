package crypto

import (
	"bytes"
	"testing"
)

func mustPair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub, err = PublicFromPrivate(priv)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	return priv, pub
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	privA, pubA := mustPair(t)
	_, pubB := mustPair(t)

	secret := []byte("DB_PASSWORD=super-secret\nAPI_KEY=abcd\n")
	env, err := Encrypt(secret, "staging", [][]byte{pubA, pubB})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if len(env.Recipients) != 2 {
		t.Fatalf("expected 2 recipient seals, got %d", len(env.Recipients))
	}
	// Ciphertext must never contain the plaintext bytes.
	data, _ := env.Encode()
	if bytes.Contains(data, secret) {
		t.Fatal("envelope contains plaintext, security violation")
	}

	// Correct key decrypts.
	got, label, err := Decrypt(env, privA)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("round-trip mismatch")
	}
	if label != "staging" {
		t.Errorf("label = %q, want staging", label)
	}
}

func TestDecryptRequiresMatchingKey(t *testing.T) {
	_, pubA := mustPair(t)
	privB, _ := mustPair(t)

	secret := []byte("TOKEN=xyz\n")
	env, err := Encrypt(secret, "default", [][]byte{pubA})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// pubB's owner (not sealed) must not be able to decrypt.
	if _, _, err := Decrypt(env, privB); err == nil {
		t.Fatal("expected error decrypting with unsealed key")
	}
}

func TestTamperDetection(t *testing.T) {
	privA, pubA := mustPair(t)
	secret := []byte("A=1\n")
	env, err := Encrypt(secret, "default", [][]byte{pubA})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Flip a byte in the ciphertext -> authentication must fail.
	env.Ciphertext[0] ^= 0xff
	if _, _, err := Decrypt(env, privA); err == nil {
		t.Fatal("expected authentication failure after tampering with ciphertext")
	}
}

func TestUnknownEnvelopeVersion(t *testing.T) {
	privA, pubA := mustPair(t)
	secret := []byte("A=1\n")
	env, err := Encrypt(secret, "default", [][]byte{pubA})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	env.Version = 999
	if _, _, err := Decrypt(env, privA); err == nil {
		t.Fatal("expected version error")
	}
}

func TestEnvelopeSerialization(t *testing.T) {
	privA, pubA := mustPair(t)
	secret := []byte("K=v\n")
	env, err := Encrypt(secret, "prod", [][]byte{pubA})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	data, err := env.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	env2, err := DecodeEnvelope(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, label, err := Decrypt(env2, privA)
	if err != nil {
		t.Fatalf("decrypt after round-trip: %v", err)
	}
	if !bytes.Equal(got, secret) || label != "prod" {
		t.Fatal("round-trip through serialization corrupted payload")
	}
}

func TestFingerprintOrdering(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	b[0] = 1
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("distinct keys should have distinct fingerprints")
	}
}
