package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writeTestSSHKey writes a fresh ed25519 private key in OpenSSH format.
func writeTestSSHKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func TestDeriveFromSSH_Ed25519(t *testing.T) {
	path := writeTestSSHKey(t)
	priv, pub, err := DeriveFromSSH(path, nil)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(priv) != KeyLength || len(pub) != KeyLength {
		t.Fatalf("unexpected key sizes priv=%d pub=%d", len(priv), len(pub))
	}
	// Public must match the derived private.
	wantPub, err := PublicFromPrivate(priv)
	if err != nil || !EqualPublicKeys(pub, wantPub) {
		t.Fatalf("public key does not match private (err=%v)", err)
	}

	// Derived key must actually encrypt/decrypt.
	secret := []byte("K=v\n")
	env, err := Encrypt(secret, "default", [][]byte{pub})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, _, err := Decrypt(env, priv)
	if err != nil || string(got) != "K=v\n" {
		t.Fatalf("decrypt with ssh-derived key failed: %v", err)
	}
}

func TestDeriveFromSSH_Stable(t *testing.T) {
	path := writeTestSSHKey(t)
	p1, _, err := DeriveFromSSH(path, nil)
	if err != nil {
		t.Fatalf("first derive: %v", err)
	}
	p2, _, err := DeriveFromSSH(path, nil)
	if err != nil {
		t.Fatalf("second derive: %v", err)
	}
	if !EqualPublicKeys(mustPub(t, p1), mustPub(t, p2)) {
		t.Fatal("derivation is not stable across runs")
	}
}

func TestDeriveFromSSH_MissingFile(t *testing.T) {
	if _, _, err := DeriveFromSSH(filepath.Join(t.TempDir(), "nope"), nil); err == nil {
		t.Fatal("expected an error for a missing key file")
	}
}

func mustPub(t *testing.T, priv []byte) []byte {
	t.Helper()
	pub, err := PublicFromPrivate(priv)
	if err != nil {
		t.Fatalf("public from private: %v", err)
	}
	return pub
}
