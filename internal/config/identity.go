package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

// EnvSealHome is the per-user directory storing the operator's own keys.
// On most platforms this resolves to ~/.envseal, but it can be relocated by
// setting the ENVSEAL_HOME environment variable (also used by tests).
func EnvSealHome() string {
	if v := os.Getenv("ENVSEAL_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".envseal")
}

// KeyPaths returns the private and public key file paths for the local
// operator identity.
func KeyPaths() (priv, pub string) {
	home := EnvSealHome()
	return filepath.Join(home, "identity.key"), filepath.Join(home, "identity.pub")
}

// EnsureHome creates the key directory if it does not yet exist.
func EnsureHome() error {
	return os.MkdirAll(EnvSealHome(), 0o700)
}

// HasIdentity reports whether a local keypair has been generated.
func HasIdentity() bool {
	priv, _ := KeyPaths()
	_, err := os.Stat(priv)
	return err == nil
}

// WriteIdentity persists the operator's private and public keys. The private
// key is stored as raw bytes with owner-only permissions; the public key is
// stored as base64 text so it can be shared verbatim via `team add --pubkey`.
func WriteIdentity(privKey, pubKey []byte) error {
	if err := EnsureHome(); err != nil {
		return err
	}
	privPath, pubPath := KeyPaths()
	if err := os.WriteFile(privPath, privKey, 0o600); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(pubKey)
	if err := os.WriteFile(pubPath, []byte(encoded), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// LoadIdentityPrivate reads the local private key material.
func LoadIdentityPrivate() ([]byte, error) {
	priv, _ := KeyPaths()
	return os.ReadFile(priv)
}

// LoadIdentityPublic reads the local public key material.
func LoadIdentityPublic() ([]byte, error) {
	_, pub := KeyPaths()
	return os.ReadFile(pub)
}
