package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// DeriveFromSSH loads an OpenSSH/SSH2 private key and derives a stable X25519
// keypair from it. Ed25519 keys map directly via the standard seed->scalar
// conversion; other key types (RSA/ECDSA/DSA) derive a 256-bit scalar from the
// marshaled key material. The derived X25519 private key is stable across runs
// so a developer can use their existing SSH key as their EnvSync identity.
//
// `path` is the private key file (e.g. ~/.ssh/id_ed25519). `passphrase` is
// optional and only required for passphrase-encrypted keys.
func DeriveFromSSH(path string, passphrase []byte) (priv, pub []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read ssh key %s: %w", path, err)
	}

	var raw any
	if len(passphrase) > 0 {
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
	} else {
		raw, err = ssh.ParseRawPrivateKey(data)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse ssh key %s: %w", path, err)
	}

	switch k := raw.(type) {
	case ed25519.PrivateKey:
		return ed25519ToX25519(k.Seed())
	case *ed25519.PrivateKey:
		return ed25519ToX25519((*k).Seed())
	default:
		// RSA / ECDSA / DSA. Derive a 256-bit scalar deterministically from the
		// key material so the EnvSync identity is stable.
		if der, merr := x509.MarshalPKCS8PrivateKey(k); merr == nil {
			return scalarKey(sha256.Sum256(der))
		}
		return scalarKey(sha256.Sum256(data))
	}
}

// ed25519ToX25519 derives an X25519 keypair from an Ed25519 seed using the
// standard conversion (the first half of SHA-512 over the seed becomes the
// X25519 scalar).
func ed25519ToX25519(seed []byte) (priv, pub []byte, err error) {
	if len(seed) != 32 {
		return nil, nil, fmt.Errorf("invalid ed25519 seed length %d", len(seed))
	}
	sum := sha512.Sum512(seed)
	priv = make([]byte, 32)
	copy(priv, sum[:32])
	pub, err = PublicFromPrivate(priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// scalarKey builds a keypair from an explicit 32-byte scalar seed.
func scalarKey(scalar [32]byte) (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	copy(priv, scalar[:])
	pub, err = PublicFromPrivate(priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}
