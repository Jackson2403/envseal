// Package transport handles the mechanics of exchanging encrypted secret
// bundles between developers. The file transport reads/writes standalone
// .envseal.* files that can be sent over AirDrop, USB, shared drives, etc.
package transport

import (
	"os"
	"path/filepath"

	"github.com/Jackson2403/envseal/internal/crypto"
)

// DefaultOutputExt is the suffix used for exported bundles.
const DefaultOutputExt = ".envseal.enc"

// WriteEnvelope persists an envelope to path.
func WriteEnvelope(path string, env *crypto.Envelope) error {
	data, err := env.Encode()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// ReadEnvelope loads an envelope from path.
func ReadEnvelope(path string) (*crypto.Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return crypto.DecodeEnvelope(data)
}

// OutputName builds an output filename for an env, e.g.
// "STAGING" -> "STAGING.envseal.enc". An explicit dir is preserved.
func OutputName(envName, dir string) string {
	return filepath.Join(dir, envName+DefaultOutputExt)
}
