// Package config manages the per-project `.envseal.toml` configuration
// and the local identity/team key storage.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config is the top-level `.envseal.toml` structure.
type Config struct {
	Project Project `toml:"project"`
	Envs    Envs    `toml:"envs"`
	Team    Team    `toml:"team"`
	Crypto  Crypto  `toml:"crypto"`
	Check   Check   `toml:"check"`
}

// Project holds project metadata.
type Project struct {
	Name string `toml:"name"`
}

// Envs describes which env files exist and the canonical example file.
type Envs struct {
	Files   []string `toml:"files"`
	Example string   `toml:"example"`
}

// Team configures the team key directory.
type Team struct {
	KeysDir string `toml:"keys_dir"`
}

// Crypto stores algorithm choice.
type Crypto struct {
	Algorithm string `toml:"algorithm"`
}

// Check holds audit-related settings.
type Check struct {
	DangerousPatterns []string `toml:"dangerous_patterns"`
}

// Member is a single team member record stored in <keysdir>/<email>.toml
// (only public information is persisted).
type Member struct {
	Name    string `toml:"name"`
	Email   string `toml:"email"`
	PubKey  string `toml:"pubkey"`   // base64 x25519 public key
	KeyType string `toml:"key_type"` // "x25519"
}

// Default returns a Config populated with sensible defaults.
func Default() Config {
	return Config{
		Project: Project{Name: "my-app"},
		Envs: Envs{
			Files:   []string{"local", "staging", "production"},
			Example: ".env.example",
		},
		Team:   Team{KeysDir: ".envseal/team-keys"},
		Crypto: Crypto{Algorithm: "x25519-aes256gcm"},
		Check: Check{
			DangerousPatterns: []string{
				"password",
				"secret",
				"token",
				"api_key",
				"private_key",
				"credential",
			},
		},
	}
}

// Filename is the canonical config file name.
const Filename = ".envseal.toml"

// Load reads the config from the current directory (or dir when provided).
// If the file can't be found, a default config is returned without error so
// commands can still offer helpful behavior via eager features (e.g. `check`).
func Load(dir string) (Config, error) {
	path := filepath.Join(dir, Filename)
	cfg := Default()

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}

	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}

	// Normalize: point insecure string fields at their paths. If a relative
	// keys_dir was provided, resolve it relative to CWD for predictability.
	if cfg.Team.KeysDir != "" {
		if abs, err := filepath.Abs(cfg.Team.KeysDir); err == nil {
			cfg.Team.KeysDir = abs
		}
	}

	return cfg, nil
}

// Save writes cfg to <dir>/<Filename>.
func Save(dir string, cfg Config) error {
	path := filepath.Join(dir, Filename)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(cfg)
}
