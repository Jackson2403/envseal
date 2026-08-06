package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// KeysDir returns the absolute path to where team public keys live.
func (c Config) KeysDir() string {
	if c.Team.KeysDir == "" {
		return ".envsync/team-keys"
	}
	return c.Team.KeysDir
}

// memberPath builds the file path for a member's record inside keysDir.
func memberPath(keysDir, email string) string {
	safe := strings.ToLower(strings.ReplaceAll(email, "@", "_at_"))
	return filepath.Join(keysDir, safe+".toml")
}

// AddMember persists a public key record for a team member.
func AddMember(keysDir string, m Member) error {
	if m.Email == "" || m.PubKey == "" {
		return fmt.Errorf("member email and public key are required")
	}
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return err
	}
	path := memberPath(keysDir, m.Email)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := toml.NewEncoder(f).Encode(m); err != nil {
		return err
	}
	return nil
}

// RemoveMember deletes a member record.
func RemoveMember(keysDir, email string) error {
	path := memberPath(keysDir, email)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ListMembers returns all members stored under keysDir.
func ListMembers(keysDir string) ([]Member, error) {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var members []Member
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		var m Member
		full := filepath.Join(keysDir, e.Name())
		if _, err := toml.DecodeFile(full, &m); err != nil {
			continue // skip unreadable member files
		}
		members = append(members, m)
	}
	return members, nil
}

// TeamKeysDir is a convenience wrapper that reads the config and returns the
// absolute team keys directory, creating it if needed.
func TeamKeysDir(cfg Config) string {
	return cfg.KeysDir()
}
