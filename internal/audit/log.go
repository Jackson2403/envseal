// Package audit maintains a small, local-only, append-only, cryptographically
// signed log of EnvSeal operations (share, sync, rotate). It lives under
// ~/.envseal/history and is never synced or committed.
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Jackson2403/envseal/internal/config"
	"github.com/Jackson2403/envseal/internal/crypto"
)

// Entry is a single signed, timestamped audit record.
type Entry struct {
	Timestamp    string   `json:"timestamp"`
	Action       string   `json:"action"` // share | sync | rotate
	EnvName      string   `json:"env_name"`
	KeysTouched  []string `json:"keys_touched,omitempty"`
	Peers        []string `json:"peers,omitempty"` // recipient fingerprints
	EnvelopeHash string   `json:"envelope_hash,omitempty"`
	Signature    []byte   `json:"signature,omitempty"`
}

// Dir is the per-user history directory.
func Dir() string {
	return filepath.Join(config.EnvSealHome(), "history")
}

// sanitize mangles a project name into a safe filename component.
func sanitize(project string) string {
	var b strings.Builder
	for _, r := range project {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}

// PathFor returns the log file path for a project.
func PathFor(project string) string {
	return filepath.Join(Dir(), sanitize(project)+".log")
}

// sigBody returns the canonical bytes that are signed; the signature field is
// always zeroed so verify() can reproduce the same bytes.
func (e Entry) sigBody() []byte {
	cp := e
	cp.Signature = nil
	b, _ := json.Marshal(cp)
	return b
}

// Append signs and appends an entry to the project's log. It returns an
// error only on hard I/O or identity failures.
func Append(project string, e Entry) error {
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	priv, err := config.LoadIdentityPrivate()
	if err != nil {
		return fmt.Errorf("load identity for audit signature: %w", err)
	}
	sig, err := crypto.SignIdentity(priv, e.sigBody())
	if err != nil {
		return fmt.Errorf("sign audit entry: %w", err)
	}
	e.Signature = sig

	rec, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(PathFor(project), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(rec, '\n')); err != nil {
		return err
	}
	return nil
}

// Read loads all entries for a project, in append order.
func Read(project string) ([]Entry, error) {
	f, err := os.Open(PathFor(project))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("parse audit entry %d: %w", line, err)
		}
		entries = append(entries, e)
	}
	return entries, sc.Err()
}

// Verify checks an entry's signature using the local identity.
func Verify(project string, e Entry) (bool, error) {
	priv, err := config.LoadIdentityPrivate()
	if err != nil {
		return false, fmt.Errorf("load identity: %w", err)
	}
	return crypto.VerifyIdentity(priv, e.sigBody(), e.Signature), nil
}
