package audit

import (
	"path/filepath"
	"testing"

	"github.com/Jackson2403/envsync/internal/config"
	"github.com/Jackson2403/envsync/internal/crypto"
)

// setTestIdentity installs an identity under an isolated ENVSYNC_HOME.
func setTestIdentity(t *testing.T) {
	t.Helper()
	t.Setenv("ENVSYNC_HOME", filepath.Join(t.TempDir(), ".envsync"))
	if err := config.EnsureHome(); err != nil {
		t.Fatalf("ensure home: %v", err)
	}
	priv, err := crypto.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := crypto.PublicFromPrivate(priv)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	if err := config.WriteIdentity(priv, pub); err != nil {
		t.Fatalf("write identity: %v", err)
	}
}

func TestAppendReadVerify(t *testing.T) {
	setTestIdentity(t)
	entry := Entry{
		Action:       "share",
		EnvName:      "staging",
		KeysTouched:  []string{"API_KEY", "DB_PASSWORD"},
		Peers:        []string{"abcdef01"},
		EnvelopeHash: "aabbcc",
	}
	if err := Append("acme", entry); err != nil {
		t.Fatalf("append: %v", err)
	}
	entries, err := Read("acme")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Action != "share" || entries[0].EnvName != "staging" {
		t.Fatalf("entry fields lost: %+v", entries[0])
	}
	ok, err := Verify("acme", entries[0])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("signature should verify")
	}
}

func TestTamperDetection(t *testing.T) {
	setTestIdentity(t)
	if err := Append("acme", Entry{Action: "sync", EnvName: "prod"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	entries, err := Read("acme")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Tamper with a recorded field.
	entries[0].EnvName = "PWNED"
	ok, err := Verify("acme", entries[0])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("tampered entry must not verify")
	}
}

func TestPathIsolatedByProject(t *testing.T) {
	setTestIdentity(t)
	_ = Append("project one", Entry{Action: "share"})
	_ = Append("project one", Entry{Action: "sync"})
	if got, _ := Read("project one"); len(got) != 2 {
		t.Fatalf("expected 2 entries for project, got %d", len(got))
	}
	if got, _ := Read("other"); len(got) != 0 {
		t.Fatalf("expected 0 entries for other project, got %d", len(got))
	}
}
