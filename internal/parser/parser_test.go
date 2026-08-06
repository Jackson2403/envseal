package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndKeys(t *testing.T) {
	content := `# Database
DB_HOST=localhost
DB_PORT=5432
export DEBUG="true"
API_KEY='s3cr3t'   # inline comment
EMPTY=
`
	f, err := Parse([]byte(content))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"DB_HOST", "DB_PORT", "DEBUG", "API_KEY", "EMPTY"}
	got := f.Keys()
	if len(got) != len(want) {
		t.Fatalf("got %d keys %v, want %d: %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key[%d]=%q, want %q", i, got[i], want[i])
		}
	}
	if f.Get("DB_HOST") != "localhost" {
		t.Errorf("DB_HOST = %q", f.Get("DB_HOST"))
	}
	if f.Get("DEBUG") != "true" {
		t.Errorf("DEBUG = %q", f.Get("DEBUG"))
	}
	// Inline comment must be parsed off the value.
	if f.Get("API_KEY") != "s3cr3t" {
		t.Errorf("API_KEY = %q, want s3cr3t", f.Get("API_KEY"))
	}
}

func TestParseMalformed(t *testing.T) {
	if _, err := Parse([]byte("NO_EQUALS_HERE\n")); err == nil {
		t.Error("expected error for line without '='")
	}
	if _, err := Parse([]byte("=incomplete\n")); err == nil {
		t.Error("expected error for line without a key")
	}
}

func TestRoundTripPreservesLayout(t *testing.T) {
	content := "# comment\n\nFOO=bar   # keep me\nBAZ=\"qux\"\n"
	f, err := Parse([]byte(content))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := f.Write(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, _ := os.ReadFile(path)
	out := string(raw)
	// Untouched lines must be reproduced verbatim.
	for _, want := range []string{"# comment", "", "FOO=bar   # keep me", "BAZ=\"qux\""} {
		if !strings.Contains(out, want) {
			t.Errorf("round-trip lost %q\n%s", want, out)
		}
	}
}

func TestMergeUpdatesAndAppends(t *testing.T) {
	existing, _ := Parse([]byte("A=1\nB=2\n"))
	incoming, _ := Parse([]byte("A=new\nC=3\n"))

	touched := existing.Merge(incoming)
	if len(touched) != 2 {
		t.Fatalf("touched = %v, want 2", touched)
	}
	if existing.Get("A") != "new" {
		t.Errorf("A = %q, want new", existing.Get("A"))
	}
	if existing.Get("B") != "2" {
		t.Errorf("B unexpectedly changed: %q", existing.Get("B"))
	}
	if existing.Get("C") != "3" {
		t.Errorf("C = %q, want 3", existing.Get("C"))
	}
}

func TestMergeNoChangeWhenIdentical(t *testing.T) {
	existing, _ := Parse([]byte("A=1\n"))
	incoming, _ := Parse([]byte("A=1\n"))
	if touched := existing.Merge(incoming); len(touched) != 0 {
		t.Fatalf("touched = %v, want none for identical values", touched)
	}
}

func TestSortedKeys(t *testing.T) {
	f, _ := Parse([]byte("Z=1\nA=2\nM=3\n"))
	got := f.SortedKeys()
	want := []string{"A", "M", "Z"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted got %v want %v", got, want)
		}
	}
}
