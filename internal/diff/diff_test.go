package diff

import (
	"strings"
	"testing"

	"github.com/Jackson2403/envsync/internal/parser"
)

func mustParse(t *testing.T, s string) *parser.File {
	t.Helper()
	f, err := parser.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

func TestCheckMissingExtra(t *testing.T) {
	example := mustParse(t, "A=\nB=\nC=\n")
	local := mustParse(t, "A=1\nB=2\nEXTRA=x\n")

	rep := Check(example, local, nil)

	var missing, extra bool
	for _, r := range rep.Results {
		switch r.Kind {
		case Missing:
			if r.Key == "C" {
				missing = true
			}
		case Extra:
			if r.Key == "EXTRA" {
				extra = true
			}
		}
	}
	if !missing {
		t.Error("expected 'C' to be missing")
	}
	if !extra {
		t.Error("expected 'EXTRA' to be flagged as extra")
	}
	if rep.MissingCount() != 1 {
		t.Errorf("missing count = %d, want 1", rep.MissingCount())
	}
}

func TestCheckDangerousValues(t *testing.T) {
	example := mustParse(t, "API_TOKEN=\nDEF=\n")
	local := mustParse(t, "API_TOKEN=abcdef123\nDEF=changeme\n")
	patterns := []string{"password", "secret", "token", "api_key"}

	rep := Check(example, local, patterns)

	// API_TOKEN has a real-ish value and matches a pattern -> dangerous.
	// DEF=changeme is a recognized placeholder -> should not be flagged.
	var dangerous, placeholderFlagged bool
	for _, r := range rep.Results {
		if r.Kind == Dangerous {
			if r.Key == "API_TOKEN" {
				dangerous = true
			}
			if r.Key == "DEF" {
				placeholderFlagged = true
			}
		}
	}
	if !dangerous {
		t.Error("expected API_TOKEN to be flagged dangerous")
	}
	if placeholderFlagged {
		t.Error("placeholder value 'changeme' should not be flagged dangerous")
	}
}

func TestCheckIdenticalNoIssues(t *testing.T) {
	example := mustParse(t, "A=\nB=\n")
	local := mustParse(t, "A=x\nB=y\n")
	rep := Check(example, local, nil)
	if rep.HasIssues() {
		t.Errorf("expected no issues, got %v", rep.Results)
	}
}

func TestMaskIndependence(t *testing.T) {
	// Sanity: matchesAny is case-insensitive and trims quotes.
	example := mustParse(t, "P=")
	local := mustParse(t, "P=\"SECRET_KEY_123\"\n")
	rep := Check(example, local, []string{"secret"})
	found := false
	for _, r := range rep.Results {
		if r.Kind == Dangerous && r.Key == "P" {
			found = true
		}
	}
	if !found {
		t.Error("expected quoted value containing 'secret' to be dangerous")
	}
}

func TestReportStrings(t *testing.T) {
	if !strings.Contains("missing", string(Missing)) {
		t.Fatal("Missing constant changed")
	}
}
