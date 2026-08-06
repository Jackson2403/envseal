// Package diff implements the missing/extra/dangerous variable analysis
// between a reference (e.g. .env.example) and local environment files.
package diff

import (
	"sort"
	"strings"

	"github.com/Jackson2403/envsync/internal/parser"
)

// EntryKind classifies a discrepancy.
type EntryKind string

const (
	Missing     EntryKind = "missing"             // in example, not in local
	Extra       EntryKind = "extra"               // in local, not in example
	Dangerous   EntryKind = "dangerous-value-set" // key present in local with a suspicious value
	Placeholder EntryKind = "placeholder-empty"   // in example but empty/placeholder in both
)

// Result is one discrepancy row.
type Result struct {
	Kind   EntryKind
	Key    string
	Local  string // value in local env (truncated for display later)
	Reason string
}

// Report aggregates audit results.
type Report struct {
	Results []Result
}

// Check diffs example vs local and flags dangerous local values.
func Check(example, local *parser.File, dangerousPatterns []string) Report {
	var rep Report

	exampleKeys := example.KeySet()
	localKeys := local.KeySet()

	// Missing: present in example but absent from local.
	for _, k := range example.Keys() {
		if _, ok := localKeys[k]; ok {
			continue
		}
		if rep.has(k, Missing) {
			continue
		}
		rep.Results = append(rep.Results, Result{
			Kind:   Missing,
			Key:    k,
			Reason: "defined in .env.example but missing locally",
		})
	}

	// Extra: present in local but not in example.
	for _, k := range local.Keys() {
		if _, ok := exampleKeys[k]; ok {
			continue
		}
		rep.Results = append(rep.Results, Result{
			Kind:   Extra,
			Key:    k,
			Local:  local.Get(k),
			Reason: "present locally but not declared in .env.example",
		})
	}
	sortResults(&rep)

	// Dangerous: a key that looks sensitive, or a value that contains a
	// sensitive-looking substring, while holding a real (non-placeholder) value.
	for _, k := range local.Keys() {
		val := local.Get(k)
		if !isSensitiveEntry(k, val, dangerousPatterns) {
			continue
		}
		rep.Results = append(rep.Results, Result{
			Kind:   Dangerous,
			Key:    k,
			Local:  val,
			Reason: "key or value matches a dangerous pattern",
		})
	}
	return rep
}

// isSensitiveEntry reports whether key/value should be flagged as dangerous.
// A value that is clearly a placeholder or empty is never flagged, so default
// scaffolding does not raise alarms.
func isSensitiveEntry(key, value string, patterns []string) bool {
	value = normalizeValue(value)
	if value == "" || isUnsetValue(value) {
		return false
	}
	if matchesAnyString(key, patterns) {
		return true
	}
	return matchesAnyString(value, patterns)
}

// normalizeValue trims surrounding quotes/whitespace and lowercases.
func normalizeValue(v string) string {
	return strings.ToLower(strings.Trim(v, ` "'`))
}

// matchesAnyString does a plain case-insensitive substring check.
func matchesAnyString(s string, patterns []string) bool {
	s = strings.ToLower(s)
	for _, p := range patterns {
		if p != "" && strings.Contains(s, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// has reports whether a row for key/kind already exists.
func (r *Report) has(key string, kind EntryKind) bool {
	for _, res := range r.Results {
		if res.Key == key && res.Kind == kind {
			return true
		}
	}
	return false
}

// sortResults orders rows: missing, extra, then dangerous, each alphabetical.
func sortResults(rep *Report) {
	sort.SliceStable(rep.Results, func(i, j int) bool {
		if rep.Results[i].Kind != rep.Results[j].Kind {
			return rep.Results[i].Kind < rep.Results[j].Kind
		}
		return rep.Results[i].Key < rep.Results[j].Key
	})
}

// isUnsetValue detects common empty/placeholder sentinels.
func isUnsetValue(v string) bool {
	switch v {
	case "", "empty", "none", "null", "nil", "changeme", "replace-me",
		"your-value-here", "xxx", "placeholder":
		return true
	}
	return false
}

// MissingCount returns the number of missing variables.
func (r Report) MissingCount() int {
	n := 0
	for _, res := range r.Results {
		if res.Kind == Missing {
			n++
		}
	}
	return n
}

// HasIssues reports whether any problems were found.
func (r Report) HasIssues() bool {
	return len(r.Results) > 0
}
