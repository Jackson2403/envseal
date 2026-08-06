// Package parser implements an ordered, comment-aware reader/writer for
// dotenv files. Unlike some parsing libraries it preserves key order and
// comments, which is important for auditing and scaffolding.
package parser

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Entry is a single parsed line from a dotenv file.
type Entry struct {
	Key     string // variable name (empty for comment/blank lines)
	Value   string // unquoted value
	Comment string // inline or full-line comment text WITHOUT leading '#'
	Raw     string // original raw line (for lossless round-tripping)
	Blank   bool   // true when Raw is an empty/whitespace-only line
	Changed bool   // set true by Merge when a value was updated in memory
}

// File is an ordered collection of parsed entries.
type File struct {
	Path    string
	Entries []Entry
}

// Read parses a dotenv file at path. A missing file returns an empty File
// (and a nil error) so callers can treat an absent local .env gracefully.
func Read(path string) (*File, error) {
	f := &File{Path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return f, nil
		}
		return nil, err
	}
	f.Entries, err = parseBytes(raw)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Parse parses dotenv content provided in memory.
func Parse(content []byte) (*File, error) {
	entries, err := parseBytes(content)
	if err != nil {
		return nil, err
	}
	return &File{Entries: entries}, nil
}

// parseBytes converts raw content into entries.
func parseBytes(raw []byte) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		e, err := parseLine(line, lineNo)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// parseLine parses a single logical line into an Entry.
func parseLine(line string, lineNo int) (Entry, error) {
	e := Entry{Raw: line}

	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		e.Blank = true
		return e, nil
	}

	// Full-line comment.
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
		e.Comment = strings.TrimSpace(trimmed[1:])
		return e, nil
	}

	body := trimmed
	// Optional "export " prefix.
	if strings.HasPrefix(body, "export ") {
		body = strings.TrimSpace(strings.TrimPrefix(body, "export "))
	}

	// Split key/value at the first '='.
	eq := strings.IndexByte(body, '=')
	if eq < 0 {
		return e, fmt.Errorf("line %d: expected KEY=VALUE, got %q", lineNo, trimmed)
	}

	key := strings.TrimSpace(body[:eq])
	if key == "" {
		return e, fmt.Errorf("line %d: empty variable name", lineNo)
	}
	e.Key = key

	rest := strings.TrimSpace(body[eq+1:])

	// Split inline comment, but not inside quotes.
	value, comment := splitValueComment(rest)
	e.Value = unquote(value)
	e.Comment = comment
	return e, nil
}

// splitValueComment separates a trailing comment (#...) from a value,
// respecting single- and double-quoted regions.
func splitValueComment(s string) (value, comment string) {
	var quote rune
	inQuote := false
	for i, r := range s {
		switch {
		case inQuote:
			if r == quote {
				inQuote = false
				quote = 0
			}
		case r == '\'' || r == '"':
			inQuote = true
			quote = r
		case r == '#' && i > 0:
			// Ensure '#' is not glued to a non-whitespace char unless it's a
			// legitimate part of the value operand (e.g. URL fragments).
			if i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
				return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
			}
		}
	}
	return strings.TrimSpace(s), ""
}

// unquote strips surrounding single or double quotes from a value.
func unquote(v string) string {
	if len(v) >= 2 {
		if (v[0] == '\'' && v[len(v)-1] == '\'') ||
			(v[0] == '"' && v[len(v)-1] == '"') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// Keys returns the non-blank, non-comment keys in file order.
func (f *File) Keys() []string {
	var keys []string
	for _, e := range f.Entries {
		if e.Key != "" {
			keys = append(keys, e.Key)
		}
	}
	return keys
}

// KeySet returns a set of keys present in the file.
func (f *File) KeySet() map[string]struct{} {
	set := make(map[string]struct{}, len(f.Entries))
	for _, e := range f.Entries {
		if e.Key != "" {
			set[e.Key] = struct{}{}
		}
	}
	return set
}

// Get returns the value for a key, or "" if absent.
func (f *File) Get(key string) string {
	for _, e := range f.Entries {
		if e.Key == key {
			return e.Value
		}
	}
	return ""
}

// SortedKeys returns keys in lexicographic order (useful for generating a
// clean .env.example).
func (f *File) SortedKeys() []string {
	keys := f.Keys()
	sort.Strings(keys)
	return keys
}

// Write persists the file back to path. Untouched entries reproduce their
// original raw formatting; changed/appended entries are re-rendered.
func (f *File) Write(path string) error {
	var sb strings.Builder
	for _, e := range f.Entries {
		sb.WriteString(renderRow(e))
		sb.WriteString("\n")
	}
	return os.WriteFile(path, []byte(sb.String()), 0o600)
}

// renderRow decides the final representation of an entry.
func renderRow(e Entry) string {
	// Untouched entries keep their exact original line.
	if e.Raw != "" && !e.Changed {
		return e.Raw
	}
	switch {
	case e.Blank:
		return ""
	case e.Key == "":
		return "#" + e.Comment
	default:
		return e.Key + "=" + quoteIfNeeded(e.Value)
	}
}

// quoteIfNeeded wraps a value in quotes when it would otherwise be ambiguous.
func quoteIfNeeded(v string) string {
	if strings.ContainsAny(v, " \t#;\"'") || strings.HasPrefix(v, "export ") {
		return `"` + v + `"`
	}
	return v
}

// Merge overlays the named keys/values from src into f. Existing keys keep
// their position and comments but take the incoming value; new keys are
// appended. It returns the list of keys that changed or were added.
func (f *File) Merge(src *File) []string {
	incoming := src.KeySet()
	var touched []string

	// Update existing entries that actually change value.
	for i := range f.Entries {
		e := &f.Entries[i]
		if e.Key == "" {
			continue
		}
		if v, ok := src.GetEntry(e.Key); ok && v.Value != e.Value {
			e.Value = v.Value
			e.Changed = true
			touched = append(touched, e.Key)
		}
	}

	// Append keys not already present.
	for _, k := range src.Keys() {
		if _, exists := incoming[k]; !exists {
			continue
		}
		if _, ok := f.KeySet()[k]; ok {
			continue
		}
		e, _ := src.GetEntry(k)
		f.Entries = append(f.Entries, Entry{
			Key:     e.Key,
			Value:   e.Value,
			Changed: true,
		})
		touched = append(touched, k)
	}
	return touched
}

// GetEntry returns the entry for a key and whether it exists.
func (f *File) GetEntry(key string) (Entry, bool) {
	for _, e := range f.Entries {
		if e.Key == key {
			return e, true
		}
	}
	return Entry{}, false
}
