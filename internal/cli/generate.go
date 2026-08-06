package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Jackson2403/envseal/internal/config"
	"github.com/Jackson2403/envseal/internal/parser"
	"github.com/spf13/cobra"
)

// envCallPatterns match common environment-variable access patterns across
// several languages. Capturing group 1 is the variable name.
var envCallPatterns = []*regexp.Regexp{
	// Go
	regexp.MustCompile(`os\.Getenv\(["']([A-Za-z_][A-Za-z0-9_]*)["']\)`),
	regexp.MustCompile(`os\.LookupEnv\(["']([A-Za-z_][A-Za-z0-9_]*)["']\)`),
	// Node.js
	regexp.MustCompile(`process\.env\.([A-Za-z_][A-Za-z0-9_]*)`),
	regexp.MustCompile(`process\.env\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]`),
	// Python
	regexp.MustCompile(`os\.(?:getenv|environ)\.get\(["']([A-Za-z_][A-Za-z0-9_]*)["']`),
	regexp.MustCompile(`os\.environ\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]`),
	// Ruby
	regexp.MustCompile(`ENV\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]`),
	// Rust (std::env)
	regexp.MustCompile(`env::var(?:_os)?\(["']([A-Za-z_][A-Za-z0-9_]*)["']`),
	// Shell
	regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`),
}

// DefaultPlaceholder is the value written for new keys in .env.example.
const DefaultPlaceholder = "changeme"

func newGenerateCmd() *cobra.Command {
	var dirs []string
	var outPath string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Scaffold .env.example from env vars referenced in code",
		Long: `Scan source files for common environment-variable access patterns
and scaffold (or append to) .env.example. Existing keys are preserved.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(".")
			if err != nil {
				return err
			}
			out := outPath
			if out == "" {
				out = cfg.Envs.Example
				if out == "" {
					out = ".env.example"
				}
			}

			// Default search dirs to "." so projects with no flag still work.
			searchDirs := dirs
			if len(searchDirs) == 0 {
				searchDirs = []string{"."}
			}

			found, err := scanVars(searchDirs)
			if err != nil {
				return err
			}

			// Load existing example to preserve current entries.
			existing, err := parser.Read(out)
			if err != nil {
				return err
			}

			// Build combined list: existing keys first, then new ones sorted.
			newKeys := sortedNew(existing, found)
			if len(newKeys) == 0 && len(existing.Keys()) == 0 {
				return fmt.Errorf("no env vars detected and %s is empty", out)
			}

			if dryRun {
				fmt.Printf("Would add %d new key(s) to %s\n", len(newKeys), out)
				for _, k := range newKeys {
					fmt.Printf("  %s=\n", k)
				}
				return nil
			}

			for _, k := range newKeys {
				existing.Entries = append(existing.Entries, parser.Entry{
					Key:     k,
					Value:   DefaultPlaceholder,
					Changed: true,
				})
			}
			if err := existing.Write(out); err != nil {
				return err
			}
			fmt.Printf("Wrote %s (%d new key(s))\n", out, len(newKeys))
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&dirs, "dir", "d", nil, "directories to scan (repeatable; default: current)")
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "output file (default: cfg example)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would be added without writing")
	return cmd
}

// scanVars walks the given directories and collects referenced env var names.
func scanVars(dirs []string) (map[string]struct{}, error) {
	found := map[string]struct{}{}
	for _, dir := range dirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			if info.IsDir() {
				return skipDir(path)
			}
			if !isScannable(path) {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			text := string(data)
			for _, re := range envCallPatterns {
				for _, m := range re.FindAllStringSubmatch(text, -1) {
					if len(m) > 1 && m[1] != "" {
						found[m[1]] = struct{}{}
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	delete(found, "PATH") // avoid noise from generic shell patterns
	for k := range found {
		if strings.HasPrefix(k, "CLINE") || strings.HasPrefix(k, "EnvSeal") {
			delete(found, k)
		}
	}
	return found, nil
}

// skipDir excludes common directories that shouldn't be scanned.
func skipDir(name string) error {
	switch name {
	case "", ".git", "node_modules", "vendor", "target", "build", "dist",
		".envseal", ".venv", "venv", "__pycache__":
		return filepath.SkipDir
	}
	return nil
}

// isScannable reports whether the file extension is a common source type.
func isScannable(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".rb",
		".rs", ".sh", ".bash", ".zsh", ".env", ".env.example":
		return true
	}
	return false
}

// sortedNew returns keys present in found but missing from existing, sorted.
func sortedNew(existing *parser.File, found map[string]struct{}) []string {
	set := existing.KeySet()
	var out []string
	for k := range found {
		if _, ok := set[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
