package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Jackson2403/envseal/internal/audit"
	"github.com/Jackson2403/envseal/internal/config"
	"github.com/Jackson2403/envseal/internal/parser"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

func newHistoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show the local, signed audit log",
		Long: `Inspect the local-only, append-only, signed audit log kept at
~/.envseal/history for this project. It records every share, sync, and rotate
operation so you can trace who gave you a secret and when.`,
	}
	cmd.AddCommand(newHistoryShowCmd(), newHistoryVerifyCmd())
	return cmd
}

// historyProject resolves the project key used to name the log file.
func historyProject(cfg config.Config) string {
	name := cfg.Project.Name
	if strings.TrimSpace(name) == "" {
		return "default"
	}
	return strings.TrimSpace(name)
}

func newHistoryShowCmd() *cobra.Command {
	var since string
	return &cobra.Command{
		Use:   "show",
		Short: "Show audit log entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(".")
			if err != nil {
				return err
			}
			entries, err := audit.Read(historyProject(cfg))
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("No audit entries recorded yet for this project.")
				return nil
			}

			var sinceT time.Time
			if since != "" {
				sinceT, err = time.Parse(time.RFC3339, since)
				if err != nil {
					// Accept simple forms like 7d, 30d.
					if n, pe := parseDays(since); pe == nil {
						sinceT = time.Now().Add(-time.Duration(n) * 24 * time.Hour)
					} else {
						return fmt.Errorf("invalid --since %q (use RFC3339 or e.g. 7d)", since)
					}
				}
			}

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Timestamp", "Action", "Env", "Keys", "Peers"})
			for _, e := range entries {
				if !sinceT.IsZero() {
					ts, err := time.Parse(time.RFC3339, e.Timestamp)
					if err != nil || ts.Before(sinceT) {
						continue
					}
				}
				table.Append([]string{
					e.Timestamp,
					e.Action,
					e.EnvName,
					strings.Join(e.KeysTouched, ","),
					strings.Join(e.Peers, ","),
				})
			}
			table.Render()
			return nil
		},
	}
}

func parseDays(s string) (int, error) {
	if len(s) < 2 || s[len(s)-1] != 'd' {
		return 0, fmt.Errorf("bad duration")
	}
	var n int
	if _, err := fmt.Sscanf(s, "%dd", &n); err != nil {
		return 0, err
	}
	return n, nil
}

func newHistoryVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify signatures of all audit entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(".")
			if err != nil {
				return err
			}
			if !config.HasIdentity() {
				return requireIdentityErr()
			}
			project := historyProject(cfg)
			entries, err := audit.Read(project)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("No audit entries recorded yet for this project.")
				return nil
			}
			red := color.New(color.FgRed).SprintFunc()
			green := color.New(color.FgGreen).SprintFunc()
			ok := 0
			for i, e := range entries {
				v, err := audit.Verify(project, e)
				if err != nil {
					return err
				}
				if v {
					ok++
					fmt.Printf("  entry %d: %s verified\n", i+1, green("OK"))
				} else {
					fmt.Printf("  entry %d: %s (signature mismatch - log may be tampered)\n", i+1, red("FAIL"))
				}
			}
			if ok == len(entries) {
				fmt.Printf("%s all %d audit entries verified\n", green("✓"), ok)
				return nil
			}
			return fmt.Errorf("audit log verification FAILED for %d of %d entries", len(entries)-ok, len(entries))
		},
	}
}

// keyNames extracts the key names from a plaintext env payload for auditing.
func keyNames(plaintext []byte) []string {
	f, err := parser.Parse(plaintext)
	if err != nil {
		return nil
	}
	return f.Keys()
}

// recipientFingerprints returns fingerprints for a set of public keys.
func recipientFingerprints(pubs [][]byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range pubs {
		fp := fpOf(p)
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, fp)
	}
	return out
}

func fpOf(pub []byte) string {
	if len(pub) == 0 {
		return ""
	}
	return fingerprintHex(pub)
}

func fingerprintHex(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:4])
}

// sha256HexFile returns the hex sha256 of a file, or "" on error.
func sha256HexFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// recordAudit best-effort appends an audit entry and prints a warning on
// failure, so a non-writable home directory never blocks a secret operation.
func recordAudit(project, action, envName string, plaintext []byte, fps []string, bundleHash string) {
	entry := audit.Entry{
		Action:       action,
		EnvName:      envName,
		KeysTouched:  keyNames(plaintext),
		Peers:        fps,
		EnvelopeHash: bundleHash,
	}
	if err := audit.Append(project, entry); err != nil {
		yellow := color.New(color.FgYellow)
		yellow.Fprintf(os.Stderr, "warning: could not write audit log: %v\n", err)
	}
}
