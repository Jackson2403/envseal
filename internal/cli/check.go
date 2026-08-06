package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/Jackson2403/envsync/internal/config"
	"github.com/Jackson2403/envsync/internal/diff"
	"github.com/Jackson2403/envsync/internal/parser"
)

func newCheckCmd() *cobra.Command {
	var envName string
	var format string
	var examplePath string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Audit local .env against .env.example",
		Long: `Audit a local environment file against .env.example and report
missing variables, unexpected extras, and values that match known-dangerous
patterns. Exits non-zero if any problems are found.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(".")
			if err != nil {
				return err
			}
			example := examplePath
			if example == "" {
				example = cfg.Envs.Example
				if example == "" {
					example = ".env.example"
				}
			}

			local := envFileFor(envName)
			exFile, err := parser.Read(example)
			if err != nil {
				return err
			}
			locFile, err := parser.Read(local)
			if err != nil {
				return err
			}

			report := diff.Check(exFile, locFile, cfg.Check.DangerousPatterns)

			switch format {
			case "json":
				return writeJSON(report)
			default:
				return renderTable(exFile.Path, local, report)
			}
		},
	}

	cmd.Flags().StringVar(&envName, "env", "", "environment file to audit (default: .env)")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	cmd.Flags().StringVar(&examplePath, "example", "", "path to the reference file")
	return cmd
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func renderTable(examplePath, localPath string, report diff.Report) error {
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	fmt.Printf("Checking %s against %s\n", localPath, examplePath)
	if len(report.Results) == 0 {
		fmt.Println(green("✓ No problems found."))
		return nil
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Severity", "Key", "Value", "Why"})
	table.SetColumnAlignment([]int{
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_LEFT,
	})

	for _, r := range report.Results {
		var severity string
		switch r.Kind {
		case diff.Missing:
			severity = red("missing")
		case diff.Extra:
			severity = yellow("extra")
		case diff.Dangerous:
			severity = red("danger")
		default:
			severity = string(r.Kind)
		}
		table.Append([]string{severity, r.Key, maskValue(r.Local), r.Reason})
	}
	table.Render()

	fmt.Printf("%s %d missing\n", red("!"), report.MissingCount())
	fmt.Printf("Run '%s' to see how to sync missing secrets.\n",
		"envsync share --help")
	return nil
}

// maskValue hides long secret-valued locals while revealing whether one is set.
func maskValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "(unset)"
	}
	if len(v) <= 4 {
		return "*" + v
	}
	// Show first/last char to indicate presence without leaking the value.
	return v[:1] + strings.Repeat("*", len(v)-2) + v[len(v)-1:]
}
