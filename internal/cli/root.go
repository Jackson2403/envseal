// Package cli wires the cobra command tree for EnvSeal.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is overridable at build time via -ldflags.
var Version = "0.1.0"

// rootCmd is the top-level command.
var rootCmd = &cobra.Command{
	Use:   "envseal",
	Short: "Securely manage and sync .env files across a team",
	Long: `EnvSeal is a developer tool for managing and sharing .env files
without ever storing secrets in the cloud. It audits missing variables
between env.example and local setups, and uses local keys to encrypt secrets
for the specific teammates who are allowed to see them.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose logging")
	rootCmd.Version = Version
	rootCmd.SetVersionTemplate("envseal version {{.Version}}\n")

	rootCmd.AddCommand(
		newInitCmd(),
		newCheckCmd(),
		newShareCmd(),
		newSyncCmd(),
		newTeamCmd(),
		newGenerateCmd(),
		newRotateCmd(),
		newHookCmd(),
		newHistoryCmd(),
		newP2PCmd(),
		newCompletionCmd(),
		newManCmd(),
	)
}

// Execute runs the CLI. Returns an error to be handled by main.
func Execute() error {
	return rootCmd.Execute()
}

// requireIdentityErr is a sentinel used when no local keypair exists yet.
func requireIdentityErr() error {
	return fmt.Errorf("no local identity found; run 'envseal init' first")
}

// envFileFor returns the path for a named environment. The default ".env"
// represents the base environment; named ones are ".env.<name>".
func envFileFor(name string) string {
	if name == "" {
		return ".env"
	}
	return fmt.Sprintf(".env.%s", name)
}

// hasStdin reports whether data is piped on stdin.
func hasStdin() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeNamedPipe != 0
}
