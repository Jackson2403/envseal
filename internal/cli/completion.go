package cli

import (
	"os"

	"github.com/spf13/cobra"
)

// newCompletionCmd generates shell completion scripts via Cobra.
func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion <shell>",
		Short: "Generate a shell completion script",
		Long: `Generate autocompletion for bash, zsh, fish, or PowerShell.

Usage examples:
  envsync completion bash > /etc/bash_completion.d/envsync
  source <(envsync completion zsh)
  envsync completion zsh > $(brew --prefix)/share/zsh/site-functions/_envsync
  envsync completion fish | source`,
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "bash",
			Short: "Generate the bash completion script",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return rootCmd.GenBashCompletion(os.Stdout)
			},
		},
		&cobra.Command{
			Use:   "zsh",
			Short: "Generate the zsh completion script",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return rootCmd.GenZshCompletion(os.Stdout)
			},
		},
		&cobra.Command{
			Use:   "fish",
			Short: "Generate the fish completion script",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return rootCmd.GenFishCompletion(os.Stdout, true)
			},
		},
		&cobra.Command{
			Use:   "powershell",
			Short: "Generate the PowerShell completion script",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
			},
		},
	)
	return cmd
}
