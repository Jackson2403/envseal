package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/Jackson2403/envsync/internal/config"
	"github.com/Jackson2403/envsync/internal/crypto"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

func newTeamCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "team",
		Short: "Manage team members and their public keys",
	}

	cmd.AddCommand(
		newTeamAddCmd(),
		newTeamRemoveCmd(),
		newTeamListCmd(),
	)
	return cmd
}

func newTeamAddCmd() *cobra.Command {
	var name, pubKey, pubKeyFile string
	cmd := &cobra.Command{
		Use:   "add <email>",
		Short: "Register a teammate's public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("usage: envsync team add <email>")
			}
			email := strings.ToLower(args[0])

			keyB64 := pubKey
			if pubKeyFile != "" {
				raw, err := os.ReadFile(pubKeyFile)
				if err != nil {
					return err
				}
				keyB64 = strings.TrimSpace(string(raw))
			}
			if keyB64 == "" {
				return fmt.Errorf("provide a public key via --pubkey or --pubkey-file")
			}

			pub, err := crypto.DecodePublicKey(strings.TrimSpace(keyB64))
			if err != nil {
				return fmt.Errorf("invalid public key: %w", err)
			}
			if err := crypto.ParsePublicKey(pub); err != nil {
				return err
			}

			cfg, err := config.Load(".")
			if err != nil {
				return err
			}
			m := config.Member{
				Name:    name,
				Email:   email,
				PubKey:  crypto.PublicKeyString(pub),
				KeyType: "x25519",
			}
			if err := config.AddMember(cfg.KeysDir(), m); err != nil {
				return fmt.Errorf("add member: %w", err)
			}
			fmt.Printf("Registered %s (fingerprint %s)\n", email, crypto.Fingerprint(pub))
			fmt.Printf("Stored at %s\n", cfg.KeysDir())
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "display name for the teammate")
	cmd.Flags().StringVar(&pubKey, "pubkey", "", "base64 x25519 public key")
	cmd.Flags().StringVar(&pubKeyFile, "pubkey-file", "", "path to a file containing the public key")
	return cmd
}

func newTeamRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <email>",
		Short: "Remove a teammate's public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("usage: envsync team remove <email>")
			}
			cfg, err := config.Load(".")
			if err != nil {
				return err
			}
			if err := config.RemoveMember(cfg.KeysDir(), strings.ToLower(args[0])); err != nil {
				return err
			}
			fmt.Printf("Removed %s\n", args[0])
			return nil
		},
	}
}

func newTeamListCmd() *cobra.Command {
	var outputJSON bool
	return &cobra.Command{
		Use:   "list",
		Short: "List registered team members",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(".")
			if err != nil {
				return err
			}
			members, err := config.ListMembers(cfg.KeysDir())
			if err != nil {
				return err
			}
			if outputJSON {
				return writeJSON(members)
			}

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Name", "Email", "Fingerprint"})
			for _, m := range members {
				pub, _ := crypto.DecodePublicKey(m.PubKey)
				table.Append([]string{m.Name, m.Email, crypto.Fingerprint(pub)})
			}
			red := color.New(color.FgRed)
			if len(members) == 0 {
				red.Fprintln(os.Stdout, "No team members registered yet.")
			} else {
				table.Render()
			}
			return nil
		},
	}
}
