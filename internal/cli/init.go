package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Jackson2403/envseal/internal/config"
	"github.com/Jackson2403/envseal/internal/crypto"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var teamName string
	var force bool
	var fromSSH bool
	var sshKey string
	var passphrase string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize EnvSeal for this project",
		Long: `Initialize EnvSeal: generates a local identity keypair in
~/.envseal and writes a .envseal.toml project configuration file.

By default a fresh X25519 keypair is generated. With --ssh the identity is
derived from an existing SSH private key (e.g. ~/.ssh/id_ed25519) so a
developer's existing key can double as their EnvSeal identity.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// 1. Identity.
			if config.HasIdentity() && !force {
				return fmt.Errorf("identity already exists in %s; use --force to regenerate",
					config.EnvSealHome())
			}

			var priv, pub []byte
			if fromSSH {
				if sshKey == "" {
					home, _ := os.UserHomeDir()
					sshKey = filepath.Join(home, ".ssh", "id_ed25519")
				}
				var err error
				priv, pub, err = crypto.DeriveFromSSH(sshKey, []byte(passphrase))
				if err != nil {
					return err
				}
				fmt.Printf("Identity derived from SSH key: %s\n", sshKey)
			} else {
				var err error
				priv, err = crypto.GeneratePrivateKey()
				if err != nil {
					return err
				}
				pub, err = crypto.PublicFromPrivate(priv)
				if err != nil {
					return err
				}
				fmt.Printf("Identity generated: %s\n", config.EnvSealHome())
			}
			if err := config.WriteIdentity(priv, pub); err != nil {
				return err
			}

			fmt.Printf("  fingerprint: %s\n", crypto.Fingerprint(pub))
			fmt.Printf("  public key:  %s\n", crypto.PublicKeyString(pub))

			// 2. Config (idempotent).
			if _, err := os.Stat(config.Filename); err == nil && !force {
				fmt.Println("Note: .envseal.toml already exists (left untouched).")
				return nil
			}
			cfg := config.Default()
			if teamName != "" {
				cfg.Project.Name = teamName
			}
			if err := config.Save(".", cfg); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			fmt.Printf("Project config written: %s\n", config.Filename)
			fmt.Println("Next: run 'envseal team add <email> --pubkey <base64>'")
			return nil
		},
	}

	cmd.Flags().StringVar(&teamName, "name", "", "project name to record in .envseal.toml")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing identity/config")
	cmd.Flags().BoolVar(&fromSSH, "ssh", false, "derive the identity from an existing SSH private key")
	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "path to the SSH private key (default ~/.ssh/id_ed25519)")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "passphrase for an encrypted SSH key")
	return cmd
}
