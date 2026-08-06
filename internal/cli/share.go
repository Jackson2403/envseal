package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/Jackson2403/envsync/internal/config"
	"github.com/Jackson2403/envsync/internal/crypto"
	"github.com/Jackson2403/envsync/internal/transport"
	"github.com/spf13/cobra"
)

func newShareCmd() *cobra.Command {
	var to []string
	var outputDir string
	var envName string
	var file string

	cmd := &cobra.Command{
		Use:     "share [recipient-email...]",
		Aliases: []string{"encrypt", "export"},
		Short:   "Encrypt an env file for specific teammates",
		Long: `Reads an environment file, encrypts it with AES-256-GCM using a
random session key, and wraps that key for each named recipient's public key.
Produces a standalone .envsync.enc bundle that can be sent out-of-band.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				to = append(to, args...)
			}
			cfg, err := config.Load(".")
			if err != nil {
				return err
			}

			recipients, err := resolveRecipients(cfg, to)
			if err != nil {
				return err
			}

			// Source file: --file wins, else <env>.env file.
			src := file
			if src == "" {
				src = envFileFor(envName)
			}
			if _, err := os.Stat(src); err != nil {
				return fmt.Errorf("source file %q not found", src)
			}

			plaintext, err := os.ReadFile(src)
			if err != nil {
				return err
			}

			label := envName
			if label == "" {
				label = "default"
			}
			env, err := crypto.Encrypt(plaintext, label, recipients)
			if err != nil {
				return fmt.Errorf("encrypt: %w", err)
			}

			outPath := transport.OutputName(strings.ToUpper(label), outputDir)
			if err := transport.WriteEnvelope(outPath, env); err != nil {
				return err
			}

			recordAudit(historyProject(cfg), "share", label, plaintext,
				recipientFingerprints(recipients), sha256HexFile(outPath))

			fmt.Printf("Encrypted %q for %d recipient(s)\n", src, len(recipients))
			fmt.Printf("Bundle:    %s\n", outPath)
			fmt.Println("Share this file out-of-band (e.g. AirDrop/USB/encrypted chat).")
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&to, "to", "t", nil, "recipient email(s); repeatable, or pass as args")
	cmd.Flags().StringVarP(&outputDir, "output", "o", ".", "directory to write the bundle into")
	cmd.Flags().StringVar(&envName, "env", "", "environment name for labels; defaults to .env")
	cmd.Flags().StringVarP(&file, "file", "f", "", "explicit source env file path")
	return cmd
}

// resolveRecipients maps requested emails to their registered public keys.
func resolveRecipients(cfg config.Config, emails []string) ([][]byte, error) {
	if len(emails) == 0 {
		return nil, fmt.Errorf("no recipients given; use --to <email> or positional args")
	}
	members, err := config.ListMembers(cfg.KeysDir())
	if err != nil {
		return nil, err
	}
	byEmail := make(map[string]config.Member, len(members))
	for _, m := range members {
		byEmail[m.Email] = m
	}

	var pubs [][]byte
	seen := map[string]bool{}
	for _, email := range emails {
		if seen[email] {
			continue
		}
		seen[email] = true
		m, ok := byEmail[strings.ToLower(email)]
		if !ok {
			return nil, fmt.Errorf("no public key on file for %q; add it with 'envsync team add %s'",
				email, email)
		}
		pub, err := crypto.DecodePublicKey(m.PubKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key for %q: %w", email, err)
		}
		pubs = append(pubs, pub)
	}
	return pubs, nil
}
