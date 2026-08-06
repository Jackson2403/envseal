package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/Jackson2403/envsync/internal/config"
	"github.com/Jackson2403/envsync/internal/crypto"
	"github.com/Jackson2403/envsync/internal/parser"
	"github.com/Jackson2403/envsync/internal/transport"
)

func newSyncCmd() *cobra.Command {
	var bundlePath string
	var merge bool
	var outPath string
	var dryRun bool

	cmd := &cobra.Command{
		Use:     "sync [bundle]",
		Aliases: []string{"decrypt", "import"},
		Short:   "Decrypt a received bundle into your environment",
		Long: `Decrypt an .envsync.enc bundle using your local identity key and
load the recovered values into a local env file. By default the whole file is
replaced; use --merge to only update/add keys, preserving existing layout.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if bundlePath == "" && len(args) > 0 {
				bundlePath = args[0]
			}
			if bundlePath == "" {
				return fmt.Errorf("bundle path required (positional arg or --file)")
			}
			if !config.HasIdentity() {
				return requireIdentityErr()
			}

			priv, err := config.LoadIdentityPrivate()
			if err != nil {
				return err
			}

			cfg, err := config.Load(".")
			if err != nil {
				return err
			}

			env, err := transport.ReadEnvelope(bundlePath)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			plaintext, label, err := crypto.Decrypt(env, priv)
			if err != nil {
				return err
			}

			target := outPath
			if target == "" {
				target = fileForLabel(label)
			}

			if dryRun {
				fmt.Printf("Would write %d bytes to %s (env=%s)\n",
					len(plaintext), target, label)
				return nil
			}

			// Peers = recipients sealed into the received bundle.
			var fps []string
			for _, s := range env.Recipients {
				fps = append(fps, s.Fingerprint)
			}

			if merge {
				if err := mergeWrite(target, plaintext); err != nil {
					return err
				}
				recordAudit(historyProject(cfg), "sync", label, plaintext,
					fps, sha256HexFile(bundlePath))
				return nil
			}
			if err := os.WriteFile(target, plaintext, 0o600); err != nil {
				return err
			}
			recordAudit(historyProject(cfg), "sync", label, plaintext,
				fps, sha256HexFile(bundlePath))
			fmt.Printf("Decrypted %q into %s\n", bundlePath, target)
			return nil
		},
	}

	cmd.Flags().StringVarP(&bundlePath, "file", "f", "", "path to the .envsync.enc bundle")
	cmd.Flags().BoolVar(&merge, "merge", false, "merge values into the existing env file")
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "explicit destination env file path")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would happen without writing")
	return cmd
}

// mergeWrite overlays decrypted values into the target env file.
func mergeWrite(target string, plaintext []byte) error {
	incoming, err := parser.Parse(plaintext)
	if err != nil {
		return err
	}
	existing, err := parser.Read(target)
	if err != nil {
		return err
	}
	touched := existing.Merge(incoming)
	if len(touched) == 0 {
		fmt.Println("No changes to apply (all keys up to date).")
		return nil
	}
	if err := existing.Write(target); err != nil {
		return err
	}
	fmt.Printf("Merged %d key(s) into %s\n", len(touched), target)
	return nil
}

// fileForLabel maps a bundle environment label to an env file path.
func fileForLabel(label string) string {
	lower := strings.ToLower(label)
	switch lower {
	case "", "default":
		return ".env"
	default:
		return ".env." + lower
	}
}
