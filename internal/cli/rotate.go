package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/Jackson2403/envsync/internal/config"
	"github.com/Jackson2403/envsync/internal/crypto"
	"github.com/Jackson2403/envsync/internal/transport"
)

func newRotateCmd() *cobra.Command {
	var bundlePath string
	var to []string
	var outputDir string

	cmd := &cobra.Command{
		Use:   "rotate <bundle>",
		Short: "Re-encrypt a bundle for the current team key set",
		Long: `Decrypt a received bundle with your local key and re-encrypt it for
the current team members. Use this after a member leaves: their public key is
removed from .envsync/team-keys, then run rotate so the departing member can no
longer open future bundles.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if bundlePath == "" && len(args) > 0 {
				bundlePath = args[0]
			}
			if bundlePath == "" {
				return fmt.Errorf("bundle path required")
			}
			if !config.HasIdentity() {
				return requireIdentityErr()
			}

			priv, err := config.LoadIdentityPrivate()
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

			cfg, err := config.Load(".")
			if err != nil {
				return err
			}
			recipients, err := resolveRecipients(cfg, to)
			if err != nil {
				return err
			}
			if len(to) == 0 {
				// Unlike share, reuse resolveRecipients with the full team.
				// resolveRecipients requires at least one address, so load all members.
				recipients, err = allTeamPubKeys(cfg)
				if err != nil {
					return err
				}
			}

			newEnv, err := crypto.Encrypt(plaintext, label, recipients)
			if err != nil {
				return fmt.Errorf("re-encrypt: %w", err)
			}

			outName := transport.OutputName(strings.ToUpper(label)+".reencrypted", outputDir)
			if err := transport.WriteEnvelope(outName, newEnv); err != nil {
				return err
			}

			recordAudit(historyProject(cfg), "rotate", label, plaintext,
				recipientFingerprints(recipients), sha256HexFile(outName))

			fmt.Printf("Rotated %q -> %s for %d member(s)\n", bundlePath, outName, len(recipients))
			fmt.Println("WARNING: any previously distributed bundles for removed members should be discarded.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&bundlePath, "file", "f", "", "path to the bundle to rotate")
	cmd.Flags().StringSliceVarP(&to, "to", "t", nil, "restrict recipients (default: all team members)")
	cmd.Flags().StringVarP(&outputDir, "output", "o", ".", "output directory")
	return cmd
}

// allTeamPubKeys returns the public keys of every registered team member plus
// the operator themselves (so the operator can still open the result).
func allTeamPubKeys(cfg config.Config) ([][]byte, error) {
	members, err := config.ListMembers(cfg.KeysDir())
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("no team members registered; use --to or 'envsync team add'")
	}

	seen := map[string]bool{}
	var pubs [][]byte
	for _, m := range members {
		pub, err := crypto.DecodePublicKey(m.PubKey)
		if err != nil {
			continue
		}
		fp := crypto.Fingerprint(pub)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		pubs = append(pubs, pub)
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("no valid public keys found for team members")
	}

	// Always include the operator so the rotated bundle can be verified locally.
	if config.HasIdentity() {
		myPub, err := config.LoadIdentityPublic()
		if err == nil {
			pub, perr := crypto.DecodePublicKey(strings.TrimSpace(string(myPub)))
			if perr == nil {
				fp := crypto.Fingerprint(pub)
				if !seen[fp] {
					pubs = append(pubs, pub)
				}
			}
		}
	}
	return pubs, nil
}
