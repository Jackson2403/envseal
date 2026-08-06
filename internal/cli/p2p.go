package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/Jackson2403/envsync/internal/config"
	"github.com/Jackson2403/envsync/internal/crypto"
	"github.com/Jackson2403/envsync/internal/transport"
)

func newP2PCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "p2p",
		Short: "Exchange bundles directly over an encrypted connection",
		Long: `Direct, encrypted machine-to-machine exchange. Use 'envsync p2p
share' to listen for a teammate, then 'envsync p2p sync --addr <host:port>
--code <code>' on the receiving machine. The pairing code cryptographically
pins both ends (TLS certificate derived from the code), so a man-in-the-middle
cannot impersonate the sender without knowing the code.`,
	}
	cmd.AddCommand(newP2PShareCmd(), newP2PSyncCmd())
	return cmd
}

func newP2PShareCmd() *cobra.Command {
	var file, envName, to string
	var port int
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "share",
		Short: "Encrypt an env file and serve it to one recipient over TCP",
		RunE: func(cmd *cobra.Command, args []string) error {
			if to == "" {
				return fmt.Errorf("recipient required via --to <email>")
			}
			cfg, err := config.Load(".")
			if err != nil {
				return err
			}
			recipients, err := resolveRecipients(cfg, []string{to})
			if err != nil {
				return err
			}

			src := file
			if src == "" {
				src = envFileFor(envName)
			}
			plaintext, err := os.ReadFile(src)
			if err != nil {
				return fmt.Errorf("read %q: %w", src, err)
			}
			label := envName
			if label == "" {
				label = "default"
			}
			env, err := crypto.Encrypt(plaintext, label, recipients)
			if err != nil {
				return fmt.Errorf("encrypt: %w", err)
			}
			data, err := env.Encode()
			if err != nil {
				return err
			}

			addr, code, done, err := transport.StartSender(port, func() ([]byte, error) {
				return data, nil
			})
			if err != nil {
				return err
			}

			cyan := color.New(color.FgCyan).SprintFunc()
			fmt.Printf("Listening on %s for %d recipient(s)\n", cyan(addr), len(recipients))
			fmt.Printf("Pairing code: %s\n", cyan(code))
			fmt.Printf("Tell the recipient to run:\n")
			fmt.Printf("  envsync p2p sync --addr %s --code %s\n", addr, code)
			fmt.Println("Waiting for connection... (connection bearer / MITM needs to know the code)")

			select {
			case err := <-done:
				if err != nil {
					return err
				}
			case <-time.After(timeout):
				return fmt.Errorf("timed out waiting for a recipient")
			}

			recordAudit(historyProject(cfg), "share", label, plaintext,
				recipientFingerprints(recipients), "")
			fmt.Printf("Sent %q (%d bytes) to %s\n", src, len(data), to)
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "source env file to share")
	cmd.Flags().StringVar(&envName, "env", "", "environment name (default .env)")
	cmd.Flags().StringVar(&to, "to", "", "recipient email registered via 'envsync team add'")
	cmd.Flags().IntVarP(&port, "port", "p", 0, "port to listen on (0 = random)")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "how long to wait for a recipient")
	return cmd
}

func newP2PSyncCmd() *cobra.Command {
	var addr, code string
	var outPath string
	var merge bool
	var dryRun bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Connect to a sender and pull a decrypted env file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if addr == "" || code == "" {
				return fmt.Errorf("both --addr <host:port> and --code <code> are required")
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

			data, err := transport.Fetch(addr, code, timeout)
			if err != nil {
				return err
			}
			env, err := crypto.DecodeEnvelope(data)
			if err != nil {
				return fmt.Errorf("decode bundle: %w", err)
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

			var fps []string
			for _, s := range env.Recipients {
				fps = append(fps, s.Fingerprint)
			}
			if merge {
				if err := mergeWrite(target, plaintext); err != nil {
					return err
				}
			} else {
				if err := os.WriteFile(target, plaintext, 0o600); err != nil {
					return err
				}
			}
			recordAudit(historyProject(cfg), "sync", label, plaintext, fps, "")
			fmt.Printf("Received and decrypted %d bytes; wrote %s (env=%s)\n",
				len(plaintext), target, strings.ToLower(label))
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "", "sender address, host:port")
	cmd.Flags().StringVar(&code, "code", "", "pairing code printed by the sender")
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "destination env file path")
	cmd.Flags().BoolVar(&merge, "merge", false, "merge into existing env file")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would happen without writing")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "connection timeout")
	return cmd
}
