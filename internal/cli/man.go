package cli

import (
	"bytes"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// newManCmd prints the roff(7) man page for envseal to stdout. Redirect to a
// file for install:   envseal man > docs/envseal.1
func newManCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "man",
		Short: "Print the envseal man page (roff) to stdout",
		Long:  `Print the generated man page for envseal to stdout.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			header := &doc.GenManHeader{
				Title:   "ENVSEAL",
				Section: "1",
			}
			buf := new(bytes.Buffer)
			if err := doc.GenMan(rootCmd, header, buf); err != nil {
				return err
			}
			_, err := os.Stdout.Write(buf.Bytes())
			return err
		},
	}
}
