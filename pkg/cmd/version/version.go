package version

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/version"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := fmt.Fprintln(os.Stdout, version.String()); err != nil {
				return errors.Wrap(err, "version")
			}
			return nil
		},
	}
	return cmd
}
