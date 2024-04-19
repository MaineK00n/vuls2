package version

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/version"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Fprintln(os.Stdout, version.String())
		},
	}
	return cmd
}
