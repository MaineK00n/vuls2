package version

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version  string
	revision string
)

func NewCmdVersion() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Fprintf(os.Stdout, "vuls %s %s\n", version, revision)
		},
	}
	return cmd
}
