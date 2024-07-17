package root

import (
	"github.com/spf13/cobra"

	dbCmd "github.com/MaineK00n/vuls2/pkg/cmd/db"
	versionCmd "github.com/MaineK00n/vuls2/pkg/cmd/version"
)

func NewCmdRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "vuls <command>",
		Short:         "Vulnerability Scanner: Vuls",
		Long:          "Vulnerability Scanner: Vuls",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.AddCommand(
		dbCmd.NewCmd(),
		// detectCmd.NewCmdDetect(),
		// reportCmd.NewCmdReport(),
		versionCmd.NewCmd(),
	)

	return cmd
}
