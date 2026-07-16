package root

import (
	"github.com/spf13/cobra"

	dataCmd "github.com/MaineK00n/vuls2/pkg/cmd/data"
	dbCmd "github.com/MaineK00n/vuls2/pkg/cmd/db"
	detectCmd "github.com/MaineK00n/vuls2/pkg/cmd/detect"
	diffCmd "github.com/MaineK00n/vuls2/pkg/cmd/diff"
	scanCmd "github.com/MaineK00n/vuls2/pkg/cmd/scan"
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
		dataCmd.NewCmd(),
		scanCmd.NewCmd(),
		detectCmd.NewCmd(),
		diffCmd.NewCmd(),
		// reportCmd.NewCmd(),
		versionCmd.NewCmd(),
	)

	return cmd
}
