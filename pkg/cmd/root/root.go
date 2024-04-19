package root

import (
	"github.com/spf13/cobra"

	configCmd "github.com/MaineK00n/vuls2/pkg/cmd/config"
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

	cmd.AddCommand(configCmd.NewCmdConfig())
	// cmd.AddCommand(dbCmd.NewCmdDB())
	// cmd.AddCommand(scanCmd.NewCmdScan())
	// cmd.AddCommand(detectCmd.NewCmdDetect())
	// cmd.AddCommand(reportCmd.NewCmdReport())
	// cmd.AddCommand(serverCmd.NewCmdServer())
	cmd.AddCommand(versionCmd.NewCmdVersion())

	return cmd
}
