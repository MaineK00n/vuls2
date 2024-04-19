package config

import (
	"github.com/spf13/cobra"

	cmdDetect "github.com/MaineK00n/vuls2/pkg/cmd/config/detect"
	cmdHost "github.com/MaineK00n/vuls2/pkg/cmd/config/host"
	cmdInit "github.com/MaineK00n/vuls2/pkg/cmd/config/init"
	cmdReport "github.com/MaineK00n/vuls2/pkg/cmd/config/report"
	cmdScan "github.com/MaineK00n/vuls2/pkg/cmd/config/scan"
	cmdServer "github.com/MaineK00n/vuls2/pkg/cmd/config/server"
)

func NewCmdConfig() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Vuls Config Operation",
	}

	cmd.AddCommand(
		cmdInit.NewCmd(),
		cmdScan.NewCmd(),
		cmdDetect.NewCmd(),
		cmdReport.NewCmd(),
		cmdServer.NewCmd(),
		cmdHost.NewCmd(),
	)

	return cmd
}
