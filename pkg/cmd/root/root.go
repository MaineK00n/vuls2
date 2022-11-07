package root

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	configCmd "github.com/MaineK00n/vuls2/pkg/cmd/config"
	dbCmd "github.com/MaineK00n/vuls2/pkg/cmd/db"
	detectCmd "github.com/MaineK00n/vuls2/pkg/cmd/detect"
	reportCmd "github.com/MaineK00n/vuls2/pkg/cmd/report"
	scanCmd "github.com/MaineK00n/vuls2/pkg/cmd/scan"
	serverCmd "github.com/MaineK00n/vuls2/pkg/cmd/server"
	tuiCmd "github.com/MaineK00n/vuls2/pkg/cmd/tui"
	versionCmd "github.com/MaineK00n/vuls2/pkg/cmd/version"
)

func NewCmdRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "vuls <command>",
		Short:         "Vuls",
		Long:          "Vulnerability Scanner: Vuls",
		SilenceErrors: true,
		SilenceUsage:  true,
		Example: heredoc.Doc(`
			$ vuls config init
			$ vuls db fetch
			$ vuls scan
			$ vuls detect
			$ vuls report
			$ vuls tui
		`),
	}

	cmd.AddCommand(configCmd.NewCmdConfig())
	cmd.AddCommand(dbCmd.NewCmdDB())
	cmd.AddCommand(detectCmd.NewCmdDetect())
	cmd.AddCommand(reportCmd.NewCmdReport())
	cmd.AddCommand(scanCmd.NewCmdScan())
	cmd.AddCommand(serverCmd.NewCmdServer())
	cmd.AddCommand(tuiCmd.NewCmdTUI())
	cmd.AddCommand(versionCmd.NewCmdVersion())

	return cmd
}
