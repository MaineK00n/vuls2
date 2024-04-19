package report

import (
	"github.com/spf13/cobra"

	cmdEdit "github.com/MaineK00n/vuls2/pkg/cmd/config/report/edit"
	cmdTest "github.com/MaineK00n/vuls2/pkg/cmd/config/report/test"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Vuls Report Config Operation",
	}

	cmd.AddCommand(
		cmdEdit.NewCmd(),
		cmdTest.NewCmd(),
	)

	return cmd
}
