package scan

import (
	"github.com/spf13/cobra"

	cmdEdit "github.com/MaineK00n/vuls2/pkg/cmd/config/scan/edit"
	cmdTest "github.com/MaineK00n/vuls2/pkg/cmd/config/scan/test"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Vuls Scan Config Operation",
	}

	cmd.AddCommand(
		cmdEdit.NewCmd(),
		cmdTest.NewCmd(),
	)

	return cmd
}
