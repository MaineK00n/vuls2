package detect

import (
	"github.com/spf13/cobra"

	cmdEdit "github.com/MaineK00n/vuls2/pkg/cmd/config/detect/edit"
	cmdTest "github.com/MaineK00n/vuls2/pkg/cmd/config/detect/test"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Vuls Detect Config Operation",
	}

	cmd.AddCommand(
		cmdEdit.NewCmd(),
		cmdTest.NewCmd(),
	)

	return cmd
}
