package server

import (
	"github.com/spf13/cobra"

	cmdEdit "github.com/MaineK00n/vuls2/pkg/cmd/config/server/edit"
	cmdTest "github.com/MaineK00n/vuls2/pkg/cmd/config/server/test"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Vuls Server Config Operation",
	}

	cmd.AddCommand(
		cmdEdit.NewCmd(),
		cmdTest.NewCmd(),
	)

	return cmd
}
