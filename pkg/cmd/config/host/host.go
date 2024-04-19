package host

import (
	"github.com/spf13/cobra"

	cmdAdd "github.com/MaineK00n/vuls2/pkg/cmd/config/host/add"
	cmdEdit "github.com/MaineK00n/vuls2/pkg/cmd/config/host/edit"
	cmdRemove "github.com/MaineK00n/vuls2/pkg/cmd/config/host/remove"
	cmdShow "github.com/MaineK00n/vuls2/pkg/cmd/config/host/show"
	cmdTest "github.com/MaineK00n/vuls2/pkg/cmd/config/host/test"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Vuls Host Config Operation",
	}

	cmd.AddCommand(
		cmdAdd.NewCmd(),
		cmdEdit.NewCmd(),
		cmdRemove.NewCmd(),
		cmdShow.NewCmd(),
		cmdTest.NewCmd(),
	)

	return cmd
}
