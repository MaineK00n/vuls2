package db

import (
	"github.com/spf13/cobra"

	addCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/add"
	fetchCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/fetch"
	initCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/init"
	removeCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/remove"
	searchCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/search"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Vuls DB Operation",
	}

	cmd.AddCommand(
		fetchCmd.NewCmd(),
		initCmd.NewCmd(),
		addCmd.NewCmd(),
		removeCmd.NewCmd(),
		searchCmd.NewCmd(),
	)

	return cmd
}
