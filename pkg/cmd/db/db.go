package db

import (
	"github.com/spf13/cobra"

	addCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/add"
	compressCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/compress"
	fetchCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/fetch"
	initCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/init"
	pushCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/push"
	removeCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/remove"
	searchCmd "github.com/MaineK00n/vuls2/pkg/cmd/db/search"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Vuls DB Operation",
	}

	cmd.AddCommand(
		fetchCmd.NewCmd(), compressCmd.NewCmd(), pushCmd.NewCmd(),
		initCmd.NewCmd(), addCmd.NewCmd(), removeCmd.NewCmd(),
		searchCmd.NewCmd(),
	)

	return cmd
}
