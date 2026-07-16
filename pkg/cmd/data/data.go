package data

import (
	"github.com/spf13/cobra"

	validateCmd "github.com/MaineK00n/vuls2/pkg/cmd/data/validate"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "data",
		Short: "Vuls Extracted Data Operation",
	}

	cmd.AddCommand(
		validateCmd.NewCmd(),
	)

	return cmd
}
