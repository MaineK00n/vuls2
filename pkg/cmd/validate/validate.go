package validate

import (
	"github.com/spf13/cobra"

	dataCmd "github.com/MaineK00n/vuls2/pkg/cmd/validate/data"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Vuls Extracted Data Validation",
	}

	cmd.AddCommand(
		dataCmd.NewCmd(),
	)

	return cmd
}
