package diff

import (
	"github.com/spf13/cobra"

	dbCmd "github.com/MaineK00n/vuls2/pkg/cmd/diff/db"
	detectionCmd "github.com/MaineK00n/vuls2/pkg/cmd/diff/detection"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "compare vuls detection results or DB contents between two versions",
	}

	cmd.AddCommand(
		dbCmd.NewCmd(),
		detectionCmd.NewCmd(),
	)

	return cmd
}
