package db

import (
	"github.com/spf13/cobra"

	diffdb "github.com/MaineK00n/vuls2/pkg/db/diff/db"
)

func NewCmd() *cobra.Command {
	options := struct {
		changeRateThreshold float64
		debug               bool
	}{
		changeRateThreshold: 0,
		debug:               false,
	}

	cmd := &cobra.Command{
		Use:   "db <baseline-db> <target-db>",
		Short: "compare detection data directly between two vuls DBs",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return diffdb.DiffBoltDB(
				args[0], args[1],
				diffdb.WithChangeRateThreshold(options.changeRateThreshold),
				diffdb.WithDebug(options.debug),
			)
		},
	}

	cmd.Flags().Float64Var(&options.changeRateThreshold, "change-rate-threshold", options.changeRateThreshold, "change rate (%) threshold per ecosystem; exit non-zero if exceeded")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
