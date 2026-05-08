package db

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/override"
	diffdb "github.com/MaineK00n/vuls2/pkg/db/diff/db"
)

func NewCmd() *cobra.Command {
	options := struct {
		changeRateThreshold          float64
		changeRateThresholdOverrides []string
		debug                        bool
	}{
		changeRateThreshold: 0,
		debug:               false,
	}
	// Parsed in PreRunE so a malformed --change-rate-threshold-override aborts
	// before opening any DB; RunE reads it back via this closure.
	var overrides map[string]float64

	cmd := &cobra.Command{
		Use:   "db <baseline-db> <target-db>",
		Short: "compare detection data directly between two vuls DBs",
		Args:  cobra.ExactArgs(2),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			m, err := override.Parse(options.changeRateThresholdOverrides)
			if err != nil {
				return errors.Wrap(err, "parse change-rate-threshold-override")
			}
			overrides = m
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			return diffdb.DiffBoltDB(
				args[0], args[1],
				diffdb.WithChangeRateThreshold(options.changeRateThreshold),
				diffdb.WithChangeRateThresholdOverrides(overrides),
				diffdb.WithDebug(options.debug),
			)
		},
	}

	cmd.Flags().Float64Var(&options.changeRateThreshold, "change-rate-threshold", options.changeRateThreshold, "change rate (%) threshold per ecosystem; exit non-zero if exceeded")
	cmd.Flags().StringSliceVar(&options.changeRateThresholdOverrides, "change-rate-threshold-override", nil,
		"per-ecosystem override of the threshold; format: <ecosystem>=<rate> (repeatable; comma-separated entries also accepted)")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
