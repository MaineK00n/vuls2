package db

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/override"
	diffdb "github.com/MaineK00n/vuls2/pkg/diff/db"
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
	cmd := &cobra.Command{
		Use:   "db <baseline-db> <target-db>",
		Short: "compare detection data directly between two vuls DBs",
		Example: heredoc.Doc(`
		# fail when any ecosystem drifts more than 10%
		$ vuls diff db ./baseline.db ./target.db --change-rate-threshold 10

		# relax ubuntu:26.04 (new-distro churn) and fedora:45 individually,
		# keep every other ecosystem at the 10% default
		$ vuls diff db ./baseline.db ./target.db \
		    --change-rate-threshold 10 \
		    --change-rate-threshold-override ubuntu:26.04=25 \
		    --change-rate-threshold-override fedora:45=15

		# comma-separated form is equivalent
		$ vuls diff db ./baseline.db ./target.db \
		    --change-rate-threshold 10 \
		    --change-rate-threshold-override 'ubuntu:26.04=25,fedora:45=15'
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			overrides, err := override.Parse(options.changeRateThresholdOverrides)
			if err != nil {
				return errors.Wrap(err, "parse change-rate-threshold-override")
			}
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
