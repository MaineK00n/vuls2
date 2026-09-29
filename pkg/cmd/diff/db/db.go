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
		changeRateThresholdZ         float64
		debug                        bool
	}{
		changeRateThreshold:  0,
		changeRateThresholdZ: 0,
		debug:                false,
	}
	cmd := &cobra.Command{
		Use:   "db <baseline-db> <target-db>",
		Short: "compare detection data directly between two vuls DBs",
		Example: heredoc.Doc(`
		# fail when any data source in any ecosystem drifts more than 10%
		$ vuls diff db ./baseline.db ./target.db --change-rate-threshold 10

		# judge each rate against the threshold widened by 2 standard
		# deviations of the change count expected at it (small baselines get
		# absolute slack of a few units; large ones converge to the bare
		# threshold)
		$ vuls diff db ./baseline.db ./target.db \
		    --change-rate-threshold 10 \
		    --change-rate-threshold-z 2

		# relax ubuntu:26.04 (new-distro churn) and fedora:45 individually,
		# keep every other ecosystem at the 10% default
		$ vuls diff db ./baseline.db ./target.db \
		    --change-rate-threshold 10 \
		    --change-rate-threshold-override ubuntu:26.04=25 \
		    --change-rate-threshold-override fedora:45=15

		# relax a single data source within an ecosystem;
		# <ecosystem>/<source> takes precedence over <ecosystem>
		$ vuls diff db ./baseline.db ./target.db \
		    --change-rate-threshold 10 \
		    --change-rate-threshold-override cpe/cisco-json=30

		# comma-separated form is equivalent
		$ vuls diff db ./baseline.db ./target.db \
		    --change-rate-threshold 10 \
		    --change-rate-threshold-override 'ubuntu:26.04=25,fedora:45=15'
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if options.changeRateThresholdZ < 0 {
				return errors.Errorf("change-rate-threshold-z must be non-negative, got %g", options.changeRateThresholdZ)
			}
			overrides, err := override.Parse(options.changeRateThresholdOverrides)
			if err != nil {
				return errors.Wrap(err, "parse change-rate-threshold-override")
			}
			return diffdb.DiffBoltDB(
				args[0], args[1],
				diffdb.WithChangeRateThreshold(options.changeRateThreshold),
				diffdb.WithChangeRateThresholdOverrides(overrides),
				diffdb.WithChangeRateThresholdZ(options.changeRateThresholdZ),
				diffdb.WithDebug(options.debug),
			)
		},
	}

	cmd.Flags().Float64Var(&options.changeRateThreshold, "change-rate-threshold", options.changeRateThreshold, "change rate (%) threshold per (ecosystem, data source); exit non-zero if exceeded")
	cmd.Flags().Float64Var(&options.changeRateThresholdZ, "change-rate-threshold-z", options.changeRateThresholdZ,
		"statistical slack multiplier z: judge each rate against threshold + z*10*sqrt(threshold/baseline units), i.e. z standard deviations of the change count expected at the threshold; 0 disables")
	cmd.Flags().StringSliceVar(&options.changeRateThresholdOverrides, "change-rate-threshold-override", nil,
		"override of the threshold; format: <ecosystem>=<rate> (all sources in the ecosystem) or <ecosystem>/<source>=<rate> (single source, wins over the ecosystem key) (repeatable; comma-separated entries also accepted)")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
