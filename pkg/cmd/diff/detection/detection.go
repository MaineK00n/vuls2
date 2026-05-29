package detection

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/override"
	diffdetection "github.com/MaineK00n/vuls2/pkg/diff/detection"
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
		Use:   "detection <scan-results-dir> <baseline-db> <baseline-vuls0-binary> <target-db> <target-vuls0-binary>",
		Short: "compare detection results between baseline and target (binary, DB) pairs",
		Example: heredoc.Doc(`
		# fail when any scan-result file drifts more than 5%
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --change-rate-threshold 5

		# relax debian_13 (new CVEs landed) without weakening the default
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --change-rate-threshold 5 \
		    --change-rate-threshold-override debian_13=8

		# repeated and comma-separated forms are interchangeable
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --change-rate-threshold 5 \
		    --change-rate-threshold-override 'debian_13=8,ubuntu_2604=12'
		`),
		Args: cobra.ExactArgs(5),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			for i := range args {
				abs, err := filepath.Abs(args[i])
				if err != nil {
					return errors.Wrapf(err, "abs path. arg: %q", args[i])
				}
				args[i] = abs
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			overrides, err := override.Parse(options.changeRateThresholdOverrides)
			if err != nil {
				return errors.Wrap(err, "parse change-rate-threshold-override")
			}
			return diffdetection.Diff(
				args[0], args[1], args[2], args[3], args[4],
				diffdetection.WithChangeRateThreshold(options.changeRateThreshold),
				diffdetection.WithChangeRateThresholdOverrides(overrides),
				diffdetection.WithDebug(options.debug),
			)
		},
	}

	cmd.Flags().Float64Var(&options.changeRateThreshold, "change-rate-threshold", options.changeRateThreshold, "change rate (%) threshold per scan result file; exit non-zero if exceeded")
	cmd.Flags().StringSliceVar(&options.changeRateThresholdOverrides, "change-rate-threshold-override", nil,
		"per-file override of the threshold; format: <file-basename>=<rate> (repeatable; comma-separated entries also accepted)")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
