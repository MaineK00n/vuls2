package detection

import (
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	diffdetection "github.com/MaineK00n/vuls2/pkg/db/diff/detection"
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
		Use:   "detection <scan-results-dir> <baseline-db> <baseline-vuls0-binary> <target-db> <target-vuls0-binary>",
		Short: "compare detection results between baseline and target (binary, DB) pairs",
		Args:  cobra.ExactArgs(5),
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
			return diffdetection.Diff(
				args[0], args[1], args[2], args[3], args[4],
				diffdetection.WithChangeRateThreshold(options.changeRateThreshold),
				diffdetection.WithDebug(options.debug),
			)
		},
	}

	cmd.Flags().Float64Var(&options.changeRateThreshold, "change-rate-threshold", options.changeRateThreshold, "change rate (%) threshold per scan result file; exit non-zero if exceeded")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
