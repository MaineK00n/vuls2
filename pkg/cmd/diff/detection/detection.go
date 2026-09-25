package detection

import (
	"bytes"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/outputjson"
	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/override"
	diffdetection "github.com/MaineK00n/vuls2/pkg/diff/detection"
)

func NewCmd() *cobra.Command {
	options := struct {
		changeRateThreshold          float64
		changeRateThresholdOverrides []string
		outputJSON                   string
		debug                        bool
	}{
		changeRateThreshold: 0,
		debug:               false,
	}

	cmd := &cobra.Command{
		Use:   "detection <scan-results-dir> <baseline-db> <baseline-vuls0-binary> <target-db> <target-vuls0-binary>",
		Short: "compare detection results between baseline and target (binary, DB) pairs",
		Example: heredoc.Doc(`
		# fail when any data source in any scan-result file drifts more than 5%
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

		# relax a single data source within a file;
		# <file>/<source> takes precedence over <file>
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --change-rate-threshold 5 \
		    --change-rate-threshold-override cpe_jvn/jvn-feed-rss=25

		# repeated and comma-separated forms are interchangeable
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --change-rate-threshold 5 \
		    --change-rate-threshold-override 'debian_13=8,cpe_jvn/jvn-feed-rss=25'

		# also write the Summary table as JSON for CI to consume
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --change-rate-threshold 5 \
		    --output-json ./diff-detection.json
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
			// Drop a previous run's summary before anything can fail, so a
			// malformed flag or an unreadable input never leaves stale rows
			// at --output-json for CI to consume.
			if err := outputjson.Clear(options.outputJSON); err != nil {
				return err
			}

			overrides, err := override.Parse(options.changeRateThresholdOverrides)
			if err != nil {
				return errors.Wrap(err, "parse change-rate-threshold-override")
			}

			opts := []diffdetection.Option{
				diffdetection.WithChangeRateThreshold(options.changeRateThreshold),
				diffdetection.WithChangeRateThresholdOverrides(overrides),
				diffdetection.WithDebug(options.debug),
			}
			var summary bytes.Buffer
			if options.outputJSON != "" {
				opts = append(opts, diffdetection.WithSummaryWriter(&summary))
			}

			err = diffdetection.Diff(args[0], args[1], args[2], args[3], args[4], opts...)
			if werr := outputjson.Write(options.outputJSON, summary.Bytes()); werr != nil {
				return werr
			}
			return err
		},
	}

	cmd.Flags().Float64Var(&options.changeRateThreshold, "change-rate-threshold", options.changeRateThreshold, "change rate (%) threshold per (scan result file, data source); exit non-zero if exceeded")
	cmd.Flags().StringSliceVar(&options.changeRateThresholdOverrides, "change-rate-threshold-override", nil,
		"override of the threshold; format: <file-basename>=<rate> (all data sources in the file) or <file-basename>/<source>=<rate> (single source, e.g. cpe_jvn/jvn-feed-rss, wins over the file key) (repeatable; comma-separated entries also accepted)")
	cmd.Flags().StringVar(&options.outputJSON, "output-json", "", "also write the Summary table as JSON to this file (schema_version 1, see pkg/diff/summary); written whether the diff passes or fails")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
