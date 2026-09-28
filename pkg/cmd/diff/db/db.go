package db

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/outputjson"
	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/override"
	diffdb "github.com/MaineK00n/vuls2/pkg/diff/db"
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
		Use:   "db <baseline-db> <target-db>",
		Short: "compare detection data directly between two vuls DBs",
		Example: heredoc.Doc(`
		# fail when any data source in any ecosystem drifts more than 10%
		$ vuls diff db ./baseline.db ./target.db --change-rate-threshold 10

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

		# also write the Summary table as JSON for CI to consume
		$ vuls diff db ./baseline.db ./target.db \
		    --change-rate-threshold 10 \
		    --output-json ./diff-db.json
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			// Refuse an output path that names an input: Create would
			// truncate it. Usage errors (unparseable flag values, wrong
			// argument count) are rejected by Cobra before RunE, so they
			// never reach the output file at all.
			if err := outputjson.Validate(options.outputJSON, args[0], args[1]); err != nil {
				return err
			}
			if err := override.CheckRate(options.changeRateThreshold); err != nil {
				return errors.Wrapf(err, "unexpected change-rate-threshold %v", options.changeRateThreshold)
			}
			overrides, err := override.Parse(options.changeRateThresholdOverrides)
			if err != nil {
				return errors.Wrap(err, "parse change-rate-threshold-override")
			}

			opts := []diffdb.Option{
				diffdb.WithChangeRateThreshold(options.changeRateThreshold),
				diffdb.WithChangeRateThresholdOverrides(overrides),
				diffdb.WithDebug(options.debug),
			}
			// The summary is streamed straight into the file: a diff that
			// fails before producing one leaves it empty, which is fine
			// because CI gates on the exit status before reading it. What
			// matters is that Create truncated a previous run's rows.
			summaryFile, err := outputjson.Create(options.outputJSON)
			if err != nil {
				return err
			}
			if summaryFile != nil {
				opts = append(opts, diffdb.WithSummaryWriter(summaryFile))
			}

			err = diffdb.DiffBoltDB(args[0], args[1], opts...)
			if summaryFile != nil {
				if cerr := summaryFile.Close(); cerr != nil && err == nil {
					err = errors.Wrapf(cerr, "close %s", options.outputJSON)
				}
			}
			return err
		},
	}

	cmd.Flags().Float64Var(&options.changeRateThreshold, "change-rate-threshold", options.changeRateThreshold, "change rate (%) threshold per (ecosystem, data source); exit non-zero if exceeded")
	cmd.Flags().StringSliceVar(&options.changeRateThresholdOverrides, "change-rate-threshold-override", nil,
		"override of the threshold; format: <ecosystem>=<rate> (all sources in the ecosystem) or <ecosystem>/<source>=<rate> (single source, wins over the ecosystem key) (repeatable; comma-separated entries also accepted)")
	cmd.Flags().StringVar(&options.outputJSON, "output-json", "", "also write the Summary table as JSON to this file (schema_version 1, see pkg/diff/summary); written whether the diff passes or fails; the file is truncated before the diff runs, so a diff that fails early leaves it empty (gate on the exit status before reading it)")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
