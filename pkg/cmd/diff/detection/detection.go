package detection

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/thresholdflag"
	diffdetection "github.com/MaineK00n/vuls2/pkg/diff/detection"
)

func NewCmd() *cobra.Command {
	options := struct {
		thresholds *thresholdflag.Flags
		debug      bool
	}{
		debug: false,
	}

	cmd := &cobra.Command{
		Use:   "detection <scan-results-dir> <baseline-db> <baseline-vuls0-binary> <target-db> <target-vuls0-binary>",
		Short: "compare detection results between baseline and target (binary, DB) pairs",
		Example: heredoc.Doc(`
		# defaults: fail when any data source in any scan-result file gains
		# more than 30%, or loses more than 5%, of its CVEs
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0

		# tighten removals for every (file, source) pair
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --removed-rate-threshold 1

		# relax additions for debian_13 (new CVEs landing) without weakening
		# the removal default
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --rate-threshold-override debian_13=added:50

		# relax removals for a single data source within a file;
		# <file>/<source> takes precedence over <file>
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --rate-threshold-override cpe_jvn/jvn-feed-rss=removed:25

		# repeated and comma-separated forms are interchangeable
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --rate-threshold-override 'debian_13=added:50,cpe_jvn/jvn-feed-rss=removed:25'

		# legacy single-threshold form (deprecated): one value applied to
		# added and removed alike; cannot be mixed with the flags above
		$ vuls diff detection \
		    ./scan-results \
		    ./baseline.db ./vuls0 \
		    ./target.db ./vuls0 \
		    --change-rate-threshold 5
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
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := options.thresholds.Config(cmd.Flags())
			if err != nil {
				return errors.Wrap(err, "resolve thresholds")
			}
			return diffdetection.Diff(
				args[0], args[1], args[2], args[3], args[4],
				diffdetection.WithThresholds(cfg),
				diffdetection.WithDebug(options.debug),
			)
		},
	}

	options.thresholds = thresholdflag.Register(cmd.Flags(), diffdetection.Axes, diffdetection.Defaults,
		"(scan result file, data source)",
		"<file-basename> (all data sources in the file, e.g. debian_13) or <file-basename>/<source> (single source, e.g. cpe_jvn/jvn-feed-rss, wins over the file key)")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
