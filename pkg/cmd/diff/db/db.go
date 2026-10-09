package db

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/thresholdflag"
	diffdb "github.com/MaineK00n/vuls2/pkg/diff/db"
)

func NewCmd() *cobra.Command {
	options := struct {
		thresholds *thresholdflag.Flags
		debug      bool
	}{
		debug: false,
	}
	cmd := &cobra.Command{
		Use:   "db <baseline-db> <target-db>",
		Short: "compare detection data directly between two vuls DBs",
		Example: heredoc.Doc(`
		# defaults: fail when any data source in any ecosystem adds more than
		# 30%, or changes or removes more than 10%, of its units
		$ vuls diff db ./baseline.db ./target.db

		# tighten removals for every (ecosystem, source) pair; axes not
		# named keep their default
		$ vuls diff db ./baseline.db ./target.db --rate-threshold removed:5

		# set every axis explicitly (comma-separated or repeated)
		$ vuls diff db ./baseline.db ./target.db --rate-threshold added:50,changed:10,removed:5

		# relax additions for ubuntu:26.04 (new-distro backfill) and removals
		# for a single source; <ecosystem>/<source> takes precedence over
		# <ecosystem>, and each override touches only the axis it names
		$ vuls diff db ./baseline.db ./target.db \
		    --rate-threshold-override ubuntu:26.04=added:80 \
		    --rate-threshold-override cpe/cisco-json=removed:25

		# comma-separated form is equivalent
		$ vuls diff db ./baseline.db ./target.db \
		    --rate-threshold-override 'ubuntu:26.04=added:80,cpe/cisco-json=removed:25'

		# legacy single-threshold form (deprecated): one value applied to
		# added, changed and removed alike; cannot be mixed with the flags above
		$ vuls diff db ./baseline.db ./target.db --change-rate-threshold 10
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := options.thresholds.Config(cmd.Flags())
			if err != nil {
				return errors.Wrap(err, "resolve thresholds")
			}
			return diffdb.DiffBoltDB(
				args[0], args[1],
				diffdb.WithThresholds(cfg),
				diffdb.WithDebug(options.debug),
			)
		},
	}

	options.thresholds = thresholdflag.Register(cmd.Flags(), diffdb.Axes, diffdb.Defaults, "(ecosystem, data source)", "<ecosystem> (all sources in the ecosystem, e.g. ubuntu:26.04) or <ecosystem>/<source> (single source, e.g. cpe/cisco-json, wins over the ecosystem key)")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
