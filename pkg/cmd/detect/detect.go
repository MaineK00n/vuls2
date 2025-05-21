package detect

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	utilflag "github.com/MaineK00n/vuls2/pkg/cmd/util/flag"
	"github.com/MaineK00n/vuls2/pkg/detect"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	options := struct {
		resultsDir string
		dbtype     utilflag.DBType
		dbpath     string
		debug      bool
	}{
		resultsDir: filepath.Join(utilos.UserCacheDir(), "results"),
		dbtype:     utilflag.DBTypeBoltDB,
		dbpath:     filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		debug:      false,
	}

	cmd := &cobra.Command{
		Use:   "detect [<UUID>]...",
		Short: "detect vulnerabilities",
		Example: heredoc.Doc(`
		$ vuls scan results
		`),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := detect.Detect(args, detect.WithResultsDir(options.resultsDir), detect.WithDBType(options.dbtype.String()), detect.WithDBPath(options.dbpath), detect.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "detect")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.resultsDir, "results-dir", "", options.resultsDir, "vuls results path")
	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, redis, sqlite3, mysql, postgres])")
	_ = cmd.RegisterFlagCompletionFunc("dbtype", utilflag.DBTypeCompletion)
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
