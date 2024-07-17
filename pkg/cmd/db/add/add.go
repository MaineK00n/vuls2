package add

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	db "github.com/MaineK00n/vuls2/pkg/db/add"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	options := struct {
		dbtype string
		dbpath string
		debug  bool
	}{
		dbtype: "boltdb",
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		debug:  false,
	}

	cmd := &cobra.Command{
		Use:   "add <extracted repository>",
		Short: "add data to vuls db",
		Example: heredoc.Doc(`
		$ vuls db add vuls-data-extracted-arch
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Add(args[0], db.WithDBType(options.dbtype), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db add")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dbtype, "dbtype", "", options.dbtype, "vuls db type (default: boltdb, accepts: [boltdb, redis, sqlite3])")
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
