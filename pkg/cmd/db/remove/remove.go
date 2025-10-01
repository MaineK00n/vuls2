package remove

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	utilflag "github.com/MaineK00n/vuls2/pkg/cmd/util/flag"
	db "github.com/MaineK00n/vuls2/pkg/db/remove"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	options := struct {
		dbtype utilflag.DBType
		dbpath string
		debug  bool
	}{
		dbtype: utilflag.DBTypeBoltDB,
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		debug:  false,
	}

	cmd := &cobra.Command{
		Use:   "remove <datasource id>",
		Short: "remove data source from vuls db",
		Example: heredoc.Doc(`
		$ vuls db remove redhat-vex
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Remove(args[0], db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db remove")
			}
			return nil
		},
	}

	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, redis, sqlite3, mysql, postgres])")
	_ = cmd.RegisterFlagCompletionFunc("dbtype", utilflag.DBTypeCompletion)
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
