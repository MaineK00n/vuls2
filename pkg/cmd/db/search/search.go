package search

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	db "github.com/MaineK00n/vuls2/pkg/db/search"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search",
		Short: "search in vuls db",
	}

	cmd.AddCommand(
		newDataCmd(),
		newDetectionCmd(),
	)

	return cmd
}

func newDataCmd() *cobra.Command {
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
		Use:   "data <Root ID>",
		Short: "search data in vuls db",
		Example: heredoc.Doc(`
		$ vuls db search data AVG-1
		$ vuls db search data CVE-2016-6352
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search("data", args, db.WithDBType(options.dbtype), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dbtype, "dbtype", "", options.dbtype, "vuls db type (default: boltdb, accepts: [boltdb, redis, sqlite3])")
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}

func newDetectionCmd() *cobra.Command {
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
		Use:   "detection <Ecosystem> <Package name | CPE>",
		Short: "search data in vuls db",
		Example: heredoc.Doc(`
		$ vuls db search detection arch bash
		$ vuls db search detection nvd linux:linux
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search("detection", args, db.WithDBType(options.dbtype), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dbtype, "dbtype", "", options.dbtype, "vuls db type (default: boltdb, accepts: [boltdb, redis, sqlite3])")
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
