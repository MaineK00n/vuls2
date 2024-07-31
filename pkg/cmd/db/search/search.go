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
	cmd := &cobra.Command{
		Use:   "data",
		Short: "search data in vuls db",
	}

	cmd.AddCommand(
		newDataRootCmd(),
		newDataAdvisoryCmd(),
		newDataVulnerabilityCmd(),
	)

	return cmd
}

func newDataRootCmd() *cobra.Command {
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
		Use:   "root <Root ID>",
		Short: "search data in vuls db by root id",
		Example: heredoc.Doc(`
		$ vuls db search data root AVG-1
		$ vuls db search data root CVE-2016-6352
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search("data-root", args, db.WithDBType(options.dbtype), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
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

func newDataAdvisoryCmd() *cobra.Command {
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
		Use:   "advisory <Advisory ID>",
		Short: "search data in vuls db by advisory id",
		Example: heredoc.Doc(`
		$ vuls db search data AVG-1
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search("data-advisory", args, db.WithDBType(options.dbtype), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
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

func newDataVulnerabilityCmd() *cobra.Command {
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
		Use:   "vulnerability <Vulnerability ID>",
		Short: "search data in vuls db by vulnerability id",
		Example: heredoc.Doc(`
		$ vuls db search data CVE-2016-6352
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search("data-vulnerability", args, db.WithDBType(options.dbtype), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
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
	cmd := &cobra.Command{
		Use:   "detection",
		Short: "search detection criteria in vuls db",
	}

	cmd.AddCommand(
		newDetectionPkgCmd(),
		newDetectionRootCmd(),
		newDetectionAdvisoryCmd(),
		newDetectionVulnerabilityCmd(),
	)

	return cmd
}

func newDetectionPkgCmd() *cobra.Command {
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
		Use:   "pkg <Ecosystem> <Package name | CPE>",
		Short: "search detection criteria in vuls db by package name or CPE",
		Example: heredoc.Doc(`
		$ vuls db search detection pkg arch bash
		$ vuls db search detection pkg nvd linux:linux
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search("detection-pkg", args, db.WithDBType(options.dbtype), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
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

func newDetectionRootCmd() *cobra.Command {
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
		Use:   "root <Root ID>",
		Short: "search detection criteria in vuls db by root id",
		Example: heredoc.Doc(`
		$ vuls db search detection root AVG-1
		$ vuls db search detection root CVE-2016-6352
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search("detection-root", args, db.WithDBType(options.dbtype), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
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

func newDetectionAdvisoryCmd() *cobra.Command {
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
		Use:   "advisory <Advisory ID>",
		Short: "search detection criteria in vuls db by advisory id",
		Example: heredoc.Doc(`
		$ vuls db search detection advisory AVG-1
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search("detection-advisory", args, db.WithDBType(options.dbtype), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
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

func newDetectionVulnerabilityCmd() *cobra.Command {
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
		Use:   "vulnerability <Vulnerability ID>",
		Short: "search detection criteria in vuls db by vulnerability id",
		Example: heredoc.Doc(`
		$ vuls db search detection vulnerability CVE-2016-6352
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search("detection-vulnerability", args, db.WithDBType(options.dbtype), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
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
