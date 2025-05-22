package search

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	utilflag "github.com/MaineK00n/vuls2/pkg/cmd/util/flag"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	db "github.com/MaineK00n/vuls2/pkg/db/search"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search",
		Short: "search in vuls db",
	}

	cmd.AddCommand(
		newRootCmd(),
		newAdvisoryCmd(),
		newVulnerabilityCmd(),
		newPackageCmd(),
		newMetadataCmd(),
		newDataSourcesCmd(),
		newEcosystemsCmd(),
	)

	return cmd
}

func newRootCmd() *cobra.Command {
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
		Use:   "root <Root ID>...",
		Short: "search data in vuls db by root id",
		Example: heredoc.Doc(`
		$ vuls db search data root AVG-1
		$ vuls db search data root CVE-2016-6352
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search(dbTypes.SearchRoot, args, db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
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

func newAdvisoryCmd() *cobra.Command {
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
		Use:   "advisory <Advisory ID>...",
		Short: "search data in vuls db by advisory id",
		Example: heredoc.Doc(`
		$ vuls db search advisory AVG-1
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search(dbTypes.SearchAdvisory, args, db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
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

func newVulnerabilityCmd() *cobra.Command {
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
		Use:   "vulnerability <Vulnerability ID>...",
		Short: "search data in vuls db by vulnerability id",
		Example: heredoc.Doc(`
		$ vuls db search vulnerability CVE-2016-6352
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search(dbTypes.SearchVulnerability, args, db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
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

func newPackageCmd() *cobra.Command {
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
		Use:   "package <Ecosystem> <Package Name>...",
		Short: "search data in vuls db by ecosystem and package names",
		Example: heredoc.Doc(`
		$ vuls db search package redhat:9 kernel
		`),
		Args: cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Search(dbTypes.SearchPackage, args, db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
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

func newMetadataCmd() *cobra.Command {
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
		Use:   "metadata",
		Short: "search metadata in vuls db",
		Example: heredoc.Doc(`
		$ vuls db search metadata
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := db.Search(dbTypes.SearchMetadata, nil, db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
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

func newDataSourcesCmd() *cobra.Command {
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
		Use:   "datasources",
		Short: "search datasources in vuls db",
		Example: heredoc.Doc(`
		$ vuls db search datasources
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := db.Search(dbTypes.SearchDataSources, nil, db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
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

func newEcosystemsCmd() *cobra.Command {
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
		Use:   "ecosystems",
		Short: "search ecosystems in vuls db",
		Example: heredoc.Doc(`
		$ vuls db search ecosystems
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := db.Search(dbTypes.SearchEcosystems, nil, db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
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
