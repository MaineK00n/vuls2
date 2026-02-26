package search

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	utilflag "github.com/MaineK00n/vuls2/pkg/cmd/util/flag"
	db "github.com/MaineK00n/vuls2/pkg/db/search"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
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

type filterOptions struct {
	contents    []dbTypes.FilterContentType
	datasources []string
	ecosystems  []string
	rootIDs     []string
}

func newRootCmd() *cobra.Command {
	options := struct {
		dbtype     utilflag.DBType
		dbpath     string
		filterOpts filterOptions
		debug      bool
	}{
		dbtype: utilflag.DBTypeBoltDB,
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		filterOpts: filterOptions{
			contents: dbTypes.AllFilterContentTypes(),
		},
		debug: false,
	}

	cmd := &cobra.Command{
		Use:   "root <Root ID>...",
		Short: "search data in vuls db by root id",
		Example: heredoc.Doc(`
		$ vuls db search root AVG-1
		$ vuls db search root CVE-2016-6352
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			as := make([]dataTypes.RootID, 0, len(args))
			for _, a := range args {
				as = append(as, dataTypes.RootID(a))
			}
			if err := db.SearchRoot(as, db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithFilter(options.filterOpts.buildFilter()), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
			}
			return nil
		},
	}

	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, pebble, redis, sqlite3, mysql, postgres])")
	_ = cmd.RegisterFlagCompletionFunc("dbtype", utilflag.DBTypeCompletion)
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")

	cmd.Flags().VarP(newContentSliceValue(options.filterOpts.contents, &options.filterOpts.contents), "content", "", "types of content to include")
	_ = cmd.RegisterFlagCompletionFunc("content", cobra.FixedCompletions(allFilterContentCandidates(), cobra.ShellCompDirectiveNoFileComp))
	cmd.Flags().StringSliceVarP(&options.filterOpts.datasources, "datasource", "", options.filterOpts.datasources, "filter by datasource (e.g., redhat-vex, ubuntu-cve-tracker)")
	cmd.Flags().StringSliceVarP(&options.filterOpts.ecosystems, "ecosystem", "", options.filterOpts.ecosystems, "filter by ecosystem (e.g., redhat:9, ubuntu:24.04)")
	cmd.Flags().StringSliceVarP(&options.filterOpts.rootIDs, "root-id", "", options.filterOpts.rootIDs, "filter by root ID (e.g., ELSA-2024-2881, CVE-2024-4367)")

	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}

func newAdvisoryCmd() *cobra.Command {
	options := struct {
		dbtype     utilflag.DBType
		dbpath     string
		filterOpts filterOptions
		debug      bool
	}{
		dbtype: utilflag.DBTypeBoltDB,
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		filterOpts: filterOptions{
			contents: dbTypes.AllFilterContentTypes(),
		},
		debug: false,
	}

	cmd := &cobra.Command{
		Use:   "advisory <Advisory ID>...",
		Short: "search data in vuls db by advisory id",
		Example: heredoc.Doc(`
		$ vuls db search advisory AVG-1
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			as := make([]advisoryContentTypes.AdvisoryID, 0, len(args))
			for _, a := range args {
				as = append(as, advisoryContentTypes.AdvisoryID(a))
			}
			if err := db.SearchAdisory(as, db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithFilter(options.filterOpts.buildFilter()), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
			}
			return nil
		},
	}

	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, pebble, redis, sqlite3, mysql, postgres])")
	_ = cmd.RegisterFlagCompletionFunc("dbtype", utilflag.DBTypeCompletion)
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")

	cmd.Flags().VarP(newContentSliceValue(options.filterOpts.contents, &options.filterOpts.contents), "content", "", "types of content to include")
	_ = cmd.RegisterFlagCompletionFunc("content", cobra.FixedCompletions(allFilterContentCandidates(), cobra.ShellCompDirectiveNoFileComp))
	cmd.Flags().StringSliceVarP(&options.filterOpts.datasources, "datasource", "", options.filterOpts.datasources, "filter by datasource (e.g., redhat-vex, ubuntu-cve-tracker)")
	cmd.Flags().StringSliceVarP(&options.filterOpts.ecosystems, "ecosystem", "", options.filterOpts.ecosystems, "filter by ecosystem (e.g., redhat:9, ubuntu:24.04)")
	cmd.Flags().StringSliceVarP(&options.filterOpts.rootIDs, "root-id", "", options.filterOpts.rootIDs, "filter by root ID (e.g., ELSA-2024-2881, CVE-2024-4367)")

	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}

func newVulnerabilityCmd() *cobra.Command {
	options := struct {
		dbtype     utilflag.DBType
		dbpath     string
		filterOpts filterOptions
		debug      bool
	}{
		dbtype: utilflag.DBTypeBoltDB,
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		filterOpts: filterOptions{
			contents: dbTypes.AllFilterContentTypes(),
		},
		debug: false,
	}

	cmd := &cobra.Command{
		Use:   "vulnerability <Vulnerability ID>...",
		Short: "search data in vuls db by vulnerability id",
		Example: heredoc.Doc(`
		$ vuls db search vulnerability CVE-2016-6352
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			as := make([]vulnerabilityContentTypes.VulnerabilityID, 0, len(args))
			for _, a := range args {
				as = append(as, vulnerabilityContentTypes.VulnerabilityID(a))
			}
			if err := db.SearchVulnerability(as, db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithFilter(options.filterOpts.buildFilter()), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
			}
			return nil
		},
	}

	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, pebble, redis, sqlite3, mysql, postgres])")
	_ = cmd.RegisterFlagCompletionFunc("dbtype", utilflag.DBTypeCompletion)
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")

	cmd.Flags().VarP(newContentSliceValue(options.filterOpts.contents, &options.filterOpts.contents), "content", "", "types of content to include")
	_ = cmd.RegisterFlagCompletionFunc("content", cobra.FixedCompletions(allFilterContentCandidates(), cobra.ShellCompDirectiveNoFileComp))
	cmd.Flags().StringSliceVarP(&options.filterOpts.datasources, "datasource", "", options.filterOpts.datasources, "filter by datasource (e.g., redhat-vex, ubuntu-cve-tracker)")
	cmd.Flags().StringSliceVarP(&options.filterOpts.ecosystems, "ecosystem", "", options.filterOpts.ecosystems, "filter by ecosystem (e.g., redhat:9, ubuntu:24.04)")
	cmd.Flags().StringSliceVarP(&options.filterOpts.rootIDs, "root-id", "", options.filterOpts.rootIDs, "filter by root ID (e.g., ELSA-2024-2881, CVE-2024-4367)")

	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}

func newPackageCmd() *cobra.Command {
	options := struct {
		dbtype     utilflag.DBType
		dbpath     string
		filterOpts filterOptions
		debug      bool
	}{
		dbtype: utilflag.DBTypeBoltDB,
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		filterOpts: filterOptions{
			contents: dbTypes.AllFilterContentTypes(),
		},
		debug: false,
	}

	cmd := &cobra.Command{
		Use:   "package <Ecosystem> <Package Name>...",
		Short: "search data in vuls db by ecosystem and package names",
		Example: heredoc.Doc(`
		$ vuls db search package redhat:9 kernel
		`),
		Args: cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.SearchPackage(ecosystemTypes.Ecosystem(args[0]), args[1:], db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug), db.WithFilter(options.filterOpts.buildFilter())); err != nil {
				return errors.Wrap(err, "db search")
			}
			return nil
		},
	}

	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, pebble, redis, sqlite3, mysql, postgres])")
	_ = cmd.RegisterFlagCompletionFunc("dbtype", utilflag.DBTypeCompletion)
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")

	cmd.Flags().VarP(newContentSliceValue(options.filterOpts.contents, &options.filterOpts.contents), "content", "", "types of content to include")
	_ = cmd.RegisterFlagCompletionFunc("content", cobra.FixedCompletions(allFilterContentCandidates(), cobra.ShellCompDirectiveNoFileComp))
	cmd.Flags().StringSliceVarP(&options.filterOpts.datasources, "datasource", "", options.filterOpts.datasources, "filter by datasource (e.g., redhat-vex, ubuntu-cve-tracker)")
	cmd.Flags().StringSliceVarP(&options.filterOpts.ecosystems, "ecosystem", "", options.filterOpts.ecosystems, "filter by ecosystem (e.g., redhat:9, ubuntu:24.04)")
	cmd.Flags().StringSliceVarP(&options.filterOpts.rootIDs, "root-id", "", options.filterOpts.rootIDs, "filter by root ID (e.g., ELSA-2024-2881, CVE-2024-4367)")

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
			if err := db.SearchMetadata(db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
			}
			return nil
		},
	}

	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, pebble, redis, sqlite3, mysql, postgres])")
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
			if err := db.SearchDataSources(db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
			}
			return nil
		},
	}

	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, pebble, redis, sqlite3, mysql, postgres])")
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
			if err := db.SearchEcosystems(db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db search")
			}
			return nil
		},
	}

	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, pebble, redis, sqlite3, mysql, postgres])")
	_ = cmd.RegisterFlagCompletionFunc("dbtype", utilflag.DBTypeCompletion)
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}

func allFilterContentCandidates() []string {
	ss := make([]string, 0, len(dbTypes.AllFilterContentTypes()))
	for _, v := range dbTypes.AllFilterContentTypes() {
		ss = append(ss, v.String())
	}
	return ss
}

func (o filterOptions) buildFilter() dbTypes.Filter {
	return dbTypes.Filter{
		Contents: o.contents,
		DataSources: func() []sourceTypes.SourceID {
			ds := make([]sourceTypes.SourceID, 0, len(o.datasources))
			for _, d := range o.datasources {
				ds = append(ds, sourceTypes.SourceID(d))
			}
			return ds
		}(),
		Ecosystems: func() []ecosystemTypes.Ecosystem {
			es := make([]ecosystemTypes.Ecosystem, 0, len(o.ecosystems))
			for _, e := range o.ecosystems {
				es = append(es, ecosystemTypes.Ecosystem(e))
			}
			return es
		}(),
		RootIDs: func() []dataTypes.RootID {
			rs := make([]dataTypes.RootID, 0, len(o.rootIDs))
			for _, r := range o.rootIDs {
				rs = append(rs, dataTypes.RootID(r))
			}
			return rs
		}(),
	}
}
