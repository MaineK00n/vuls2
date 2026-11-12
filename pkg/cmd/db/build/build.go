package build

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	utilflag "github.com/MaineK00n/vuls2/pkg/cmd/util/flag"
	db "github.com/MaineK00n/vuls2/pkg/db/build"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	options := struct {
		lock         string
		dbtype       utilflag.DBType
		dbpath       string
		dir          string
		validateOnly bool
		debug        bool
	}{
		dbtype: utilflag.DBTypeBoltDB,
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		debug:  false,
	}

	cmd := &cobra.Command{
		Use:   "build",
		Short: "build vuls db from a lock file",
		Long: heredoc.Doc(`
		Build a vuls db from a lock file: the extracted dotgit of every data
		source, pinned to one commit each.

		  {"branch": "nightly",
		   "registry": "ghcr.io/vulsio/vuls-data-db",
		   "sources": [
		     {"name": "alma-errata", "commit": "<40 hex>"},
		     {"name": "ubuntu-cve-tracker", "commit": "<40 hex>"}
		   ]}

		Sources are built one at a time, in lock order: each is pulled from
		<registry>:vuls-data-extracted-<name> (the .git only), restored at
		its commit (which must belong to the branch), stamped into
		datasource.json, added, and removed before the next one, so one
		dotgit and one tree are on disk at a time. A boltdb is written to a
		scratch file and renamed to --dbpath only after every source has
		been added and verified, so a failed build leaves nothing behind.
		For boltdb, --dbpath must not exist already.
		`),
		Example: heredoc.Doc(`
		$ vuls db build --lock db-nightly.lock.json --dbpath ./vuls.db
		$ vuls db build --lock db-nightly.lock.json --validate-only
		$ jq '.sources |= map(select(.name == "alma-errata"))' db-nightly.lock.json | vuls db build --lock - --dbpath ./mini.db
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := db.Build(options.lock,
				db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath),
				db.WithDir(options.dir),
				db.WithValidateOnly(options.validateOnly), db.WithDebug(options.debug),
			); err != nil {
				return errors.Wrap(err, "db build")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.lock, "lock", "", "", "lock file to build from (\"-\" reads stdin)")
	_ = cmd.MarkFlagRequired("lock")
	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, redis, sqlite3, mysql, postgres])")
	_ = cmd.RegisterFlagCompletionFunc("dbtype", utilflag.DBTypeCompletion)
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")
	cmd.Flags().StringVarP(&options.dir, "dir", "", "", "directory under which this build's work directory is created and removed afterwards (default: the system temporary directory)")
	cmd.Flags().BoolVarP(&options.validateOnly, "validate-only", "", false, "validate the lock file and exit without building")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
