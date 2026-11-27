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
		dbtype    utilflag.DBType
		dbpath    string
		dir       string
		writeLock string
		debug     bool
	}{
		dbtype: utilflag.DBTypeBoltDB,
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		dir:    utilos.UserCacheDir(),
		debug:  false,
	}

	cmd := &cobra.Command{
		Use:   "build <lock file>",
		Short: "build vuls db from a lock file",
		Long: heredoc.Doc(`
		Build a vuls db from a lock file ("-" reads stdin): the extracted
		dotgit of every data source, each pinned to one commit or following
		the head of its branch.

		  {"sources": [
		     {"name": "alma-errata",
		      "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata",
		      "branch": "nightly",
		      "commit": "<40 hex>"},
		     {"name": "ubuntu-cve-tracker",
		      "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-ubuntu-cve-tracker",
		      "branch": "main",
		      "commit": "<40 hex>"}
		   ]}

		Each source names the extracted branch its commit must belong to, so
		one db can take a source from main and the others from nightly. A
		source without "commit" follows its branch: it is built at the head
		of the branch in the dotgit pulled, so the same lock can build
		different data at different times. --write-lock writes the lock with
		the commit every source was built at, so the db can be built again.

		A source with a commit may also carry "hold": true. It tells whatever
		maintains the lock not to move that row; the build does not read it.

		Sources are built one at a time, in lock order: each is pulled from
		its repository with the tree of its commit written out (the commit
		must belong to the source's branch), stamped into datasource.json,
		added, and removed before the next one, so one dotgit and one tree
		are on disk at a time. The db is written to a scratch file and
		renamed to --dbpath only after every source has been added and
		verified, so a build that fails with an error leaves nothing behind
		(one killed by a signal may leave its work directory and scratch
		file). --dbpath must not exist already.
		`),
		Example: heredoc.Doc(`
		$ vuls db build db-nightly.lock.json --dbpath ./vuls.db
		$ vuls db build db-main.lock.json --dbpath ./vuls.db --write-lock ./built.lock.json
		$ jq '.sources |= map(select(.name == "alma-errata"))' db-nightly.lock.json | vuls db build - --dbpath ./mini.db
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := db.Build(args[0],
				db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath),
				db.WithDir(options.dir), db.WithWriteLock(options.writeLock), db.WithDebug(options.debug),
			); err != nil {
				return errors.Wrap(err, "db build")
			}
			return nil
		},
	}

	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb])")
	_ = cmd.RegisterFlagCompletionFunc("dbtype", utilflag.DBTypeCompletion)
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")
	cmd.Flags().StringVarP(&options.dir, "dir", "", options.dir, "directory under which this build's work directory is created and removed afterwards (the pulled dotgits and restored trees go there, so avoid a tmpfs)")
	cmd.Flags().StringVarP(&options.writeLock, "write-lock", "", options.writeLock, "after the build, write the lock with the commit every source was built at to this path (\"-\" writes stdout; it may be the lock read)")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
