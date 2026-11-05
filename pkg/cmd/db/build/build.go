package build

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	utilflag "github.com/MaineK00n/vuls2/pkg/cmd/util/flag"
	db "github.com/MaineK00n/vuls2/pkg/db/build"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	options := struct {
		lock                string
		dbtype              utilflag.DBType
		dbpath              string
		dir                 string
		downloadConcurrency int
		restoreConcurrency  int
		report              string
		check               bool
		debug               bool
	}{
		dbtype:              utilflag.DBTypeBoltDB,
		dbpath:              filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		downloadConcurrency: runtime.NumCPU(),
		restoreConcurrency:  1,
		debug:               false,
	}

	cmd := &cobra.Command{
		Use:   "build",
		Short: "build vuls db from a lock file",
		Long: heredoc.Doc(`
		Build a vuls db from a lock file: the extracted dotgit of every data
		source, pinned to one commit each, added in the order listed.

		  {"branch": "nightly",
		   "registry": "ghcr.io/vulsio/vuls-data-db",
		   "sources": [
		     {"name": "alma-errata", "commit": "<40 hex>"},
		     {"name": "ubuntu-cve-tracker", "commit": "<40 hex>"}
		   ]}

		Each source is pulled from <registry>:vuls-data-extracted-<name>,
		restored at its commit (which must belong to the branch), stamped
		into datasource.json, and added, in three stages: dotgits (the .git
		only) are pulled --download-concurrency at a time for every source
		ahead of the adds; trees are restored --restore-concurrency sources
		ahead of the one being added, so that many plus one trees are on
		disk at most; adds are serial, in lock order. A boltdb is written to
		a scratch file and renamed over --dbpath only after every source has
		been added and verified, so a failed build leaves nothing behind.
		`),
		Example: heredoc.Doc(`
		$ vuls db build --lock db-nightly.lock.json --dbpath ./vuls.db
		$ vuls db build --lock db-nightly.lock.json --dbpath ./vuls.db --download-concurrency 8 --restore-concurrency 1 --report report.json
		$ vuls db build --lock db-nightly.lock.json --check
		$ jq '.sources |= map(select(.name == "alma-errata"))' db-nightly.lock.json | vuls db build --lock - --dbpath ./mini.db
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			lock, err := readLock(options.lock)
			if err != nil {
				return errors.Wrapf(err, "read lock %s", options.lock)
			}
			if options.check {
				slog.Info("Lock is valid", slog.String("branch", lock.Branch), slog.String("registry", lock.Registry), slog.Int("sources", len(lock.Sources)))
				return nil
			}

			if _, err := db.Build(lock,
				db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath),
				db.WithDir(options.dir), db.WithDownloadConcurrency(options.downloadConcurrency), db.WithRestoreConcurrency(options.restoreConcurrency), db.WithReport(options.report),
				db.WithDebug(options.debug),
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
	cmd.Flags().IntVarP(&options.downloadConcurrency, "download-concurrency", "", options.downloadConcurrency, "dotgits pulled at once (network; .git only, so this does not grow the trees on disk)")
	cmd.Flags().IntVarP(&options.restoreConcurrency, "restore-concurrency", "", options.restoreConcurrency, "sources restored ahead of the add; this many plus one extracted trees are on disk at most")
	cmd.Flags().StringVarP(&options.report, "report", "", "", "write a JSON report of what was built (datasource ids, commits, how far behind the branch, seconds per stage) to this path")
	cmd.Flags().BoolVarP(&options.check, "check", "", false, "validate the lock file and exit without building")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}

func readLock(path string) (db.Lock, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return db.Lock{}, errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()
		r = f
	}
	return db.ReadLock(r)
}
