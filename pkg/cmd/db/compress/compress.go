package compress

import (
	"path/filepath"
	"runtime"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	utilflag "github.com/MaineK00n/vuls2/pkg/cmd/util/flag"
	db "github.com/MaineK00n/vuls2/pkg/db/compress"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	options := struct {
		dbtype utilflag.DBType
		dbpath string

		boltdbNoSync           bool
		boltdbTxMaxSize        int64
		zstdCompressionLevel   int
		zstdCompressionThreads int

		debug bool
	}{
		dbtype: utilflag.DBTypeBoltDB,
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),

		boltdbNoSync:           false,
		boltdbTxMaxSize:        65536,
		zstdCompressionLevel:   22,
		zstdCompressionThreads: runtime.NumCPU(),

		debug: false,
	}

	cmd := &cobra.Command{
		Use:   "compress",
		Short: "compress vuls db",
		Example: heredoc.Doc(`
		$ vuls db compress
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := db.Compress(
				db.WithDBType(options.dbtype.String()), db.WithDBPath(options.dbpath),
				db.WithBoltDBNoSync(options.boltdbNoSync), db.WithBoltDBTxMaxSize(options.boltdbTxMaxSize),
				db.WithZstdCompressionLevel(options.zstdCompressionLevel), db.WithZstdCompressionThreads(options.zstdCompressionThreads),
				db.WithDebug(options.debug),
			); err != nil {
				return errors.Wrap(err, "db compress")
			}
			return nil
		},
	}

	cmd.Flags().VarP(&options.dbtype, "dbtype", "", "vuls db type (default: boltdb, accepts: [boltdb, redis, sqlite3, mysql, postgres])")
	_ = cmd.RegisterFlagCompletionFunc("dbtype", utilflag.DBTypeCompletion)
	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")
	cmd.Flags().BoolVarP(&options.boltdbNoSync, "boltdb-nosync", "", options.boltdbNoSync, "boltdb nosync")
	cmd.Flags().Int64VarP(&options.boltdbTxMaxSize, "boltdb-txmaxsize", "", options.boltdbTxMaxSize, "boltdb tx max size")
	cmd.Flags().IntVarP(&options.zstdCompressionLevel, "zstd-compression-level", "", options.zstdCompressionLevel, "zstd compression level (1-22)")
	cmd.Flags().IntVarP(&options.zstdCompressionThreads, "zstd-compression-threads", "", options.zstdCompressionThreads, "zstd compression threads")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
