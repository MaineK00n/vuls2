package compress

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"
	"go.etcd.io/bbolt"

	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

type options struct {
	dbtype string
	dbpath string

	boltdbNoSync           bool
	boltdbTxMaxSize        int64
	zstdCompressionLevel   int
	zstdCompressionThreads int

	debug bool
}

type Option interface {
	apply(*options)
}

type dbtypeOption string

func (o dbtypeOption) apply(opts *options) {
	opts.dbtype = string(o)
}

func WithDBType(dbtype string) Option {
	return dbtypeOption(dbtype)
}

type dbpathOption string

func (o dbpathOption) apply(opts *options) {
	opts.dbpath = string(o)
}

func WithDBPath(dbpath string) Option {
	return dbpathOption(dbpath)
}

type boltdbNoSyncOption bool

func (o boltdbNoSyncOption) apply(opts *options) {
	opts.boltdbNoSync = bool(o)
}

func WithBoltDBNoSync(noSync bool) Option {
	return boltdbNoSyncOption(noSync)
}

type boltdbTxMaxSizeOption int64

func (o boltdbTxMaxSizeOption) apply(opts *options) {
	opts.boltdbTxMaxSize = int64(o)
}

func WithBoltDBTxMaxSize(size int64) Option {
	return boltdbTxMaxSizeOption(size)
}

type zstdCompressionLevelOption int

func (o zstdCompressionLevelOption) apply(opts *options) {
	opts.zstdCompressionLevel = int(o)
}

func WithZstdCompressionLevel(level int) Option {
	return zstdCompressionLevelOption(level)
}

type zstdCompressionThreadsOption int

func (o zstdCompressionThreadsOption) apply(opts *options) {
	opts.zstdCompressionThreads = int(o)
}

func WithZstdCompressionThreads(threads int) Option {
	return zstdCompressionThreadsOption(threads)
}

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(debug bool) Option {
	return debugOption(debug)
}

func Compress(opts ...Option) error {
	options := &options{
		dbtype:                 "boltdb",
		dbpath:                 filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		boltdbNoSync:           false,
		boltdbTxMaxSize:        65536,
		zstdCompressionLevel:   22,
		zstdCompressionThreads: runtime.NumCPU(),
		debug:                  false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	slog.Info("Compress vuls.db", "dbtype", options.dbtype, "dbpath", options.dbpath)

	switch options.dbtype {
	case "boltdb":
		if err := compactBoltDB(options.dbpath, options.boltdbNoSync, options.boltdbTxMaxSize); err != nil {
			return errors.Wrap(err, "compact boltdb")
		}
		if err := compressZstandard(options.dbpath, options.zstdCompressionLevel, options.zstdCompressionThreads); err != nil {
			_ = os.Remove(fmt.Sprintf("%s.zst", options.dbpath))
			return errors.Wrap(err, "compress db with zstd")
		}
	default:
		return errors.Errorf("%s is not support dbtype", options.dbtype)
	}

	return nil
}

func compactBoltDB(dbpath string, noSync bool, txMaxSize int64) error {
	si, err := os.Stat(dbpath)
	if err != nil {
		return errors.Wrapf(err, "stat %q", dbpath)
	}

	src, err := bbolt.Open(dbpath, 0400, &bbolt.Options{ReadOnly: true})
	if err != nil {
		return errors.Wrapf(err, "open %q", dbpath)
	}
	defer src.Close() //nolint:errcheck

	tmpdb, err := func() (string, error) {
		f, err := os.CreateTemp(filepath.Dir(dbpath), fmt.Sprintf("%s.*", filepath.Base(dbpath)))
		if err != nil {
			return "", errors.Wrapf(err, "create %q", filepath.Join(filepath.Dir(dbpath), fmt.Sprintf("%s.*", filepath.Base(dbpath))))
		}
		defer f.Close() //nolint:errcheck
		return f.Name(), nil
	}()
	if err != nil {
		return errors.Wrapf(err, "create temp db")
	}
	defer os.Remove(tmpdb) //nolint:errcheck

	dst, err := bbolt.Open(tmpdb, 0600, &bbolt.Options{NoSync: noSync})
	if err != nil {
		return errors.Wrapf(err, "open %q", tmpdb)
	}
	defer dst.Close() //nolint:errcheck

	if err := bbolt.Compact(dst, src, txMaxSize); err != nil {
		return errors.Wrap(err, "compact")
	}

	di, err := os.Stat(tmpdb)
	if err != nil {
		return errors.Wrapf(err, "stat %q", tmpdb)
	}
	if di.Size() == 0 {
		return errors.Errorf("size of %q is 0", tmpdb)
	}

	sizeunit := unit(si.Size())
	slog.Info("BoltDB compaction", "before", format(si.Size(), sizeunit), "after", format(di.Size(), sizeunit), "gain", fmt.Sprintf("%.2fx", float64(si.Size())/float64(di.Size())))

	if err := os.Rename(tmpdb, dbpath); err != nil {
		return errors.Wrapf(err, "rename %q to %q", tmpdb, dbpath)
	}

	return nil
}

func compressZstandard(dbpath string, compressionLevel, compressionThreads int) error {
	si, err := os.Stat(dbpath)
	if err != nil {
		return errors.Wrapf(err, "stat %s", dbpath)
	}

	if _, err := exec.LookPath("zstd"); err != nil {
		sf, err := os.Open(dbpath)
		if err != nil {
			return errors.Wrapf(err, "open %s", dbpath)
		}
		defer sf.Close() //nolint:errcheck

		df, err := os.Create(fmt.Sprintf("%s.zst", dbpath))
		if err != nil {
			return errors.Wrapf(err, "create %s", fmt.Sprintf("%s.zst", dbpath))
		}
		defer df.Close() //nolint:errcheck

		e, err := zstd.NewWriter(df, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(compressionLevel)), zstd.WithEncoderConcurrency(compressionThreads))
		if err != nil {
			return errors.Wrap(err, "create zstd encoder")
		}
		defer e.Close() //nolint:errcheck

		if _, err := io.Copy(e, sf); err != nil {
			return errors.Wrapf(err, "compress %s to %s", dbpath, fmt.Sprintf("%s.zst", dbpath))
		}
	} else {
		var args []string
		if compressionLevel > 19 {
			args = append(args, "--ultra")
		}
		args = append(args,
			fmt.Sprintf("-%d", compressionLevel),
			fmt.Sprintf("-T%d", compressionThreads),
			dbpath,
			"-o",
			fmt.Sprintf("%s.zst", dbpath),
		)
		cmd := exec.Command("zstd", args...)
		if err := cmd.Run(); err != nil {
			return errors.Wrap(err, cmd.String())
		}
	}

	di, err := os.Stat(fmt.Sprintf("%s.zst", dbpath))
	if err != nil {
		return errors.Wrapf(err, "stat %s", fmt.Sprintf("%s.zst", dbpath))
	}
	if di.Size() == 0 {
		return errors.Errorf("size of %s is 0", fmt.Sprintf("%s.zst", dbpath))
	}

	sizeunit := unit(si.Size())
	slog.Info("Zstandard compression", "before", format(si.Size(), sizeunit), "after", format(di.Size(), sizeunit), "gain", fmt.Sprintf("%.2fx", float64(si.Size())/float64(di.Size())))

	return nil
}
