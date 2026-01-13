package init

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
	"github.com/MaineK00n/vuls2/pkg/version"
)

type options struct {
	dbtype      string
	dbpath      string
	storageopts session.StorageOptions

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

type storageoptsOption session.StorageOptions

func (o storageoptsOption) apply(opts *options) {
	opts.storageopts = session.StorageOptions(o)
}

func WithStorageOptions(storageopts session.StorageOptions) Option {
	return storageoptsOption(storageopts)
}

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(debug bool) Option {
	return debugOption(debug)
}

func Init(opts ...Option) error {
	options := &options{
		dbtype:      "boltdb",
		dbpath:      filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		storageopts: session.StorageOptions{BoltDB: bolt.DefaultOptions},
		debug:       false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := os.MkdirAll(filepath.Dir(options.dbpath), 0755); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(options.dbpath))
	}

	s, err := (&session.Config{
		Type:    options.dbtype,
		Path:    options.dbpath,
		Debug:   options.debug,
		Options: options.storageopts,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

	sv, err := session.SchemaVersion(options.dbtype)
	if err != nil {
		return errors.Wrap(err, "get schema version")
	}

	slog.Info("Delete All Data")
	if err := s.Storage().DeleteAll(); err != nil {
		return errors.Wrap(err, "delete all")
	}

	slog.Info("Initialize DB")
	if err := s.Storage().Initialize(); err != nil {
		return errors.Wrap(err, "initialize")
	}

	slog.Info("Put Metadata")
	if err := s.Storage().PutMetadata(dbTypes.Metadata{
		SchemaVersion: sv,
		CreatedBy:     version.String(),
		LastModified:  time.Now().UTC(),
	}); err != nil {
		return errors.Wrap(err, "put metadata")
	}

	return nil
}
