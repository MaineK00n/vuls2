package remove

import (
	"log/slog"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
	"github.com/MaineK00n/vuls2/pkg/version"
)

type options struct {
	dbtype string
	dbpath string
	dbopts db.DBOptions

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

type dboptsOption db.DBOptions

func (o dboptsOption) apply(opts *options) {
	opts.dbopts = db.DBOptions(o)
}

func WithDBOptions(dbopts db.DBOptions) Option {
	return dboptsOption(dbopts)
}

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(debug bool) Option {
	return debugOption(debug)
}

func Remove(id string, opts ...Option) error {
	options := &options{
		dbtype: "boltdb",
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		dbopts: db.DBOptions{BoltDB: bolt.DefaultOptions},
		debug:  false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	dbc, err := (&db.Config{
		Type:    options.dbtype,
		Path:    options.dbpath,
		Debug:   options.debug,
		Options: options.dbopts,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}
	if err := dbc.Open(); err != nil {
		return errors.Wrap(err, "open db")
	}
	defer dbc.Close()

	slog.Info("Get Metadata")
	meta, err := dbc.GetMetadata()
	if err != nil || meta == nil {
		return errors.Wrap(err, "get metadata")
	}
	if meta.SchemaVersion != db.SchemaVersion {
		return errors.Errorf("unexpected schema version. expected: %d, actual: %d", db.SchemaVersion, meta.SchemaVersion)
	}

	slog.Info("Remove DataSource")
	if err := dbc.RemoveDataSource(sourceTypes.SourceID(id)); err != nil {
		return errors.Wrap(err, "remove datasource")
	}

	slog.Info("Remove Vulnerability Data")
	if err := dbc.RemoveVulnerabilityData(sourceTypes.SourceID(id)); err != nil {
		return errors.Wrap(err, "remove data")
	}

	slog.Info("Put Metadata")
	if err := dbc.PutMetadata(dbTypes.Metadata{
		SchemaVersion: db.SchemaVersion,
		CreatedBy:     version.String(),
		LastModified:  time.Now().UTC(),
	}); err != nil {
		return errors.Wrap(err, "put metadata")
	}

	return nil
}
