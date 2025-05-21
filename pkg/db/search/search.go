package search

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	db "github.com/MaineK00n/vuls2/pkg/db/common"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
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

func Search(searchType dbTypes.SearchType, queries []string, opts ...Option) error {
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
	defer dbc.Close() //nolint:errcheck

	slog.Info("Get Metadata")
	meta, err := dbc.GetMetadata()
	if err != nil || meta == nil {
		return errors.Wrap(err, "get metadata")
	}
	if meta.SchemaVersion != db.SchemaVersion {
		return errors.Errorf("unexpected schema version. expected: %d, actual: %d", db.SchemaVersion, meta.SchemaVersion)
	}

	slog.Info("Get Vulnerability Data", "queries", queries)
	e := json.NewEncoder(os.Stdout)
	e.SetEscapeHTML(false)
	for d, err := range dbc.GetVulnerabilityData(searchType, queries...) {
		if err != nil {
			return errors.Wrap(err, "get vulnerability data")
		}
		if err := e.Encode(d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}
	}
	return nil
}
