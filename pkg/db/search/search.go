package search

import (
	"encoding/json/v2"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

type options struct {
	dbtype      string
	dbpath      string
	storageopts session.StorageOptions
	filter      dbTypes.Filter

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

type filterOption dbTypes.Filter

func (o filterOption) apply(opts *options) {
	opts.filter = dbTypes.Filter(o)
}

func WithFilter(filter dbTypes.Filter) Option {
	return filterOption(filter)
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
		dbtype:      "boltdb",
		dbpath:      filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		storageopts: session.StorageOptions{BoltDB: bolt.DefaultOptions},
		filter: dbTypes.Filter{
			Contents: dbTypes.AllFilterContentTypes(),
		},
		debug: false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	dbc, err := (&session.Config{
		Type:      options.dbtype,
		Path:      options.dbpath,
		Debug:     options.debug,
		Options:   options.storageopts,
		WithCache: true,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := dbc.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer dbc.Storage().Close()

	defer dbc.Cache().Close()

	slog.Info("Get Metadata")
	meta, err := dbc.Storage().GetMetadata()
	if err != nil || meta == nil {
		return errors.Wrap(err, "get metadata")
	}
	sv, err := session.SchemaVersion(options.dbtype)
	if err != nil {
		return errors.Wrap(err, "get schema version")
	}
	if meta.SchemaVersion != sv {
		return errors.Errorf("unexpected schema version. expected: %d, actual: %d", sv, meta.SchemaVersion)
	}

	switch searchType {
	case dbTypes.SearchMetadata:
		if err := json.MarshalWrite(os.Stdout, meta); err != nil {
			return errors.Wrap(err, "encode metadata")
		}
	case dbTypes.SearchDataSources:
		slog.Info("Get DataSources")
		datasources, err := dbc.Storage().GetDataSources()
		if err != nil {
			return errors.Wrap(err, "get data sources")
		}

		if err := json.MarshalWrite(os.Stdout, datasources); err != nil {
			return errors.Wrap(err, "encode data sources")
		}
	case dbTypes.SearchEcosystems:
		slog.Info("Get Ecosystems")
		ecosystems, err := dbc.Storage().GetEcosystems()
		if err != nil {
			return errors.Wrap(err, "get ecosystems")
		}

		if err := json.MarshalWrite(os.Stdout, ecosystems); err != nil {
			return errors.Wrap(err, "encode ecosystems")
		}
	default:
		slog.Info("Get Vulnerability Data", "queries", queries)
		for d, err := range dbc.GetVulnerabilityData(searchType, options.filter, queries...) {
			if err != nil {
				return errors.Wrap(err, "get vulnerability data")
			}
			if err := json.MarshalWrite(os.Stdout, d); err != nil {
				return errors.Wrapf(err, "encode %s", d.ID)
			}
		}
	}

	return nil
}
