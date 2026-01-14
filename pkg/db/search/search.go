package search

import (
	"encoding/json/v2"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
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

func SearchMetadata(opts ...Option) error {
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

	s, err := (&session.Config{
		Type:      options.dbtype,
		Path:      options.dbpath,
		Debug:     options.debug,
		Options:   options.storageopts,
		WithCache: true,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

	defer s.Cache().Close()

	slog.Info("Get Metadata")
	meta, err := s.Storage().GetMetadata()
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

	if err := json.MarshalWrite(os.Stdout, meta); err != nil {
		return errors.Wrap(err, "encode metadata")
	}

	return nil
}

func SearchDataSources(opts ...Option) error {
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

	s, err := (&session.Config{
		Type:      options.dbtype,
		Path:      options.dbpath,
		Debug:     options.debug,
		Options:   options.storageopts,
		WithCache: true,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

	defer s.Cache().Close()

	slog.Info("Get Metadata")
	meta, err := s.Storage().GetMetadata()
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

	slog.Info("Get DataSources")
	datasources, err := s.Storage().GetDataSources()
	if err != nil {
		return errors.Wrap(err, "get data sources")
	}

	if err := json.MarshalWrite(os.Stdout, datasources); err != nil {
		return errors.Wrap(err, "encode data sources")
	}

	return nil
}

func SearchEcosystems(opts ...Option) error {
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

	s, err := (&session.Config{
		Type:      options.dbtype,
		Path:      options.dbpath,
		Debug:     options.debug,
		Options:   options.storageopts,
		WithCache: true,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

	defer s.Cache().Close()

	slog.Info("Get Metadata")
	meta, err := s.Storage().GetMetadata()
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

	slog.Info("Get Ecosystems")
	ecosystems, err := s.Storage().GetEcosystems()
	if err != nil {
		return errors.Wrap(err, "get ecosystems")
	}

	if err := json.MarshalWrite(os.Stdout, ecosystems); err != nil {
		return errors.Wrap(err, "encode ecosystems")
	}

	return nil
}

func SearchRoot(queries []dataTypes.RootID, opts ...Option) error {
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

	s, err := (&session.Config{
		Type:      options.dbtype,
		Path:      options.dbpath,
		Debug:     options.debug,
		Options:   options.storageopts,
		WithCache: true,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

	defer s.Cache().Close()

	slog.Info("Get Metadata")
	meta, err := s.Storage().GetMetadata()
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

	slog.Info("Get Vulnerability Data", "root id", queries)
	for _, query := range queries {
		d, err := s.GetVulnerabilityData(query, options.filter)
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundRoot) {
				slog.Warn(err.Error())
				continue
			}
			return errors.Wrap(err, "get vulnerability data by root id")
		}
		if err := json.MarshalWrite(os.Stdout, d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}
	}

	return nil
}

func SearchAdisory(queries []advisoryContentTypes.AdvisoryID, opts ...Option) error {
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

	s, err := (&session.Config{
		Type:      options.dbtype,
		Path:      options.dbpath,
		Debug:     options.debug,
		Options:   options.storageopts,
		WithCache: true,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

	defer s.Cache().Close()

	slog.Info("Get Metadata")
	meta, err := s.Storage().GetMetadata()
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

	slog.Info("Get Vulnerability Data", "advisory id", queries)
	for _, query := range queries {
		d, err := s.GetVulnerabilityDataByAdvisoryID(query, options.filter)
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundAdvisory) {
				slog.Warn(err.Error())
				continue
			}
			return errors.Wrap(err, "get vulnerability data by advisory id")
		}
		if err := json.MarshalWrite(os.Stdout, d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}
	}

	return nil
}

func SearchVulnerability(queries []vulnerabilityContentTypes.VulnerabilityID, opts ...Option) error {
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

	s, err := (&session.Config{
		Type:      options.dbtype,
		Path:      options.dbpath,
		Debug:     options.debug,
		Options:   options.storageopts,
		WithCache: true,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

	defer s.Cache().Close()

	slog.Info("Get Metadata")
	meta, err := s.Storage().GetMetadata()
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

	slog.Info("Get Vulnerability Data", "vulnerability id", queries)
	for _, query := range queries {
		d, err := s.GetVulnerabilityDataByVulnerabilityID(query, options.filter)
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
				slog.Warn(err.Error())
				continue
			}
			return errors.Wrap(err, "get vulnerability data by vulnerability id")
		}
		if err := json.MarshalWrite(os.Stdout, d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}
	}

	return nil
}

func SearchPackage(ecosytem ecosystemTypes.Ecosystem, queries []string, opts ...Option) error {
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

	s, err := (&session.Config{
		Type:      options.dbtype,
		Path:      options.dbpath,
		Debug:     options.debug,
		Options:   options.storageopts,
		WithCache: true,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

	defer s.Cache().Close()

	slog.Info("Get Metadata")
	meta, err := s.Storage().GetMetadata()
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

	slog.Info("Get Vulnerability Data", "ecosystem", ecosytem, "package", queries)
	for d, err := range s.GetVulnerabilityDataByPackage(ecosytem, queries, options.filter) {
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundEcosystem) {
				slog.Warn(err.Error())
				return nil
			}
			if errors.Is(err, dbTypes.ErrNotFoundIndex) {
				slog.Warn(err.Error())
				continue
			}
			return errors.Wrap(err, "get vulnerability data by package")
		}
		if err := json.MarshalWrite(os.Stdout, d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}
	}

	return nil
}
