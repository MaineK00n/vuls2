package add

import (
	"log/slog"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/db/common"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
	"github.com/MaineK00n/vuls2/pkg/version"
)

type options struct {
	dbtype string
	dbpath string

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

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(debug bool) Option {
	return debugOption(debug)
}

func Add(root string, opts ...Option) error {
	options := &options{
		dbtype: "boltdb",
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		debug:  false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	db, err := (&common.Config{
		Type:  options.dbtype,
		Path:  options.dbpath,
		Debug: options.debug,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}
	if err := db.Open(); err != nil {
		return errors.Wrap(err, "open db")
	}
	defer db.Close()

	slog.Info("Get Metadata")
	meta, err := db.GetMetadata()
	if err != nil || meta == nil {
		return errors.Wrap(err, "get metadata")
	}
	if meta.SchemaVersion < common.SchemaVersion {
		return errors.Errorf("schema version is old. expected: %q, actual: %q", common.SchemaVersion, meta.SchemaVersion)
	}

	slog.Info("Put Vulnerability Data")
	if err := db.PutVulnerabilityData(filepath.Join(root, "data")); err != nil {
		return errors.Wrap(err, "put data")
	}

	slog.Info("Put DataSource")
	if err := db.PutDataSource(filepath.Join(root, "datasource.json")); err != nil {
		return errors.Wrap(err, "put datasource")
	}

	slog.Info("Put Metadata")
	if err := db.PutMetadata(dbTypes.Metadata{
		SchemaVersion: common.SchemaVersion,
		CreatedBy:     version.String(),
		LastModified:  time.Now(),
	}); err != nil {
		return errors.Wrap(err, "put metadata")
	}

	return nil
}
