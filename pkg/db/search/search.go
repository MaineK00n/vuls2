package search

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/db/common"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
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

func Search(searchType string, queries []string, opts ...Option) error {
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

	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	e.SetEscapeHTML(false)
	switch searchType {
	case "detection":
		slog.Info("Get Vulnerability Detections")
		ch, err := db.GetVulnerabilityDetections(queries[0], queries[1])
		if err != nil {
			return errors.Wrap(err, "get detection")
		}
		for d := range ch {
			if err := e.Encode(d); err != nil {
				return errors.Wrapf(err, "encode %s", d.ID)
			}
		}
	case "data":
		slog.Info("Get Vulnerability Data")
		d, err := db.GetVulnerabilityData(queries[0])
		if err != nil {
			return errors.Wrap(err, "get data")
		}

		if err := e.Encode(d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}
	default:
		return errors.Errorf("unexpected search type. expected: %q, actual: %q", []string{"detection", "data"}, searchType)
	}

	return nil
}
