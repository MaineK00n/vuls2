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

func Search(searchType string, queries []string, opts ...Option) error {
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

	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	e.SetEscapeHTML(false)
	switch searchType {
	case "detection-pkg":
		slog.Info("Get Vulnerability Detections", "ecosystem", queries[0], "key", queries[1])
		done := make(chan struct{})
		defer close(done)
		resCh, errCh := dbc.GetVulnerabilityDetections(done, dbTypes.SearchDetectionPkg, queries[0], queries[1])
		for {
			select {
			case item, ok := <-resCh:
				if !ok {
					return nil
				}
				if err := e.Encode(item); err != nil {
					return errors.Wrapf(err, "encode %s %s", queries[0], queries[1])
				}
			case err, ok := <-errCh:
				if ok {
					return errors.Wrap(err, "get pkg detections")
				}
			}
		}
	case "detection-root":
		slog.Info("Get Vulnerability Detections", "root id", queries[0])
		done := make(chan struct{})
		defer close(done)
		resCh, errCh := dbc.GetVulnerabilityDetections(done, dbTypes.SearchDetectionRoot, queries[0])
		for {
			select {
			case item, ok := <-resCh:
				if !ok {
					return nil
				}
				if err := e.Encode(item); err != nil {
					return errors.Wrapf(err, "encode %s", queries[0])
				}
			case err, ok := <-errCh:
				if ok {
					return errors.Wrap(err, "get root detections")
				}
			}
		}
	case "detection-advisory":
		slog.Info("Get Vulnerability Detections", "advisory id", queries[0])
		done := make(chan struct{})
		defer close(done)
		resCh, errCh := dbc.GetVulnerabilityDetections(done, dbTypes.SearchDetectionAdvisory, queries[0])
		for {
			select {
			case item, ok := <-resCh:
				if !ok {
					return nil
				}
				if err := e.Encode(item); err != nil {
					return errors.Wrapf(err, "encode %s", queries[0])
				}
			case err, ok := <-errCh:
				if ok {
					return errors.Wrap(err, "get advisory detections")
				}
			}
		}
	case "detection-vulnerability":
		slog.Info("Get Vulnerability Detections", "vulnerability id", queries[0])
		done := make(chan struct{})
		defer close(done)
		resCh, errCh := dbc.GetVulnerabilityDetections(done, dbTypes.SearchDetectionVulnerability, queries[0])
		for {
			select {
			case item, ok := <-resCh:
				if !ok {
					return nil
				}
				if err := e.Encode(item); err != nil {
					return errors.Wrapf(err, "encode %s", queries[0])
				}
			case err, ok := <-errCh:
				if ok {
					return errors.Wrap(err, "get vulnerability detections")
				}
			}
		}
	case "data-root":
		slog.Info("Get Vulnerability Data", "root id", queries[0])
		d, err := dbc.GetVulnerabilityData(dbTypes.SearchDataRoot, queries[0])
		if err != nil {
			return errors.Wrap(err, "get root data")
		}

		if err := e.Encode(d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}

		return nil
	case "data-advisory":
		slog.Info("Get Vulnerability Data", "advisory id", queries[0])
		d, err := dbc.GetVulnerabilityData(dbTypes.SearchDataAdvisory, queries[0])
		if err != nil {
			return errors.Wrap(err, "get advisory data")
		}

		if err := e.Encode(d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}

		return nil
	case "data-vulnerability":
		slog.Info("Get Vulnerability Data", "vulnerability id", queries[0])
		d, err := dbc.GetVulnerabilityData(dbTypes.SearchDataVulnerability, queries[0])
		if err != nil {
			return errors.Wrap(err, "get vulnerability data")
		}

		if err := e.Encode(d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}

		return nil
	default:
		return errors.Errorf("unexpected search type. expected: %q, actual: %q", []string{"detection-pkg", "detection-root", "detection-advisory", "detection-vulnerability", "data-root", "data-advisory", "data-vulnerability"}, searchType)
	}
}
