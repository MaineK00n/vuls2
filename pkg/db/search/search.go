package search

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/db/common"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
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
	case "detection-pkg":
		slog.Info("Get Vulnerability Detections", "ecosystem", queries[0], "key", queries[1])
		resCh, errCh := db.GetVulnerabilityDetections(dbTypes.SearchDetectionPkg, queries[0], queries[1])
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
		resCh, errCh := db.GetVulnerabilityDetections(dbTypes.SearchDetectionRoot, queries[0])
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
		resCh, errCh := db.GetVulnerabilityDetections(dbTypes.SearchDetectionAdvisory, queries[0])
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
		resCh, errCh := db.GetVulnerabilityDetections(dbTypes.SearchDetectionVulnerability, queries[0])
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
		d, err := db.GetVulnerabilityData(dbTypes.SearchDataRoot, queries[0])
		if err != nil {
			return errors.Wrap(err, "get root data")
		}

		if err := e.Encode(d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}

		return nil
	case "data-advisory":
		slog.Info("Get Vulnerability Data", "advisory id", queries[0])
		d, err := db.GetVulnerabilityData(dbTypes.SearchDataAdvisory, queries[0])
		if err != nil {
			return errors.Wrap(err, "get advisory data")
		}

		if err := e.Encode(d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}

		return nil
	case "data-vulnerability":
		slog.Info("Get Vulnerability Data", "vulnerability id", queries[0])
		d, err := db.GetVulnerabilityData(dbTypes.SearchDataVulnerability, queries[0])
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
