package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/types"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

type options struct {
	resultsDir string

	dbtype string
	dbpath string

	debug bool
}

type Option interface {
	apply(*options)
}

type resultsDirOption string

func (o resultsDirOption) apply(opts *options) {
	opts.resultsDir = string(o)
}

func WithResultsDir(resultsDir string) Option {
	return resultsDirOption(resultsDir)
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

func Detect(targets []string, opts ...Option) error {
	options := &options{
		resultsDir: filepath.Join(utilos.UserCacheDir(), "results"),
		dbtype:     "boltdb",
		dbpath:     filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		debug:      false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if len(targets) == 0 {
		ds, err := os.ReadDir(options.resultsDir)
		if err != nil {
			return errors.Wrapf(err, "read %s", options.resultsDir)
		}
		for _, d := range ds {
			targets = append(targets, d.Name())
		}
	}

	for _, target := range targets {
		if err := func() error {
			ds, err := os.ReadDir(filepath.Join(options.resultsDir, target))
			if err != nil {
				return errors.Wrapf(err, "read %s", filepath.Join(options.resultsDir, target))
			}

			var latest time.Time
			for _, d := range ds {
				t, err := time.Parse("2006-01-02T15-04-05-0700", d.Name())
				if err != nil {
					return errors.Wrapf(err, "parse %s", d.Name())
				}
				if latest.Before(t) {
					latest = t
				}
			}

			f, err := os.Open(filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "scan.json"))
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "scan.json"))
			}
			defer f.Close()

			var sr types.ScanResult
			if err := json.NewDecoder(f).Decode(&sr); err != nil {
				return errors.Wrapf(err, "decode %s", filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "scan.json"))
			}

			dr, err := detect(sr)
			if err != nil {
				return errors.Wrapf(err, "detect %s", sr.ServerUUID)
			}

			f, err = os.Create(filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "detect.json"))
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "detect.json"))
			}
			defer f.Close()

			e := json.NewEncoder(f)
			e.SetEscapeHTML(false)
			e.SetIndent("", "  ")
			if err := e.Encode(dr); err != nil {
				return errors.Wrapf(err, "encode %s", filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "detect.json"))
			}

			return nil
		}(); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func detect(sr types.ScanResult) (types.DetectResult, error) {
	return types.DetectResult{
		JSONVersion: 0,
		ServerUUID:  sr.ServerUUID,
		ServerName:  sr.ServerName,
	}, nil
}
