package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	dbtypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
	"github.com/MaineK00n/vuls2/pkg/version"
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

	c := db.Config{
		Type: options.dbtype,
		Path: options.dbpath,

		Debug: options.debug,
	}
	dbc, err := c.New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}
	defer dbc.Close()

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

			var sr scanTypes.ScanResult
			if err := json.NewDecoder(f).Decode(&sr); err != nil {
				return errors.Wrapf(err, "decode %s", filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "scan.json"))
			}

			dr, err := detect(db, sr)
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

func detect(db db.DB, sr scanTypes.ScanResult) (detectTypes.DetectResult, error) {
	pkgs := make(map[string][]scanTypes.OSPackage)
	for _, p := range sr.OSPackages {
		bn, sn := p.Name, p.SrcName
		if p.ModularityLabel != "" {
			bn, sn = fmt.Sprintf("%s::%s", p.ModularityLabel, p.Name), fmt.Sprintf("%s::%s", p.ModularityLabel, p.SrcName) // modularitylabel -> <module name>:<stream>
		}

		if !slices.Contains(pkgs[bn], p) {
			pkgs[bn] = append(pkgs[bn], p)
		}
		if !slices.Contains(pkgs[sn], p) {
			pkgs[sn] = append(pkgs[sn], p)
		}
	}

	for name, ps := range pkgs {
		resCh, errCh := db.GetVulnerabilityDetections(dbtypes.SearchDetectionPkg, func() string {
			if sr.Release == "" {
				return sr.Family
			}
			return fmt.Sprintf("%s:%s", sr.Family, sr.Release)
		}(), name)
		for {
			select {
			case item, ok := <-resCh:
				if !ok {
					return detectTypes.DetectResult{}, nil
				}
				for rootID, m := range item.Contents {
					for sourceID, ca := range m {
						for _, p := range ps {
							ca.Contains(criterionTypes.Query{Package: &criterionTypes.QueryPackage{
								Name:       p.Name,
								Version:    p.Version,
								SrcName:    p.SrcName,
								SrcVersion: p.SrcVersion,
								Arch:       p.Arch,
								Repository: p.Repository,
							}})
						}
					}
				}
			case err, ok := <-errCh:
				if ok {
					return detectTypes.DetectResult{}, errors.Wrap(err, "get detection")
				}
			}
		}

	}

	for _, cpe := range sr.CPE {
		wfn, err := naming.UnbindFS(cpe)
		if err != nil {
			return detectTypes.DetectResult{}, errors.Wrapf(err, "unbind %q to WFN", cpe)
		}

		resCh, errCh := db.GetVulnerabilityDetections(dbtypes.SearchDetectionPkg, "cpe", fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct)))
		for {
			select {
			case item, ok := <-resCh:
				if !ok {
					return detectTypes.DetectResult{}, nil
				}
				for rootID, m := range item.Contents {
					for sourceID, ca := range m {
						// check affected?
					}
				}
			case err, ok := <-errCh:
				if ok {
					return detectTypes.DetectResult{}, errors.Wrap(err, "get detection")
				}
			}
		}
	}

	return detectTypes.DetectResult{
		JSONVersion: 0,
		ServerUUID:  sr.ServerUUID,
		ServerName:  sr.ServerName,

		DetectedAt: time.Now(),
		DetectedBy: version.String(),
	}, nil
}
