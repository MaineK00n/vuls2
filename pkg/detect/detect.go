package detect

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
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
	if err := dbc.Open(); err != nil {
		return errors.Wrap(err, "open db")
	}
	defer dbc.Close()

	slog.Info("Get Metadata")
	meta, err := dbc.GetMetadata()
	if err != nil || meta == nil {
		return errors.Wrap(err, "get metadata")
	}
	if meta.SchemaVersion < db.SchemaVersion {
		return errors.Errorf("schema version is old. expected: %q, actual: %q", db.SchemaVersion, meta.SchemaVersion)
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

			var sr scanTypes.ScanResult
			if err := json.NewDecoder(f).Decode(&sr); err != nil {
				return errors.Wrapf(err, "decode %s", filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "scan.json"))
			}

			slog.Info("Detect", "ServerUUID", sr.ServerUUID, "scanned", latest)
			dr, err := detect(dbc, sr)
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

func detect(dbc db.DB, sr scanTypes.ScanResult) (detectTypes.DetectResult, error) {
	pkgs := make(map[string][]int)
	for i, p := range sr.OSPackages {
		bn, sn := p.Name, p.SrcName
		if p.ModularityLabel != "" {
			bn, sn = fmt.Sprintf("%s::%s", p.ModularityLabel, p.Name), fmt.Sprintf("%s::%s", p.ModularityLabel, p.SrcName) // modularitylabel -> <module name>:<stream>
		}

		if !slices.Contains(pkgs[bn], i) {
			pkgs[bn] = append(pkgs[bn], i)
		}
		if !slices.Contains(pkgs[sn], i) {
			pkgs[sn] = append(pkgs[sn], i)
		}
	}

	type filtered struct {
		criteria criteriaTypes.Criteria
		indexes  struct {
			pkg []int
			cpe []int
		}
	}

	cm := make(map[string]map[sourceTypes.SourceID]filtered)
	for name, pkgIdxs := range pkgs {
		if err := func() error {
			resCh, errCh := dbc.GetVulnerabilityDetections(dbtypes.SearchDetectionPkg, func() string {
				switch sr.Family {
				case "oracle":
					return fmt.Sprintf("%s:%s", sr.Family, strings.Split(sr.Release, ".")[0])
				default:
					if sr.Release == "" {
						return sr.Family
					}
					return fmt.Sprintf("%s:%s", sr.Family, sr.Release)
				}
			}(), name)

			for {
				select {
				case item, ok := <-resCh:
					if !ok {
						return nil
					}
					for rootID, m := range item.Contents {
						for sourceID, ca := range m {
							for _, idx := range pkgIdxs {
								isContains, err := ca.Contains(criterionTypes.Query{Package: &criterionTypes.QueryPackage{
									Name: func() string {
										if sr.OSPackages[idx].ModularityLabel != "" {
											return fmt.Sprintf("%s::%s", sr.OSPackages[idx].ModularityLabel, sr.OSPackages[idx].Name)
										}
										return sr.OSPackages[idx].Name
									}(),
									Version: fmt.Sprintf("%s-%s", sr.OSPackages[idx].Version, sr.OSPackages[idx].Release),
									SrcName: func() string {
										if sr.OSPackages[idx].ModularityLabel != "" {
											return fmt.Sprintf("%s::%s", sr.OSPackages[idx].ModularityLabel, sr.OSPackages[idx].SrcName)
										}
										return sr.OSPackages[idx].SrcName
									}(),
									SrcVersion: fmt.Sprintf("%s-%s", sr.OSPackages[idx].SrcVersion, sr.OSPackages[idx].SrcRelease),
									Arch:       sr.OSPackages[idx].Arch,
									Repository: sr.OSPackages[idx].Repository,
								}})
								if err != nil {
									return errors.Wrap(err, "criteria contains")
								}

								if isContains {
									if cm[rootID] == nil {
										cm[rootID] = make(map[sourceTypes.SourceID]filtered)
									}
									base, ok := cm[rootID][sourceID]
									if !ok {
										base = filtered{criteria: ca}
									}
									base.indexes.pkg = append(base.indexes.pkg, idx)
									cm[rootID][sourceID] = base
								}
							}
						}
					}
				case err, ok := <-errCh:
					if ok {
						return errors.Wrap(err, "get detection")
					}
				}
			}
		}(); err != nil {
			return detectTypes.DetectResult{}, errors.Wrapf(err, "detect pkg: %s %s", func() string {
				switch sr.Family {
				case "oracle":
					return fmt.Sprintf("%s:%s", sr.Family, strings.Split(sr.Release, ".")[0])
				default:
					if sr.Release == "" {
						return sr.Family
					}
					return fmt.Sprintf("%s:%s", sr.Family, sr.Release)
				}
			}(), name)
		}
	}

	for i, cpe := range sr.CPE {
		if err := func() error {
			wfn, err := naming.UnbindFS(cpe)
			if err != nil {
				return errors.Wrapf(err, "unbind %q to WFN", cpe)
			}

			resCh, errCh := dbc.GetVulnerabilityDetections(dbtypes.SearchDetectionPkg, "cpe", fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct)))
			for {
				select {
				case item, ok := <-resCh:
					if !ok {
						return nil
					}
					for rootID, m := range item.Contents {
						for sourceID, ca := range m {
							isContains, err := ca.Contains(criterionTypes.Query{CPE: &cpe})
							if err != nil {
								return errors.Wrap(err, "criteria contains")
							}

							if isContains {
								if cm[rootID] == nil {
									cm[rootID] = make(map[sourceTypes.SourceID]filtered)
								}
								base, ok := cm[rootID][sourceID]
								if !ok {
									base = filtered{criteria: ca}
								}
								base.indexes.cpe = append(base.indexes.cpe, i)
								cm[rootID][sourceID] = base
							}
						}
					}
				case err, ok := <-errCh:
					if ok {
						return errors.Wrap(err, "get detection")
					}
				}
			}
		}(); err != nil {
			return detectTypes.DetectResult{}, errors.Wrapf(err, "detect cpe: %q", cpe)
		}
	}

	for rootID, m := range cm {
		for sourceID, fca := range m {
			qs := make([]criterionTypes.Query, 0, len(fca.indexes.pkg)+len(fca.indexes.cpe))
			for _, idx := range fca.indexes.pkg {
				qs = append(qs, criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{
						Name: func() string {
							if sr.OSPackages[idx].ModularityLabel != "" {
								return fmt.Sprintf("%s::%s", sr.OSPackages[idx].ModularityLabel, sr.OSPackages[idx].Name)
							}
							return sr.OSPackages[idx].Name
						}(),
						Version: fmt.Sprintf("%s-%s", sr.OSPackages[idx].Version, sr.OSPackages[idx].Release),
						SrcName: func() string {
							if sr.OSPackages[idx].ModularityLabel != "" {
								return fmt.Sprintf("%s::%s", sr.OSPackages[idx].ModularityLabel, sr.OSPackages[idx].SrcName)
							}
							return sr.OSPackages[idx].SrcName
						}(),
						SrcVersion: fmt.Sprintf("%s-%s", sr.OSPackages[idx].SrcVersion, sr.OSPackages[idx].SrcRelease),
						Arch:       sr.OSPackages[idx].Arch,
						Repository: sr.OSPackages[idx].Repository,
					},
				})
			}
			for _, idx := range fca.indexes.cpe {
				qs = append(qs, criterionTypes.Query{CPE: &sr.CPE[idx]})
			}

			ac, err := fca.criteria.Accept(qs)
			if err != nil {
				return detectTypes.DetectResult{}, errors.Wrap(err, "criteria accept")
			}

			isAffected, err := ac.Affected()
			if err != nil {
				return detectTypes.DetectResult{}, errors.Wrap(err, "criteria affected")
			}

			if isAffected {
				bs, err := json.MarshalIndent(ac, "", "  ")
				if err != nil {
					return detectTypes.DetectResult{}, err
				}
				fmt.Printf("%s:%s\ncriteria: %s\n", rootID, sourceID, string(bs))
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
