package detect

import (
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/pkg/errors"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	"github.com/MaineK00n/vuls2/pkg/detect/cpe"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg"
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
	detected := make(map[string]detectTypes.VulnerabilityData)

	if len(sr.OSPackages) > 0 {
		m, err := ospkg.Detect(dbc, sr)
		if err != nil {
			return detectTypes.DetectResult{}, errors.Wrap(err, "detect os packages")
		}

		for rootID, mm := range m.Contents {
			base, ok := detected[rootID]
			if !ok {
				d, err := dbc.GetVulnerabilityData(dbTypes.SearchDataRoot, rootID)
				if err != nil {
					return detectTypes.DetectResult{}, errors.Wrapf(err, "get vulnerability data with RootID: %s", rootID)
				}
				base = detectTypes.VulnerabilityData{
					ID:              rootID,
					Advisories:      d.Advisories,
					Vulnerabilities: d.Vulnerabilities,
				}
			}

			for sourceID, fca := range mm {
				base.Detections = append(base.Detections, detectTypes.VulnerabilityDataDetection{
					Ecosystem: m.Ecosystem,
					Contents:  map[string]map[sourceTypes.SourceID]criteriaTypes.FilteredCriteria{rootID: {sourceID: fca}},
				})
			}

			detected[rootID] = base
		}
	}

	if len(sr.CPE) > 0 {
		m, err := cpe.Detect(dbc, sr)
		if err != nil {
			return detectTypes.DetectResult{}, errors.Wrap(err, "detect cpe")
		}

		for rootID, mm := range m.Contents {
			base, ok := detected[rootID]
			if !ok {
				d, err := dbc.GetVulnerabilityData(dbTypes.SearchDataRoot, rootID)
				if err != nil {
					return detectTypes.DetectResult{}, errors.Wrapf(err, "get vulnerability data with RootID: %s", rootID)
				}
				base = detectTypes.VulnerabilityData{
					ID:              rootID,
					Advisories:      d.Advisories,
					Vulnerabilities: d.Vulnerabilities,
				}
			}

			for sourceID, fca := range mm {
				base.Detections = append(base.Detections, detectTypes.VulnerabilityDataDetection{
					Ecosystem: m.Ecosystem,
					Contents:  map[string]map[sourceTypes.SourceID]criteriaTypes.FilteredCriteria{rootID: {sourceID: fca}},
				})
			}

			detected[rootID] = base
		}
	}

	var sourceIDs []sourceTypes.SourceID
	for _, data := range detected {
		for _, a := range data.Advisories {
			for sourceID := range a.Contents {
				if !slices.Contains(sourceIDs, sourceID) {
					sourceIDs = append(sourceIDs, sourceID)
				}
			}
		}
		for _, v := range data.Vulnerabilities {
			for sourceID := range v.Contents {
				if !slices.Contains(sourceIDs, sourceID) {
					sourceIDs = append(sourceIDs, sourceID)
				}
			}
		}
		for _, d := range data.Detections {
			for _, m := range d.Contents {
				for sourceID := range m {
					if !slices.Contains(sourceIDs, sourceID) {
						sourceIDs = append(sourceIDs, sourceID)
					}
				}
			}
		}
	}

	datasources := make([]datasourceTypes.DataSource, 0, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		s, err := dbc.GetDataSource(sourceID)
		if err != nil {
			return detectTypes.DetectResult{}, errors.Wrapf(err, "get datasource with %s", sourceID)
		}
		datasources = append(datasources, *s)
	}

	return detectTypes.DetectResult{
		JSONVersion: 0,
		ServerUUID:  sr.ServerUUID,
		ServerName:  sr.ServerName,

		Detected:    slices.Collect(maps.Values(detected)),
		DataSources: datasources,

		DetectedAt: time.Now(),
		DetectedBy: version.String(),
	}, nil
}
