package detect

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/detect/cpe"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
	"github.com/MaineK00n/vuls2/pkg/version"
)

type options struct {
	resultsDir string

	dbtype      string
	dbpath      string
	storageopts session.StorageOptions

	concurrency int

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

type storageoptsOption session.StorageOptions

func (o storageoptsOption) apply(opts *options) {
	opts.storageopts = session.StorageOptions(o)
}

func WithStorageOptions(storageopts session.StorageOptions) Option {
	return storageoptsOption(storageopts)
}

type concurrencyOption int

func (o concurrencyOption) apply(opts *options) {
	opts.concurrency = int(o)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
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

		dbtype:      "boltdb",
		dbpath:      filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		storageopts: session.StorageOptions{BoltDB: bolt.DefaultOptions},

		concurrency: 1,

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
			if err := json.UnmarshalRead(f, &sr); err != nil {
				return errors.Wrapf(err, "decode %s", filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "scan.json"))
			}

			slog.Info("Detect", "ServerUUID", sr.ServerUUID, "scanned", latest)
			dr, err := detect(s, sr, options.concurrency)
			if err != nil {
				return errors.Wrapf(err, "detect %s", sr.ServerUUID)
			}

			f, err = os.Create(filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "detect.json"))
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "detect.json"))
			}
			defer f.Close()

			if err := json.MarshalWrite(f, dr, jsontext.WithIndent("  ")); err != nil {
				return errors.Wrapf(err, "encode %s", filepath.Join(options.resultsDir, target, latest.Format("2006-01-02T15-04-05-0700"), "detect.json"))
			}

			return nil
		}(); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func detect(s *session.Session, sr scanTypes.ScanResult, concurrency int) (detectTypes.DetectResult, error) {
	detected := make(map[dataTypes.RootID]detectTypes.VulnerabilityData)

	m, err := ospkg.Detect(s.Storage(), sr, concurrency)
	if err != nil {
		return detectTypes.DetectResult{}, errors.Wrap(err, "detect os packages")
	}
	for rootID, d := range m {
		base, ok := detected[rootID]
		if !ok {
			base = detectTypes.VulnerabilityData{ID: rootID}
		}
		base.Detections = append(base.Detections, d)
		detected[rootID] = base
	}

	m, err = cpe.Detect(s.Storage(), sr, concurrency)
	if err != nil {
		return detectTypes.DetectResult{}, errors.Wrap(err, "detect cpe")
	}
	for rootID, d := range m {
		base, ok := detected[rootID]
		if !ok {
			base = detectTypes.VulnerabilityData{ID: rootID}
		}
		base.Detections = append(base.Detections, d)
		detected[rootID] = base
	}

	// Aggregate the evaluation warnings recorded on the FilteredCriteria
	// trees before the affected gate below prunes not-affected conditions —
	// an unevaluable criterion contributes "not affected", so its condition
	// is exactly the kind the gate drops, and collecting afterwards would
	// silently lose the recorded skips.
	warnings := collectWarnings(detected)

	// util.Detect now passes every condition through unconditionally, so
	// apply the per-condition Affected gate here for the default consumer
	// path. Conditions whose FilteredCriteria evaluates as not-affected are
	// dropped; Detections / VulnerabilityData that end up empty are pruned.
	detected, err = filterAffected(detected)
	if err != nil {
		return detectTypes.DetectResult{}, errors.Wrap(err, "filter affected")
	}

	for rootID, base := range detected {
		d, err := s.GetVulnerabilityData(rootID, dbTypes.Filter{
			Contents: []dbTypes.FilterContentType{
				dbTypes.FilterContentTypeAdvisories,
				dbTypes.FilterContentTypeVulnerabilities,
			},
		})
		if err != nil {
			return detectTypes.DetectResult{}, errors.Wrapf(err, "get vulnerability data with root id: %s", rootID)
		}
		base.Advisories = d.Advisories
		base.Vulnerabilities = d.Vulnerabilities
		detected[rootID] = base
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
			for sourceID := range d.Contents {
				if !slices.Contains(sourceIDs, sourceID) {
					sourceIDs = append(sourceIDs, sourceID)
				}
			}
		}
	}

	datasources := make([]datasourceTypes.DataSource, 0, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		ds, err := s.Storage().GetDataSource(sourceID)
		if err != nil {
			return detectTypes.DetectResult{}, errors.Wrapf(err, "get datasource with %s", sourceID)
		}
		datasources = append(datasources, ds)
	}

	return detectTypes.DetectResult{
		JSONVersion: 0,
		ServerUUID:  sr.ServerUUID,
		ServerName:  sr.ServerName,

		Detected:    slices.Collect(maps.Values(detected)),
		DataSources: datasources,
		Warnings:    warnings,

		DetectedAt: time.Now(),
		DetectedBy: version.String(),
	}, nil
}

// filterAffected drops conditions whose FilteredCriteria evaluates as
// not-affected, restoring the per-condition gate that util.Detect no longer
// applies. Detections with no remaining conditions and VulnerabilityData
// with no remaining detections are pruned. Callers of the lower-level
// ospkg.Detect / cpe.Detect / util.Detect that want to apply different
// filtering rules (e.g. ecosystem-specific relaxation) can do so without
// being short-circuited upstream.
// collectWarnings gathers the non-fatal evaluation warnings recorded on every
// FilteredCriterion across the detection results, deduplicated and in
// warning.Compare order for deterministic output.
func collectWarnings(detected map[dataTypes.RootID]detectTypes.VulnerabilityData) []warningTypes.Warning {
	var ws []warningTypes.Warning
	var walk func(fca criteriaTypes.FilteredCriteria)
	walk = func(fca criteriaTypes.FilteredCriteria) {
		for _, ca := range fca.Criterias {
			walk(ca)
		}
		for _, cn := range fca.Criterions {
			for _, w := range cn.Warnings {
				if !slices.Contains(ws, w) {
					ws = append(ws, w)
				}
			}
		}
	}
	for _, data := range detected {
		for _, d := range data.Detections {
			for _, conds := range d.Contents {
				for _, cond := range conds {
					walk(cond.Criteria)
				}
			}
		}
	}
	slices.SortFunc(ws, warningTypes.Compare)
	return ws
}

func filterAffected(detected map[dataTypes.RootID]detectTypes.VulnerabilityData) (map[dataTypes.RootID]detectTypes.VulnerabilityData, error) {
	out := make(map[dataTypes.RootID]detectTypes.VulnerabilityData, len(detected))
	for rootID, data := range detected {
		keptDetections := make([]detectTypes.VulnerabilityDataDetection, 0, len(data.Detections))
		for _, d := range data.Detections {
			keptContents := make(map[sourceTypes.SourceID][]conditionTypes.FilteredCondition, len(d.Contents))
			for sid, conds := range d.Contents {
				kept := make([]conditionTypes.FilteredCondition, 0, len(conds))
				for _, cond := range conds {
					// Route through FilteredCondition.Affected() (rather than
					// Criteria.Affected() directly) so any future per-condition
					// logic added to the upstream type is picked up here.
					isAffected, err := cond.Affected()
					if err != nil {
						return nil, errors.Wrapf(err, "condition affected (rootID: %s, sourceID: %s)", rootID, sid)
					}
					if isAffected {
						kept = append(kept, cond)
					}
				}
				if len(kept) > 0 {
					keptContents[sid] = kept
				}
			}
			if len(keptContents) == 0 {
				continue
			}
			d.Contents = keptContents
			keptDetections = append(keptDetections, d)
		}
		if len(keptDetections) == 0 {
			continue
		}
		data.Detections = keptDetections
		out[rootID] = data
	}
	return out, nil
}
