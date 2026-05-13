package search

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg/microsoft"
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

func SearchKBInfo(queries []string, datasources []sourceTypes.SourceID, opts ...Option) error {
	options := &options{
		dbtype:      "boltdb",
		dbpath:      filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		storageopts: session.StorageOptions{BoltDB: bolt.DefaultOptions},
		debug:       false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	s, err := (&session.Config{
		Type:    options.dbtype,
		Path:    options.dbpath,
		Debug:   options.debug,
		Options: options.storageopts,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

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

	slog.Info("Get Microsoft KB", "kb", queries)
	for _, query := range queries {
		kb, err := s.Storage().GetMicrosoftKB(query)
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundMicrosoftKB) {
				slog.Warn(err.Error())
				continue
			}
			return errors.Wrap(err, "get microsoft kb")
		}

		if len(datasources) > 0 {
			filtered := make(map[sourceTypes.SourceID]microsoftkbTypes.KB, len(kb))
			for id, v := range kb {
				if slices.Contains(datasources, id) {
					filtered[id] = v
				}
			}
			kb = filtered
		}
		if err := json.MarshalWrite(os.Stdout, kb); err != nil {
			return errors.Wrapf(err, "encode kb %s", query)
		}
	}

	return nil
}

func SearchKBVuln(queries []string, datasources []sourceTypes.SourceID, opts ...Option) error {
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

	slog.Info("Get Vulnerability Data by KB ID", "kb", queries)
	for d, err := range s.GetVulnerabilityDataByKBID(queries, datasources, options.filter) {
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundMicrosoftKB) {
				slog.Warn(err.Error())
				continue
			}
			return errors.Wrap(err, "get vulnerability data by kb id")
		}
		if err := json.MarshalWrite(os.Stdout, d); err != nil {
			return errors.Wrapf(err, "encode %s", d.ID)
		}
	}

	return nil
}

// KBExpandResult is the JSON-serialisable summary of a kb-expand run.
// It carries the classification (Covered / Unapplied / Conflicts) plus
// the post-filter views, but intentionally omits the per-edge data-source
// attribution and per-KB products that ExpandKBs collects; those are
// rendered only by --explain, which gives chain-walking diagnostics a
// human-friendly tree without expanding the JSON surface.
//
// Fields are ordered by lifecycle: inputs, then filter inputs, then the
// covered/unapplied results paired with their post-filter views. The
// covered_after_filter / *_dropped_by_filter fields are populated only
// when Releases (and optionally DataSources) was supplied; the Releases
// and DataSources fields carry the filter context.
type KBExpandResult struct {
	Inputs                   KBExpandInputs         `json:"inputs"`
	Conflicts                []string               `json:"conflicts,omitempty"`
	DataSources              []sourceTypes.SourceID `json:"datasources,omitempty"`
	Releases                 []string               `json:"releases,omitempty"`
	Covered                  []string               `json:"covered"`
	CoveredAfterFilter       []string               `json:"covered_after_filter,omitempty"`
	CoveredDroppedByFilter   []string               `json:"covered_dropped_by_filter,omitempty"`
	Unapplied                []string               `json:"unapplied"`
	UnappliedAfterFilter     []string               `json:"unapplied_after_filter,omitempty"`
	UnappliedDroppedByFilter []string               `json:"unapplied_dropped_by_filter,omitempty"`
}

type KBExpandInputs struct {
	Applied   []string `json:"applied,omitempty"`
	Unapplied []string `json:"unapplied,omitempty"`
}

// KBExpandRequest captures the inputs and filters for a kb-expand run.
type KBExpandRequest struct {
	Applied     []string
	Unapplied   []string
	Releases    []string
	DataSources []sourceTypes.SourceID
	Explain     bool
}

// SearchKBExpand expands the given Applied/Unapplied KB inputs through
// Microsoft KB supersession chains using the same logic detect uses, and
// reports the resulting Covered/Unapplied classification. When Releases is
// non-empty, also applies the same release filter detect applies (with union
// semantics across releases) and reports what was dropped. When DataSources
// is non-empty, only edges and products contributed by those sources are
// considered. When Explain is true, renders a human-readable tree instead
// of JSON.
func SearchKBExpand(req KBExpandRequest, opts ...Option) error {
	options := &options{
		dbtype:      "boltdb",
		dbpath:      filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		storageopts: session.StorageOptions{BoltDB: bolt.DefaultOptions},
		debug:       false,
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

	slog.Info("Expand Microsoft KB", "applied", req.Applied, "unapplied", req.Unapplied, "datasources", req.DataSources)
	exp, err := microsoft.ExpandKBs(s.Storage(), req.Applied, req.Unapplied, req.DataSources)
	if err != nil {
		return errors.Wrap(err, "expand microsoft kb")
	}

	var (
		coveredAfter, unappliedAfter     []string
		coveredDropped, unappliedDropped []string
	)
	if len(req.Releases) > 0 {
		coveredAfter, coveredDropped = microsoft.PartitionKBIDsByReleases(exp.Products, exp.Covered, req.Releases)
		unappliedAfter, unappliedDropped = microsoft.PartitionKBIDsByReleases(exp.Products, exp.Unapplied, req.Releases)
	}

	// Sort once here so the JSON and tree outputs are deterministic.
	// ExpandKBs returns slices in map-iteration order and
	// PartitionKBIDsByReleases preserves input order, so sorting after
	// Partition leaves the kept/dropped slices consistent with their
	// already-sorted source. The per-node edge slices in exp.Edges are
	// also sorted because multi-source edges (e.g. cvrf + msuc both
	// reporting the same SupersededBy) would otherwise render in storage
	// map-iteration order.
	slices.Sort(exp.Covered)
	slices.Sort(exp.Unapplied)
	slices.Sort(exp.Conflicts)
	slices.Sort(coveredAfter)
	slices.Sort(unappliedAfter)
	slices.Sort(coveredDropped)
	slices.Sort(unappliedDropped)
	for _, es := range exp.Edges {
		slices.SortFunc(es, func(a, b microsoft.ExpandEdge) int {
			return cmp.Or(
				cmp.Compare(a.To, b.To),
				cmp.Compare(string(a.Source), string(b.Source)),
				cmp.Compare(int(a.Level), int(b.Level)),
				cmp.Compare(a.UpdateID, b.UpdateID),
			)
		})
	}

	if req.Explain {
		return printKBExpandTree(os.Stdout, exp, req.DataSources, req.Releases, coveredAfter, unappliedAfter, coveredDropped, unappliedDropped)
	}

	out := KBExpandResult{
		Inputs:      KBExpandInputs{Applied: req.Applied, Unapplied: req.Unapplied},
		DataSources: req.DataSources,
		Covered:     exp.Covered,
		Unapplied:   exp.Unapplied,
		Conflicts:   exp.Conflicts,
	}
	if len(req.Releases) > 0 {
		out.Releases = req.Releases
		out.CoveredAfterFilter = coveredAfter
		out.UnappliedAfterFilter = unappliedAfter
		out.CoveredDroppedByFilter = coveredDropped
		out.UnappliedDroppedByFilter = unappliedDropped
	}
	if err := json.MarshalWrite(os.Stdout, out); err != nil {
		return errors.Wrap(err, "encode kb-expand result")
	}
	return nil
}

func printKBExpandTree(w io.Writer, exp *microsoft.ExpandResult, datasources []sourceTypes.SourceID, releases []string, coveredAfter, unappliedAfter, coveredDropped, unappliedDropped []string) error {
	classify := makeKBExpandClassifier(exp)

	if err := writeKBExpandInputs(w, exp.Inputs, datasources); err != nil {
		return errors.Wrap(err, "write inputs section")
	}
	if err := writeKBExpandConflicts(w, exp.Conflicts); err != nil {
		return errors.Wrap(err, "write conflicts section")
	}
	if err := writeKBExpandChains(w, exp, classify); err != nil {
		return errors.Wrap(err, "write supersession chains section")
	}
	if err := writeKBExpandResult(w, exp); err != nil {
		return errors.Wrap(err, "write result section")
	}
	if len(releases) > 0 {
		if err := writeKBExpandFilter(w, releases, coveredAfter, unappliedAfter, coveredDropped, unappliedDropped); err != nil {
			return errors.Wrap(err, "write release filter section")
		}
	}
	return nil
}

func makeKBExpandClassifier(exp *microsoft.ExpandResult) func(string) string {
	appliedSet := toSet(exp.Inputs.Applied)
	unappliedSet := toSet(exp.Inputs.Unapplied)
	coveredSet := toSet(exp.Covered)
	resultUnappliedSet := toSet(exp.Unapplied)
	return func(kbid string) string {
		var tags []string
		_, isAppliedInput := appliedSet[kbid]
		_, isUnappliedInput := unappliedSet[kbid]
		switch {
		case isAppliedInput && isUnappliedInput:
			tags = append(tags, "input:applied", "input:unapplied", "conflict→unapplied")
		case isAppliedInput:
			tags = append(tags, "input:applied")
		case isUnappliedInput:
			tags = append(tags, "input:unapplied")
		default:
			tags = append(tags, "discovered")
		}
		if _, ok := coveredSet[kbid]; ok {
			tags = append(tags, "covered")
		}
		if _, ok := resultUnappliedSet[kbid]; ok {
			tags = append(tags, "unapplied")
		}
		return fmt.Sprintf("[%s]", strings.Join(tags, ", "))
	}
}

func writeKBExpandInputs(w io.Writer, in microsoft.ExpandInputs, datasources []sourceTypes.SourceID) error {
	if _, err := fmt.Fprintf(w, "Inputs:\n  Applied:   %s\n  Unapplied: %s\n", joinKBList(in.Applied), joinKBList(in.Unapplied)); err != nil {
		return errors.Wrap(err, "write inputs header")
	}
	if len(datasources) > 0 {
		dsStrs := make([]string, len(datasources))
		for i, d := range datasources {
			dsStrs[i] = string(d)
		}
		if _, err := fmt.Fprintf(w, "  Data sources: %s\n", joinKBList(dsStrs)); err != nil {
			return errors.Wrap(err, "write data sources")
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return errors.Wrap(err, "write inputs trailing newline")
	}
	return nil
}

func writeKBExpandConflicts(w io.Writer, conflicts []string) error {
	if _, err := fmt.Fprintln(w, "Conflicts (in both Applied & Unapplied → treated as Unapplied):"); err != nil {
		return errors.Wrap(err, "write conflicts header")
	}
	if len(conflicts) == 0 {
		if _, err := fmt.Fprintln(w, "  (none)"); err != nil {
			return errors.Wrap(err, "write empty conflicts marker")
		}
	} else {
		for _, kb := range conflicts {
			if _, err := fmt.Fprintf(w, "  %s\n", kb); err != nil {
				return errors.Wrapf(err, "write conflict %s", kb)
			}
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return errors.Wrap(err, "write conflicts trailing newline")
	}
	return nil
}

// directedNeighbor is an edge in the unified bidirectional adjacency used by
// the explain tree, consolidated by (To, Source, Direction). All KB-level
// and Update-level attestations from the same data source pointing in the
// same direction to the same target are merged into a single neighbor so
// that the tree shows one line per (data source, direction) pair rather
// than one line per Update. The original UpdateIDs are preserved in the
// label.
//
// Newer=true means "To" is a KB that supersedes the source node (the source
// is superseded by To); Newer=false means "To" is an older KB that the
// source node supersedes.
type directedNeighbor struct {
	To        string
	Source    sourceTypes.SourceID
	Newer     bool
	HasKB     bool     // true when at least one KB-level edge contributes
	UpdateIDs []string // sorted, deduplicated Update IDs (empty when no Update-level edge)
}

// buildKBExpandNeighbors merges exp.Edges and its reverse into one adjacency
// keyed by node, where every edge carries an explicit direction and all
// attestations of the same (target, source, direction) tuple are
// consolidated. This lets the tree printer descend through any KB the
// bidirectional walk in microsoft.ExpandKBs discovered (including KBs
// reached via mixed-direction chains) without exploding the output with one
// line per MSUC Update.
func buildKBExpandNeighbors(edges map[string][]microsoft.ExpandEdge) map[string][]directedNeighbor {
	type groupKey struct {
		From, To string
		Source   sourceTypes.SourceID
		Newer    bool
	}
	type groupAgg struct {
		hasKB     bool
		updateIDs map[string]struct{}
	}
	groups := make(map[groupKey]*groupAgg)
	addContribution := func(from, to string, source sourceTypes.SourceID, level microsoft.ExpandEdgeLevel, updateID string, newer bool) {
		k := groupKey{From: from, To: to, Source: source, Newer: newer}
		g, ok := groups[k]
		if !ok {
			g = &groupAgg{updateIDs: make(map[string]struct{})}
			groups[k] = g
		}
		switch level {
		case microsoft.ExpandEdgeLevelKB:
			g.hasKB = true
		case microsoft.ExpandEdgeLevelUpdate:
			if updateID != "" {
				g.updateIDs[updateID] = struct{}{}
			}
		}
	}
	for from, es := range edges {
		for _, e := range es {
			addContribution(from, e.To, e.Source, e.Level, e.UpdateID, true)
			addContribution(e.To, from, e.Source, e.Level, e.UpdateID, false)
		}
	}

	neighbors := make(map[string][]directedNeighbor, len(groups))
	for k, g := range groups {
		ids := make([]string, 0, len(g.updateIDs))
		for id := range g.updateIDs {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		neighbors[k.From] = append(neighbors[k.From], directedNeighbor{
			To:        k.To,
			Source:    k.Source,
			Newer:     k.Newer,
			HasKB:     g.hasKB,
			UpdateIDs: ids,
		})
	}
	// Sort each adjacency list so that forward (newer) edges appear before
	// backward (older) edges, then by (To, Source). Sorting "newer first"
	// preserves the section ordering ("Superseded by:" before "Supersedes:")
	// that previous releases established for the root.
	for _, ns := range neighbors {
		slices.SortFunc(ns, func(a, b directedNeighbor) int {
			var an, bn int
			if !a.Newer {
				an = 1
			}
			if !b.Newer {
				bn = 1
			}
			return cmp.Or(
				cmp.Compare(an, bn),
				cmp.Compare(a.To, b.To),
				cmp.Compare(string(a.Source), string(b.Source)),
			)
		})
	}
	return neighbors
}

func writeKBExpandChains(w io.Writer, exp *microsoft.ExpandResult, classify func(string) string) error {
	if _, err := fmt.Fprintln(w, "Supersession chains:"); err != nil {
		return errors.Wrap(err, "write chains header")
	}

	roots := dedupedRoots(exp.Inputs.Applied, exp.Inputs.Unapplied)
	neighbors := buildKBExpandNeighbors(exp.Edges)

	// emittedSubtree tracks nodes whose subtrees have already been printed
	// in this run. The first occurrence of a KB renders fully; subsequent
	// occurrences (across siblings, between forward/backward sections, or
	// from later roots) are collapsed with "(→ see above)" to keep the
	// tree readable in the presence of multiple data sources or
	// supersession cycles.
	emittedSubtree := make(map[string]struct{})
	for _, root := range roots {
		if _, err := fmt.Fprintf(w, "\n  %s  %s\n", root, classify(root)); err != nil {
			return errors.Wrapf(err, "write root %s", root)
		}
		emittedSubtree[root] = struct{}{}

		var fwd, bwd []directedNeighbor
		for _, n := range neighbors[root] {
			if n.Newer {
				fwd = append(fwd, n)
			} else {
				bwd = append(bwd, n)
			}
		}
		if len(fwd) == 0 && len(bwd) == 0 {
			continue
		}
		if len(fwd) > 0 {
			if _, err := fmt.Fprintln(w, "    Superseded by:"); err != nil {
				return errors.Wrapf(err, "write Superseded by header for root %s", root)
			}
			if err := writeKBExpandSubtree(w, neighbors, classify, fwd, root, "      ", emittedSubtree); err != nil {
				return errors.Wrapf(err, "write Superseded by subtree for root %s", root)
			}
		}
		if len(bwd) > 0 {
			if _, err := fmt.Fprintln(w, "    Supersedes:"); err != nil {
				return errors.Wrapf(err, "write Supersedes header for root %s", root)
			}
			if err := writeKBExpandSubtree(w, neighbors, classify, bwd, root, "      ", emittedSubtree); err != nil {
				return errors.Wrapf(err, "write Supersedes subtree for root %s", root)
			}
		}
	}
	return nil
}

func writeKBExpandResult(w io.Writer, exp *microsoft.ExpandResult) error {
	if _, err := fmt.Fprintf(w, "\nResult:\n  Covered:   %s\n  Unapplied: %s\n", joinKBList(exp.Covered), joinKBList(exp.Unapplied)); err != nil {
		return errors.Wrap(err, "write result section")
	}
	return nil
}

func writeKBExpandFilter(w io.Writer, releases, coveredAfter, unappliedAfter, coveredDropped, unappliedDropped []string) error {
	dropped := append(append([]string{}, coveredDropped...), unappliedDropped...)
	slices.Sort(dropped)
	dropped = slices.Compact(dropped)
	if _, err := fmt.Fprintf(w, "\nRelease filter (%s):\n  Covered after filter:   %s\n  Unapplied after filter: %s\n  Dropped:                %s\n",
		formatReleases(releases),
		joinKBList(coveredAfter),
		joinKBList(unappliedAfter),
		joinKBList(dropped),
	); err != nil {
		return errors.Wrap(err, "write filter section")
	}
	return nil
}

func dedupedRoots(applied, unapplied []string) []string {
	// applied/unapplied echo raw user input (Inputs.Applied/Unapplied), so
	// drop empty entries here — ExpandKBs treats them as inert at walk
	// time, and rendering a blank "Supersession chains:" root would be
	// misleading.
	roots := slices.DeleteFunc(slices.Concat(applied, unapplied), func(s string) bool { return s == "" })
	slices.Sort(roots)
	return slices.Compact(roots)
}

func formatReleases(releases []string) string {
	if len(releases) == 1 {
		return fmt.Sprintf("%q", releases[0])
	}
	quoted := make([]string, len(releases))
	for i, r := range releases {
		quoted[i] = fmt.Sprintf("%q", r)
	}
	return fmt.Sprintf("[%s]", strings.Join(quoted, ", "))
}

// writeKBExpandSubtree renders edges as tree branches and recursively walks
// neighbors of each target, descending bidirectionally through the unified
// adjacency. Each edge label includes a "newer" / "older" direction tag so
// that mixed-direction chains (a backward step followed by a forward step,
// or vice versa) remain self-describing in a single tree.
//
// When recursing into a child, edges back to the immediate parent are
// skipped to suppress noisy "(→ see above)" lines for the parent at every
// node. Cycles between non-parent ancestors are still surfaced through
// emittedSubtree's "(→ see above)" marker.
func writeKBExpandSubtree(w io.Writer, neighbors map[string][]directedNeighbor, classify func(string) string, edges []directedNeighbor, parent string, indent string, emittedSubtree map[string]struct{}) error {
	for i, e := range edges {
		branch, nextIndent := "├─", fmt.Sprintf("%s│   ", indent)
		if i == len(edges)-1 {
			branch, nextIndent = "└─", fmt.Sprintf("%s    ", indent)
		}
		// Direction label uses the same vocabulary as the section headers
		// ("Superseded by:" / "Supersedes:") with the parent as the implicit
		// subject. Newer=true means the parent is superseded by the child;
		// Newer=false means the parent supersedes the child.
		dirLabel := "superseded by"
		if !e.Newer {
			dirLabel = "supersedes"
		}
		// Attestations of the same (To, Source, Direction) are consolidated
		// into one label. The form is always "Updates <id1>, <id2>, ..."
		// (plural even for one Update) so the visual structure stays the
		// same regardless of the attestation count, and the trailing
		// direction word remains an unambiguous label terminator.
		var levelParts []string
		if e.HasKB {
			levelParts = append(levelParts, "KB-level")
		}
		if len(e.UpdateIDs) > 0 {
			levelParts = append(levelParts, "Updates "+strings.Join(e.UpdateIDs, ", "))
		}
		var srcLabel string
		if len(levelParts) > 0 {
			srcLabel = fmt.Sprintf("%s, %s, %s", e.Source, strings.Join(levelParts, " + "), dirLabel)
		} else {
			srcLabel = fmt.Sprintf("%s, %s", e.Source, dirLabel)
		}
		if _, ok := emittedSubtree[e.To]; ok {
			if _, err := fmt.Fprintf(w, "%s%s [%s] %s  (→ see above)\n", indent, branch, srcLabel, e.To); err != nil {
				return errors.Wrapf(err, "write subtree edge %s -> %s", parent, e.To)
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "%s%s [%s] %s  %s\n", indent, branch, srcLabel, e.To, classify(e.To)); err != nil {
			return errors.Wrapf(err, "write subtree edge %s -> %s", parent, e.To)
		}
		emittedSubtree[e.To] = struct{}{}

		var childEdges []directedNeighbor
		for _, n := range neighbors[e.To] {
			if n.To == parent {
				continue
			}
			childEdges = append(childEdges, n)
		}
		if err := writeKBExpandSubtree(w, neighbors, classify, childEdges, e.To, nextIndent, emittedSubtree); err != nil {
			return errors.Wrapf(err, "walk subtree under %s", e.To)
		}
	}
	return nil
}

func toSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

func joinKBList(ss []string) string {
	// Some callers pass raw Inputs.Applied/Unapplied which may contain
	// "" entries (ExpandKBs skips them but echoes the input verbatim).
	// Filter on a clone to avoid mutating the caller's slice.
	filtered := slices.DeleteFunc(slices.Clone(ss), func(s string) bool { return s == "" })
	if len(filtered) == 0 {
		return "(none)"
	}
	return strings.Join(filtered, " ")
}
