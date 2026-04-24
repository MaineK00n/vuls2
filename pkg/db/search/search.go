package search

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

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

// KBExpandResult is the JSON-serialisable form of a kb-expand run.
type KBExpandResult struct {
	Inputs                      KBExpandInputs         `json:"inputs"`
	DataSources                 []sourceTypes.SourceID `json:"datasources,omitempty"`
	Covered                     []string               `json:"covered"`
	Unapplied                   []string               `json:"unapplied"`
	Conflicts                   []string               `json:"conflicts,omitempty"`
	Releases                    []string               `json:"releases,omitempty"`
	CoveredAfterReleaseFilter   []string               `json:"covered_after_release_filter,omitempty"`
	UnappliedAfterReleaseFilter []string               `json:"unapplied_after_release_filter,omitempty"`
	DroppedByRelease            *KBExpandDrop          `json:"dropped_by_release,omitempty"`
}

type KBExpandInputs struct {
	Applied   []string `json:"applied,omitempty"`
	Unapplied []string `json:"unapplied,omitempty"`
}

type KBExpandDrop struct {
	Covered   []string `json:"covered,omitempty"`
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

	slog.Info("Expand Microsoft KB", "applied", req.Applied, "unapplied", req.Unapplied, "datasources", req.DataSources)
	expandOpts := []microsoft.ExpandOption{}
	if len(req.DataSources) > 0 {
		expandOpts = append(expandOpts, microsoft.WithExpandDataSources(req.DataSources))
	}
	exp, err := microsoft.ExpandKBs(s.Storage(), req.Applied, req.Unapplied, expandOpts...)
	if err != nil {
		return errors.Wrap(err, "expand microsoft kb")
	}

	var (
		coveredAfter, unappliedAfter     []string
		coveredDropped, unappliedDropped []string
	)
	if len(req.Releases) > 0 {
		coveredAfter, coveredDropped, err = microsoft.PartitionKBIDsByReleases(s.Storage(), exp.Covered, req.Releases, expandOpts...)
		if err != nil {
			return errors.Wrap(err, "partition covered KBs by release")
		}
		unappliedAfter, unappliedDropped, err = microsoft.PartitionKBIDsByReleases(s.Storage(), exp.Unapplied, req.Releases, expandOpts...)
		if err != nil {
			return errors.Wrap(err, "partition unapplied KBs by release")
		}
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
		out.CoveredAfterReleaseFilter = coveredAfter
		out.UnappliedAfterReleaseFilter = unappliedAfter
		if len(coveredDropped) > 0 || len(unappliedDropped) > 0 {
			out.DroppedByRelease = &KBExpandDrop{
				Covered:   coveredDropped,
				Unapplied: unappliedDropped,
			}
		}
	}
	if err := json.MarshalWrite(os.Stdout, out); err != nil {
		return errors.Wrap(err, "encode kb-expand result")
	}
	return nil
}

func printKBExpandTree(w io.Writer, exp *microsoft.ExpandResult, datasources []sourceTypes.SourceID, releases []string, coveredAfter, unappliedAfter, coveredDropped, unappliedDropped []string) error {
	appliedSet := toSet(exp.Inputs.Applied)
	unappliedSet := toSet(exp.Inputs.Unapplied)
	coveredSet := toSet(exp.Covered)
	resultUnappliedSet := toSet(exp.Unapplied)

	classify := func(kbid string) string {
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
		return fmt.Sprintf("[%s]", joinComma(tags))
	}

	if _, err := fmt.Fprintln(w, "Inputs:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Applied:   %s\n", joinSpace(exp.Inputs.Applied)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Unapplied: %s\n", joinSpace(exp.Inputs.Unapplied)); err != nil {
		return err
	}
	if len(datasources) > 0 {
		dsStrs := make([]string, len(datasources))
		for i, d := range datasources {
			dsStrs[i] = string(d)
		}
		if _, err := fmt.Fprintf(w, "  Data sources: %s\n", joinSpace(dsStrs)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "Conflicts (in both Applied & Unapplied → treated as Unapplied):"); err != nil {
		return err
	}
	if len(exp.Conflicts) == 0 {
		if _, err := fmt.Fprintln(w, "  (none)"); err != nil {
			return err
		}
	} else {
		for _, kb := range exp.Conflicts {
			if _, err := fmt.Fprintf(w, "  %s\n", kb); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "Supersession chains:"); err != nil {
		return err
	}

	roots := make([]string, 0, len(exp.Inputs.Applied)+len(exp.Inputs.Unapplied))
	rootSeen := make(map[string]struct{})
	for _, kb := range exp.Inputs.Applied {
		if _, ok := rootSeen[kb]; ok {
			continue
		}
		rootSeen[kb] = struct{}{}
		roots = append(roots, kb)
	}
	for _, kb := range exp.Inputs.Unapplied {
		if _, ok := rootSeen[kb]; ok {
			continue
		}
		rootSeen[kb] = struct{}{}
		roots = append(roots, kb)
	}

	// incoming is the reverse of exp.Edges: incoming[X] lists edges whose To
	// is X, with To rewritten to point at the original "from" KB. Walking
	// incoming from a root surfaces the older KBs that root supersedes
	// (either via Supersedes on root, or via SupersededBy on those older
	// KBs). Without this, an input KB that sits at the newer end of its
	// chain would render with no children even though it covers older KBs.
	incoming := make(map[string][]microsoft.ExpandEdge, len(exp.Edges))
	for from, es := range exp.Edges {
		for _, e := range es {
			incoming[e.To] = append(incoming[e.To], microsoft.ExpandEdge{
				To:       from,
				Source:   e.Source,
				Level:    e.Level,
				UpdateID: e.UpdateID,
			})
		}
	}

	// emittedSubtree tracks nodes whose subtrees have already been printed
	// in this run. The first occurrence of a KB renders fully; subsequent
	// occurrences (across siblings, between forward/backward sections, or
	// from later roots) are collapsed with "(→ see above)" to keep the
	// tree readable in the presence of multiple data sources or
	// supersession cycles.
	emittedSubtree := make(map[string]struct{})
	for _, root := range roots {
		if _, err := fmt.Fprintf(w, "\n  %s  %s\n", root, classify(root)); err != nil {
			return err
		}
		emittedSubtree[root] = struct{}{}

		hasForward := len(exp.Edges[root]) > 0
		hasBackward := len(incoming[root]) > 0

		// When a root has neither direction (e.g., the input KB is unknown
		// to the database), keep the output minimal: just the root line.
		if !hasForward && !hasBackward {
			continue
		}

		if hasForward {
			if _, err := fmt.Fprintln(w, "    Superseded by:"); err != nil {
				return err
			}
			if err := writeKBExpandSubtree(w, exp.Edges, classify, root, "      ", emittedSubtree); err != nil {
				return err
			}
		}
		if hasBackward {
			if _, err := fmt.Fprintln(w, "    Supersedes:"); err != nil {
				return err
			}
			if err := writeKBExpandSubtree(w, incoming, classify, root, "      ", emittedSubtree); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "Result:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Covered:   %s\n", joinSpace(exp.Covered)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Unapplied: %s\n", joinSpace(exp.Unapplied)); err != nil {
		return err
	}

	if len(releases) > 0 {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "Release filter (%s):\n", formatReleases(releases)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Covered after filter:   %s\n", joinSpace(coveredAfter)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Unapplied after filter: %s\n", joinSpace(unappliedAfter)); err != nil {
			return err
		}
		dropped := append(append([]string{}, coveredDropped...), unappliedDropped...)
		slices.Sort(dropped)
		dropped = slices.Compact(dropped)
		if len(dropped) == 0 {
			if _, err := fmt.Fprintln(w, "  Dropped:                (none)"); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, "  Dropped:                %s\n", joinSpace(dropped)); err != nil {
				return err
			}
		}
	}

	return nil
}

func formatReleases(releases []string) string {
	if len(releases) == 1 {
		return fmt.Sprintf("%q", releases[0])
	}
	parts := make([]string, len(releases))
	for i, r := range releases {
		parts[i] = fmt.Sprintf("%q", r)
	}
	return "[" + joinComma(parts) + "]"
}

// writeKBExpandSubtree walks the adjacency map from the given node and
// writes each reachable edge as a tree branch. The adjacency map can be
// the forward map (exp.Edges) for the "Superseded by" view or the reverse
// map for the "Supersedes" view; the rendering is identical because the
// edge metadata (source, level, update id) describes the same logical
// relationship regardless of direction.
func writeKBExpandSubtree(w io.Writer, adj map[string][]microsoft.ExpandEdge, classify func(string) string, from string, indent string, emittedSubtree map[string]struct{}) error {
	edges := adj[from]
	if len(edges) == 0 {
		return nil
	}
	for i, e := range edges {
		last := i == len(edges)-1
		branch := "├─"
		nextIndent := indent + "│   "
		if last {
			branch = "└─"
			nextIndent = indent + "    "
		}
		var srcLabel string
		switch e.Level {
		case microsoft.ExpandEdgeLevelKB:
			srcLabel = fmt.Sprintf("%s, KB-level", e.Source)
		case microsoft.ExpandEdgeLevelUpdate:
			srcLabel = fmt.Sprintf("%s, Update %s", e.Source, e.UpdateID)
		default:
			srcLabel = string(e.Source)
		}
		if _, ok := emittedSubtree[e.To]; ok {
			if _, err := fmt.Fprintf(w, "%s%s [%s] %s  (→ see above)\n", indent, branch, srcLabel, e.To); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "%s%s [%s] %s  %s\n", indent, branch, srcLabel, e.To, classify(e.To)); err != nil {
			return err
		}
		emittedSubtree[e.To] = struct{}{}
		if err := writeKBExpandSubtree(w, adj, classify, e.To, nextIndent, emittedSubtree); err != nil {
			return err
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

func joinSpace(ss []string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
