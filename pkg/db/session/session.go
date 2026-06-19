package session

import (
	"iter"
	"maps"
	"slices"

	"github.com/pkg/errors"
	"github.com/redis/rueidis"
	bolt "go.etcd.io/bbolt"
	"gorm.io/gorm"

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
	kindTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/kind"
	capecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/boltdb"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/cache"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/rdb"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/redis"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
)

type Storage interface {
	Open() error
	Close() error

	GetMetadata() (*dbTypes.Metadata, error)
	PutMetadata(dbTypes.Metadata) error

	Put(string) error
	GetRoot(dataTypes.RootID) (dbTypes.VulnerabilityData, error)
	GetAdvisory(advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error)
	GetVulnerability(vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error)
	GetEcosystems() ([]ecosystemTypes.Ecosystem, error)
	GetIndex(ecosystemTypes.Ecosystem, string) ([]dataTypes.RootID, error)
	GetDetection(ecosystemTypes.Ecosystem, dataTypes.RootID) (map[sourceTypes.SourceID][]conditionTypes.Condition, error)
	GetMicrosoftKB(string) (map[sourceTypes.SourceID]microsoftkbTypes.KB, error)
	GetAttack(kindTypes.Kind, string) (map[sourceTypes.SourceID]attackTypes.Attack, error)
	GetCAPEC(string) (map[sourceTypes.SourceID]capecTypes.CAPEC, error)
	GetCWE(string) (map[sourceTypes.SourceID]cweTypes.CWE, error)
	GetDataSources() ([]datasourceTypes.DataSource, error)
	GetDataSource(sourceTypes.SourceID) (datasourceTypes.DataSource, error)

	DeleteAll() error
	Initialize() error
}

type Config struct {
	Type      string
	Path      string
	Debug     bool
	Options   StorageOptions
	WithCache bool
}

type StorageOptions struct {
	BoltDB *bolt.Options
	Redis  *rueidis.ClientOption
	RDB    []gorm.Option
}

type Session struct {
	storage Storage
	cache   *cache.Cache
}

func (c Config) New() (*Session, error) {
	s, err := func() (Storage, error) {
		switch c.Type {
		case "boltdb":
			return &boltdb.Connection{Config: &boltdb.Config{Path: c.Path, Options: c.Options.BoltDB}}, nil
		case "redis":
			conf := c.Options.Redis
			if conf == nil {
				c, err := rueidis.ParseURL(c.Path)
				if err != nil {
					return nil, errors.Wrap(err, "parse redis url")
				}
				conf = &c
			}
			return &redis.Connection{Config: conf}, nil
		case "sqlite3", "mysql", "postgres":
			return &rdb.Connection{Config: &rdb.Config{Type: c.Type, Path: c.Path, Options: c.Options.RDB}}, nil
		default:
			return nil, errors.Errorf("%s is not support dbtype", c.Type)
		}
	}()
	if err != nil {
		return nil, errors.Wrap(err, "new db connection")
	}
	sesh := &Session{
		storage: s,
		cache: func() *cache.Cache {
			if c.WithCache {
				return cache.New()
			}
			return nil
		}(),
	}
	return sesh, nil
}

func (s Session) Storage() Storage {
	return s.storage
}

func (s Session) Cache() *cache.Cache {
	return s.cache
}

func SchemaVersion(t string) (uint, error) {
	switch t {
	case "boltdb":
		return boltdb.SchemaVersion, nil
	case "redis":
		return redis.SchemaVersion, nil
	case "sqlite3", "mysql", "postgres":
		return rdb.SchemaVersion, nil
	default:
		return 0, errors.Errorf("%s is not support dbtype", t)
	}
}

func (s Session) GetVulnerabilityData(id dataTypes.RootID, filter dbTypes.Filter) (dbTypes.VulnerabilityData, error) {
	root := dbTypes.VulnerabilityData{ID: string(id)}

	if filter.ExcludesRootID(id) {
		return root, nil
	}

	r, err := s.Storage().GetRoot(id)
	if err != nil {
		return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
	}

	r = filter.ApplyShallowly(r)

	for _, a := range r.Advisories {
		m, err := s.getAdvisory(a.ID)
		if err != nil {
			return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get advisory")
		}

		m = filter.ApplyToAdvisories(m)
		if len(m) == 0 {
			continue
		}

		root.Advisories = append(root.Advisories, dbTypes.VulnerabilityDataAdvisory{
			ID:       a.ID,
			Contents: m,
		})
	}

	for _, v := range r.Vulnerabilities {
		m, err := s.getVulnerability(v.ID)
		if err != nil {
			return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
		}

		m = filter.ApplyToVulnerabilities(m)
		if len(m) == 0 {
			continue
		}

		root.Vulnerabilities = append(root.Vulnerabilities, dbTypes.VulnerabilityDataVulnerability{
			ID:       v.ID,
			Contents: m,
		})
	}

	for _, d := range r.Detections {
		if filter.ExcludesEcosystem(d.Ecosystem) {
			continue
		}

		m, err := s.Storage().GetDetection(d.Ecosystem, id)
		if err != nil {
			return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get detection")
		}

		m = filter.ApplyToDetections(m)
		if len(m) == 0 {
			continue
		}

		root.Detections = append(root.Detections, dbTypes.VulnerabilityDataDetection{
			Ecosystem: d.Ecosystem,
			Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{id: m},
		})
	}

	for _, datasource := range r.DataSources {
		if filter.ExcludesDataSource(datasource.ID) {
			continue
		}

		ds, err := s.Storage().GetDataSource(datasource.ID)
		if err != nil {
			return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get datasource")
		}

		root.DataSources = append(root.DataSources, ds)
	}

	return root, nil
}

func (s Session) GetVulnerabilityDataByAdvisoryID(id advisoryContentTypes.AdvisoryID, filter dbTypes.Filter) (dbTypes.VulnerabilityData, error) {
	root := dbTypes.VulnerabilityData{ID: string(id)}

	am, err := s.getAdvisory(id)
	if err != nil {
		return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get advisory")
	}

	am = filter.ApplyToAdvisories(am)
	if len(am) == 0 {
		return root, nil
	}

	if slices.Contains(filter.Contents, dbTypes.FilterContentTypeAdvisories) {
		root.Advisories = []dbTypes.VulnerabilityDataAdvisory{
			{
				ID:       id,
				Contents: am,
			},
		}
	}

	for rootID := range func() iter.Seq[dataTypes.RootID] {
		return func(yield func(dataTypes.RootID) bool) {
			for _, m := range am {
				for rootID := range m {
					if !yield(rootID) {
						return
					}
				}
			}
		}
	}() {
		d, err := s.GetVulnerabilityData(rootID, dbTypes.Filter{
			Contents:    slices.DeleteFunc(filter.Contents, func(e dbTypes.FilterContentType) bool { return e == dbTypes.FilterContentTypeAdvisories }),
			DataSources: filter.DataSources,
			Ecosystems:  filter.Ecosystems,
			RootIDs:     filter.RootIDs,
		})
		if err != nil {
			return dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by root id: %s", rootID)
		}

		for _, v := range d.Vulnerabilities {
			if !slices.ContainsFunc(root.Vulnerabilities, func(e dbTypes.VulnerabilityDataVulnerability) bool {
				return e.ID == v.ID
			}) {
				root.Vulnerabilities = append(root.Vulnerabilities, v)
			}
		}

		for _, dd := range d.Detections {
			switch i := slices.IndexFunc(root.Detections, func(e dbTypes.VulnerabilityDataDetection) bool { return e.Ecosystem == dd.Ecosystem }); i {
			case -1:
				root.Detections = append(root.Detections, dd)
			default:
				rd := root.Detections[i]
				maps.Copy(rd.Contents, dd.Contents)
				root.Detections[i] = rd
			}
		}

		for _, ds := range d.DataSources {
			if !slices.ContainsFunc(root.DataSources, func(e datasourceTypes.DataSource) bool {
				return e.ID == ds.ID
			}) {
				root.DataSources = append(root.DataSources, ds)
			}
		}
	}

	return root, nil
}

func (s Session) GetVulnerabilityDataByVulnerabilityID(id vulnerabilityContentTypes.VulnerabilityID, filter dbTypes.Filter) (dbTypes.VulnerabilityData, error) {
	root := dbTypes.VulnerabilityData{ID: string(id)}

	vm, err := s.getVulnerability(id)
	if err != nil {
		return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
	}

	vm = filter.ApplyToVulnerabilities(vm)
	if len(vm) == 0 {
		return root, nil
	}

	if slices.Contains(filter.Contents, dbTypes.FilterContentTypeVulnerabilities) {
		root.Vulnerabilities = []dbTypes.VulnerabilityDataVulnerability{
			{
				ID:       id,
				Contents: vm,
			},
		}
	}

	for rootID := range func() iter.Seq[dataTypes.RootID] {
		return func(yield func(dataTypes.RootID) bool) {
			for _, m := range vm {
				for rootID := range m {
					if !yield(rootID) {
						return
					}
				}
			}
		}
	}() {
		d, err := s.GetVulnerabilityData(rootID, dbTypes.Filter{
			Contents:    slices.DeleteFunc(filter.Contents, func(e dbTypes.FilterContentType) bool { return e == dbTypes.FilterContentTypeVulnerabilities }),
			DataSources: filter.DataSources,
			Ecosystems:  filter.Ecosystems,
			RootIDs:     filter.RootIDs,
		})
		if err != nil {
			return dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by root id: %s", rootID)
		}

		for _, a := range d.Advisories {
			if !slices.ContainsFunc(root.Advisories, func(e dbTypes.VulnerabilityDataAdvisory) bool {
				return e.ID == a.ID
			}) {
				root.Advisories = append(root.Advisories, a)
			}
		}

		for _, dd := range d.Detections {
			switch i := slices.IndexFunc(root.Detections, func(e dbTypes.VulnerabilityDataDetection) bool { return e.Ecosystem == dd.Ecosystem }); i {
			case -1:
				root.Detections = append(root.Detections, dd)
			default:
				rd := root.Detections[i]
				maps.Copy(rd.Contents, dd.Contents)
				root.Detections[i] = rd
			}
		}

		for _, ds := range d.DataSources {
			if !slices.ContainsFunc(root.DataSources, func(e datasourceTypes.DataSource) bool {
				return e.ID == ds.ID
			}) {
				root.DataSources = append(root.DataSources, ds)
			}
		}
	}

	return root, nil
}

func (s Session) GetVulnerabilityDataByPackage(ecosystem ecosystemTypes.Ecosystem, packages []string, filter dbTypes.Filter) iter.Seq2[dbTypes.VulnerabilityData, error] {
	return func(yield func(dbTypes.VulnerabilityData, error) bool) {
		if filter.ExcludesEcosystem(ecosystem) {
			return
		}

		im := make(map[dataTypes.RootID][]string)
		for _, p := range packages {
			rs, err := s.Storage().GetIndex(ecosystem, p)
			if err != nil {
				if !yield(dbTypes.VulnerabilityData{}, errors.Wrap(err, "get index")) {
					return
				}
				return
			}
			for _, r := range rs {
				if filter.ExcludesRootID(r) {
					continue
				}
				im[r] = append(im[r], p)
			}
		}

		for rootID := range im {
			d, err := s.GetVulnerabilityData(rootID, filter)
			if err != nil {
				if !yield(dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by root id: %s", rootID)) {
					return
				}
				return
			}

			d.Detections = func() []dbTypes.VulnerabilityDataDetection {
				var ds []dbTypes.VulnerabilityDataDetection
				for _, dd := range d.Detections {
					if dd.Ecosystem == ecosystem {
						ds = append(ds, dbTypes.VulnerabilityDataDetection{
							Ecosystem: dd.Ecosystem,
							Contents:  dd.Contents,
						})
					}
				}
				return ds
			}()

			if !yield(d, nil) {
				return
			}
		}
	}
}

func (s Session) GetVulnerabilityDataByKBID(kbIDs []string, datasources []sourceTypes.SourceID, filter dbTypes.Filter) iter.Seq2[dbTypes.VulnerabilityData, error] {
	return func(yield func(dbTypes.VulnerabilityData, error) bool) {
		if filter.ExcludesEcosystem(ecosystemTypes.EcosystemTypeMicrosoft) {
			return
		}

		// Collect all products from all KB IDs, then deduplicate rootIDs.
		products := make(map[string]struct{})
		for _, kbid := range kbIDs {
			kb, err := s.Storage().GetMicrosoftKB(kbid)
			if err != nil {
				if !yield(dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get microsoft kb %s", kbid)) {
					return
				}
				continue
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

			for _, v := range kb {
				for _, p := range v.Products {
					products[p] = struct{}{}
				}
			}
		}

		if len(products) == 0 {
			return
		}

		ecosystem := ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeMicrosoft)

		// Look up rootIDs for all products
		rootIDs := make(map[dataTypes.RootID]struct{})
		for p := range products {
			rs, err := s.Storage().GetIndex(ecosystem, p)
			if err != nil {
				if !yield(dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get index for product %s", p)) {
					return
				}
				continue
			}
			for _, r := range rs {
				if filter.ExcludesRootID(r) {
					continue
				}
				rootIDs[r] = struct{}{}
			}
		}

		for rootID := range rootIDs {
			d, err := s.GetVulnerabilityData(rootID, filter)
			if err != nil {
				if !yield(dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by root id: %s", rootID)) {
					return
				}
				continue
			}

			// Filter detections to only the microsoft ecosystem
			d.Detections = func() []dbTypes.VulnerabilityDataDetection {
				var ds []dbTypes.VulnerabilityDataDetection
				for _, dd := range d.Detections {
					if dd.Ecosystem == ecosystem {
						ds = append(ds, dbTypes.VulnerabilityDataDetection{
							Ecosystem: dd.Ecosystem,
							Contents:  dd.Contents,
						})
					}
				}
				return ds
			}()

			if !yield(d, nil) {
				return
			}
		}
	}
}

func (s Session) getAdvisory(id advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	if m, ok := s.cache.LoadAdvisory(id); ok {
		return m, nil
	}
	m, err := s.storage.GetAdvisory(id)
	if err != nil {
		return nil, errors.Wrap(err, "get advisory from db")
	}
	s.cache.StoreAdvisory(id, m)
	return m, nil
}

func (s Session) getVulnerability(id vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
	if m, ok := s.cache.LoadVulnerability(id); ok {
		return m, nil
	}
	m, err := s.storage.GetVulnerability(id)
	if err != nil {
		return nil, errors.Wrap(err, "get vulnerability from db")
	}
	s.cache.StoreVulnerability(id, m)
	return m, nil
}

// GetAttackData fetches the per-source ATT&CK record(s) for (kind, id)
// and resolves one level of within-catalog references so the returned
// AttackData carries embedded {ID, Name, Description} refs alongside
// each Mitigation / Sub-technique / Procedure / etc. The DataSources
// field collects the per-source provenance for the queried record and
// every referenced record contributing to the embedded refs. (kind, id)
// rather than id alone is the composite primary key because pre-2019
// 1:1 mitigation course-of-action records share T#### ids with their
// live Techniques.
func (s Session) GetAttackData(kind kindTypes.Kind, id string) (dbTypes.AttackData, error) {
	d := dbTypes.AttackData{Kind: kind, ID: id}

	primary, err := s.Storage().GetAttack(kind, id)
	if err != nil {
		return dbTypes.AttackData{}, errors.Wrap(err, "get attack")
	}
	if len(primary) == 0 {
		return d, nil
	}

	selfKey := dbTypes.AttackRefID{Kind: kind, ID: id}
	refCache := make(map[dbTypes.AttackRefID]attackTypes.Attack)
	sourceIDs := make(map[sourceTypes.SourceID]struct{})
	for sid, a := range primary {
		if _, ok := refCache[selfKey]; !ok {
			refCache[selfKey] = a
		}
		sourceIDs[sid] = struct{}{}
	}

	seenRef := map[dbTypes.AttackRefID]struct{}{selfKey: {}}
	for _, a := range primary {
		for _, ref := range dbTypes.CollectAttackRefs(a) {
			if _, ok := seenRef[ref]; ok {
				continue
			}
			seenRef[ref] = struct{}{}
			rm, err := s.Storage().GetAttack(ref.Kind, ref.ID)
			if err != nil {
				if errors.Is(err, dbTypes.ErrNotFoundAttack) {
					continue
				}
				return dbTypes.AttackData{}, errors.Wrap(err, "get attack")
			}
			for sid, ra := range rm {
				if _, ok := refCache[ref]; !ok {
					refCache[ref] = ra
				}
				sourceIDs[sid] = struct{}{}
			}
		}
	}

	d.Contents = make(map[sourceTypes.SourceID]dbTypes.AttackContent, len(primary))
	for sid, a := range primary {
		d.Contents[sid] = dbTypes.ToAttackContent(a, refCache)
	}

	for id := range sourceIDs {
		ds, err := s.Storage().GetDataSource(id)
		if err != nil {
			return dbTypes.AttackData{}, errors.Wrap(err, "get datasource")
		}
		d.DataSources = append(d.DataSources, ds)
	}
	return d, nil
}

// GetCAPECData fetches the per-source CAPEC record(s) for id and
// resolves one level of within-catalog references (ChildOf / ParentOf /
// CanFollow / CanPrecede / PeerOf). Cross-catalog references
// (RelatedCWEs, RelatedAttacks) stay as raw ID strings.
func (s Session) GetCAPECData(id string) (dbTypes.CAPECData, error) {
	d := dbTypes.CAPECData{ID: id}

	primary, err := s.Storage().GetCAPEC(id)
	if err != nil {
		return dbTypes.CAPECData{}, errors.Wrap(err, "get capec")
	}
	if len(primary) == 0 {
		return d, nil
	}

	refCache := make(map[string]capecTypes.CAPEC)
	sourceIDs := make(map[sourceTypes.SourceID]struct{})
	for sid, c := range primary {
		if _, ok := refCache[c.ID]; !ok {
			refCache[c.ID] = c
		}
		sourceIDs[sid] = struct{}{}
	}

	seenRef := map[string]struct{}{id: {}}
	for _, c := range primary {
		for _, ref := range dbTypes.CollectCAPECRefs(c) {
			if _, ok := seenRef[ref]; ok {
				continue
			}
			seenRef[ref] = struct{}{}
			rm, err := s.Storage().GetCAPEC(ref)
			if err != nil {
				if errors.Is(err, dbTypes.ErrNotFoundCAPEC) {
					continue
				}
				return dbTypes.CAPECData{}, errors.Wrap(err, "get capec")
			}
			for sid, rc := range rm {
				if _, ok := refCache[rc.ID]; !ok {
					refCache[rc.ID] = rc
				}
				sourceIDs[sid] = struct{}{}
			}
		}
	}

	d.Contents = make(map[sourceTypes.SourceID]dbTypes.CAPECContent, len(primary))
	for sid, c := range primary {
		d.Contents[sid] = dbTypes.ToCAPECContent(c, refCache)
	}

	for id := range sourceIDs {
		ds, err := s.Storage().GetDataSource(id)
		if err != nil {
			return dbTypes.CAPECData{}, errors.Wrap(err, "get datasource")
		}
		d.DataSources = append(d.DataSources, ds)
	}
	return d, nil
}

// GetCWEData fetches the per-source CWE record(s) for id and resolves
// one level of within-catalog references (Weakness.RelatedWeaknesses
// and Category/View.Members). RelatedAttackPatterns (CAPEC IDs) stays
// as raw ID strings since it crosses catalogs.
func (s Session) GetCWEData(id string) (dbTypes.CWEData, error) {
	d := dbTypes.CWEData{ID: id}

	primary, err := s.Storage().GetCWE(id)
	if err != nil {
		return dbTypes.CWEData{}, errors.Wrap(err, "get cwe")
	}
	if len(primary) == 0 {
		return d, nil
	}

	refCache := make(map[string]cweTypes.CWE)
	sourceIDs := make(map[sourceTypes.SourceID]struct{})
	for sid, w := range primary {
		if _, ok := refCache[w.ID]; !ok {
			refCache[w.ID] = w
		}
		sourceIDs[sid] = struct{}{}
	}

	seenRef := map[string]struct{}{id: {}}
	for _, w := range primary {
		for _, ref := range dbTypes.CollectCWERefs(w) {
			if _, ok := seenRef[ref]; ok {
				continue
			}
			seenRef[ref] = struct{}{}
			rm, err := s.Storage().GetCWE(ref)
			if err != nil {
				if errors.Is(err, dbTypes.ErrNotFoundCWE) {
					continue
				}
				return dbTypes.CWEData{}, errors.Wrap(err, "get cwe")
			}
			for sid, rw := range rm {
				if _, ok := refCache[rw.ID]; !ok {
					refCache[rw.ID] = rw
				}
				sourceIDs[sid] = struct{}{}
			}
		}
	}

	d.Contents = make(map[sourceTypes.SourceID]dbTypes.CWEContent, len(primary))
	for sid, w := range primary {
		d.Contents[sid] = dbTypes.ToCWEContent(w, refCache)
	}

	for id := range sourceIDs {
		ds, err := s.Storage().GetDataSource(id)
		if err != nil {
			return dbTypes.CWEData{}, errors.Wrap(err, "get datasource")
		}
		d.DataSources = append(d.DataSources, ds)
	}
	return d, nil
}
