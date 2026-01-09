package session

import (
	"iter"
	"slices"

	"github.com/pkg/errors"
	"github.com/redis/rueidis"
	bolt "go.etcd.io/bbolt"
	"gorm.io/gorm"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
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

func (s Session) GetVulnerabilityDataByRootID(id dataTypes.RootID, filter dbTypes.Filter) (dbTypes.VulnerabilityData, error) {
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

	root.Advisories = []dbTypes.VulnerabilityDataAdvisory{
		{
			ID:       id,
			Contents: am,
		},
	}

	dm := make(map[ecosystemTypes.Ecosystem]map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
	for _, mm := range am {
		for rootID := range mm {
			r, err := s.Storage().GetRoot(rootID)
			if err != nil {
				return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
			}

			r = filter.ApplyShallowly(r)

			for _, v := range r.Vulnerabilities {
				if !slices.ContainsFunc(root.Vulnerabilities, func(e dbTypes.VulnerabilityDataVulnerability) bool {
					return e.ID == v.ID
				}) {
					vm, err := s.getVulnerability(v.ID)
					if err != nil {
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
					}

					vm = filter.ApplyToVulnerabilities(vm)
					if len(vm) == 0 {
						continue
					}

					root.Vulnerabilities = append(root.Vulnerabilities, dbTypes.VulnerabilityDataVulnerability{
						ID:       v.ID,
						Contents: vm,
					})
				}
			}

			for _, d := range r.Detections {
				if filter.ExcludesEcosystem(d.Ecosystem) {
					continue
				}

				m, err := s.Storage().GetDetection(d.Ecosystem, rootID)
				if err != nil {
					return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get detection")
				}

				m = filter.ApplyToDetections(m)
				if len(m) == 0 {
					continue
				}

				if _, ok := dm[d.Ecosystem]; !ok {
					dm[d.Ecosystem] = make(map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
				}
				dm[d.Ecosystem][rootID] = m
			}

			for _, d := range r.DataSources {
				if filter.ExcludesDataSource(d.ID) {
					continue
				}

				if !slices.ContainsFunc(root.DataSources, func(e datasourceTypes.DataSource) bool {
					return e.ID == d.ID
				}) {
					ds, err := s.Storage().GetDataSource(d.ID)
					if err != nil {
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get datasource")
					}
					root.DataSources = append(root.DataSources, ds)
				}
			}
		}
	}
	for e, m := range dm {
		root.Detections = append(root.Detections, dbTypes.VulnerabilityDataDetection{
			Ecosystem: e,
			Contents:  m,
		})
	}

	return filter.ApplyShallowly(root), nil
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

	root.Vulnerabilities = []dbTypes.VulnerabilityDataVulnerability{
		{
			ID:       id,
			Contents: vm,
		},
	}

	dm := make(map[ecosystemTypes.Ecosystem]map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
	for _, mm := range vm {
		for rootID := range mm {
			r, err := s.Storage().GetRoot(rootID)
			if err != nil {
				return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
			}

			r = filter.ApplyShallowly(r)

			for _, a := range r.Advisories {
				if !slices.ContainsFunc(root.Advisories, func(e dbTypes.VulnerabilityDataAdvisory) bool {
					return e.ID == a.ID
				}) {
					am, err := s.getAdvisory(a.ID)
					if err != nil {
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get advisory")
					}

					am = filter.ApplyToAdvisories(am)
					if len(am) == 0 {
						continue
					}

					root.Advisories = append(root.Advisories, dbTypes.VulnerabilityDataAdvisory{
						ID:       a.ID,
						Contents: am,
					})
				}
			}

			for _, d := range r.Detections {
				if filter.ExcludesEcosystem(d.Ecosystem) {
					continue
				}

				m, err := s.Storage().GetDetection(d.Ecosystem, rootID)
				if err != nil {
					return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get detection")
				}

				m = filter.ApplyToDetections(m)
				if len(m) == 0 {
					continue
				}

				if _, ok := dm[d.Ecosystem]; !ok {
					dm[d.Ecosystem] = make(map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
				}
				dm[d.Ecosystem][rootID] = m
			}

			for _, d := range r.DataSources {
				if filter.ExcludesDataSource(d.ID) {
					continue
				}

				if !slices.ContainsFunc(root.DataSources, func(e datasourceTypes.DataSource) bool {
					return e.ID == d.ID
				}) {
					ds, err := s.Storage().GetDataSource(d.ID)
					if err != nil {
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get datasource")
					}
					root.DataSources = append(root.DataSources, ds)
				}
			}
		}
	}
	for e, m := range dm {
		root.Detections = append(root.Detections, dbTypes.VulnerabilityDataDetection{
			Ecosystem: e,
			Contents:  m,
		})
	}

	return filter.ApplyShallowly(root), nil
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
			d, err := func() (dbTypes.VulnerabilityData, error) {
				root := dbTypes.VulnerabilityData{ID: string(rootID)}
				r, err := s.Storage().GetRoot(rootID)
				if err != nil {
					return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
				}

				r = filter.ApplyShallowly(r)

				for _, d := range r.Detections {
					if d.Ecosystem != ecosystem {
						continue
					}

					dm, err := s.Storage().GetDetection(d.Ecosystem, rootID)
					if err != nil {
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get detection")
					}

					dm = filter.ApplyToDetections(dm)
					if len(dm) == 0 {
						continue
					}

					root.Detections = []dbTypes.VulnerabilityDataDetection{
						{
							Ecosystem: d.Ecosystem,
							Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{rootID: dm},
						},
					}
				}

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

				for _, d := range r.DataSources {
					if filter.ExcludesDataSource(d.ID) {
						continue
					}

					ds, err := s.Storage().GetDataSource(d.ID)
					if err != nil {
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get datasource")
					}
					root.DataSources = append(root.DataSources, ds)
				}

				return root, nil
			}()
			if err != nil {
				if !yield(dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by root id: %s", rootID)) {
					return
				}
				return
			}

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
