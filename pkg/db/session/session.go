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
	GetIndexes(ecosystemTypes.Ecosystem, ...string) (map[dataTypes.RootID][]string, error)
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
	conn := &Session{
		storage: s,
		cache: func() *cache.Cache {
			if c.WithCache {
				return cache.New()
			}
			return nil
		}(),
	}
	return conn, nil
}

func (c Session) Storage() Storage {
	return c.storage
}

func (c Session) Cache() *cache.Cache {
	return c.cache
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

func (c *Session) GetVulnerabilityData(searchType dbTypes.SearchType, filter dbTypes.Filter, queries ...string) iter.Seq2[dbTypes.VulnerabilityData, error] {
	return func(yield func(dbTypes.VulnerabilityData, error) bool) {
		switch searchType {
		case dbTypes.SearchRoot:
			for _, query := range queries {
				if filter.ExcludesRootID(dataTypes.RootID(query)) {
					continue
				}

				d, err := func() (dbTypes.VulnerabilityData, error) {
					root := dbTypes.VulnerabilityData{ID: query}

					r, err := c.Storage().GetRoot(dataTypes.RootID(query))
					if err != nil {
						if errors.Is(err, dbTypes.ErrNotFoundRoot) {
							return dbTypes.VulnerabilityData{}, errors.WithStack(err)
						}
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
					}

					r = filter.ApplyShallowly(r)

					for _, a := range r.Advisories {
						m, err := c.getAdvisory(a.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundAdvisory) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
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
						m, err := c.getVulnerability(v.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
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

						m, err := c.Storage().GetDetection(d.Ecosystem, dataTypes.RootID(query))
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundDetection) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
							return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get detection")
						}

						m = filter.ApplyToDetections(m)
						if len(m) == 0 {
							continue
						}

						root.Detections = append(root.Detections, dbTypes.VulnerabilityDataDetection{
							Ecosystem: d.Ecosystem,
							Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{dataTypes.RootID(query): m},
						})
					}

					for _, datasource := range r.DataSources {
						if filter.ExcludesDataSource(datasource.ID) {
							continue
						}

						ds, err := c.Storage().GetDataSource(datasource.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundDataSource) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
							return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get datasource")
						}

						root.DataSources = append(root.DataSources, ds)
					}

					return root, nil
				}()
				if err != nil {
					if !yield(dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by root id: %s", query)) {
						return
					}
					return
				}

				if !yield(d, err) {
					return
				}
			}
			return
		case dbTypes.SearchAdvisory:
			for _, query := range queries {
				d, err := func() (dbTypes.VulnerabilityData, error) {
					root := dbTypes.VulnerabilityData{ID: query}

					am, err := c.getAdvisory(advisoryContentTypes.AdvisoryID(query))
					if err != nil {
						if errors.Is(err, dbTypes.ErrNotFoundAdvisory) {
							return dbTypes.VulnerabilityData{}, errors.WithStack(err)
						}
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get advisory")
					}

					am = filter.ApplyToAdvisories(am)
					if len(am) == 0 {
						return root, nil
					}

					root.Advisories = []dbTypes.VulnerabilityDataAdvisory{
						{
							ID:       advisoryContentTypes.AdvisoryID(query),
							Contents: am,
						},
					}

					dm := make(map[ecosystemTypes.Ecosystem]map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
					for _, mm := range am {
						for rootID := range mm {
							r, err := c.Storage().GetRoot(rootID)
							if err != nil {
								if errors.Is(err, dbTypes.ErrNotFoundRoot) {
									return dbTypes.VulnerabilityData{}, errors.WithStack(err)
								}
								return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
							}

							r = filter.ApplyShallowly(r)

							for _, v := range r.Vulnerabilities {
								if !slices.ContainsFunc(root.Vulnerabilities, func(e dbTypes.VulnerabilityDataVulnerability) bool {
									return e.ID == v.ID
								}) {
									vm, err := c.getVulnerability(v.ID)
									if err != nil {
										if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
											return dbTypes.VulnerabilityData{}, errors.WithStack(err)
										}
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

								m, err := c.Storage().GetDetection(d.Ecosystem, rootID)
								if err != nil {
									if errors.Is(err, dbTypes.ErrNotFoundDetection) {
										return dbTypes.VulnerabilityData{}, errors.WithStack(err)
									}
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
									ds, err := c.Storage().GetDataSource(d.ID)
									if err != nil {
										if errors.Is(err, dbTypes.ErrNotFoundDataSource) {
											return dbTypes.VulnerabilityData{}, errors.WithStack(err)
										}
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
				}()
				if err != nil {
					if !yield(dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by advisory id: %s", query)) {
						return
					}
					return
				}

				if !yield(d, err) {
					return
				}
			}
			return
		case dbTypes.SearchVulnerability:
			for _, query := range queries {
				d, err := func() (dbTypes.VulnerabilityData, error) {
					root := dbTypes.VulnerabilityData{ID: query}

					vm, err := c.getVulnerability(vulnerabilityContentTypes.VulnerabilityID(query))
					if err != nil {
						if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
							return dbTypes.VulnerabilityData{}, errors.WithStack(err)
						}
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
					}

					vm = filter.ApplyToVulnerabilities(vm)
					if len(vm) == 0 {
						return root, nil
					}

					root.Vulnerabilities = []dbTypes.VulnerabilityDataVulnerability{
						{
							ID:       vulnerabilityContentTypes.VulnerabilityID(query),
							Contents: vm,
						},
					}

					dm := make(map[ecosystemTypes.Ecosystem]map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
					for _, mm := range vm {
						for rootID := range mm {
							r, err := c.Storage().GetRoot(rootID)
							if err != nil {
								if errors.Is(err, dbTypes.ErrNotFoundRoot) {
									return dbTypes.VulnerabilityData{}, errors.WithStack(err)
								}
								return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
							}

							r = filter.ApplyShallowly(r)

							for _, a := range r.Advisories {
								if !slices.ContainsFunc(root.Advisories, func(e dbTypes.VulnerabilityDataAdvisory) bool {
									return e.ID == a.ID
								}) {
									am, err := c.getAdvisory(a.ID)
									if err != nil {
										if errors.Is(err, dbTypes.ErrNotFoundAdvisory) {
											return dbTypes.VulnerabilityData{}, errors.WithStack(err)
										}
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

								m, err := c.Storage().GetDetection(d.Ecosystem, rootID)
								if err != nil {
									if errors.Is(err, dbTypes.ErrNotFoundDetection) {
										return dbTypes.VulnerabilityData{}, errors.WithStack(err)
									}
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
									ds, err := c.Storage().GetDataSource(d.ID)
									if err != nil {
										if errors.Is(err, dbTypes.ErrNotFoundDataSource) {
											return dbTypes.VulnerabilityData{}, errors.WithStack(err)
										}
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
				}()
				if err != nil {
					if !yield(dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by vulnerability id: %s", query)) {
						return
					}
					return
				}

				if !yield(d, nil) {
					return
				}
			}
		case dbTypes.SearchPackage:
			if len(queries) < 2 {
				if !yield(dbTypes.VulnerabilityData{}, errors.Errorf("unexpected queries. expected: %q, actual: %q", []string{"<ecosystem>", "<package>"}, queries)) {
					return
				}
				return
			}

			if filter.ExcludesEcosystem(ecosystemTypes.Ecosystem(queries[0])) {
				return
			}

			im, err := c.Storage().GetIndexes(ecosystemTypes.Ecosystem(queries[0]), queries[1:]...)
			if err != nil {
				if !yield(dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get indexes by ecosystem: %s, packages: %s", queries[0], queries[1:])) {
					return
				}
				return
			}

			for rootID := range im {
				if filter.ExcludesRootID(rootID) {
					continue
				}

				d, err := func() (dbTypes.VulnerabilityData, error) {
					root := dbTypes.VulnerabilityData{ID: string(rootID)}
					r, err := c.Storage().GetRoot(rootID)
					if err != nil {
						if errors.Is(err, dbTypes.ErrNotFoundRoot) {
							return dbTypes.VulnerabilityData{}, errors.WithStack(err)
						}
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
					}

					r = filter.ApplyShallowly(r)

					for _, d := range r.Detections {
						if d.Ecosystem != ecosystemTypes.Ecosystem(queries[0]) {
							continue
						}

						dm, err := c.Storage().GetDetection(d.Ecosystem, rootID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundDetection) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
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
						m, err := c.getAdvisory(a.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundAdvisory) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
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
						m, err := c.getVulnerability(v.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
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

						ds, err := c.Storage().GetDataSource(d.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundDataSource) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
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
		default:
			if !yield(dbTypes.VulnerabilityData{}, errors.Errorf("unexpected search type. expected: %q, actual: %s", []dbTypes.SearchType{dbTypes.SearchRoot, dbTypes.SearchAdvisory, dbTypes.SearchVulnerability, dbTypes.SearchPackage}, searchType)) {
				return
			}
		}
	}
}

func (c Session) getAdvisory(id advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	if m, ok := c.cache.LoadAdvisory(id); ok {
		return m, nil
	}
	m, err := c.storage.GetAdvisory(id)
	if err != nil {
		return nil, errors.Wrap(err, "get advisory from db")
	}
	c.cache.StoreAdvisory(id, m)
	return m, nil
}

func (c Session) getVulnerability(id vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
	if m, ok := c.cache.LoadVulnerability(id); ok {
		return m, nil
	}
	m, err := c.storage.GetVulnerability(id)
	if err != nil {
		return nil, errors.Wrap(err, "get vulnerability from db")
	}
	c.cache.StoreVulnerability(id, m)
	return m, nil
}
