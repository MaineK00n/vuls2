package boltdb

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"slices"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	"github.com/MaineK00n/vuls2/pkg/db/common/util"
)

// boltdb: metadata:db -> dbTypes.Metadata

// boltdb: vulnerability:root:<Root ID> -> vulnerabilityRoot

// boltdb: vulnerability:advisory:<Advisory ID> -> map[<Source ID>][<Root ID>][]advisoryTypes.Advisory

// boltdb: vulnerability:vulnerability:<CVE ID> -> map[<Source ID>][<Root ID>][]vulnerabilityTypes.Vulnerability

// boltdb: <ecosystem>:index:<package> -> [<Root ID>]

// boltdb: <ecosystem>:detection:<Root ID> -> map[<Source ID>]criteriaTypes.Criteria

// boltdb: datasource:<Source ID> -> datasourceTypes.DataSource

type Config struct {
	Path string

	Options *bolt.Options
}

type Connection struct {
	Config *Config

	conn *bolt.DB
}

func (c *Connection) Open() error {
	if c.Config == nil {
		return errors.New("connection config is not set")
	}

	db, err := bolt.Open(c.Config.Path, 0600, c.Config.Options)
	if err != nil {
		return errors.WithStack(err)
	}
	c.conn = db
	return nil
}

func (c *Connection) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Connection) GetMetadata() (*dbTypes.Metadata, error) {
	var v dbTypes.Metadata
	if err := c.conn.View(func(tx *bolt.Tx) error {
		mb := tx.Bucket([]byte("metadata"))
		if mb == nil {
			return errors.Errorf("bucket: %s is not exists", "metadata")
		}

		bs := mb.Get([]byte("db"))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundMetadata, "metadata -> db not found")
		}

		if err := util.Unmarshal(bs, &v); err != nil {
			return errors.Wrapf(err, "unmarshal %s", "metadata -> db")
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &v, nil
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		mb := tx.Bucket([]byte("metadata"))
		if mb == nil {
			return errors.Errorf("bucket: %s is not exists", "metadata")
		}

		bs, err := util.Marshal(metadata)
		if err != nil {
			return errors.Wrap(err, "marshal metadata")
		}

		if err := mb.Put([]byte("db"), bs); err != nil {
			return errors.Wrapf(err, "put %s", "metadata -> db")
		}

		return nil
	})
}

func (c *Connection) GetVulnerabilityData(searchType dbTypes.SearchType, queries ...string) iter.Seq2[dbTypes.VulnerabilityData, error] {
	return func(yield func(dbTypes.VulnerabilityData, error) bool) {
		switch searchType {
		case dbTypes.SearchRoot:
			for _, query := range queries {
				d, err := func() (dbTypes.VulnerabilityData, error) {
					root := dbTypes.VulnerabilityData{ID: query}

					r, err := c.GetRoot(dataTypes.RootID(query))
					if err != nil {
						if errors.Is(err, dbTypes.ErrNotFoundRoot) {
							return dbTypes.VulnerabilityData{}, errors.WithStack(err)
						}
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
					}

					for _, a := range r.Advisories {
						m, err := c.GetAdvisory(a.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundAdvisory) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
							return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get advisory")
						}
						root.Advisories = append(root.Advisories, dbTypes.VulnerabilityDataAdvisory{
							ID:       a.ID,
							Contents: m,
						})
					}

					for _, v := range r.Vulnerabilities {
						m, err := c.GetVulnerability(v.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
							return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
						}
						root.Vulnerabilities = append(root.Vulnerabilities, dbTypes.VulnerabilityDataVulnerability{
							ID:       v.ID,
							Contents: m,
						})
					}

					for _, d := range r.Detections {
						m, err := c.GetDetection(d.Ecosystem, dataTypes.RootID(query))
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundDetection) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
							return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get detection")
						}
						root.Detections = append(root.Detections, dbTypes.VulnerabilityDataDetection{
							Ecosystem: d.Ecosystem,
							Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{dataTypes.RootID(query): m},
						})
					}

					for _, datasource := range r.DataSources {
						ds, err := c.GetDataSource(datasource.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundDataSource) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
							return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get datasource")
						}
						root.DataSources = append(root.DataSources, *ds)
					}

					return root, nil
				}()
				if err != nil {
					if errors.Is(err, dbTypes.ErrNotFoundRoot) {
						continue
					}
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

					am, err := c.GetAdvisory(advisoryContentTypes.AdvisoryID(query))
					if err != nil {
						if errors.Is(err, dbTypes.ErrNotFoundAdvisory) {
							return dbTypes.VulnerabilityData{}, errors.WithStack(err)
						}
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get advisory")
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
							r, err := c.GetRoot(rootID)
							if err != nil {
								if errors.Is(err, dbTypes.ErrNotFoundRoot) {
									return dbTypes.VulnerabilityData{}, errors.WithStack(err)
								}
								return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
							}

							for _, v := range r.Vulnerabilities {
								if !slices.ContainsFunc(root.Vulnerabilities, func(e dbTypes.VulnerabilityDataVulnerability) bool {
									return e.ID == v.ID
								}) {
									vm, err := c.GetVulnerability(v.ID)
									if err != nil {
										if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
											return dbTypes.VulnerabilityData{}, errors.WithStack(err)
										}
										return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
									}
									root.Vulnerabilities = append(root.Vulnerabilities, dbTypes.VulnerabilityDataVulnerability{
										ID:       v.ID,
										Contents: vm,
									})
								}
							}

							for _, d := range r.Detections {
								m, err := c.GetDetection(d.Ecosystem, rootID)
								if err != nil {
									if errors.Is(err, dbTypes.ErrNotFoundDetection) {
										return dbTypes.VulnerabilityData{}, errors.WithStack(err)
									}
									return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get detection")
								}

								if _, ok := dm[d.Ecosystem]; !ok {
									dm[d.Ecosystem] = make(map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
								}
								dm[d.Ecosystem][rootID] = m
							}

							for _, datasource := range r.DataSources {
								if !slices.ContainsFunc(root.DataSources, func(e datasourceTypes.DataSource) bool {
									return e.ID == datasource.ID
								}) {
									ds, err := c.GetDataSource(datasource.ID)
									if err != nil {
										if errors.Is(err, dbTypes.ErrNotFoundDataSource) {
											return dbTypes.VulnerabilityData{}, errors.WithStack(err)
										}
										return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get datasource")
									}
									root.DataSources = append(root.DataSources, *ds)
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

					return root, nil
				}()
				if err != nil {
					if errors.Is(err, dbTypes.ErrNotFoundAdvisory) {
						continue
					}
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

					vm, err := c.GetVulnerability(vulnerabilityContentTypes.VulnerabilityID(query))
					if err != nil {
						if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
							return dbTypes.VulnerabilityData{}, errors.WithStack(err)
						}
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
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
							r, err := c.GetRoot(rootID)
							if err != nil {
								if errors.Is(err, dbTypes.ErrNotFoundRoot) {
									return dbTypes.VulnerabilityData{}, errors.WithStack(err)
								}
								return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
							}

							for _, a := range r.Advisories {
								if !slices.ContainsFunc(root.Advisories, func(e dbTypes.VulnerabilityDataAdvisory) bool {
									return e.ID == a.ID
								}) {
									am, err := c.GetAdvisory(a.ID)
									if err != nil {
										if errors.Is(err, dbTypes.ErrNotFoundAdvisory) {
											return dbTypes.VulnerabilityData{}, errors.WithStack(err)
										}
										return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get advisory")
									}
									root.Advisories = append(root.Advisories, dbTypes.VulnerabilityDataAdvisory{
										ID:       a.ID,
										Contents: am,
									})
								}
							}

							for _, d := range r.Detections {
								m, err := c.GetDetection(d.Ecosystem, rootID)
								if err != nil {
									if errors.Is(err, dbTypes.ErrNotFoundDetection) {
										return dbTypes.VulnerabilityData{}, errors.WithStack(err)
									}
									return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get detection")
								}

								if _, ok := dm[d.Ecosystem]; !ok {
									dm[d.Ecosystem] = make(map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
								}
								dm[d.Ecosystem][rootID] = m
							}

							for _, datasource := range r.DataSources {
								if !slices.ContainsFunc(root.DataSources, func(e datasourceTypes.DataSource) bool {
									return e.ID == datasource.ID
								}) {
									ds, err := c.GetDataSource(datasource.ID)
									if err != nil {
										if errors.Is(err, dbTypes.ErrNotFoundDataSource) {
											return dbTypes.VulnerabilityData{}, errors.WithStack(err)
										}
										return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get datasource")
									}
									root.DataSources = append(root.DataSources, *ds)
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

					return root, nil
				}()
				if err != nil {
					if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
						continue
					}
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

			im, err := c.GetIndexes(ecosystemTypes.Ecosystem(queries[0]), queries[1:]...)
			if err != nil {
				if !yield(dbTypes.VulnerabilityData{}, errors.Wrapf(err, "get indexes by ecosystem: %s, packages: %s", queries[0], queries[1:])) {
					return
				}
				return
			}

			for rootID := range im {
				d, err := func() (dbTypes.VulnerabilityData, error) {
					root := dbTypes.VulnerabilityData{ID: string(rootID)}

					dm, err := c.GetDetection(ecosystemTypes.Ecosystem(queries[0]), rootID)
					if err != nil {
						if errors.Is(err, dbTypes.ErrNotFoundDetection) {
							return dbTypes.VulnerabilityData{}, errors.WithStack(err)
						}
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get detection")
					}
					root.Detections = []dbTypes.VulnerabilityDataDetection{
						{
							Ecosystem: ecosystemTypes.Ecosystem(queries[0]),
							Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{rootID: dm},
						},
					}

					r, err := c.GetRoot(rootID)
					if err != nil {
						if errors.Is(err, dbTypes.ErrNotFoundRoot) {
							return dbTypes.VulnerabilityData{}, errors.WithStack(err)
						}
						return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get root")
					}

					for _, a := range r.Advisories {
						m, err := c.GetAdvisory(a.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundAdvisory) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
							return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get advisory")
						}
						root.Advisories = append(root.Advisories, dbTypes.VulnerabilityDataAdvisory{
							ID:       a.ID,
							Contents: m,
						})
					}

					for _, v := range r.Vulnerabilities {
						m, err := c.GetVulnerability(v.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
							return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
						}
						root.Vulnerabilities = append(root.Vulnerabilities, dbTypes.VulnerabilityDataVulnerability{
							ID:       v.ID,
							Contents: m,
						})
					}

					for _, datasource := range r.DataSources {
						ds, err := c.GetDataSource(datasource.ID)
						if err != nil {
							if errors.Is(err, dbTypes.ErrNotFoundDataSource) {
								return dbTypes.VulnerabilityData{}, errors.WithStack(err)
							}
							return dbTypes.VulnerabilityData{}, errors.Wrap(err, "get datasource")
						}
						root.DataSources = append(root.DataSources, *ds)
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

func (c *Connection) PutVulnerabilityData(root string) error {
	if err := c.conn.Update(func(tx *bolt.Tx) error {
		if err := filepath.WalkDir(filepath.Join(root, "data"), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			f, err := os.Open(path)
			if err != nil {
				return errors.Wrapf(err, "open %s", path)
			}
			defer f.Close()

			var data dataTypes.Data
			if err := json.NewDecoder(f).Decode(&data); err != nil {
				return errors.Wrapf(err, "decode %s", path)
			}

			if err := putDetection(tx, data); err != nil {
				return errors.Wrap(err, "put detection")
			}

			if err := putAdvisory(tx, data); err != nil {
				return errors.Wrap(err, "put advisory")
			}

			if err := putVulnerability(tx, data); err != nil {
				return errors.Wrap(err, "put vulnerability")
			}

			if err := putRoot(tx, data); err != nil {
				return errors.Wrap(err, "put root")
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", root)
		}

		return nil
	}); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func putDetection(tx *bolt.Tx, data dataTypes.Data) error {
	for _, d := range data.Detections {
		eb, err := tx.CreateBucketIfNotExists([]byte(d.Ecosystem))
		if err != nil {
			return errors.Wrapf(err, "create bucket: %s if not exists", d.Ecosystem)
		}

		edb, err := eb.CreateBucketIfNotExists([]byte("detection"))
		if err != nil {
			return errors.Wrapf(err, "create bucket: %s if not exists", fmt.Sprintf("%s -> detection", d.Ecosystem))
		}

		m := make(map[sourceTypes.SourceID][]conditionTypes.Condition)
		if bs := edb.Get([]byte(data.ID)); len(bs) > 0 {
			if err := util.Unmarshal(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> detection -> %s", d.Ecosystem, data.ID))
			}
		}
		m[data.DataSource.ID] = d.Conditions

		bs, err := util.Marshal(m)
		if err != nil {
			return errors.Wrap(err, "marshal conditions map")
		}

		if err := edb.Put([]byte(data.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("%s -> detection -> %s", d.Ecosystem, data.ID))
		}

		eib, err := eb.CreateBucketIfNotExists([]byte("index"))
		if err != nil {
			return errors.Wrapf(err, "create bucket: %s if not exists", fmt.Sprintf("%s -> index", d.Ecosystem))
		}

		var pkgs []string
		for _, cond := range d.Conditions {
			ps, err := util.WalkCriteria(cond.Criteria)
			if err != nil {
				return errors.Wrap(err, "walk criteria")
			}
			pkgs = append(pkgs, ps...)
		}
		slices.Sort(pkgs)

		for _, p := range slices.Compact(pkgs) {
			var rootIDs []dataTypes.RootID
			if bs := eib.Get([]byte(p)); len(bs) > 0 {
				if err := util.Unmarshal(bs, &rootIDs); err != nil {
					return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> index -> %s", d.Ecosystem, p))
				}
			}
			if !slices.Contains(rootIDs, data.ID) {
				rootIDs = append(rootIDs, data.ID)
			}

			bs, err := util.Marshal(rootIDs)
			if err != nil {
				return errors.Wrap(err, "marshal root IDs")
			}

			if err := eib.Put([]byte(p), bs); err != nil {
				return errors.Wrapf(err, "put %s", fmt.Sprintf("%s -> index -> %s", d.Ecosystem, p))
			}
		}
	}

	return nil
}

func putAdvisory(tx *bolt.Tx, data dataTypes.Data) error {
	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability")
	}

	vab := vb.Bucket([]byte("advisory"))
	if vab == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability -> advisory")
	}

	for _, a := range data.Advisories {
		m := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory)
		if bs := vab.Get([]byte(a.Content.ID)); len(bs) > 0 {
			if err := util.Unmarshal(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> advisory -> %s", a.Content.ID))
			}
		}
		if m[data.DataSource.ID] == nil {
			m[data.DataSource.ID] = make(map[dataTypes.RootID][]advisoryTypes.Advisory)
		}
		m[data.DataSource.ID][data.ID] = append(m[data.DataSource.ID][data.ID], a)

		bs, err := util.Marshal(m)
		if err != nil {
			return errors.Wrap(err, "marshal advisory map")
		}

		if err := vab.Put([]byte(a.Content.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability -> advisory -> %s", a.Content.ID))
		}
	}

	return nil
}

func putVulnerability(tx *bolt.Tx, data dataTypes.Data) error {
	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability")
	}

	vvb := vb.Bucket([]byte("vulnerability"))
	if vvb == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability -> vulnerability")
	}

	for _, v := range data.Vulnerabilities {
		m := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
		if bs := vvb.Get([]byte(v.Content.ID)); len(bs) > 0 {
			if err := util.Unmarshal(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> vulnerability -> %s", v.Content.ID))
			}
		}
		if m[data.DataSource.ID] == nil {
			m[data.DataSource.ID] = make(map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
		}
		m[data.DataSource.ID][data.ID] = append(m[data.DataSource.ID][data.ID], v)

		bs, err := util.Marshal(m)
		if err != nil {
			return errors.Wrap(err, "marshal vulnerability map")
		}

		if err := vvb.Put([]byte(v.Content.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability -> vulnerability -> %s", v.Content.ID))
		}
	}

	return nil
}

func putRoot(tx *bolt.Tx, data dataTypes.Data) error {
	root := vulnerabilityRoot{
		ID: data.ID,
		Advisories: func() []advisoryContentTypes.AdvisoryID {
			as := make([]advisoryContentTypes.AdvisoryID, 0, len(data.Advisories))
			for _, a := range data.Advisories {
				as = append(as, a.Content.ID)
			}
			return as
		}(),
		Vulnerabilities: func() []vulnerabilityContentTypes.VulnerabilityID {
			vs := make([]vulnerabilityContentTypes.VulnerabilityID, 0, len(data.Vulnerabilities))
			for _, v := range data.Vulnerabilities {
				vs = append(vs, v.Content.ID)
			}
			return vs
		}(),
		Ecosystems: func() []ecosystemTypes.Ecosystem {
			es := make([]ecosystemTypes.Ecosystem, 0, len(data.Detections))
			for _, d := range data.Detections {
				es = append(es, d.Ecosystem)
			}
			return es
		}(),
		DataSources: []sourceTypes.SourceID{data.DataSource.ID},
	}

	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability")
	}

	vrb := vb.Bucket([]byte("root"))
	if vrb == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability -> root")
	}

	if bs := vrb.Get([]byte(root.ID)); len(bs) > 0 {
		var r vulnerabilityRoot
		if err := util.Unmarshal(bs, &r); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> root -> %s", r.ID))
		}

		for _, a := range r.Advisories {
			if !slices.Contains(root.Advisories, a) {
				root.Advisories = append(root.Advisories, a)
			}
		}
		for _, v := range r.Vulnerabilities {
			if !slices.Contains(root.Vulnerabilities, v) {
				root.Vulnerabilities = append(root.Vulnerabilities, v)
			}
		}
		for _, e := range r.Ecosystems {
			if !slices.Contains(root.Ecosystems, e) {
				root.Ecosystems = append(root.Ecosystems, e)
			}
		}
		for _, d := range r.DataSources {
			if !slices.Contains(root.DataSources, d) {
				root.DataSources = append(root.DataSources, d)
			}
		}
	}

	bs, err := util.Marshal(root)
	if err != nil {
		return errors.Wrap(err, "marshal root")
	}

	if err := vrb.Put([]byte(root.ID), bs); err != nil {
		return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability -> root -> %s", root.ID))
	}

	return nil
}

func (c *Connection) GetRoot(id dataTypes.RootID) (*dbTypes.VulnerabilityData, error) {
	var d dbTypes.VulnerabilityData
	if err := c.conn.View(func(tx *bolt.Tx) error {
		vb := tx.Bucket([]byte("vulnerability"))
		if vb == nil {
			return errors.Errorf("bucket: %s is not exists", "vulnerability")
		}

		vrb := vb.Bucket([]byte("root"))
		if vrb == nil {
			return errors.Errorf("bucket: %s is not exists", "vulnerability -> root")
		}

		bs := vrb.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundRoot, "vulnerability -> root -> %s not found", id)
		}

		var r vulnerabilityRoot
		if err := util.Unmarshal(bs, &r); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> root -> %s", id))
		}

		d = dbTypes.VulnerabilityData{
			ID: string(r.ID),
			Advisories: func() []dbTypes.VulnerabilityDataAdvisory {
				as := make([]dbTypes.VulnerabilityDataAdvisory, 0, len(r.Advisories))
				for _, a := range r.Advisories {
					as = append(as, dbTypes.VulnerabilityDataAdvisory{ID: a})
				}
				return as
			}(),
			Vulnerabilities: func() []dbTypes.VulnerabilityDataVulnerability {
				vs := make([]dbTypes.VulnerabilityDataVulnerability, 0, len(r.Vulnerabilities))
				for _, v := range r.Vulnerabilities {
					vs = append(vs, dbTypes.VulnerabilityDataVulnerability{ID: v})
				}
				return vs
			}(),
			Detections: func() []dbTypes.VulnerabilityDataDetection {
				ds := make([]dbTypes.VulnerabilityDataDetection, 0, len(r.Ecosystems))
				for _, e := range r.Ecosystems {
					ds = append(ds, dbTypes.VulnerabilityDataDetection{Ecosystem: e})
				}
				return ds
			}(),
			DataSources: func() []datasourceTypes.DataSource {
				ds := make([]datasourceTypes.DataSource, 0, len(r.DataSources))
				for _, d := range r.DataSources {
					ds = append(ds, datasourceTypes.DataSource{ID: d})
				}
				return ds
			}(),
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &d, nil
}

func (c *Connection) GetAdvisory(id advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	var m map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
	if err := c.conn.View(func(tx *bolt.Tx) error {
		vb := tx.Bucket([]byte("vulnerability"))
		if vb == nil {
			return errors.Errorf("bucket: %s is not exists", "vulnerability")
		}

		vab := vb.Bucket([]byte("advisory"))
		if vab == nil {
			return errors.Errorf("bucket: %s is not exists", "vulnerability -> advisory")
		}

		bs := vab.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundAdvisory, "vulnerability -> advisory -> %s not found", id)
		}

		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> advisory -> %s", id))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func (c *Connection) GetVulnerability(id vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
	var m map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
	if err := c.conn.View(func(tx *bolt.Tx) error {
		vb := tx.Bucket([]byte("vulnerability"))
		if vb == nil {
			return errors.Errorf("bucket: %s is not exists", "vulnerability")
		}

		vvb := vb.Bucket([]byte("vulnerability"))
		if vvb == nil {
			return errors.Errorf("bucket: %s is not exists", "vulnerability -> vulnerability")
		}

		bs := vvb.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundVulnerability, "vulnerability -> vulnerability -> %s not found", id)
		}

		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> vulnerability -> %s", id))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func (c *Connection) GetEcosystems() ([]ecosystemTypes.Ecosystem, error) {
	var es []ecosystemTypes.Ecosystem
	if err := c.conn.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			if b.Bucket([]byte("index")) != nil && b.Bucket([]byte("detection")) != nil {
				es = append(es, ecosystemTypes.Ecosystem(name))
			}
			return nil
		})
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return es, nil
}

func (c *Connection) GetIndexes(ecosystem ecosystemTypes.Ecosystem, queries ...string) (map[dataTypes.RootID][]string, error) {
	m := make(map[dataTypes.RootID][]string)
	if err := c.conn.View(func(tx *bolt.Tx) error {
		eb := tx.Bucket([]byte(ecosystem))
		if eb == nil {
			return errors.Errorf("bucket: %s is not exists", ecosystem)
		}

		eib := eb.Bucket([]byte("index"))
		if eib == nil {
			return errors.Errorf("bucket: %s is not exists", fmt.Sprintf("%s -> index", ecosystem))
		}

		for _, query := range queries {
			bs := eib.Get([]byte(query))
			if len(bs) == 0 {
				continue
			}

			var rootIDs []dataTypes.RootID
			if err := util.Unmarshal(bs, &rootIDs); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> index -> %s", ecosystem, query))
			}

			for _, rootID := range rootIDs {
				m[rootID] = append(m[rootID], query)
			}
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func (c *Connection) GetDetection(ecosystem ecosystemTypes.Ecosystem, rootID dataTypes.RootID) (map[sourceTypes.SourceID][]conditionTypes.Condition, error) {
	var m map[sourceTypes.SourceID][]conditionTypes.Condition
	if err := c.conn.View(func(tx *bolt.Tx) error {
		eb := tx.Bucket([]byte(ecosystem))
		if eb == nil {
			return errors.Errorf("bucket: %s is not exists", ecosystem)
		}

		edb := eb.Bucket([]byte("detection"))
		if edb == nil {
			return errors.Errorf("bucket: %s is not exists", fmt.Sprintf("%s -> detection", ecosystem))
		}

		bs := edb.Get([]byte(rootID))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundDetection, "%s -> detection -> %s not found", ecosystem, rootID)
		}

		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> detection -> %s", ecosystem, rootID))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func (c *Connection) GetDataSources() ([]datasourceTypes.DataSource, error) {
	var ds []datasourceTypes.DataSource
	if err := c.conn.View(func(tx *bolt.Tx) error {
		sb := tx.Bucket([]byte("datasource"))
		if sb == nil {
			return errors.Errorf("bucket: %s is not exists", "datasource")
		}

		return sb.ForEach(func(k, v []byte) error {
			var d datasourceTypes.DataSource
			if err := util.Unmarshal(v, &d); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("datasource -> %s", k))
			}
			ds = append(ds, d)
			return nil
		})
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return ds, nil
}

func (c *Connection) GetDataSource(id sourceTypes.SourceID) (*datasourceTypes.DataSource, error) {
	var v datasourceTypes.DataSource
	if err := c.conn.View(func(tx *bolt.Tx) error {
		sb := tx.Bucket([]byte("datasource"))
		if sb == nil {
			return errors.Errorf("bucket: %s is not exists", "datasource")
		}

		bs := sb.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundDataSource, "datasource -> %s not found", id)
		}

		if err := util.Unmarshal(bs, &v); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("datasource -> %s", id))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &v, nil
}

func (c *Connection) PutDataSource(root string) error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		f, err := os.Open(root)
		if err != nil {
			return errors.Wrapf(err, "open %s", root)
		}
		defer f.Close()

		var datasource datasourceTypes.DataSource
		if err := json.NewDecoder(f).Decode(&datasource); err != nil {
			return errors.Wrapf(err, "decode %s", root)
		}

		bs, err := util.Marshal(datasource)
		if err != nil {
			return errors.Wrap(err, "marshal datasource")
		}

		sb := tx.Bucket([]byte("datasource"))
		if sb == nil {
			return errors.Errorf("bucket: %s is not exists", "datasource")
		}

		if sb.Get([]byte(datasource.ID)) != nil {
			return errors.Errorf("%s already exists", fmt.Sprintf("datasource -> %s", datasource.ID))
		}

		if err := sb.Put([]byte(datasource.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("datasource -> %s", datasource.ID))
		}

		return nil
	})
}

func (c *Connection) DeleteAll() error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		var ns [][]byte
		if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			ns = append(ns, name)
			return nil
		}); err != nil {
			return errors.Wrap(err, "foreach root")
		}

		for _, n := range ns {
			if err := tx.DeleteBucket(n); err != nil {
				return errors.Wrapf(err, "delete bucket: %s", n)
			}
		}

		return nil
	})
}

func (c *Connection) Initialize() error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket([]byte("metadata")); err != nil {
			return errors.Wrapf(err, "create bucket: %s", "metadata")
		}

		vb, err := tx.CreateBucket([]byte("vulnerability"))
		if err != nil {
			return errors.Wrapf(err, "create bucket: %s", "vulnerability")
		}

		if _, err := vb.CreateBucket([]byte("root")); err != nil {
			return errors.Wrapf(err, "create bucket: %s", "vulnerability -> root")
		}

		if _, err := vb.CreateBucket([]byte("advisory")); err != nil {
			return errors.Wrapf(err, "create bucket: %s", "vulnerability -> advisory")
		}

		if _, err := vb.CreateBucket([]byte("vulnerability")); err != nil {
			return errors.Wrapf(err, "create bucket: %s", "vulnerability -> vulnerability")
		}

		if _, err := tx.CreateBucket([]byte("datasource")); err != nil {
			return errors.Wrapf(err, "create bucket: %s", "datasource")
		}

		return nil
	})
}
