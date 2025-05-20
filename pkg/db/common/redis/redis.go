package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pkg/errors"
	"github.com/redis/rueidis"

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

// redis: HASH KEY: "metadata" FIELD: "db" VALUE: dbtypes.Metadata

// redis: STRING KEY: "vulnerability#root#<Root ID>" VALUE: dbtypes.VulnerabilityData

// redis: HASH KEY: "vulnerability#advisory#<Advisory ID>" FIELD: "<Source ID>#<Root ID>" VALUE: []advisoryTypes.Advisory

// redis: HASH KEY: "vulnerability#vulnerability#<CVE ID>" FIELD: "<Source ID>#<Root ID>" VALUE: []vulnerabilityTypes.Vulnerability

// redis: SET KEY: "<ecosystem>#index#<package>" MEMBER: <Root ID>

// redis: HASH KEY: "<ecosystem>#detection#<Root ID>" FIELD: <Source ID> VALUE: []conditionTypes.Condition

// redis: HASH KEY "datasource" FIELD: <Source ID> VALUE: datasourceTypes.DataSource

type Connection struct {
	Config *rueidis.ClientOption

	conn rueidis.Client
}

func (c *Connection) Open() error {
	if c.Config == nil {
		return errors.New("connection config is not set")
	}

	client, err := rueidis.NewClient(*c.Config)
	if err != nil {
		return errors.WithStack(err)
	}
	c.conn = client
	return nil
}

func (c *Connection) Close() error {
	if c.conn == nil {
		return nil
	}
	c.conn.Close() //nolint:errcheck
	return nil
}

func (c *Connection) GetMetadata() (*dbTypes.Metadata, error) {
	bs, err := c.conn.Do(context.TODO(), c.conn.B().Hget().Key("metadata").Field("db").Build()).AsBytes()
	if err != nil {
		return nil, errors.Wrapf(err, "HGET %s %s", "metadata", "db")
	}

	var v dbTypes.Metadata
	if err := util.Unmarshal(bs, &v); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", "metadata -> db")
	}

	return &v, nil
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	bs, err := util.Marshal(metadata)
	if err != nil {
		return errors.Wrap(err, "marshal metadata")
	}

	if err := c.conn.Do(context.TODO(), c.conn.B().Hset().Key("metadata").FieldValue().FieldValue("db", string(bs)).Build()).Error(); err != nil {
		return errors.Wrapf(err, "HSET %s %s %q", "metadata", "db", string(bs))
	}

	return nil
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
	ctx := context.TODO()

	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
		defer f.Close() //nolint:errcheck

		var data dataTypes.Data
		if err := json.NewDecoder(f).Decode(&data); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		if err := c.putDetection(ctx, data); err != nil {
			return errors.Wrap(err, "put detection")
		}

		if err := c.putAdvisory(ctx, data); err != nil {
			return errors.Wrap(err, "put advisory")
		}

		if err := c.putVulnerability(ctx, data); err != nil {
			return errors.Wrap(err, "put vulnerability")
		}

		if err := c.putRoot(ctx, data); err != nil {
			return errors.Wrap(err, "put root")
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	return nil
}

func (c *Connection) putDetection(ctx context.Context, data dataTypes.Data) error {
	for _, d := range data.Detections {
		bs, err := util.Marshal(d.Conditions)
		if err != nil {
			return errors.Wrap(err, "marshal conditions")
		}

		if err := c.conn.Do(ctx, c.conn.B().Hset().Key(fmt.Sprintf("%s#detection#%s", d.Ecosystem, data.ID)).FieldValue().FieldValue(string(data.DataSource.ID), string(bs)).Build()).Error(); err != nil {
			return errors.Wrapf(err, "HSET %s %s %q", fmt.Sprintf("%s#detection#%s", d.Ecosystem, data.ID), data.DataSource.ID, string(bs))
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
			if err := c.conn.Do(ctx, c.conn.B().Sadd().Key(fmt.Sprintf("%s#index#%s", d.Ecosystem, p)).Member(string(data.ID)).Build()).Error(); err != nil {
				return errors.Wrapf(err, "SADD %s %s", fmt.Sprintf("%s#index#%s", d.Ecosystem, p), data.ID)
			}
		}
	}

	return nil
}

func (c *Connection) putAdvisory(ctx context.Context, data dataTypes.Data) error {
	m := make(map[advisoryContentTypes.AdvisoryID][]advisoryTypes.Advisory)
	for _, a := range data.Advisories {
		m[a.Content.ID] = append(m[a.Content.ID], a)
	}

	for id, as := range m {
		bs, err := util.Marshal(as)
		if err != nil {
			return errors.Wrap(err, "marshal advisories")
		}

		if err := c.conn.Do(ctx, c.conn.B().Hset().Key(fmt.Sprintf("vulnerability#advisory#%s", id)).FieldValue().FieldValue(fmt.Sprintf("%s#%s", data.DataSource.ID, data.ID), string(bs)).Build()).Error(); err != nil {
			return errors.Wrapf(err, "HSET %s %s %q", fmt.Sprintf("vulnerability#advisory#%s", id), fmt.Sprintf("%s#%s", data.DataSource.ID, data.ID), string(bs))
		}
	}

	return nil
}

func (c *Connection) putVulnerability(ctx context.Context, data dataTypes.Data) error {
	m := make(map[vulnerabilityContentTypes.VulnerabilityID][]vulnerabilityTypes.Vulnerability)
	for _, v := range data.Vulnerabilities {
		m[v.Content.ID] = append(m[v.Content.ID], v)
	}

	for id, vs := range m {
		bs, err := util.Marshal(vs)
		if err != nil {
			return errors.Wrap(err, "marshal vulnerabilities")
		}

		if err := c.conn.Do(ctx, c.conn.B().Hset().Key(fmt.Sprintf("vulnerability#vulnerability#%s", id)).FieldValue().FieldValue(fmt.Sprintf("%s#%s", data.DataSource.ID, data.ID), string(bs)).Build()).Error(); err != nil {
			return errors.Wrapf(err, "HSET %s %s %q", fmt.Sprintf("vulnerability#vulnerability#%s", id), fmt.Sprintf("%s#%s", data.DataSource.ID, data.ID), string(bs))
		}
	}

	return nil
}

func (c *Connection) putRoot(ctx context.Context, data dataTypes.Data) error {
	root := dbTypes.VulnerabilityData{
		ID: string(data.ID),
		Advisories: func() []dbTypes.VulnerabilityDataAdvisory {
			as := make([]dbTypes.VulnerabilityDataAdvisory, 0, len(data.Advisories))
			for _, a := range data.Advisories {
				as = append(as, dbTypes.VulnerabilityDataAdvisory{ID: a.Content.ID})
			}
			return as
		}(),
		Vulnerabilities: func() []dbTypes.VulnerabilityDataVulnerability {
			vs := make([]dbTypes.VulnerabilityDataVulnerability, 0, len(data.Vulnerabilities))
			for _, v := range data.Vulnerabilities {
				vs = append(vs, dbTypes.VulnerabilityDataVulnerability{ID: v.Content.ID})
			}
			return vs
		}(),
		Detections: func() []dbTypes.VulnerabilityDataDetection {
			ds := make([]dbTypes.VulnerabilityDataDetection, 0, len(data.Detections))
			for _, d := range data.Detections {
				ds = append(ds, dbTypes.VulnerabilityDataDetection{Ecosystem: d.Ecosystem})
			}
			return ds
		}(),
		DataSources: []datasourceTypes.DataSource{{ID: data.DataSource.ID}},
	}

	bs, err := c.conn.Do(ctx, c.conn.B().Get().Key(fmt.Sprintf("vulnerability#root#%s", data.ID)).Build()).AsBytes()
	if err != nil && !rueidis.IsRedisNil(err) {
		return errors.Wrapf(err, "GET %s", fmt.Sprintf("vulnerability#root#%s", data.ID))
	}

	if len(bs) > 0 {
		var r dbTypes.VulnerabilityData
		if err := util.Unmarshal(bs, &r); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability#root#%s", r.ID))
		}

		for _, a := range r.Advisories {
			if !slices.ContainsFunc(root.Advisories, func(e dbTypes.VulnerabilityDataAdvisory) bool {
				return e.ID == a.ID
			}) {
				root.Advisories = append(root.Advisories, a)
			}
		}
		for _, v := range r.Vulnerabilities {
			if !slices.ContainsFunc(root.Vulnerabilities, func(e dbTypes.VulnerabilityDataVulnerability) bool {
				return e.ID == v.ID
			}) {
				root.Vulnerabilities = append(root.Vulnerabilities, v)
			}
		}
		for _, d := range r.Detections {
			if !slices.ContainsFunc(root.Detections, func(e dbTypes.VulnerabilityDataDetection) bool {
				return e.Ecosystem == d.Ecosystem
			}) {
				root.Detections = append(root.Detections, d)
			}
		}
		for _, d := range r.DataSources {
			if !slices.ContainsFunc(root.DataSources, func(e datasourceTypes.DataSource) bool {
				return e.ID == d.ID
			}) {
				root.DataSources = append(root.DataSources, d)
			}
		}
	}

	bs, err = util.Marshal(root)
	if err != nil {
		return errors.Wrap(err, "marshal root")
	}

	if err := c.conn.Do(ctx, c.conn.B().Set().Key(fmt.Sprintf("vulnerability#root#%s", data.ID)).Value(string(bs)).Build()).Error(); err != nil {
		return errors.Wrapf(err, "SET %s %q", fmt.Sprintf("vulnerability#root#%s", data.ID), string(bs))
	}

	return nil
}

func (c *Connection) GetRoot(id dataTypes.RootID) (*dbTypes.VulnerabilityData, error) {
	bs, err := c.conn.Do(context.TODO(), c.conn.B().Get().Key(fmt.Sprintf("vulnerability#root#%s", id)).Build()).AsBytes()
	if err != nil {
		if rueidis.IsRedisNil(err) {
			return nil, errors.Wrapf(dbTypes.ErrNotFoundRoot, "vulnerability#root#%s not found", id)
		}
		return nil, errors.Wrapf(err, "GET %s", fmt.Sprintf("vulnerability#root#%s", id))
	}

	var r dbTypes.VulnerabilityData
	if err := util.Unmarshal(bs, &r); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability#root#%s", id))
	}

	return &r, nil
}

func (c *Connection) GetAdvisory(id advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	m, err := c.conn.Do(context.TODO(), c.conn.B().Hgetall().Key(fmt.Sprintf("vulnerability#advisory#%s", id)).Build()).AsMap()
	if err != nil {
		return nil, errors.Wrapf(err, "HGETALL %s", fmt.Sprintf("vulnerability#advisory#%s", id))
	}
	if len(m) == 0 {
		return nil, errors.Wrapf(dbTypes.ErrNotFoundAdvisory, "vulnerability#advisory#%s not found", id)
	}

	am := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory)
	for k, v := range m {
		ds, rootID, ok := strings.Cut(k, "#")
		if !ok {
			return nil, errors.Errorf("unexpected field format. expected: %s, actual: %s -> %s", "<Source ID>#<Root ID>", fmt.Sprintf("vulnerability#advisory#%s", id), k)
		}

		bs, err := v.AsBytes()
		if err != nil {
			return nil, errors.Wrapf(err, "as bytes %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("vulnerability#advisory#%s", id), k))
		}

		var as []advisoryTypes.Advisory
		if err := util.Unmarshal(bs, &as); err != nil {
			return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("vulnerability#advisory#%s", id), k))
		}

		if am[sourceTypes.SourceID(ds)] == nil {
			am[sourceTypes.SourceID(ds)] = make(map[dataTypes.RootID][]advisoryTypes.Advisory)
		}
		am[sourceTypes.SourceID(ds)][dataTypes.RootID(rootID)] = as
	}

	return am, nil
}

func (c *Connection) GetVulnerability(id vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
	m, err := c.conn.Do(context.TODO(), c.conn.B().Hgetall().Key(fmt.Sprintf("vulnerability#vulnerability#%s", id)).Build()).AsMap()
	if err != nil {
		return nil, errors.Wrapf(err, "HGETALL %s", fmt.Sprintf("vulnerability#vulnerability#%s", id))
	}
	if len(m) == 0 {
		return nil, errors.Wrapf(dbTypes.ErrNotFoundVulnerability, "vulnerability#vulnerability#%s not found", id)
	}

	vm := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
	for k, v := range m {
		ds, rootID, ok := strings.Cut(k, "#")
		if !ok {
			return nil, errors.Errorf("unexpected field format. expected: %s, actual: %s -> %s", "<Source ID>#<Root ID>", fmt.Sprintf("vulnerability#advisory#%s", id), k)
		}

		bs, err := v.AsBytes()
		if err != nil {
			return nil, errors.Wrapf(err, "as bytes %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("vulnerability#vulnerability#%s", id), k))
		}

		var vs []vulnerabilityTypes.Vulnerability
		if err := util.Unmarshal(bs, &vs); err != nil {
			return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("vulnerability#vulnerability#%s", id), k))
		}

		if vm[sourceTypes.SourceID(ds)] == nil {
			vm[sourceTypes.SourceID(ds)] = make(map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
		}
		vm[sourceTypes.SourceID(ds)][dataTypes.RootID(rootID)] = vs
	}

	return vm, nil
}

func (c *Connection) GetEcosystems() ([]ecosystemTypes.Ecosystem, error) {
	ctx := context.TODO()

	var es []ecosystemTypes.Ecosystem

	var cursor uint64
	for {
		entry, err := c.conn.Do(ctx, c.conn.B().Scan().Cursor(cursor).Match("*#detection#*").Count(10000).Build()).AsScanEntry()
		if err != nil {
			return nil, errors.Wrap(err, "SCAN %s MATCH *#detection#* COUNT 10000")
		}

		for _, e := range entry.Elements {
			lhs, _, ok := strings.Cut(e, "#detection#")
			if !ok {
				return nil, errors.Errorf("unexpected key format. expected: %s, actual: %s", "<Ecosystem>#detection#<Root ID>", e)
			}
			if !slices.Contains(es, ecosystemTypes.Ecosystem(lhs)) {
				es = append(es, ecosystemTypes.Ecosystem(lhs))
			}
		}

		cursor = entry.Cursor
		if cursor == 0 {
			break
		}
	}

	return es, nil
}

func (c *Connection) GetIndexes(ecosystem ecosystemTypes.Ecosystem, queries ...string) (map[dataTypes.RootID][]string, error) {
	ctx := context.TODO()

	m := make(map[dataTypes.RootID][]string)
	for _, q := range queries {
		rootIDs, err := c.conn.Do(ctx, c.conn.B().Smembers().Key(fmt.Sprintf("%s#index#%s", ecosystem, q)).Build()).AsStrSlice()
		if err != nil {
			return nil, errors.Wrapf(err, "SMEMBERS %s", fmt.Sprintf("%s#index#%s", ecosystem, q))
		}
		for _, rootID := range rootIDs {
			m[dataTypes.RootID(rootID)] = append(m[dataTypes.RootID(rootID)], q)
		}
	}
	return m, nil
}

func (c *Connection) GetDetection(ecosystem ecosystemTypes.Ecosystem, rootID dataTypes.RootID) (map[sourceTypes.SourceID][]conditionTypes.Condition, error) {
	m, err := c.conn.Do(context.TODO(), c.conn.B().Hgetall().Key(fmt.Sprintf("%s#detection#%s", ecosystem, rootID)).Build()).AsMap()
	if err != nil {
		return nil, errors.Wrapf(err, "HGETALL %s", fmt.Sprintf("%s#detection#%s", ecosystem, rootID))
	}
	if len(m) == 0 {
		return nil, errors.Wrapf(dbTypes.ErrNotFoundDetection, "%s#detection#%s not found", ecosystem, rootID)
	}

	sm := make(map[sourceTypes.SourceID][]conditionTypes.Condition)
	for k, v := range m {
		bs, err := v.AsBytes()
		if err != nil {
			return nil, errors.Wrapf(err, "as bytes %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("%s#detection#%s", ecosystem, rootID), k))
		}

		var conds []conditionTypes.Condition
		if err := util.Unmarshal(bs, &conds); err != nil {
			return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("%s#detection#%s", ecosystem, rootID), k))
		}
		sm[sourceTypes.SourceID(k)] = conds
	}
	return sm, nil
}

func (c *Connection) GetDataSources() ([]datasourceTypes.DataSource, error) {
	m, err := c.conn.Do(context.TODO(), c.conn.B().Hgetall().Key("datasource").Build()).AsMap()
	if err != nil {
		return nil, errors.Wrapf(err, "HGETALL %s", "datasource")
	}
	if len(m) == 0 {
		return nil, errors.Wrapf(dbTypes.ErrNotFoundDataSource, "datasource not found")
	}

	datasources := make([]datasourceTypes.DataSource, 0, len(m))
	for id, v := range m {
		bs, err := v.AsBytes()
		if err != nil {
			return nil, errors.Wrapf(err, "as bytes %s", fmt.Sprintf("%s -> %s", "datasource", id))
		}

		var ds datasourceTypes.DataSource
		if err := util.Unmarshal(bs, &ds); err != nil {
			return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> %s", "datasource", id))
		}
		datasources = append(datasources, ds)
	}

	return datasources, nil
}

func (c *Connection) GetDataSource(id sourceTypes.SourceID) (*datasourceTypes.DataSource, error) {
	bs, err := c.conn.Do(context.TODO(), c.conn.B().Hget().Key("datasource").Field(string(id)).Build()).AsBytes()
	if err != nil {
		if rueidis.IsRedisNil(err) {
			return nil, errors.Wrapf(dbTypes.ErrNotFoundDataSource, "datasource -> %s not found", id)
		}
		return nil, errors.Wrapf(err, "HGET %s %s", "datasource", id)
	}

	var v datasourceTypes.DataSource
	if err := util.Unmarshal(bs, &v); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("datasource -> %s", id))
	}

	return &v, nil
}

func (c *Connection) PutDataSource(root string) error {
	f, err := os.Open(root)
	if err != nil {
		return errors.Wrapf(err, "open %s", root)
	}
	defer f.Close() //nolint:errcheck

	var datasource datasourceTypes.DataSource
	if err := json.NewDecoder(f).Decode(&datasource); err != nil {
		return errors.Wrapf(err, "decode %s", root)
	}

	bs, err := util.Marshal(datasource)
	if err != nil {
		return errors.Wrap(err, "marshal datasource")
	}

	if err := c.conn.Do(context.TODO(), c.conn.B().Hset().Key("datasource").FieldValue().FieldValue(string(datasource.ID), string(bs)).Build()).Error(); err != nil {
		return errors.Wrapf(err, "HSET %s %s %q", "datasource", datasource.ID, string(bs))
	}

	return nil
}

func (c *Connection) DeleteAll() error {
	if err := c.conn.Do(context.TODO(), c.conn.B().Flushdb().Build()).Error(); err != nil {
		return errors.Wrap(err, "FLUSHDB")
	}

	return nil
}

func (c *Connection) Initialize() error {
	return nil
}
