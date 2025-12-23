package db

import (
	"iter"
	"slices"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/common/types"
)

type Connection interface {
	Open() error
	Close() error

	GetMetadata() (*types.Metadata, error)
	PutMetadata(types.Metadata) error

	PutVulnerabilityData(string) error
	GetRoot(dataTypes.RootID) (*types.VulnerabilityData, error)
	GetAdvisory(advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error)
	GetVulnerability(vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error)
	GetEcosystems() ([]ecosystemTypes.Ecosystem, error)
	GetIndexes(ecosystemTypes.Ecosystem, ...string) (map[dataTypes.RootID][]string, error)
	GetDetection(ecosystemTypes.Ecosystem, dataTypes.RootID) (map[sourceTypes.SourceID][]conditionTypes.Condition, error)

	GetDataSources() ([]datasourceTypes.DataSource, error)
	GetDataSource(sourceTypes.SourceID) (*datasourceTypes.DataSource, error)
	PutDataSource(string) error

	DeleteAll() error
	Initialize() error
}

func GetVulnerabilityData(c Connection, searchType types.SearchType, queries ...string) iter.Seq2[types.VulnerabilityData, error] {
	return func(yield func(types.VulnerabilityData, error) bool) {
		switch searchType {
		case types.SearchRoot:
			for _, query := range queries {
				d, err := func() (types.VulnerabilityData, error) {
					root := types.VulnerabilityData{ID: query}

					r, err := c.GetRoot(dataTypes.RootID(query))
					if err != nil {
						if errors.Is(err, types.ErrNotFoundRoot) {
							return types.VulnerabilityData{}, errors.WithStack(err)
						}
						return types.VulnerabilityData{}, errors.Wrap(err, "get root")
					}

					for _, a := range r.Advisories {
						m, err := c.GetAdvisory(a.ID)
						if err != nil {
							if errors.Is(err, types.ErrNotFoundAdvisory) {
								return types.VulnerabilityData{}, errors.WithStack(err)
							}
							return types.VulnerabilityData{}, errors.Wrap(err, "get advisory")
						}
						root.Advisories = append(root.Advisories, types.VulnerabilityDataAdvisory{
							ID:       a.ID,
							Contents: m,
						})
					}

					for _, v := range r.Vulnerabilities {
						m, err := c.GetVulnerability(v.ID)
						if err != nil {
							if errors.Is(err, types.ErrNotFoundVulnerability) {
								return types.VulnerabilityData{}, errors.WithStack(err)
							}
							return types.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
						}
						root.Vulnerabilities = append(root.Vulnerabilities, types.VulnerabilityDataVulnerability{
							ID:       v.ID,
							Contents: m,
						})
					}

					for _, d := range r.Detections {
						m, err := c.GetDetection(d.Ecosystem, dataTypes.RootID(query))
						if err != nil {
							if errors.Is(err, types.ErrNotFoundDetection) {
								return types.VulnerabilityData{}, errors.WithStack(err)
							}
							return types.VulnerabilityData{}, errors.Wrap(err, "get detection")
						}
						root.Detections = append(root.Detections, types.VulnerabilityDataDetection{
							Ecosystem: d.Ecosystem,
							Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{dataTypes.RootID(query): m},
						})
					}

					for _, datasource := range r.DataSources {
						ds, err := c.GetDataSource(datasource.ID)
						if err != nil {
							if errors.Is(err, types.ErrNotFoundDataSource) {
								return types.VulnerabilityData{}, errors.WithStack(err)
							}
							return types.VulnerabilityData{}, errors.Wrap(err, "get datasource")
						}
						root.DataSources = append(root.DataSources, *ds)
					}

					return root, nil
				}()
				if err != nil {
					if errors.Is(err, types.ErrNotFoundRoot) {
						continue
					}
					if !yield(types.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by root id: %s", query)) {
						return
					}
					return
				}
				if !yield(d, err) {
					return
				}
			}
			return
		case types.SearchAdvisory:
			for _, query := range queries {
				d, err := func() (types.VulnerabilityData, error) {
					root := types.VulnerabilityData{ID: query}

					am, err := c.GetAdvisory(advisoryContentTypes.AdvisoryID(query))
					if err != nil {
						if errors.Is(err, types.ErrNotFoundAdvisory) {
							return types.VulnerabilityData{}, errors.WithStack(err)
						}
						return types.VulnerabilityData{}, errors.Wrap(err, "get advisory")
					}
					root.Advisories = []types.VulnerabilityDataAdvisory{
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
								if errors.Is(err, types.ErrNotFoundRoot) {
									return types.VulnerabilityData{}, errors.WithStack(err)
								}
								return types.VulnerabilityData{}, errors.Wrap(err, "get root")
							}

							for _, v := range r.Vulnerabilities {
								if !slices.ContainsFunc(root.Vulnerabilities, func(e types.VulnerabilityDataVulnerability) bool {
									return e.ID == v.ID
								}) {
									vm, err := c.GetVulnerability(v.ID)
									if err != nil {
										if errors.Is(err, types.ErrNotFoundVulnerability) {
											return types.VulnerabilityData{}, errors.WithStack(err)
										}
										return types.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
									}
									root.Vulnerabilities = append(root.Vulnerabilities, types.VulnerabilityDataVulnerability{
										ID:       v.ID,
										Contents: vm,
									})
								}
							}

							for _, d := range r.Detections {
								m, err := c.GetDetection(d.Ecosystem, rootID)
								if err != nil {
									if errors.Is(err, types.ErrNotFoundDetection) {
										return types.VulnerabilityData{}, errors.WithStack(err)
									}
									return types.VulnerabilityData{}, errors.Wrap(err, "get detection")
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
										if errors.Is(err, types.ErrNotFoundDataSource) {
											return types.VulnerabilityData{}, errors.WithStack(err)
										}
										return types.VulnerabilityData{}, errors.Wrap(err, "get datasource")
									}
									root.DataSources = append(root.DataSources, *ds)
								}
							}
						}
					}
					for e, m := range dm {
						root.Detections = append(root.Detections, types.VulnerabilityDataDetection{
							Ecosystem: e,
							Contents:  m,
						})
					}

					return root, nil
				}()
				if err != nil {
					if errors.Is(err, types.ErrNotFoundAdvisory) {
						continue
					}
					if !yield(types.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by advisory id: %s", query)) {
						return
					}
					return
				}
				if !yield(d, err) {
					return
				}
			}
			return
		case types.SearchVulnerability:
			for _, query := range queries {
				d, err := func() (types.VulnerabilityData, error) {
					root := types.VulnerabilityData{ID: query}

					vm, err := c.GetVulnerability(vulnerabilityContentTypes.VulnerabilityID(query))
					if err != nil {
						if errors.Is(err, types.ErrNotFoundVulnerability) {
							return types.VulnerabilityData{}, errors.WithStack(err)
						}
						return types.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
					}
					root.Vulnerabilities = []types.VulnerabilityDataVulnerability{
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
								if errors.Is(err, types.ErrNotFoundRoot) {
									return types.VulnerabilityData{}, errors.WithStack(err)
								}
								return types.VulnerabilityData{}, errors.Wrap(err, "get root")
							}

							for _, a := range r.Advisories {
								if !slices.ContainsFunc(root.Advisories, func(e types.VulnerabilityDataAdvisory) bool {
									return e.ID == a.ID
								}) {
									am, err := c.GetAdvisory(a.ID)
									if err != nil {
										if errors.Is(err, types.ErrNotFoundAdvisory) {
											return types.VulnerabilityData{}, errors.WithStack(err)
										}
										return types.VulnerabilityData{}, errors.Wrap(err, "get advisory")
									}
									root.Advisories = append(root.Advisories, types.VulnerabilityDataAdvisory{
										ID:       a.ID,
										Contents: am,
									})
								}
							}

							for _, d := range r.Detections {
								m, err := c.GetDetection(d.Ecosystem, rootID)
								if err != nil {
									if errors.Is(err, types.ErrNotFoundDetection) {
										return types.VulnerabilityData{}, errors.WithStack(err)
									}
									return types.VulnerabilityData{}, errors.Wrap(err, "get detection")
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
										if errors.Is(err, types.ErrNotFoundDataSource) {
											return types.VulnerabilityData{}, errors.WithStack(err)
										}
										return types.VulnerabilityData{}, errors.Wrap(err, "get datasource")
									}
									root.DataSources = append(root.DataSources, *ds)
								}
							}
						}
					}
					for e, m := range dm {
						root.Detections = append(root.Detections, types.VulnerabilityDataDetection{
							Ecosystem: e,
							Contents:  m,
						})
					}

					return root, nil
				}()
				if err != nil {
					if errors.Is(err, types.ErrNotFoundVulnerability) {
						continue
					}
					if !yield(types.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by vulnerability id: %s", query)) {
						return
					}
					return
				}
				if !yield(d, nil) {
					return
				}
			}
		case types.SearchPackage:
			if len(queries) < 2 {
				if !yield(types.VulnerabilityData{}, errors.Errorf("unexpected queries. expected: %q, actual: %q", []string{"<ecosystem>", "<package>"}, queries)) {
					return
				}
				return
			}

			im, err := c.GetIndexes(ecosystemTypes.Ecosystem(queries[0]), queries[1:]...)
			if err != nil {
				if !yield(types.VulnerabilityData{}, errors.Wrapf(err, "get indexes by ecosystem: %s, packages: %s", queries[0], queries[1:])) {
					return
				}
				return
			}

			for rootID := range im {
				d, err := func() (types.VulnerabilityData, error) {
					root := types.VulnerabilityData{ID: string(rootID)}

					dm, err := c.GetDetection(ecosystemTypes.Ecosystem(queries[0]), rootID)
					if err != nil {
						if errors.Is(err, types.ErrNotFoundDetection) {
							return types.VulnerabilityData{}, errors.WithStack(err)
						}
						return types.VulnerabilityData{}, errors.Wrap(err, "get detection")
					}
					root.Detections = []types.VulnerabilityDataDetection{
						{
							Ecosystem: ecosystemTypes.Ecosystem(queries[0]),
							Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{rootID: dm},
						},
					}

					r, err := c.GetRoot(rootID)
					if err != nil {
						if errors.Is(err, types.ErrNotFoundRoot) {
							return types.VulnerabilityData{}, errors.WithStack(err)
						}
						return types.VulnerabilityData{}, errors.Wrap(err, "get root")
					}

					for _, a := range r.Advisories {
						m, err := c.GetAdvisory(a.ID)
						if err != nil {
							if errors.Is(err, types.ErrNotFoundAdvisory) {
								return types.VulnerabilityData{}, errors.WithStack(err)
							}
							return types.VulnerabilityData{}, errors.Wrap(err, "get advisory")
						}
						root.Advisories = append(root.Advisories, types.VulnerabilityDataAdvisory{
							ID:       a.ID,
							Contents: m,
						})
					}

					for _, v := range r.Vulnerabilities {
						m, err := c.GetVulnerability(v.ID)
						if err != nil {
							if errors.Is(err, types.ErrNotFoundVulnerability) {
								return types.VulnerabilityData{}, errors.WithStack(err)
							}
							return types.VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
						}
						root.Vulnerabilities = append(root.Vulnerabilities, types.VulnerabilityDataVulnerability{
							ID:       v.ID,
							Contents: m,
						})
					}

					for _, datasource := range r.DataSources {
						ds, err := c.GetDataSource(datasource.ID)
						if err != nil {
							if errors.Is(err, types.ErrNotFoundDataSource) {
								return types.VulnerabilityData{}, errors.WithStack(err)
							}
							return types.VulnerabilityData{}, errors.Wrap(err, "get datasource")
						}
						root.DataSources = append(root.DataSources, *ds)
					}

					return root, nil
				}()
				if err != nil {
					if !yield(types.VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by root id: %s", rootID)) {
						return
					}
					return
				}
				if !yield(d, nil) {
					return
				}
			}
		default:
			if !yield(types.VulnerabilityData{}, errors.Errorf("unexpected search type. expected: %q, actual: %s", []types.SearchType{types.SearchRoot, types.SearchAdvisory, types.SearchVulnerability, types.SearchPackage}, searchType)) {
				return
			}
		}
	}
}
