package db

import (
	"iter"
	"slices"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

type Connection interface {
	Open() error
	Close() error

	GetMetadata() (*Metadata, error)
	PutMetadata(Metadata) error

	PutVulnerabilityData(string) error
	GetRoot(dataTypes.RootID) (*VulnerabilityData, error)
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

var (
	ErrNotFoundMetadata      = errors.New("metadata not found")
	ErrNotFoundRoot          = errors.New("root not found")
	ErrNotFoundAdvisory      = errors.New("advisory not found")
	ErrNotFoundVulnerability = errors.New("vulnerability not found")
	ErrNotFoundDetection     = errors.New("detection not found")
	ErrNotFoundDataSource    = errors.New("datasource not found")
)

type SearchType string

const (
	SearchRoot          SearchType = "root"
	SearchAdvisory      SearchType = "advisory"
	SearchVulnerability SearchType = "vulnerability"
	SearchPackage       SearchType = "package"
	SearchMetadata      SearchType = "metadata"
	SearchDataSources   SearchType = "datasources"
	SearchEcosystems    SearchType = "ecosystems"
)

type Metadata struct {
	SchemaVersion uint       `json:"schema_version"`
	CreatedBy     string     `json:"created_by,omitempty"`
	LastModified  time.Time  `json:"last_modified,omitempty"`
	Digest        *string    `json:"digest,omitempty"`
	Downloaded    *time.Time `json:"downloaded,omitempty"`
}

type VulnerabilityData struct {
	ID              string                           `json:"id,omitempty"`
	Advisories      []VulnerabilityDataAdvisory      `json:"advisories,omitempty"`
	Vulnerabilities []VulnerabilityDataVulnerability `json:"vulnerabilities,omitempty"`
	Detections      []VulnerabilityDataDetection     `json:"detections,omitempty"`
	DataSources     []datasourceTypes.DataSource     `json:"datasources,omitempty"`
}

type VulnerabilityDataAdvisory struct {
	ID       advisoryContentTypes.AdvisoryID                                        `json:"id,omitempty"`
	Contents map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory `json:"contents,omitempty"`
}

type VulnerabilityDataVulnerability struct {
	ID       vulnerabilityContentTypes.VulnerabilityID                                        `json:"id,omitempty"`
	Contents map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability `json:"contents,omitempty"`
}

type VulnerabilityDataDetection struct {
	Ecosystem ecosystemTypes.Ecosystem                                                 `json:"ecosystem,omitempty"`
	Contents  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition `json:"contents,omitempty"`
}

func GetVulnerabilityData(c Connection, searchType SearchType, queries ...string) iter.Seq2[VulnerabilityData, error] {
	return func(yield func(VulnerabilityData, error) bool) {
		switch searchType {
		case SearchRoot:
			for _, query := range queries {
				d, err := func() (VulnerabilityData, error) {
					root := VulnerabilityData{ID: query}

					r, err := c.GetRoot(dataTypes.RootID(query))
					if err != nil {
						if errors.Is(err, ErrNotFoundRoot) {
							return VulnerabilityData{}, errors.WithStack(err)
						}
						return VulnerabilityData{}, errors.Wrap(err, "get root")
					}

					for _, a := range r.Advisories {
						m, err := c.GetAdvisory(a.ID)
						if err != nil {
							if errors.Is(err, ErrNotFoundAdvisory) {
								return VulnerabilityData{}, errors.WithStack(err)
							}
							return VulnerabilityData{}, errors.Wrap(err, "get advisory")
						}
						root.Advisories = append(root.Advisories, VulnerabilityDataAdvisory{
							ID:       a.ID,
							Contents: m,
						})
					}

					for _, v := range r.Vulnerabilities {
						m, err := c.GetVulnerability(v.ID)
						if err != nil {
							if errors.Is(err, ErrNotFoundVulnerability) {
								return VulnerabilityData{}, errors.WithStack(err)
							}
							return VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
						}
						root.Vulnerabilities = append(root.Vulnerabilities, VulnerabilityDataVulnerability{
							ID:       v.ID,
							Contents: m,
						})
					}

					for _, d := range r.Detections {
						m, err := c.GetDetection(d.Ecosystem, dataTypes.RootID(query))
						if err != nil {
							if errors.Is(err, ErrNotFoundDetection) {
								return VulnerabilityData{}, errors.WithStack(err)
							}
							return VulnerabilityData{}, errors.Wrap(err, "get detection")
						}
						root.Detections = append(root.Detections, VulnerabilityDataDetection{
							Ecosystem: d.Ecosystem,
							Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{dataTypes.RootID(query): m},
						})
					}

					for _, datasource := range r.DataSources {
						ds, err := c.GetDataSource(datasource.ID)
						if err != nil {
							if errors.Is(err, ErrNotFoundDataSource) {
								return VulnerabilityData{}, errors.WithStack(err)
							}
							return VulnerabilityData{}, errors.Wrap(err, "get datasource")
						}
						root.DataSources = append(root.DataSources, *ds)
					}

					return root, nil
				}()
				if err != nil {
					if errors.Is(err, ErrNotFoundRoot) {
						continue
					}
					if !yield(VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by root id: %s", query)) {
						return
					}
					return
				}
				if !yield(d, err) {
					return
				}
			}
			return
		case SearchAdvisory:
			for _, query := range queries {
				d, err := func() (VulnerabilityData, error) {
					root := VulnerabilityData{ID: query}

					am, err := c.GetAdvisory(advisoryContentTypes.AdvisoryID(query))
					if err != nil {
						if errors.Is(err, ErrNotFoundAdvisory) {
							return VulnerabilityData{}, errors.WithStack(err)
						}
						return VulnerabilityData{}, errors.Wrap(err, "get advisory")
					}
					root.Advisories = []VulnerabilityDataAdvisory{
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
								if errors.Is(err, ErrNotFoundRoot) {
									return VulnerabilityData{}, errors.WithStack(err)
								}
								return VulnerabilityData{}, errors.Wrap(err, "get root")
							}

							for _, v := range r.Vulnerabilities {
								if !slices.ContainsFunc(root.Vulnerabilities, func(e VulnerabilityDataVulnerability) bool {
									return e.ID == v.ID
								}) {
									vm, err := c.GetVulnerability(v.ID)
									if err != nil {
										if errors.Is(err, ErrNotFoundVulnerability) {
											return VulnerabilityData{}, errors.WithStack(err)
										}
										return VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
									}
									root.Vulnerabilities = append(root.Vulnerabilities, VulnerabilityDataVulnerability{
										ID:       v.ID,
										Contents: vm,
									})
								}
							}

							for _, d := range r.Detections {
								m, err := c.GetDetection(d.Ecosystem, rootID)
								if err != nil {
									if errors.Is(err, ErrNotFoundDetection) {
										return VulnerabilityData{}, errors.WithStack(err)
									}
									return VulnerabilityData{}, errors.Wrap(err, "get detection")
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
										if errors.Is(err, ErrNotFoundDataSource) {
											return VulnerabilityData{}, errors.WithStack(err)
										}
										return VulnerabilityData{}, errors.Wrap(err, "get datasource")
									}
									root.DataSources = append(root.DataSources, *ds)
								}
							}
						}
					}
					for e, m := range dm {
						root.Detections = append(root.Detections, VulnerabilityDataDetection{
							Ecosystem: e,
							Contents:  m,
						})
					}

					return root, nil
				}()
				if err != nil {
					if errors.Is(err, ErrNotFoundAdvisory) {
						continue
					}
					if !yield(VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by advisory id: %s", query)) {
						return
					}
					return
				}
				if !yield(d, err) {
					return
				}
			}
			return
		case SearchVulnerability:
			for _, query := range queries {
				d, err := func() (VulnerabilityData, error) {
					root := VulnerabilityData{ID: query}

					vm, err := c.GetVulnerability(vulnerabilityContentTypes.VulnerabilityID(query))
					if err != nil {
						if errors.Is(err, ErrNotFoundVulnerability) {
							return VulnerabilityData{}, errors.WithStack(err)
						}
						return VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
					}
					root.Vulnerabilities = []VulnerabilityDataVulnerability{
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
								if errors.Is(err, ErrNotFoundRoot) {
									return VulnerabilityData{}, errors.WithStack(err)
								}
								return VulnerabilityData{}, errors.Wrap(err, "get root")
							}

							for _, a := range r.Advisories {
								if !slices.ContainsFunc(root.Advisories, func(e VulnerabilityDataAdvisory) bool {
									return e.ID == a.ID
								}) {
									am, err := c.GetAdvisory(a.ID)
									if err != nil {
										if errors.Is(err, ErrNotFoundAdvisory) {
											return VulnerabilityData{}, errors.WithStack(err)
										}
										return VulnerabilityData{}, errors.Wrap(err, "get advisory")
									}
									root.Advisories = append(root.Advisories, VulnerabilityDataAdvisory{
										ID:       a.ID,
										Contents: am,
									})
								}
							}

							for _, d := range r.Detections {
								m, err := c.GetDetection(d.Ecosystem, rootID)
								if err != nil {
									if errors.Is(err, ErrNotFoundDetection) {
										return VulnerabilityData{}, errors.WithStack(err)
									}
									return VulnerabilityData{}, errors.Wrap(err, "get detection")
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
										if errors.Is(err, ErrNotFoundDataSource) {
											return VulnerabilityData{}, errors.WithStack(err)
										}
										return VulnerabilityData{}, errors.Wrap(err, "get datasource")
									}
									root.DataSources = append(root.DataSources, *ds)
								}
							}
						}
					}
					for e, m := range dm {
						root.Detections = append(root.Detections, VulnerabilityDataDetection{
							Ecosystem: e,
							Contents:  m,
						})
					}

					return root, nil
				}()
				if err != nil {
					if errors.Is(err, ErrNotFoundVulnerability) {
						continue
					}
					if !yield(VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by vulnerability id: %s", query)) {
						return
					}
					return
				}
				if !yield(d, nil) {
					return
				}
			}
		case SearchPackage:
			if len(queries) < 2 {
				if !yield(VulnerabilityData{}, errors.Errorf("unexpected queries. expected: %q, actual: %q", []string{"<ecosystem>", "<package>"}, queries)) {
					return
				}
				return
			}

			im, err := c.GetIndexes(ecosystemTypes.Ecosystem(queries[0]), queries[1:]...)
			if err != nil {
				if !yield(VulnerabilityData{}, errors.Wrapf(err, "get indexes by ecosystem: %s, packages: %s", queries[0], queries[1:])) {
					return
				}
				return
			}

			for rootID := range im {
				d, err := func() (VulnerabilityData, error) {
					root := VulnerabilityData{ID: string(rootID)}

					dm, err := c.GetDetection(ecosystemTypes.Ecosystem(queries[0]), rootID)
					if err != nil {
						if errors.Is(err, ErrNotFoundDetection) {
							return VulnerabilityData{}, errors.WithStack(err)
						}
						return VulnerabilityData{}, errors.Wrap(err, "get detection")
					}
					root.Detections = []VulnerabilityDataDetection{
						{
							Ecosystem: ecosystemTypes.Ecosystem(queries[0]),
							Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{rootID: dm},
						},
					}

					r, err := c.GetRoot(rootID)
					if err != nil {
						if errors.Is(err, ErrNotFoundRoot) {
							return VulnerabilityData{}, errors.WithStack(err)
						}
						return VulnerabilityData{}, errors.Wrap(err, "get root")
					}

					for _, a := range r.Advisories {
						m, err := c.GetAdvisory(a.ID)
						if err != nil {
							if errors.Is(err, ErrNotFoundAdvisory) {
								return VulnerabilityData{}, errors.WithStack(err)
							}
							return VulnerabilityData{}, errors.Wrap(err, "get advisory")
						}
						root.Advisories = append(root.Advisories, VulnerabilityDataAdvisory{
							ID:       a.ID,
							Contents: m,
						})
					}

					for _, v := range r.Vulnerabilities {
						m, err := c.GetVulnerability(v.ID)
						if err != nil {
							if errors.Is(err, ErrNotFoundVulnerability) {
								return VulnerabilityData{}, errors.WithStack(err)
							}
							return VulnerabilityData{}, errors.Wrap(err, "get vulnerability")
						}
						root.Vulnerabilities = append(root.Vulnerabilities, VulnerabilityDataVulnerability{
							ID:       v.ID,
							Contents: m,
						})
					}

					for _, datasource := range r.DataSources {
						ds, err := c.GetDataSource(datasource.ID)
						if err != nil {
							if errors.Is(err, ErrNotFoundDataSource) {
								return VulnerabilityData{}, errors.WithStack(err)
							}
							return VulnerabilityData{}, errors.Wrap(err, "get datasource")
						}
						root.DataSources = append(root.DataSources, *ds)
					}

					return root, nil
				}()
				if err != nil {
					if !yield(VulnerabilityData{}, errors.Wrapf(err, "get vulnerability data by root id: %s", rootID)) {
						return
					}
					return
				}
				if !yield(d, nil) {
					return
				}
			}
		default:
			if !yield(VulnerabilityData{}, errors.Errorf("unexpected search type. expected: %q, actual: %s", []SearchType{SearchRoot, SearchAdvisory, SearchVulnerability, SearchPackage}, searchType)) {
				return
			}
		}
	}
}

func (data VulnerabilityData) Filter(ecosystems ...ecosystemTypes.Ecosystem) VulnerabilityData {
	filtered := VulnerabilityData{ID: data.ID}
	srcs := make(map[sourceTypes.SourceID]struct{})
	for _, adv := range data.Advisories {
		a := VulnerabilityDataAdvisory{ID: adv.ID, Contents: make(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory)}
		for sid, m := range adv.Contents {
			for rid, cs := range m {
				for _, c := range cs {
					if slices.ContainsFunc(c.Segments, func(s segmentTypes.Segment) bool {
						return slices.Contains(ecosystems, s.Ecosystem)
					}) {
						sm, ok := a.Contents[sid]
						if !ok {
							sm = make(map[dataTypes.RootID][]advisoryTypes.Advisory)
						}
						sm[rid] = append(sm[rid], c)
						a.Contents[sid] = sm
						srcs[sid] = struct{}{}
					}
				}
			}
		}
		if len(a.Contents) > 0 {
			filtered.Advisories = append(filtered.Advisories, a)
		}
	}

	for _, vuln := range data.Vulnerabilities {
		v := VulnerabilityDataVulnerability{ID: vuln.ID, Contents: make(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)}
		for sid, m := range vuln.Contents {
			for rid, cs := range m {
				for _, c := range cs {
					if slices.ContainsFunc(c.Segments, func(s segmentTypes.Segment) bool {
						return slices.Contains(ecosystems, s.Ecosystem)
					}) {
						sm, ok := v.Contents[sid]
						if !ok {
							sm = make(map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
						}
						sm[rid] = append(sm[rid], c)
						v.Contents[sid] = sm
						srcs[sid] = struct{}{}
					}
				}
			}
		}
		if len(v.Contents) > 0 {
			filtered.Vulnerabilities = append(filtered.Vulnerabilities, v)
		}
	}

	for _, d := range data.Detections {
		if slices.Contains(ecosystems, d.Ecosystem) {
			filtered.Detections = append(filtered.Detections, d)
			for _, m := range d.Contents {
				for id := range m {
					srcs[id] = struct{}{}
				}
			}
		}
	}

	for _, src := range data.DataSources {
		if _, ok := srcs[src.ID]; ok {
			filtered.DataSources = append(filtered.DataSources, src)
		}
	}

	return filtered
}
