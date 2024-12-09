package types

import (
	"slices"
	"time"

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

type SearchDetectionType string

const (
	SearchDetectionPkg           SearchDetectionType = "pkg"
	SearchDetectionRoot          SearchDetectionType = "root"
	SearchDetectionAdvisory      SearchDetectionType = "advisory"
	SearchDetectionVulnerability SearchDetectionType = "vulnerability"
)

type SearchDataType string

const (
	SearchDataRoot          SearchDataType = "root"
	SearchDataAdvisory      SearchDataType = "advisory"
	SearchDataVulnerability SearchDataType = "vulnerability"
)

type Metadata struct {
	SchemaVersion uint       `json:"schema_version"`
	CreatedBy     string     `json:"created_by,omitempty"`
	LastModified  time.Time  `json:"last_modified,omitempty"`
	Downloaded    *time.Time `json:"downloaded,omitempty"`
}

type VulnerabilityData struct {
	ID              string                           `json:"id,omitempty"`
	Advisories      []VulnerabilityDataAdvisory      `json:"advisories,omitempty"`
	Vulnerabilities []VulnerabilityDataVulnerability `json:"vulnerabilities,omitempty"`
	Detections      []VulnerabilityDataDetection     `json:"detections,omitempty"`
	DataSources     []datasourceTypes.DataSource     `json:"data_sources,omitempty"`
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
