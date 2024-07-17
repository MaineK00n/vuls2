package types

import (
	"slices"
	"time"

	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// metadata
type Metadata struct {
	SchemaVersion uint      `json:"schema_version,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	LastModified  time.Time `json:"last_modified,omitempty"`
}

type VulnerabilityData struct {
	ID              string                           `json:"id,omitempty"`
	Advisories      []VulnerabilityDataAdvisory      `json:"advisories,omitempty"`
	Vulnerabilities []VulnerabilityDataVulnerability `json:"vulnerabilities,omitempty"`
	Detections      []VulnerabilityDataDetection     `json:"detections,omitempty"`
	DataSources     []datasourceTypes.DataSource     `json:"data_sources,omitempty"`
}

type VulnerabilityDataAdvisory struct {
	ID       string                                                      `json:"id,omitempty"`
	Contents map[sourceTypes.SourceID]map[string][]VulnerabilityAdvisory `json:"contents,omitempty"`
}

type VulnerabilityDataVulnerability struct {
	ID       string                                                           `json:"id,omitempty"`
	Contents map[sourceTypes.SourceID]map[string][]VulnerabilityVulnerability `json:"contents,omitempty"`
}

type VulnerabilityDataDetection struct {
	Ecosystem detectionTypes.Ecosystem                            `json:"ecosystem,omitempty"`
	Contents  map[sourceTypes.SourceID][]detectionTypes.Detection `json:"contents,omitempty"`
}

func (v VulnerabilityData) Filter(ecosystems ...detectionTypes.Ecosystem) VulnerabilityData {
	filtered := VulnerabilityData{ID: v.ID}
	srcs := map[sourceTypes.SourceID]struct{}{}
	for _, adv := range v.Advisories {
		a := VulnerabilityDataAdvisory{ID: adv.ID, Contents: map[sourceTypes.SourceID]map[string][]VulnerabilityAdvisory{}}
		for sid, m := range adv.Contents {
			for rid, cs := range m {
				for _, c := range cs {
					if slices.ContainsFunc(c.Ecosystems, func(e detectionTypes.Ecosystem) bool {
						return slices.Contains(ecosystems, e)
					}) {
						sm, ok := a.Contents[sid]
						if !ok {
							sm = map[string][]VulnerabilityAdvisory{}
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

	for _, vuln := range v.Vulnerabilities {
		v := VulnerabilityDataVulnerability{ID: v.ID, Contents: map[sourceTypes.SourceID]map[string][]VulnerabilityVulnerability{}}
		for sid, m := range vuln.Contents {
			for rid, cs := range m {
				for _, c := range cs {
					if slices.ContainsFunc(c.Ecosystems, func(e detectionTypes.Ecosystem) bool {
						return slices.Contains(ecosystems, e)
					}) {
						sm, ok := v.Contents[sid]
						if !ok {
							sm = map[string][]VulnerabilityVulnerability{}
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

	for _, d := range v.Detections {
		if slices.Contains(ecosystems, d.Ecosystem) {
			filtered.Detections = append(filtered.Detections, d)
			for id := range d.Contents {
				srcs[id] = struct{}{}
			}
		}
	}

	for _, src := range v.DataSources {
		if _, ok := srcs[src.ID]; ok {
			filtered.DataSources = append(filtered.DataSources, src)
		}
	}

	return filtered
}

// vulnerability:root:<Root ID>
type VulnerabilityRoot struct {
	ID              string     `json:"id,omitempty"`
	Advisories      [][]string `json:"advisories,omitempty"`
	Vulnerabilities [][]string `json:"vulnerabilities,omitempty"`
	Detections      [][]string `json:"detections,omitempty"`
	DataSources     []string   `json:"data_sources,omitempty"`
}

// vulnerability:advisory:<Advisory ID>:<Source ID>:<Root ID> -> []VulnerabilityAdvisory
type VulnerabilityAdvisory struct {
	Content    advisoryTypes.Advisory     `json:"content,omitempty"`
	Ecosystems []detectionTypes.Ecosystem `json:"ecosystems,omitempty"`
}

// vulnerability:vulnerability:<CVE ID>:<Source ID>:<Root ID> -> []VulnerabilityVulnerability
type VulnerabilityVulnerability struct {
	Content    vulnerabilityTypes.Vulnerability `json:"content,omitempty"`
	Ecosystems []detectionTypes.Ecosystem       `json:"ecosystems,omitempty"`
}

// <ecosystem>:<package>:<Root ID>:<Source ID> -> []detectionTypes.Detection

// datasource:<Source ID>
