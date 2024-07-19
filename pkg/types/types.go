package types

import (
	"slices"

	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

type VulnerabilityData struct {
	ID              string                           `json:"id,omitempty"`
	Advisories      []VulnerabilityDataAdvisory      `json:"advisories,omitempty"`
	Vulnerabilities []VulnerabilityDataVulnerability `json:"vulnerabilities,omitempty"`
	Detections      []VulnerabilityDataDetection     `json:"detections,omitempty"`
	DataSources     []datasourceTypes.DataSource     `json:"data_sources,omitempty"`
}

type VulnerabilityDataAdvisory struct {
	ID       string                                                              `json:"id,omitempty"`
	Contents map[sourceTypes.SourceID]map[string][]dbTypes.VulnerabilityAdvisory `json:"contents,omitempty"`
}

type VulnerabilityDataVulnerability struct {
	ID       string                                                                   `json:"id,omitempty"`
	Contents map[sourceTypes.SourceID]map[string][]dbTypes.VulnerabilityVulnerability `json:"contents,omitempty"`
}

type VulnerabilityDataDetection struct {
	Ecosystem detectionTypes.Ecosystem                                   `json:"ecosystem,omitempty"`
	Contents  map[sourceTypes.SourceID]map[string]criteriaTypes.Criteria `json:"contents,omitempty"`
}

func (data VulnerabilityData) Filter(ecosystems ...detectionTypes.Ecosystem) VulnerabilityData {
	filtered := VulnerabilityData{ID: data.ID}
	srcs := map[sourceTypes.SourceID]struct{}{}
	for _, adv := range data.Advisories {
		a := VulnerabilityDataAdvisory{ID: adv.ID, Contents: map[sourceTypes.SourceID]map[string][]dbTypes.VulnerabilityAdvisory{}}
		for sid, m := range adv.Contents {
			for rid, cs := range m {
				for _, c := range cs {
					if slices.ContainsFunc(c.Ecosystems, func(e detectionTypes.Ecosystem) bool {
						return slices.Contains(ecosystems, e)
					}) {
						sm, ok := a.Contents[sid]
						if !ok {
							sm = map[string][]dbTypes.VulnerabilityAdvisory{}
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
		v := VulnerabilityDataVulnerability{ID: vuln.ID, Contents: map[sourceTypes.SourceID]map[string][]dbTypes.VulnerabilityVulnerability{}}
		for sid, m := range vuln.Contents {
			for rid, cs := range m {
				for _, c := range cs {
					if slices.ContainsFunc(c.Ecosystems, func(e detectionTypes.Ecosystem) bool {
						return slices.Contains(ecosystems, e)
					}) {
						sm, ok := v.Contents[sid]
						if !ok {
							sm = map[string][]dbTypes.VulnerabilityVulnerability{}
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
			for id := range d.Contents {
				srcs[id] = struct{}{}
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
