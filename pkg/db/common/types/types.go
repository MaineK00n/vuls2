package types

import (
	"fmt"
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

type Filter struct {
	Contents   []FilterContentType
	RootIDs    []dataTypes.RootID
	Ecosystems []ecosystemTypes.Ecosystem
}

type FilterContentType int

const (
	FilterContentTypeAdvisories FilterContentType = iota + 1
	FilterContentTypeVulnerabilities
	FilterContentTypeDetections
	FilterContentTypeDataSources
)

func NewFilterContentType(s string) (FilterContentType, error) {
	switch s {
	case "advisories":
		return FilterContentTypeAdvisories, nil
	case "vulnerabilities":
		return FilterContentTypeVulnerabilities, nil
	case "detections":
		return FilterContentTypeDetections, nil
	case "datasources":
		return FilterContentTypeDataSources, nil
	default:
		return 0, errors.Errorf("unexpected content type. expected: %q, actual: %q", []string{"advisories", "vulnerabilities", "detections", "datasources"}, s)
	}
}

func AllFilterContentTypes() []FilterContentType {
	return []FilterContentType{
		FilterContentTypeAdvisories,
		FilterContentTypeVulnerabilities,
		FilterContentTypeDetections,
		FilterContentTypeDataSources,
	}
}

func (f FilterContentType) String() string {
	switch f {
	case FilterContentTypeAdvisories:
		return "advisories"
	case FilterContentTypeVulnerabilities:
		return "vulnerabilities"
	case FilterContentTypeDetections:
		return "detections"
	case FilterContentTypeDataSources:
		return "datasources"
	default:
		return fmt.Sprintf("unknown(%d)", f)
	}
}

func (f Filter) ApplyShallowly(v VulnerabilityData) VulnerabilityData {
	if !slices.Contains(f.Contents, FilterContentTypeAdvisories) {
		v.Advisories = nil
	}
	if !slices.Contains(f.Contents, FilterContentTypeVulnerabilities) {
		v.Vulnerabilities = nil
	}
	if !slices.Contains(f.Contents, FilterContentTypeDetections) {
		v.Detections = nil
	}
	if !slices.Contains(f.Contents, FilterContentTypeDataSources) {
		v.DataSources = nil
	}

	return v
}

func (f Filter) ApplyToAdvisories(asmm map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory) map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory {
	if len(f.RootIDs) == 0 && len(f.Ecosystems) == 0 {
		return asmm
	}

	filtered := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory)
	for sid, asm := range asmm {
		for rid, as := range asm {
			if f.ExcludesRootId(rid) {
				continue
			}

			for _, a := range as {
				ss := make([]segmentTypes.Segment, 0, len(a.Segments))
				for _, s := range a.Segments {
					if f.ExcludesEcosystem(s.Ecosystem) {
						continue
					}
					ss = append(ss, s)
				}
				if len(ss) == 0 {
					continue
				}
				a.Segments = ss

				if _, found := filtered[sid]; !found {
					filtered[sid] = make(map[dataTypes.RootID][]advisoryTypes.Advisory)
				}
				filtered[sid][rid] = append(filtered[sid][rid], a)
			}
		}
	}

	return filtered
}

func (f Filter) ApplyToVulnerabilities(vsmm map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability) map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability {
	if len(f.RootIDs) == 0 && len(f.Ecosystems) == 0 {
		return vsmm
	}

	filtered := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
	for sid, vsm := range vsmm {
		for rid, vs := range vsm {
			if f.ExcludesRootId(rid) {
				continue
			}

			for _, v := range vs {
				ss := make([]segmentTypes.Segment, 0, len(v.Segments))
				for _, s := range v.Segments {
					if f.ExcludesEcosystem(s.Ecosystem) {
						continue
					}
					ss = append(ss, s)
				}
				if len(ss) == 0 {
					continue
				}
				v.Segments = ss

				if _, found := filtered[sid]; !found {
					filtered[sid] = make(map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
				}
				filtered[sid][rid] = append(filtered[sid][rid], v)
			}
		}
	}

	return filtered
}

func (f Filter) ApplyToEcosystems(es []ecosystemTypes.Ecosystem) []ecosystemTypes.Ecosystem {
	if len(f.Ecosystems) == 0 {
		return es
	}

	filtered := make([]ecosystemTypes.Ecosystem, 0, len(es))
	for _, e := range es {
		if !f.ExcludesEcosystem(e) {
			filtered = append(filtered, e)
		}
	}

	return filtered
}

func (f Filter) ExcludesRootId(rid dataTypes.RootID) bool {
	if len(f.RootIDs) == 0 {
		return false
	}
	return !slices.Contains(f.RootIDs, rid)
}

func (f Filter) ExcludesEcosystem(e ecosystemTypes.Ecosystem) bool {
	if len(f.Ecosystems) == 0 {
		return false
	}
	return !slices.Contains(f.Ecosystems, e)
}
