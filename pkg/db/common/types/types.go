package types

import (
	"time"

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
