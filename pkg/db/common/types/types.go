package types

import (
	"time"

	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
)

// boltdb: metadata:db
type Metadata struct {
	SchemaVersion uint      `json:"schema_version,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	LastModified  time.Time `json:"last_modified,omitempty"`
}

// boltdb: vulnerability:root:<Root ID>
type VulnerabilityRoot struct {
	ID              string   `json:"id,omitempty"`
	Advisories      []string `json:"advisories,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	DataSources     []string `json:"data_sources,omitempty"`
}

// boltdb: vulnerability:advisory:<Advisory ID>:<Source ID>:<Root ID> -> []VulnerabilityAdvisory
type VulnerabilityAdvisory struct {
	Content    advisoryTypes.Advisory     `json:"content,omitempty"`
	Ecosystems []detectionTypes.Ecosystem `json:"ecosystems,omitempty"`
}

// boltdb: vulnerability:vulnerability:<CVE ID>:<Source ID>:<Root ID> -> []VulnerabilityVulnerability
type VulnerabilityVulnerability struct {
	Content    vulnerabilityTypes.Vulnerability `json:"content,omitempty"`
	Ecosystems []detectionTypes.Ecosystem       `json:"ecosystems,omitempty"`
}

// boltdb: detection:<Root ID>:<Source ID>:<ecosystem> -> criteriaTypes.Criteria

// boltdb: <ecosystem>:<package>:<Root ID>:<Source ID> -> detection:<Root ID>:<Source ID>:<ecosystem>

// boltdb: datasource:<Source ID>
