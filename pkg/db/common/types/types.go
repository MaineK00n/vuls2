package types

import (
	"time"
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
	Ecosystems      []string `json:"ecosystems,omitempty"`
}

// FIXME(shino): rewrite following lines

// boltdb: vulnerability:advisory:<Advisory ID>:<Source ID>:<Root ID> -> []advisoryTypes.Advisory

// boltdb: vulnerability:vulnerability:<CVE ID>:<Source ID>:<Root ID> -> []vulnerabilityTypes.Vulnerability

// boltdb: detection:<Root ID>:<Source ID>:<ecosystem> -> criteriaTypes.Criteria

// boltdb: <ecosystem>:<package>:<Root ID>:<Source ID> -> detection:<Root ID>:<Source ID>:<ecosystem>

// boltdb: datasource:<Source ID>
