package types

import (
	"time"
)

type Metadata struct {
	SchemaVersion uint      `json:"schema_version,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	LastModified  time.Time `json:"last_modified,omitempty"`
}

type VulnerabilityRoot struct {
	ID              string   `json:"id,omitempty"`
	Advisories      []string `json:"advisories,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	Ecosystems      []string `json:"ecosystems,omitempty"`
	DataSources     []string `json:"data_sources,omitempty"`
}
